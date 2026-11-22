use crate::config::MeConfigBundle;
use crate::conn::{MeConnCounters, MeConnOptions, MeConnection, MeSession};
use crate::wire::MeClientProto;
use anyhow::{ensure, Result};
use mtevil_egress::compute_egress_cooldown;
use std::collections::HashMap;
use std::net::SocketAddrV4;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::Notify;

#[derive(Clone, Debug)]
pub struct MePoolConfig {
    pub conns_per_dc: usize,
    pub reconnect_base: Duration,
    pub reconnect_max: Duration,
    /// Grace period to drain existing sessions on old ME connections after `update_config`.
    pub drain_timeout: Duration,
    pub conn_opts: MeConnOptions,
}

impl Default for MePoolConfig {
    fn default() -> Self {
        Self {
            conns_per_dc: 2,
            reconnect_base: Duration::from_secs(1),
            reconnect_max: Duration::from_secs(30),
            drain_timeout: Duration::from_secs(60),
            conn_opts: MeConnOptions::default(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MePoolHealth {
    pub configured_dcs: usize,
    pub alive_connections: usize,
    pub total_slots: usize,
    pub degraded: bool,
    pub backpressure_drops: u64,
    pub dropped_close_ext: u64,
}

struct DcPoolSlot {
    conn: Option<MeConnection>,
}

struct PoolInner {
    bundle: MeConfigBundle,
    slots: HashMap<i16, Vec<DcPoolSlot>>,
    draining: HashMap<i16, Vec<MeConnection>>,
    generation: u64,
}

struct WorkerGuard {
    active_workers: Arc<AtomicUsize>,
}

impl Drop for WorkerGuard {
    fn drop(&mut self) {
        self.active_workers.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Multiplexed Telegram Middle-End connection pool with per-DC reconnect (backoff + jitter)
/// and seamless hot config swap (graceful drain of existing sessions).
#[derive(Clone)]
pub struct MePool {
    inner: Arc<Mutex<PoolInner>>,
    cfg: MePoolConfig,
    rr: Arc<AtomicUsize>,
    stopped: Arc<AtomicBool>,
    stop_notify: Arc<Notify>,
    counters: Arc<MeConnCounters>,
    active_workers: Arc<AtomicUsize>,
}

impl MePool {
    pub fn start(bundle: MeConfigBundle, cfg: MePoolConfig) -> Self {
        let conns_per_dc = cfg.conns_per_dc.clamp(1, 16);
        let mut cfg = cfg;
        cfg.conns_per_dc = conns_per_dc;

        let mut slots = HashMap::new();
        for &dc in bundle.proxy_conf.dcs.keys() {
            slots.insert(
                dc,
                (0..conns_per_dc)
                    .map(|_| DcPoolSlot { conn: None })
                    .collect(),
            );
        }

        let pool = Self {
            inner: Arc::new(Mutex::new(PoolInner {
                bundle,
                slots,
                draining: HashMap::new(),
                generation: 1,
            })),
            cfg,
            rr: Arc::new(AtomicUsize::new(0)),
            stopped: Arc::new(AtomicBool::new(false)),
            stop_notify: Arc::new(Notify::new()),
            counters: Arc::new(MeConnCounters::default()),
            active_workers: Arc::new(AtomicUsize::new(0)),
        };
        pool.spawn_workers_for_generation(1);
        pool
    }

    fn spawn_workers_for_generation(&self, generation: u64) {
        let dc_list: Vec<i16> = {
            let guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            guard.bundle.proxy_conf.dcs.keys().copied().collect()
        };
        for dc in dc_list {
            for slot_idx in 0..self.cfg.conns_per_dc {
                let pool = self.clone();
                self.active_workers.fetch_add(1, Ordering::Relaxed);
                tokio::spawn(async move {
                    let _guard = WorkerGuard {
                        active_workers: pool.active_workers.clone(),
                    };
                    pool.worker_loop(dc, slot_idx, generation).await;
                });
            }
        }
    }

    fn is_current_generation(&self, generation: u64) -> bool {
        let guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        guard.generation == generation
    }

    async fn sleep_interruptible(&self, delay: Duration, generation: u64) -> bool {
        let deadline = tokio::time::Instant::now() + delay;
        loop {
            if self.stopped.load(Ordering::Relaxed) || !self.is_current_generation(generation) {
                return false;
            }
            let notified = self.stop_notify.notified();
            if self.stopped.load(Ordering::Relaxed) || !self.is_current_generation(generation) {
                return false;
            }
            tokio::select! {
                biased;
                () = notified => {
                    if self.stopped.load(Ordering::Relaxed) || !self.is_current_generation(generation) {
                        return false;
                    }
                }
                () = tokio::time::sleep_until(deadline) => return true,
            }
        }
    }

    async fn worker_loop(&self, dc: i16, slot_idx: usize, generation: u64) {
        let mut failures: u32 = 0;
        let base = self.cfg.reconnect_base.max(Duration::from_millis(50));
        let max = self.cfg.reconnect_max.max(base);

        loop {
            if self.stopped.load(Ordering::Relaxed) {
                break;
            }
            let (endpoint, secret, still_current) = {
                let guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
                if guard.generation != generation {
                    (None, Vec::new(), false)
                } else {
                    let eps = guard.bundle.proxy_conf.endpoints_for(dc);
                    let ep = if eps.is_empty() {
                        None
                    } else {
                        Some(eps[(slot_idx + failures as usize) % eps.len()])
                    };
                    (ep, guard.bundle.proxy_secret.clone(), true)
                }
            };
            if !still_current {
                break;
            }
            let Some(ep) = endpoint else {
                if !self
                    .sleep_interruptible(self.cfg.reconnect_max, generation)
                    .await
                {
                    break;
                }
                continue;
            };

            let connect_res = tokio::select! {
                biased;
                () = self.stop_notify.notified() => {
                    if self.stopped.load(Ordering::Relaxed) || !self.is_current_generation(generation) {
                        break;
                    }
                    continue;
                }
                res = MeConnection::connect_with_counters(
                    ep,
                    &secret,
                    self.cfg.conn_opts.clone(),
                    self.counters.clone(),
                ) => res,
            };

            match connect_res {
                Ok(conn) => {
                    failures = 0;
                    {
                        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
                        if self.stopped.load(Ordering::Relaxed) || guard.generation != generation {
                            conn.close();
                            break;
                        }
                        if let Some(vec) = guard.slots.get_mut(&dc) {
                            if let Some(slot) = vec.get_mut(slot_idx) {
                                slot.conn = Some(conn.clone());
                            }
                        }
                    }
                    // Wait until this connection dies, pool stops, or generation changes.
                    loop {
                        if !conn.is_alive() {
                            break;
                        }
                        if self.stopped.load(Ordering::Relaxed)
                            || !self.is_current_generation(generation)
                        {
                            // Note: on generation change, `update_config` moved `conn` to draining
                            // and owns its graceful close; on pool shutdown, `shutdown()` closes it.
                            return;
                        }
                        let stop_fut = self.stop_notify.notified();
                        if !conn.is_alive() {
                            break;
                        }
                        if self.stopped.load(Ordering::Relaxed)
                            || !self.is_current_generation(generation)
                        {
                            return;
                        }
                        tokio::select! {
                            biased;
                            () = stop_fut => {}
                            () = conn.wait_closed() => break,
                        }
                    }
                    {
                        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
                        if guard.generation == generation {
                            if let Some(vec) = guard.slots.get_mut(&dc) {
                                if let Some(slot) = vec.get_mut(slot_idx) {
                                    slot.conn = None;
                                }
                            }
                        }
                    }
                }
                Err(_) => {
                    failures = failures.saturating_add(1);
                    let delay = compute_egress_cooldown(base, max, failures);
                    if !self.sleep_interruptible(delay, generation).await {
                        break;
                    }
                }
            }
        }
    }

    /// Hot-swap ME configuration (`proxy-secret` + `proxy-multi.conf`) without breaking active
    /// sessions: existing connections are moved to a graceful drain pool until their active
    /// sessions finish (or `drain_timeout` expires), while fresh workers bring up the new generation.
    pub fn update_config(&self, bundle: MeConfigBundle) {
        let (next_gen, to_drain) = {
            let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            let mut drained: Vec<(i16, MeConnection)> = Vec::new();
            for (&dc, slots) in guard.slots.iter_mut() {
                for slot in slots.iter_mut() {
                    if let Some(old) = slot.conn.take() {
                        if old.is_alive() {
                            drained.push((dc, old));
                        }
                    }
                }
            }
            for (dc, conn) in &drained {
                guard.draining.entry(*dc).or_default().push(conn.clone());
            }
            guard.generation = guard.generation.saturating_add(1);
            let mut new_slots = HashMap::new();
            for &dc in bundle.proxy_conf.dcs.keys() {
                new_slots.insert(
                    dc,
                    (0..self.cfg.conns_per_dc)
                        .map(|_| DcPoolSlot { conn: None })
                        .collect(),
                );
            }
            guard.bundle = bundle;
            guard.slots = new_slots;
            (guard.generation, drained)
        };
        // Wake old generation workers so they exit immediately without closing drained sockets.
        self.stop_notify.notify_waiters();
        self.spawn_workers_for_generation(next_gen);

        if !to_drain.is_empty() {
            let pool = self.clone();
            let drain_timeout = self.cfg.drain_timeout;
            tokio::spawn(async move {
                let deadline = tokio::time::Instant::now() + drain_timeout;
                loop {
                    let all_idle = to_drain
                        .iter()
                        .all(|(_, c)| !c.is_alive() || c.active_sessions() == 0);
                    let new_ready = {
                        let guard = pool.inner.lock().unwrap_or_else(|e| e.into_inner());
                        guard.slots.values().any(|slots| {
                            slots
                                .iter()
                                .any(|s| s.conn.as_ref().is_some_and(MeConnection::is_alive))
                        })
                    };
                    if pool.stopped.load(Ordering::Relaxed)
                        || (all_idle && new_ready)
                        || tokio::time::Instant::now() >= deadline
                    {
                        break;
                    }
                    let step = Duration::from_millis(50);
                    tokio::select! {
                        biased;
                        () = pool.stop_notify.notified() => {
                            if pool.stopped.load(Ordering::Relaxed) {
                                break;
                            }
                        }
                        () = tokio::time::sleep(step) => {}
                    }
                }
                for (_, conn) in &to_drain {
                    conn.close();
                }
                let mut guard = pool.inner.lock().unwrap_or_else(|e| e.into_inner());
                for (dc, _) in to_drain {
                    if let Some(vec) = guard.draining.get_mut(&dc) {
                        vec.retain(MeConnection::is_alive);
                        if vec.is_empty() {
                            guard.draining.remove(&dc);
                        }
                    }
                }
            });
        }
    }

    /// Open a multiplexed session on a healthy ME connection for `dc_id` (falling back to `dc_id.abs()`
    /// or `default_dc`, and to draining connections during hot-swap warm-up). Returns `Err` immediately
    /// if no live ME connection exists so callers can fall back to Direct without stalling.
    pub fn open_session(
        &self,
        dc_id: i16,
        remote_addr: Option<SocketAddrV4>,
        proto: MeClientProto,
        ad_tag: Option<[u8; 16]>,
    ) -> Result<MeSession> {
        let candidates: Vec<MeConnection> = {
            let guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            let key = if guard.slots.contains_key(&dc_id) {
                Some(dc_id)
            } else if guard.slots.contains_key(&dc_id.abs()) {
                Some(dc_id.abs())
            } else {
                guard.bundle.proxy_conf.default_dc
            };
            let mut active: Vec<MeConnection> = key
                .and_then(|k| guard.slots.get(&k))
                .map(|slots| {
                    slots
                        .iter()
                        .filter_map(|s| s.conn.as_ref().filter(|c| c.is_alive()).cloned())
                        .collect()
                })
                .unwrap_or_default();
            if active.is_empty() {
                if let Some(k) = key {
                    if let Some(draining) = guard.draining.get(&k) {
                        active.extend(draining.iter().filter(|c| c.is_alive()).cloned());
                    }
                }
            }
            active
        };
        ensure!(
            !candidates.is_empty(),
            "no healthy ME connections available for DC {dc_id}"
        );
        let idx = self.rr.fetch_add(1, Ordering::Relaxed) % candidates.len();
        candidates[idx].open_session(remote_addr, proto, ad_tag)
    }

    pub fn health(&self) -> MePoolHealth {
        let guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let configured_dcs = guard.slots.len();
        let mut total_slots = 0usize;
        let mut alive_connections = 0usize;
        for slots in guard.slots.values() {
            total_slots += slots.len();
            alive_connections += slots
                .iter()
                .filter(|s| s.conn.as_ref().is_some_and(MeConnection::is_alive))
                .count();
        }
        MePoolHealth {
            configured_dcs,
            alive_connections,
            total_slots,
            degraded: total_slots == 0 || alive_connections < total_slots,
            backpressure_drops: self.counters.backpressure_drops.load(Ordering::Relaxed),
            dropped_close_ext: self.counters.dropped_close_ext.load(Ordering::Relaxed),
        }
    }

    pub fn active_workers(&self) -> usize {
        self.active_workers.load(Ordering::Relaxed)
    }

    pub fn shutdown(&self) {
        self.stopped.store(true, Ordering::Relaxed);
        {
            let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            for slots in guard.slots.values_mut() {
                for slot in slots.iter_mut() {
                    if let Some(conn) = slot.conn.take() {
                        conn.close();
                    }
                }
            }
            for conns in guard.draining.values_mut() {
                for conn in conns.drain(..) {
                    conn.close();
                }
            }
            guard.draining.clear();
        }
        self.stop_notify.notify_waiters();
    }
}
