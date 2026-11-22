use crate::config::MeConfigBundle;
use crate::conn::{MeConnOptions, MeConnection, MeSession};
use anyhow::{ensure, Result};
use mtevil_egress::compute_egress_cooldown;
use std::collections::HashMap;
use std::net::SocketAddrV4;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct MePoolConfig {
    pub conns_per_dc: usize,
    pub reconnect_base: Duration,
    pub reconnect_max: Duration,
    pub conn_opts: MeConnOptions,
}

impl Default for MePoolConfig {
    fn default() -> Self {
        Self {
            conns_per_dc: 2,
            reconnect_base: Duration::from_secs(1),
            reconnect_max: Duration::from_secs(30),
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
}

struct DcPoolSlot {
    conn: Option<MeConnection>,
}

struct PoolInner {
    bundle: MeConfigBundle,
    slots: HashMap<i16, Vec<DcPoolSlot>>,
    generation: u64,
}

/// Multiplexed Telegram Middle-End connection pool with per-DC reconnect (backoff + jitter)
/// and hot config swap.
#[derive(Clone)]
pub struct MePool {
    inner: Arc<Mutex<PoolInner>>,
    cfg: MePoolConfig,
    rr: Arc<AtomicUsize>,
    stopped: Arc<AtomicBool>,
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
                generation: 1,
            })),
            cfg,
            rr: Arc::new(AtomicUsize::new(0)),
            stopped: Arc::new(AtomicBool::new(false)),
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
                tokio::spawn(async move {
                    pool.worker_loop(dc, slot_idx, generation).await;
                });
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
                tokio::time::sleep(self.cfg.reconnect_max).await;
                continue;
            };

            match MeConnection::connect(ep, &secret, self.cfg.conn_opts.clone()).await {
                Ok(conn) => {
                    failures = 0;
                    {
                        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
                        if guard.generation != generation {
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
                    while conn.is_alive() && !self.stopped.load(Ordering::Relaxed) {
                        let gen_ok = {
                            let guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
                            guard.generation == generation
                        };
                        if !gen_ok {
                            conn.close();
                            return;
                        }
                        tokio::time::sleep(Duration::from_millis(100)).await;
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
                    tokio::time::sleep(delay).await;
                }
            }
        }
    }

    /// Hot-swap ME configuration (`proxy-secret` + `proxy-multi.conf`), closing old generation
    /// connections and spawning fresh workers for the new generation.
    pub fn update_config(&self, bundle: MeConfigBundle) {
        let next_gen = {
            let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            for slots in guard.slots.values_mut() {
                for slot in slots.iter_mut() {
                    if let Some(old) = slot.conn.take() {
                        old.close();
                    }
                }
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
            guard.generation
        };
        self.spawn_workers_for_generation(next_gen);
    }

    /// Open a multiplexed session on a healthy ME connection for `dc_id` (falling back to `dc_id.abs()`
    /// or `default_dc`). Returns `Err` immediately if no live ME connection exists so callers can
    /// fall back to Direct without stalling.
    pub fn open_session(
        &self,
        dc_id: i16,
        remote_addr: Option<SocketAddrV4>,
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
            key.and_then(|k| guard.slots.get(&k))
                .map(|slots| {
                    slots
                        .iter()
                        .filter_map(|s| s.conn.as_ref().filter(|c| c.is_alive()).cloned())
                        .collect()
                })
                .unwrap_or_default()
        };
        ensure!(
            !candidates.is_empty(),
            "no healthy ME connections available for DC {dc_id}"
        );
        let idx = self.rr.fetch_add(1, Ordering::Relaxed) % candidates.len();
        candidates[idx].open_session(remote_addr, ad_tag)
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
        }
    }

    pub fn shutdown(&self) {
        self.stopped.store(true, Ordering::Relaxed);
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        for slots in guard.slots.values_mut() {
            for slot in slots.iter_mut() {
                if let Some(conn) = slot.conn.take() {
                    conn.close();
                }
            }
        }
    }
}
