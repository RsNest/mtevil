//! Operational events only: no peer IPs, secrets, keys or message contents.
use serde_json::{json, Value};
use std::{
    collections::VecDeque,
    sync::{
        atomic::{AtomicU64, Ordering},
        Mutex,
    },
    time::{Instant, SystemTime, UNIX_EPOCH},
};

#[derive(Default)]
pub struct AcceptErrorCounters {
    pub emfile: AtomicU64,
    pub enfile: AtomicU64,
    pub enobufs: AtomicU64,
    pub enomem: AtomicU64,
    pub connection_aborted: AtomicU64,
    pub connection_reset: AtomicU64,
    pub interrupted: AtomicU64,
    pub would_block: AtomicU64,
    pub fatal: AtomicU64,
    pub other: AtomicU64,
}

impl AcceptErrorCounters {
    pub fn record(&self, kind: &str) {
        let slot = match kind {
            "emfile" => &self.emfile,
            "enfile" => &self.enfile,
            "enobufs" => &self.enobufs,
            "enomem" => &self.enomem,
            "connection_aborted" => &self.connection_aborted,
            "connection_reset" => &self.connection_reset,
            "interrupted" => &self.interrupted,
            "would_block" => &self.would_block,
            "fatal" => &self.fatal,
            _ => &self.other,
        };
        slot.fetch_add(1, Ordering::Relaxed);
    }

    pub fn total(&self) -> u64 {
        self.emfile.load(Ordering::Relaxed)
            + self.enfile.load(Ordering::Relaxed)
            + self.enobufs.load(Ordering::Relaxed)
            + self.enomem.load(Ordering::Relaxed)
            + self.connection_aborted.load(Ordering::Relaxed)
            + self.connection_reset.load(Ordering::Relaxed)
            + self.interrupted.load(Ordering::Relaxed)
            + self.would_block.load(Ordering::Relaxed)
            + self.fatal.load(Ordering::Relaxed)
            + self.other.load(Ordering::Relaxed)
    }

    pub fn snapshot_json(&self) -> Value {
        json!({
            "total": self.total(),
            "emfile": self.emfile.load(Ordering::Relaxed),
            "enfile": self.enfile.load(Ordering::Relaxed),
            "enobufs": self.enobufs.load(Ordering::Relaxed),
            "enomem": self.enomem.load(Ordering::Relaxed),
            "connection_aborted": self.connection_aborted.load(Ordering::Relaxed),
            "connection_reset": self.connection_reset.load(Ordering::Relaxed),
            "interrupted": self.interrupted.load(Ordering::Relaxed),
            "would_block": self.would_block.load(Ordering::Relaxed),
            "fatal": self.fatal.load(Ordering::Relaxed),
            "other": self.other.load(Ordering::Relaxed),
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClientHelloIncompleteSample {
    pub received_bytes: usize,
    pub expected_bytes: usize,
    pub timeout: bool,
}

#[derive(Default)]
pub struct Counters {
    pub next: AtomicU64,
    pub active: AtomicU64,
    pub completed: AtomicU64,
    pub failed: AtomicU64,
    pub downstream_rx_bytes: AtomicU64,
    pub downstream_tx_bytes: AtomicU64,
    pub upstream_rx_bytes: AtomicU64,
    pub upstream_tx_bytes: AtomicU64,
    pub downstream_retrans_segs: AtomicU64,
    pub upstream_retrans_segs: AtomicU64,
    pub started_unix_ms: AtomicU64,
    pub accept_errors: AcceptErrorCounters,
    pub hedge_started: AtomicU64,
    pub hedge_won_by_backup: AtomicU64,
    pub egress_failover_total: AtomicU64,
    pub cover_rejected: AtomicU64,
    pub replay_full: AtomicU64,
    pub replay_flush_failed: AtomicU64,
    pub forced_close: AtomicU64,
    pub dc_self_check_ok: AtomicU64,
    pub dc_self_check_failed: AtomicU64,
    pub cover_dns_fail: AtomicU64,
    pub egress_legacy_connections: AtomicU64,
    pub egress_mtv3_connections: AtomicU64,
    pub egress_preface_aborted: AtomicU64,
    pub egress_nonce_cache_full: AtomicU64,
    pub egress_failed_tracker_evictions: AtomicU64,
    pub alert_webhook_dropped: AtomicU64,
    pub me_active_sessions: AtomicU64,
    pub me_fallback_direct_total: AtomicU64,
    pub me_refresh_errors: AtomicU64,
    pub client_hello_incomplete_timeout: AtomicU64,
    pub client_hello_incomplete_close: AtomicU64,
    pub inner_header_incomplete: AtomicU64,
    pub last_client_hello_incomplete: Mutex<Option<ClientHelloIncompleteSample>>,
}

impl Counters {
    pub fn record_client_hello_incomplete(
        &self,
        received_bytes: usize,
        expected_bytes: usize,
        timeout: bool,
    ) {
        if timeout {
            self.client_hello_incomplete_timeout
                .fetch_add(1, Ordering::Relaxed);
        } else {
            self.client_hello_incomplete_close
                .fetch_add(1, Ordering::Relaxed);
        }
        if let Ok(mut guard) = self.last_client_hello_incomplete.lock() {
            *guard = Some(ClientHelloIncompleteSample {
                received_bytes,
                expected_bytes,
                timeout,
            });
        }
    }
    pub fn ensure_started(&self) -> u64 {
        let cur = self.started_unix_ms.load(Ordering::Relaxed);
        if cur != 0 {
            return cur;
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(1);
        match self
            .started_unix_ms
            .compare_exchange(0, now, Ordering::Relaxed, Ordering::Relaxed)
        {
            Ok(_) => now,
            Err(existing) => existing,
        }
    }

    #[cfg(test)]
    pub fn snapshot_json(&self, role: &str) -> Value {
        self.snapshot_json_with_me(role, None)
    }

    pub fn snapshot_json_with_me(
        &self,
        role: &str,
        me: Option<&crate::me::MeTelemetrySnapshot>,
    ) -> Value {
        let started_unix_ms = self.ensure_started();
        let now_unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(started_unix_ms);
        let retrans_supported = cfg!(target_os = "linux");
        let me_json = match me {
            Some(m) if m.enabled => {
                let mode = if !m.degraded {
                    "me"
                } else if m.fallback_to_direct {
                    "me_degraded_fallback_direct"
                } else {
                    "me_degraded_strict"
                };
                json!({
                    "enabled": true,
                    "mode": mode,
                    "degraded": m.degraded,
                    "fallback_to_direct": m.fallback_to_direct,
                    "alive_connections": m.alive_connections,
                    "total_slots": m.total_slots,
                    "configured_dcs": m.configured_dcs,
                    "active_sessions": self.me_active_sessions.load(Ordering::Relaxed),
                    "fallback_direct_total": self.me_fallback_direct_total.load(Ordering::Relaxed),
                    "config_age_secs": m.config_age_secs,
                    "backpressure_drops": m.backpressure_drops,
                    "dropped_close_ext": m.dropped_close_ext,
                    "refresh_errors": self.me_refresh_errors.load(Ordering::Relaxed),
                    "ad_tag": if m.ad_tag_configured { "configured" } else { "disabled" },
                })
            }
            _ => json!({
                "enabled": false,
                "mode": "disabled",
            }),
        };
        json!({
            "role": role,
            "started_unix_ms": started_unix_ms,
            "ts_unix_ms": now_unix_ms,
            "uptime_ms": now_unix_ms.saturating_sub(started_unix_ms),
            "active_sessions": self.active.load(Ordering::Relaxed),
            "completed_sessions": self.completed.load(Ordering::Relaxed),
            "failed_sessions": self.failed.load(Ordering::Relaxed),
            "downstream_rx_bytes": self.downstream_rx_bytes.load(Ordering::Relaxed),
            "downstream_tx_bytes": self.downstream_tx_bytes.load(Ordering::Relaxed),
            "upstream_rx_bytes": self.upstream_rx_bytes.load(Ordering::Relaxed),
            "upstream_tx_bytes": self.upstream_tx_bytes.load(Ordering::Relaxed),
            "downstream_retrans_segs": if retrans_supported {
                Value::from(self.downstream_retrans_segs.load(Ordering::Relaxed))
            } else {
                Value::Null
            },
            "upstream_retrans_segs": if retrans_supported {
                Value::from(self.upstream_retrans_segs.load(Ordering::Relaxed))
            } else {
                Value::Null
            },
            "retrans_supported": retrans_supported,
            "accept_errors": self.accept_errors.snapshot_json(),
            "hedge_started": self.hedge_started.load(Ordering::Relaxed),
            "hedge_won_by_backup": self.hedge_won_by_backup.load(Ordering::Relaxed),
            "egress_failover_total": self.egress_failover_total.load(Ordering::Relaxed),
            "cover_rejected": self.cover_rejected.load(Ordering::Relaxed),
            "replay_full": self.replay_full.load(Ordering::Relaxed),
            "replay_flush_failed": self.replay_flush_failed.load(Ordering::Relaxed),
            "forced_close": self.forced_close.load(Ordering::Relaxed),
            "dc_self_check_ok": self.dc_self_check_ok.load(Ordering::Relaxed),
            "dc_self_check_failed": self.dc_self_check_failed.load(Ordering::Relaxed),
            "cover_dns_fail": self.cover_dns_fail.load(Ordering::Relaxed),
            "egress_legacy_connections": self.egress_legacy_connections.load(Ordering::Relaxed),
            "egress_mtv3_connections": self.egress_mtv3_connections.load(Ordering::Relaxed),
            "egress_preface_aborted": self.egress_preface_aborted.load(Ordering::Relaxed),
            "egress_nonce_cache_full": self.egress_nonce_cache_full.load(Ordering::Relaxed),
            "egress_failed_tracker_evictions": self
                .egress_failed_tracker_evictions
                .load(Ordering::Relaxed),
            "alert_webhook_dropped": self.alert_webhook_dropped.load(Ordering::Relaxed),
            "client_hello_incomplete_timeout": self
                .client_hello_incomplete_timeout
                .load(Ordering::Relaxed),
            "client_hello_incomplete_close": self
                .client_hello_incomplete_close
                .load(Ordering::Relaxed),
            "inner_header_incomplete": self.inner_header_incomplete.load(Ordering::Relaxed),
            "last_client_hello_incomplete": self
                .last_client_hello_incomplete
                .lock()
                .ok()
                .and_then(|g| *g)
                .map(|s| {
                    json!({
                        "received_bytes": s.received_bytes,
                        "expected_bytes": s.expected_bytes,
                        "timeout": s.timeout,
                    })
                })
                .unwrap_or(Value::Null),
            "me": me_json,
        })
    }

    pub fn render_prometheus_with_me(
        &self,
        breaker_states: &[(String, u8)],
        fd_used: Option<usize>,
        fd_limit: Option<usize>,
        me: Option<&crate::me::MeTelemetrySnapshot>,
    ) -> String {
        use std::fmt::Write;
        let mut out = String::with_capacity(2048);
        let _ = writeln!(
            out,
            "# HELP mtevil_active_sessions Currently active sessions"
        );
        let _ = writeln!(out, "# TYPE mtevil_active_sessions gauge");
        let _ = writeln!(
            out,
            "mtevil_active_sessions {}",
            self.active.load(Ordering::Relaxed)
        );

        let _ = writeln!(
            out,
            "# HELP mtevil_accept_errors_total Listener accept errors by classification"
        );
        let _ = writeln!(out, "# TYPE mtevil_accept_errors_total counter");
        let accept_kinds = [
            ("emfile", self.accept_errors.emfile.load(Ordering::Relaxed)),
            ("enfile", self.accept_errors.enfile.load(Ordering::Relaxed)),
            (
                "enobufs",
                self.accept_errors.enobufs.load(Ordering::Relaxed),
            ),
            ("enomem", self.accept_errors.enomem.load(Ordering::Relaxed)),
            (
                "connection_aborted",
                self.accept_errors
                    .connection_aborted
                    .load(Ordering::Relaxed),
            ),
            (
                "connection_reset",
                self.accept_errors.connection_reset.load(Ordering::Relaxed),
            ),
            (
                "interrupted",
                self.accept_errors.interrupted.load(Ordering::Relaxed),
            ),
            (
                "would_block",
                self.accept_errors.would_block.load(Ordering::Relaxed),
            ),
            ("fatal", self.accept_errors.fatal.load(Ordering::Relaxed)),
            ("other", self.accept_errors.other.load(Ordering::Relaxed)),
        ];
        for (kind, count) in accept_kinds {
            let _ = writeln!(out, "mtevil_accept_errors_total{{kind=\"{kind}\"}} {count}");
        }

        let _ = writeln!(
            out,
            "# HELP mtevil_breaker_state Egress circuit breaker state (0=healthy, 1=open, 2=probing)"
        );
        let _ = writeln!(out, "# TYPE mtevil_breaker_state gauge");
        for (node, state) in breaker_states {
            let escaped = node.replace('\\', "\\\\").replace('"', "\\\"");
            let _ = writeln!(out, "mtevil_breaker_state{{node=\"{escaped}\"}} {state}");
        }

        let _ = writeln!(
            out,
            "# HELP mtevil_egress_failover_total Connections served by backup/failover egress"
        );
        let _ = writeln!(out, "# TYPE mtevil_egress_failover_total counter");
        let _ = writeln!(
            out,
            "mtevil_egress_failover_total {}",
            self.egress_failover_total.load(Ordering::Relaxed)
        );

        let _ = writeln!(
            out,
            "# HELP mtevil_egress_legacy_connections_total Authenticated legacy MTV2 connections accepted by egress"
        );
        let _ = writeln!(out, "# TYPE mtevil_egress_legacy_connections_total counter");
        let _ = writeln!(
            out,
            "mtevil_egress_legacy_connections_total {}",
            self.egress_legacy_connections.load(Ordering::Relaxed)
        );

        let _ = writeln!(
            out,
            "# HELP mtevil_egress_mtv3_connections_total Authenticated MTV3 connections accepted by egress"
        );
        let _ = writeln!(out, "# TYPE mtevil_egress_mtv3_connections_total counter");
        let _ = writeln!(
            out,
            "mtevil_egress_mtv3_connections_total {}",
            self.egress_mtv3_connections.load(Ordering::Relaxed)
        );

        let _ = writeln!(
            out,
            "# HELP mtevil_egress_preface_aborted_total Egress connections closed or timed out before completing preface (not auth failures)"
        );
        let _ = writeln!(out, "# TYPE mtevil_egress_preface_aborted_total counter");
        let _ = writeln!(
            out,
            "mtevil_egress_preface_aborted_total {}",
            self.egress_preface_aborted.load(Ordering::Relaxed)
        );

        let _ = writeln!(
            out,
            "# HELP mtevil_egress_nonce_cache_full_total Authenticated MTV3 connections accepted while nonce replay cache was saturated"
        );
        let _ = writeln!(out, "# TYPE mtevil_egress_nonce_cache_full_total counter");
        let _ = writeln!(
            out,
            "mtevil_egress_nonce_cache_full_total {}",
            self.egress_nonce_cache_full.load(Ordering::Relaxed)
        );

        let _ = writeln!(
            out,
            "# HELP mtevil_egress_failed_tracker_evictions_total Oldest-entry evictions from egress per-IP auth failure tracker"
        );
        let _ = writeln!(
            out,
            "# TYPE mtevil_egress_failed_tracker_evictions_total counter"
        );
        let _ = writeln!(
            out,
            "mtevil_egress_failed_tracker_evictions_total {}",
            self.egress_failed_tracker_evictions.load(Ordering::Relaxed)
        );

        let _ = writeln!(
            out,
            "# HELP mtevil_alert_webhook_dropped_total Alert webhook deliveries dropped because bounded queue (64) was full"
        );
        let _ = writeln!(out, "# TYPE mtevil_alert_webhook_dropped_total counter");
        let _ = writeln!(
            out,
            "mtevil_alert_webhook_dropped_total {}",
            self.alert_webhook_dropped.load(Ordering::Relaxed)
        );

        let _ = writeln!(
            out,
            "# HELP mtevil_hedge_started_total Hedged backup connect attempts started"
        );
        let _ = writeln!(out, "# TYPE mtevil_hedge_started_total counter");
        let _ = writeln!(
            out,
            "mtevil_hedge_started_total {}",
            self.hedge_started.load(Ordering::Relaxed)
        );

        let _ = writeln!(
            out,
            "# HELP mtevil_hedge_won_by_backup_total Hedged connects won by backup egress"
        );
        let _ = writeln!(out, "# TYPE mtevil_hedge_won_by_backup_total counter");
        let _ = writeln!(
            out,
            "mtevil_hedge_won_by_backup_total {}",
            self.hedge_won_by_backup.load(Ordering::Relaxed)
        );

        let _ = writeln!(
            out,
            "# HELP mtevil_cover_rejected_total Cover fallback attempts rejected at capacity"
        );
        let _ = writeln!(out, "# TYPE mtevil_cover_rejected_total counter");
        let _ = writeln!(
            out,
            "mtevil_cover_rejected_total {}",
            self.cover_rejected.load(Ordering::Relaxed)
        );

        let _ = writeln!(
            out,
            "# HELP mtevil_replay_full_total ClientHellos rejected because replay cache was full"
        );
        let _ = writeln!(out, "# TYPE mtevil_replay_full_total counter");
        let _ = writeln!(
            out,
            "mtevil_replay_full_total {}",
            self.replay_full.load(Ordering::Relaxed)
        );

        let _ = writeln!(
            out,
            "# HELP mtevil_replay_flush_failed_total Failed replay cache snapshot flushes"
        );
        let _ = writeln!(out, "# TYPE mtevil_replay_flush_failed_total counter");
        let _ = writeln!(
            out,
            "mtevil_replay_flush_failed_total {}",
            self.replay_flush_failed.load(Ordering::Relaxed)
        );

        let _ = writeln!(
            out,
            "# HELP mtevil_forced_close_total Sessions forcibly closed after drain timeout"
        );
        let _ = writeln!(out, "# TYPE mtevil_forced_close_total counter");
        let _ = writeln!(
            out,
            "mtevil_forced_close_total {}",
            self.forced_close.load(Ordering::Relaxed)
        );

        let _ = writeln!(
            out,
            "# HELP mtevil_fd_used Open file descriptors of the process (0 if unavailable)"
        );
        let _ = writeln!(out, "# TYPE mtevil_fd_used gauge");
        let _ = writeln!(out, "mtevil_fd_used {}", fd_used.unwrap_or(0));

        let _ = writeln!(
            out,
            "# HELP mtevil_fd_limit Soft RLIMIT_NOFILE of the process (0 if unavailable)"
        );
        let _ = writeln!(out, "# TYPE mtevil_fd_limit gauge");
        let _ = writeln!(out, "mtevil_fd_limit {}", fd_limit.unwrap_or(0));

        let _ = writeln!(
            out,
            "# HELP mtevil_client_hello_incomplete_total Client connections terminated before completing the initial TLS ClientHello record"
        );
        let _ = writeln!(out, "# TYPE mtevil_client_hello_incomplete_total counter");
        let _ = writeln!(
            out,
            "mtevil_client_hello_incomplete_total{{reason=\"timeout\"}} {}",
            self.client_hello_incomplete_timeout.load(Ordering::Relaxed)
        );
        let _ = writeln!(
            out,
            "mtevil_client_hello_incomplete_total{{reason=\"close\"}} {}",
            self.client_hello_incomplete_close.load(Ordering::Relaxed)
        );
        let _ = writeln!(
            out,
            "# HELP mtevil_inner_header_incomplete_total Client connections that failed or timed out reading the 64-byte MTProto header after ServerHello"
        );
        let _ = writeln!(out, "# TYPE mtevil_inner_header_incomplete_total counter");
        let _ = writeln!(
            out,
            "mtevil_inner_header_incomplete_total {}",
            self.inner_header_incomplete.load(Ordering::Relaxed)
        );

        if let Some(m) = me.filter(|m| m.enabled) {
            let _ = writeln!(
                out,
                "# HELP mtevil_me_active_sessions Currently active client sessions over Telegram ME"
            );
            let _ = writeln!(out, "# TYPE mtevil_me_active_sessions gauge");
            let _ = writeln!(
                out,
                "mtevil_me_active_sessions {}",
                self.me_active_sessions.load(Ordering::Relaxed)
            );
            let _ = writeln!(
                out,
                "# HELP mtevil_me_pool_degraded 1 if ME pool has fewer live connections than configured slots"
            );
            let _ = writeln!(out, "# TYPE mtevil_me_pool_degraded gauge");
            let _ = writeln!(
                out,
                "mtevil_me_pool_degraded {}",
                if m.degraded { 1 } else { 0 }
            );
            let _ = writeln!(
                out,
                "# HELP mtevil_me_pool_alive_connections Currently alive ME TCP connections"
            );
            let _ = writeln!(out, "# TYPE mtevil_me_pool_alive_connections gauge");
            let _ = writeln!(
                out,
                "mtevil_me_pool_alive_connections {}",
                m.alive_connections
            );
            let _ = writeln!(
                out,
                "# HELP mtevil_me_config_age_seconds Age in seconds of last loaded ME config"
            );
            let _ = writeln!(out, "# TYPE mtevil_me_config_age_seconds gauge");
            let _ = writeln!(
                out,
                "mtevil_me_config_age_seconds {}",
                m.config_age_secs.unwrap_or(0)
            );
            let _ = writeln!(
                out,
                "# HELP mtevil_me_fallback_direct_total Sessions that fell back from ME to Direct"
            );
            let _ = writeln!(out, "# TYPE mtevil_me_fallback_direct_total counter");
            let _ = writeln!(
                out,
                "mtevil_me_fallback_direct_total {}",
                self.me_fallback_direct_total.load(Ordering::Relaxed)
            );
            let _ = writeln!(
                out,
                "# HELP mtevil_me_backpressure_drops_total ME sessions dropped due to slow-client inbound queue overflow"
            );
            let _ = writeln!(out, "# TYPE mtevil_me_backpressure_drops_total counter");
            let _ = writeln!(
                out,
                "mtevil_me_backpressure_drops_total {}",
                m.backpressure_drops
            );
            let _ = writeln!(
                out,
                "# HELP mtevil_me_dropped_close_ext_total Dropped RPC_CLOSE_EXT notifications when ME outbound queue was full"
            );
            let _ = writeln!(out, "# TYPE mtevil_me_dropped_close_ext_total counter");
            let _ = writeln!(
                out,
                "mtevil_me_dropped_close_ext_total {}",
                m.dropped_close_ext
            );
            let _ = writeln!(
                out,
                "# HELP mtevil_me_refresh_errors_total Failed ME proxy-secret/proxy-multi.conf refresh attempts"
            );
            let _ = writeln!(out, "# TYPE mtevil_me_refresh_errors_total counter");
            let _ = writeln!(
                out,
                "mtevil_me_refresh_errors_total {}",
                self.me_refresh_errors.load(Ordering::Relaxed)
            );
        }

        out
    }
}

pub fn event(name: &str, session: u64, fields: Value) {
    let time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    eprintln!(
        "{}",
        json!({"ts_unix_ms": time, "event": name, "session_id": session, "details": fields})
    );
}

const KEEP: usize = 16;

struct Mark {
    t_us: u64,
    tag: &'static str,
    n: u64,
}

#[derive(Default)]
struct TimelineInner {
    head: Vec<Mark>,
    tail: VecDeque<Mark>,
    skipped: u64,
    closer: Option<(u64, &'static str, &'static str)>,
    final_reason: Option<&'static str>,
}

/// Monotonic per-session event log. Stores only tags, sizes and offsets from
/// session start; the first and last `KEEP` events are retained.
pub struct Timeline {
    start: Instant,
    inner: Mutex<TimelineInner>,
}

impl Timeline {
    pub fn new() -> Self {
        Self {
            start: Instant::now(),
            inner: Mutex::new(TimelineInner::default()),
        }
    }

    pub fn now_us(&self) -> u64 {
        self.start.elapsed().as_micros() as u64
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, TimelineInner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn push(inner: &mut TimelineInner, mark: Mark) {
        if inner.head.len() < KEEP {
            inner.head.push(mark);
            return;
        }
        if inner.tail.len() == KEEP {
            inner.tail.pop_front();
            inner.skipped += 1;
        }
        inner.tail.push_back(mark);
    }

    pub fn mark(&self, tag: &'static str, n: u64) {
        let t_us = self.now_us();
        Self::push(&mut self.lock(), Mark { t_us, tag, n });
    }

    /// Records a terminal event; only the first one is the initiator.
    pub fn close(&self, tag: &'static str, detail: &'static str) {
        let t_us = self.now_us();
        let mut inner = self.lock();
        if inner.closer.is_none() {
            inner.closer = Some((t_us, tag, detail));
        }
        inner.final_reason = Some(tag);
        Self::push(&mut inner, Mark { t_us, tag, n: 0 });
    }

    pub fn closer(&self) -> Option<(u64, &'static str, &'static str)> {
        self.lock().closer
    }

    pub fn final_reason(&self) -> Option<&'static str> {
        self.lock().final_reason
    }

    pub fn snapshot(&self) -> Value {
        let inner = self.lock();
        let list: Vec<Value> = inner
            .head
            .iter()
            .chain(inner.tail.iter())
            .map(|m| json!([m.t_us, m.tag, m.n]))
            .collect();
        json!({"events":list,"skipped":inner.skipped})
    }
}

pub struct Session<'a> {
    pub id: u64,
    counters: &'a Counters,
    start: Instant,
    outcome: &'static str,
}
impl<'a> Session<'a> {
    pub fn new(counters: &'a Counters) -> Self {
        let id = counters.next.fetch_add(1, Ordering::Relaxed) + 1;
        counters.active.fetch_add(1, Ordering::Relaxed);
        event("session_open", id, json!({}));
        Self {
            id,
            counters,
            start: Instant::now(),
            outcome: "cancelled",
        }
    }
    pub fn finish(&mut self, result: &anyhow::Result<()>) {
        if let Err(error) = result {
            self.outcome = "error";
            self.counters.failed.fetch_add(1, Ordering::Relaxed);
            event(
                "session_error",
                self.id,
                json!({"reason":format!("{error:#}")}),
            );
        } else {
            self.outcome = "ok";
            self.counters.completed.fetch_add(1, Ordering::Relaxed);
        }
    }
}
impl Drop for Session<'_> {
    fn drop(&mut self) {
        let active = self.counters.active.fetch_sub(1, Ordering::Relaxed) - 1;
        event(
            "session_close",
            self.id,
            json!({"outcome":self.outcome,"duration_ms":self.start.elapsed().as_millis() as u64,"active":active,"completed":self.counters.completed.load(Ordering::Relaxed),"failed":self.counters.failed.load(Ordering::Relaxed)}),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn incomplete_handshake_counters_export_to_stats_json_and_prometheus() {
        let counters = Counters::default();
        counters.record_client_hello_incomplete(1448, 1549, true);
        counters.record_client_hello_incomplete(1048, 1532, false);
        counters
            .inner_header_incomplete
            .fetch_add(3, Ordering::Relaxed);

        let stats = counters.snapshot_json("direct");
        assert_eq!(stats["client_hello_incomplete_timeout"], 1);
        assert_eq!(stats["client_hello_incomplete_close"], 1);
        assert_eq!(stats["inner_header_incomplete"], 3);
        assert_eq!(
            stats["last_client_hello_incomplete"]["received_bytes"],
            1048
        );
        assert_eq!(
            stats["last_client_hello_incomplete"]["expected_bytes"],
            1532
        );
        assert_eq!(stats["last_client_hello_incomplete"]["timeout"], false);

        let prom = counters.render_prometheus_with_me(&[], None, None, None);
        assert!(prom.contains("mtevil_client_hello_incomplete_total{reason=\"timeout\"} 1"));
        assert!(prom.contains("mtevil_client_hello_incomplete_total{reason=\"close\"} 1"));
        assert!(prom.contains("mtevil_inner_header_incomplete_total 3"));
    }
}
