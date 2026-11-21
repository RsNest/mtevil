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
}

impl Counters {
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

    pub fn snapshot_json(&self, role: &str) -> Value {
        let started_unix_ms = self.ensure_started();
        let now_unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(started_unix_ms);
        let retrans_supported = cfg!(target_os = "linux");
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
        })
    }

    pub fn render_prometheus(
        &self,
        breaker_states: &[(String, u8)],
        fd_used: Option<usize>,
        fd_limit: Option<usize>,
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
