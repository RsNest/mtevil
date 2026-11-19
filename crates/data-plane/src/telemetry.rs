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
pub struct Counters {
    pub next: AtomicU64,
    pub active: AtomicU64,
    pub completed: AtomicU64,
    pub failed: AtomicU64,
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
