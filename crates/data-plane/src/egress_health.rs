use super::*;

#[derive(Default, Clone, Copy)]
pub(crate) struct CooldownSlot {
    pub(crate) until: Option<Instant>,
    pub(crate) probing: bool,
    pub(crate) failures: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub(crate) enum EdgeRouteState {
    #[default]
    PrimaryOk,
    FailoverBackup(usize),
    Degraded {
        healthy: usize,
        total: usize,
    },
    AllDown,
}

impl EdgeRouteState {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            EdgeRouteState::PrimaryOk => "primary_ok",
            EdgeRouteState::FailoverBackup(_) => "failover_backup",
            EdgeRouteState::Degraded { .. } => "degraded",
            EdgeRouteState::AllDown => "all_down",
        }
    }
}

pub(crate) const ACK_TIMEOUT_ESCALATION_WINDOW: Duration = Duration::from_secs(10);
pub(crate) const ACK_TIMEOUT_ESCALATION_DISTINCT_DCS: usize = 2;
pub(crate) const ACK_TIMEOUT_ESCALATION_CONSECUTIVE: usize = 3;

#[derive(Default, Clone)]
pub(crate) struct AckTimeoutWindow {
    pub(crate) entries: std::collections::VecDeque<(Instant, i16)>,
    pub(crate) last_success: Option<Instant>,
}

#[derive(Default)]
pub(crate) struct EgressHealth {
    pub(crate) nodes: Vec<CooldownSlot>,
    pub(crate) node_failed: Vec<bool>,
    pub(crate) dc_slots: HashMap<(usize, i16), CooldownSlot>,
    pub(crate) route_state: EdgeRouteState,
    pub(crate) node_ack_samples_ms: Vec<std::collections::VecDeque<u64>>,
    pub(crate) node_ack_timeouts: Vec<AckTimeoutWindow>,
    pub(crate) node_down_notifiers: Vec<Arc<tokio::sync::Notify>>,
}

pub(crate) struct EdgeAlertEvent {
    pub(crate) prev: EdgeRouteState,
    pub(crate) next: EdgeRouteState,
    pub(crate) primary: SocketAddr,
    pub(crate) active: Option<SocketAddr>,
    pub(crate) reason: String,
    pub(crate) strategy: EgressStrategy,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BackgroundProbeOutcome {
    PositiveAck,
    NegativeAck,
    TransportFailure,
}

impl EgressHealth {
    pub(crate) fn new(node_count: usize) -> Self {
        Self {
            nodes: vec![CooldownSlot::default(); node_count],
            node_failed: vec![false; node_count],
            dc_slots: HashMap::new(),
            route_state: EdgeRouteState::PrimaryOk,
            node_ack_samples_ms: (0..node_count)
                .map(|_| std::collections::VecDeque::with_capacity(32))
                .collect(),
            node_ack_timeouts: vec![AckTimeoutWindow::default(); node_count],
            node_down_notifiers: (0..node_count)
                .map(|_| Arc::new(tokio::sync::Notify::new()))
                .collect(),
        }
    }

    pub(crate) fn record_ack_latency(
        health: &std::sync::Mutex<Self>,
        idx: usize,
        elapsed: Duration,
    ) {
        let ms = elapsed.as_millis().min(u128::from(u64::MAX)) as u64;
        let now = Instant::now();
        let mut h = health.lock().unwrap_or_else(|e| e.into_inner());
        while h.node_ack_samples_ms.len() <= idx {
            h.node_ack_samples_ms
                .push(std::collections::VecDeque::with_capacity(32));
        }
        let samples = &mut h.node_ack_samples_ms[idx];
        if samples.len() >= 32 {
            samples.pop_front();
        }
        samples.push_back(ms.max(1));
        while h.node_ack_timeouts.len() <= idx {
            h.node_ack_timeouts.push(AckTimeoutWindow::default());
        }
        h.node_ack_timeouts[idx].entries.clear();
        h.node_ack_timeouts[idx].last_success = Some(now);
    }

    /// Record a post-preface ACK timeout on `(idx, dc)` and return `true` if the node should
    /// escalate to node-level cooldown + `node_down` (>=2 distinct DCs or >=3 consecutive
    /// ACK timeouts within 10s with no successful ACK in that window).
    pub(crate) fn record_ack_timeout_and_check_escalation(
        health: &std::sync::Mutex<Self>,
        idx: usize,
        dc: i16,
        now: Instant,
    ) -> bool {
        let mut h = health.lock().unwrap_or_else(|e| e.into_inner());
        while h.node_ack_timeouts.len() <= idx {
            h.node_ack_timeouts.push(AckTimeoutWindow::default());
        }
        let win = &mut h.node_ack_timeouts[idx];
        while let Some(&(ts, _)) = win.entries.front() {
            if now.saturating_duration_since(ts) > ACK_TIMEOUT_ESCALATION_WINDOW {
                win.entries.pop_front();
            } else {
                break;
            }
        }
        win.entries.push_back((now, dc));
        let first_ts = win.entries.front().map(|(t, _)| *t).unwrap_or(now);
        let no_ok_in_window = win.last_success.is_none_or(|t| t < first_ts);
        let mut distinct_dcs: Vec<i16> = Vec::with_capacity(win.entries.len());
        for &(_, d) in &win.entries {
            if !distinct_dcs.contains(&d) {
                distinct_dcs.push(d);
            }
        }
        if no_ok_in_window
            && (distinct_dcs.len() >= ACK_TIMEOUT_ESCALATION_DISTINCT_DCS
                || win.entries.len() >= ACK_TIMEOUT_ESCALATION_CONSECUTIVE)
        {
            win.entries.clear();
            true
        } else {
            false
        }
    }

    /// Adaptive per-try connect/ACK timeout for node `idx`: `max(300 ms, 2 × p95(node_ack_samples_ms[idx]))`
    /// clamped to `max_per_try`, or `max_per_try` until the node has at least 3 samples.
    pub(crate) fn adaptive_per_try(
        health: &std::sync::Mutex<Self>,
        idx: usize,
        max_per_try: Duration,
    ) -> Duration {
        const MIN_SAMPLES: usize = 3;
        let h = health.lock().unwrap_or_else(|e| e.into_inner());
        let Some(samples) = h
            .node_ack_samples_ms
            .get(idx)
            .filter(|s| s.len() >= MIN_SAMPLES)
        else {
            return max_per_try;
        };
        let mut sorted: Vec<u64> = samples.iter().copied().collect();
        sorted.sort_unstable();
        let p95_idx = ((sorted.len() * 95).div_ceil(100))
            .saturating_sub(1)
            .min(sorted.len() - 1);
        let p95_ms = sorted[p95_idx];
        let max_ms = max_per_try.as_millis().min(u128::from(u64::MAX)) as u64;
        let min_ms = 300u64.min(max_ms);
        Duration::from_millis(p95_ms.saturating_mul(2).clamp(min_ms, max_ms))
    }

    pub(crate) fn node_down_notifier(
        health: &std::sync::Mutex<Self>,
        idx: usize,
    ) -> Arc<tokio::sync::Notify> {
        let mut h = health.lock().unwrap_or_else(|e| e.into_inner());
        while h.node_down_notifiers.len() <= idx {
            h.node_down_notifiers
                .push(Arc::new(tokio::sync::Notify::new()));
        }
        h.node_down_notifiers[idx].clone()
    }

    pub(crate) fn notify_node_down(health: &std::sync::Mutex<Self>, idx: usize) {
        let notifier = {
            let h = health.lock().unwrap_or_else(|e| e.into_inner());
            h.node_down_notifiers.get(idx).cloned()
        };
        if let Some(n) = notifier {
            n.notify_waiters();
        }
    }

    pub(crate) fn set_node_availability(
        health: &std::sync::Mutex<EgressHealth>,
        idx: usize,
        available: bool,
    ) -> (usize, usize) {
        let mut h = health.lock().unwrap_or_else(|e| e.into_inner());
        while h.node_failed.len() <= idx {
            h.node_failed.push(false);
        }
        h.node_failed[idx] = !available;
        let total = h.node_failed.len();
        let healthy = h.node_failed.iter().filter(|failed| !**failed).count();
        (healthy, total)
    }

    pub(crate) fn snapshot_breaker_states(
        health: &std::sync::Mutex<EgressHealth>,
        upstreams: &[SocketAddr],
    ) -> Vec<(String, u8)> {
        let now = Instant::now();
        let h = health.lock().unwrap_or_else(|e| e.into_inner());
        upstreams
            .iter()
            .enumerate()
            .map(|(idx, addr)| {
                let code = match h.nodes.get(idx) {
                    Some(slot) if slot.probing => 2,
                    Some(slot) if slot.until.is_some_and(|u| now < u) => 1,
                    _ => 0,
                };
                (addr.to_string(), code)
            })
            .collect()
    }

    pub(crate) fn apply_background_probe(
        health: &std::sync::Mutex<EgressHealth>,
        idx: usize,
        dc_id: i16,
        outcome: BackgroundProbeOutcome,
        base: Duration,
        max: Duration,
    ) {
        let mut h = health.lock().unwrap_or_else(|e| e.into_inner());
        while h.nodes.len() <= idx {
            h.nodes.push(CooldownSlot::default());
        }
        while h.node_failed.len() <= idx {
            h.node_failed.push(false);
        }
        match outcome {
            BackgroundProbeOutcome::PositiveAck => {
                let slot = &mut h.nodes[idx];
                slot.until = None;
                slot.probing = false;
                slot.failures = 0;
                if let Some(dc_slot) = h.dc_slots.get_mut(&(idx, dc_id)) {
                    dc_slot.until = None;
                    dc_slot.probing = false;
                    dc_slot.failures = 0;
                }
                h.node_failed[idx] = false;
            }
            BackgroundProbeOutcome::NegativeAck => {
                // Node transport is healthy; mark only the (node, dc_id) pair in cooldown.
                let slot = &mut h.nodes[idx];
                slot.until = None;
                slot.probing = false;
                slot.failures = 0;
                h.node_failed[idx] = false;
                let dc_slot = h.dc_slots.entry((idx, dc_id)).or_default();
                dc_slot.failures = dc_slot.failures.saturating_add(1);
                let cooldown = compute_egress_cooldown(base, max, dc_slot.failures);
                dc_slot.until = Some(Instant::now() + cooldown);
                dc_slot.probing = false;
            }
            BackgroundProbeOutcome::TransportFailure => {
                let slot = &mut h.nodes[idx];
                slot.failures = slot.failures.saturating_add(1);
                let cooldown = compute_egress_cooldown(base, max, slot.failures);
                slot.until = Some(Instant::now() + cooldown);
                slot.probing = false;
                h.node_failed[idx] = true;
            }
        }
    }

    pub(crate) fn transition_route_state(
        health: &std::sync::Mutex<EgressHealth>,
        next: EdgeRouteState,
        upstreams: &[SocketAddr],
        reason: String,
        strategy: EgressStrategy,
        active_override: Option<SocketAddr>,
    ) -> Option<EdgeAlertEvent> {
        let primary = *upstreams.first()?;
        let mut h = health.lock().unwrap_or_else(|e| e.into_inner());
        if h.route_state == next {
            return None;
        }
        let prev = h.route_state;
        h.route_state = next;
        let active = active_override.or(match next {
            EdgeRouteState::PrimaryOk => Some(primary),
            EdgeRouteState::FailoverBackup(idx) => upstreams.get(idx).copied(),
            EdgeRouteState::Degraded { .. } => None,
            EdgeRouteState::AllDown => None,
        });
        Some(EdgeAlertEvent {
            prev,
            next,
            primary,
            active,
            reason,
            strategy,
        })
    }
}

pub(crate) struct EgressAttemptClaim<'a> {
    pub(crate) health: &'a std::sync::Mutex<EgressHealth>,
    pub(crate) idx: usize,
    pub(crate) dc: i16,
    pub(crate) node_probe: bool,
    pub(crate) dc_probe: bool,
    pub(crate) completed: bool,
}

impl<'a> Drop for EgressAttemptClaim<'a> {
    fn drop(&mut self) {
        if !self.completed && (self.node_probe || self.dc_probe) {
            if let Ok(mut h) = self.health.lock() {
                if self.node_probe {
                    if let Some(slot) = h.nodes.get_mut(self.idx) {
                        slot.probing = false;
                    }
                }
                if self.dc_probe {
                    if let Some(slot) = h.dc_slots.get_mut(&(self.idx, self.dc)) {
                        slot.probing = false;
                    }
                }
            }
        }
    }
}

impl EgressHealth {
    pub(crate) fn try_claim<'a>(
        health: &'a std::sync::Mutex<EgressHealth>,
        idx: usize,
        dc: i16,
        now: Instant,
    ) -> Option<EgressAttemptClaim<'a>> {
        let mut h = health.lock().unwrap_or_else(|e| e.into_inner());
        while h.nodes.len() <= idx {
            h.nodes.push(CooldownSlot::default());
        }
        let mut node_probe = false;
        let node_slot = &mut h.nodes[idx];
        if let Some(until) = node_slot.until {
            if now < until || node_slot.probing {
                return None;
            }
            node_slot.probing = true;
            node_probe = true;
        }
        let mut dc_probe = false;
        if let Some(dc_slot) = h.dc_slots.get_mut(&(idx, dc)) {
            if let Some(until) = dc_slot.until {
                if now < until || dc_slot.probing {
                    if node_probe {
                        h.nodes[idx].probing = false;
                    }
                    return None;
                }
                dc_slot.probing = true;
                dc_probe = true;
            }
        }
        Some(EgressAttemptClaim {
            health,
            idx,
            dc,
            node_probe,
            dc_probe,
            completed: false,
        })
    }

    pub(crate) fn any_probing(health: &std::sync::Mutex<Self>) -> bool {
        let guard = health.lock().unwrap_or_else(|e| e.into_inner());
        guard.nodes.iter().any(|s| s.probing) || guard.dc_slots.values().any(|s| s.probing)
    }

    pub(crate) fn try_claim_forced_soonest<'a>(
        health: &'a std::sync::Mutex<EgressHealth>,
        node_count: usize,
        dc: i16,
    ) -> Option<(usize, EgressAttemptClaim<'a>)> {
        let mut h = health.lock().unwrap_or_else(|e| e.into_inner());
        while h.nodes.len() < node_count {
            h.nodes.push(CooldownSlot::default());
        }
        let mut best: Option<(usize, Option<Instant>)> = None;
        for idx in 0..node_count {
            let node_slot = &h.nodes[idx];
            if node_slot.probing {
                continue;
            }
            let dc_slot = h.dc_slots.get(&(idx, dc));
            if dc_slot.is_some_and(|s| s.probing) {
                continue;
            }
            let eff_until = match (node_slot.until, dc_slot.and_then(|s| s.until)) {
                (Some(a), Some(b)) => Some(a.max(b)),
                (Some(a), None) => Some(a),
                (None, Some(b)) => Some(b),
                (None, None) => None,
            };
            let is_better = match (&best, eff_until) {
                (None, _) => true,
                (Some((_, Some(_))), None) => true,
                (Some((_, Some(cur_min))), Some(cand)) => cand < *cur_min,
                (Some((_, None)), _) => false,
            };
            if is_better {
                best = Some((idx, eff_until));
            }
        }
        let (idx, _) = best?;
        let mut node_probe = false;
        if h.nodes[idx].until.is_some() {
            h.nodes[idx].probing = true;
            node_probe = true;
        }
        let mut dc_probe = false;
        if let Some(dc_slot) = h.dc_slots.get_mut(&(idx, dc)) {
            if dc_slot.until.is_some() {
                dc_slot.probing = true;
                dc_probe = true;
            }
        }
        if !node_probe && !dc_probe {
            h.nodes[idx].probing = true;
            node_probe = true;
        }
        Some((
            idx,
            EgressAttemptClaim {
                health,
                idx,
                dc,
                node_probe,
                dc_probe,
                completed: false,
            },
        ))
    }
}

impl<'a> EgressAttemptClaim<'a> {
    pub(crate) fn record_success(mut self) {
        self.completed = true;
        let mut h = self.health.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(slot) = h.nodes.get_mut(self.idx) {
            slot.until = None;
            slot.probing = false;
            slot.failures = 0;
        }
        if let Some(slot) = h.dc_slots.get_mut(&(self.idx, self.dc)) {
            slot.until = None;
            slot.probing = false;
            slot.failures = 0;
        }
    }

    pub(crate) fn record_node_failure(mut self, base: Duration, max: Duration) {
        self.completed = true;
        let mut h = self.health.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(slot) = h.nodes.get_mut(self.idx) {
            slot.failures = slot.failures.saturating_add(1);
            let cooldown = compute_egress_cooldown(base, max, slot.failures);
            slot.until = Some(Instant::now() + cooldown);
            slot.probing = false;
        }
        if self.dc_probe {
            if let Some(slot) = h.dc_slots.get_mut(&(self.idx, self.dc)) {
                slot.probing = false;
            }
        }
    }

    pub(crate) fn record_dc_failure(mut self, base: Duration, max: Duration) {
        self.completed = true;
        let mut h = self.health.lock().unwrap_or_else(|e| e.into_inner());
        if self.node_probe {
            if let Some(slot) = h.nodes.get_mut(self.idx) {
                slot.until = None;
                slot.probing = false;
                slot.failures = 0;
            }
        }
        let dc_slot = h.dc_slots.entry((self.idx, self.dc)).or_default();
        dc_slot.failures = dc_slot.failures.saturating_add(1);
        let cooldown = compute_egress_cooldown(base, max, dc_slot.failures);
        dc_slot.until = Some(Instant::now() + cooldown);
        dc_slot.probing = false;
    }
}
