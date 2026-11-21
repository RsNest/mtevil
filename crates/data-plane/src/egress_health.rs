use super::*;

#[derive(Default, Clone, Copy)]
pub(crate) struct CooldownSlot {
    pub(crate) until: Option<Instant>,
    pub(crate) probing: bool,
    pub(crate) failures: u32,
}

pub(crate) fn compute_egress_cooldown_unclamped_ms(
    base_ms: u64,
    max_ms: u64,
    failures: u32,
) -> u64 {
    let shift = failures.saturating_sub(1).min(20);
    let scaled = base_ms.saturating_mul(1u64 << shift);
    scaled.min(max_ms.max(base_ms))
}

pub(crate) fn apply_cooldown_jitter_ms(clamped_ms: u64, sample_permille: i64) -> u64 {
    let factor = (1000 + sample_permille.clamp(-200, 200)) as u128;
    let out = (u128::from(clamped_ms) * factor) / 1000;
    (out as u64).max(1)
}

pub(crate) fn compute_egress_cooldown(base: Duration, max: Duration, failures: u32) -> Duration {
    use rand::Rng;
    let base_ms = base.as_millis().min(u128::from(u64::MAX)) as u64;
    let max_ms = max.as_millis().min(u128::from(u64::MAX)) as u64;
    let clamped_ms = compute_egress_cooldown_unclamped_ms(base_ms, max_ms, failures);
    let sample = rand::rngs::OsRng.gen_range(-200..=200);
    Duration::from_millis(apply_cooldown_jitter_ms(clamped_ms, sample))
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

#[derive(Default)]
pub(crate) struct EgressHealth {
    pub(crate) nodes: Vec<CooldownSlot>,
    pub(crate) node_failed: Vec<bool>,
    pub(crate) dc_slots: HashMap<(usize, i16), CooldownSlot>,
    pub(crate) route_state: EdgeRouteState,
}

pub(crate) struct EdgeAlertEvent {
    pub(crate) prev: EdgeRouteState,
    pub(crate) next: EdgeRouteState,
    pub(crate) primary: SocketAddr,
    pub(crate) active: Option<SocketAddr>,
    pub(crate) reason: String,
    pub(crate) strategy: EgressStrategy,
}

impl EgressHealth {
    pub(crate) fn new(node_count: usize) -> Self {
        Self {
            nodes: vec![CooldownSlot::default(); node_count],
            node_failed: vec![false; node_count],
            dc_slots: HashMap::new(),
            route_state: EdgeRouteState::PrimaryOk,
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
        dc_abs: i16,
        available: bool,
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
        if available {
            let slot = &mut h.nodes[idx];
            slot.until = None;
            slot.probing = false;
            slot.failures = 0;
            if let Some(dc_slot) = h.dc_slots.get_mut(&(idx, dc_abs)) {
                dc_slot.until = None;
                dc_slot.probing = false;
                dc_slot.failures = 0;
            }
            h.node_failed[idx] = false;
        } else {
            let slot = &mut h.nodes[idx];
            slot.failures = slot.failures.saturating_add(1);
            let cooldown = compute_egress_cooldown(base, max, slot.failures);
            slot.until = Some(Instant::now() + cooldown);
            slot.probing = false;
            h.node_failed[idx] = true;
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
