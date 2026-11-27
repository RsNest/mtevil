use super::*;

pub(crate) fn format_edge_alert_message(ev: &EdgeAlertEvent) -> String {
    if ev.reason == "background_egress_probe_dc2" {
        return match ev.next {
            EdgeRouteState::PrimaryOk => {
                "Фоновая проверка DC2: доступность egress восстановилась.".into()
            }
            EdgeRouteState::FailoverBackup(_) => format!(
                "Фоновая проверка DC2: основной egress ({}) недоступен, резервный отвечает.",
                ev.primary
            ),
            EdgeRouteState::Degraded { healthy, total } => {
                format!("Фоновая проверка DC2: доступно egress {healthy} из {total}.")
            }
            EdgeRouteState::AllDown => "Фоновая проверка DC2: все egress недоступны.".into(),
        };
    }
    match ev.next {
        EdgeRouteState::FailoverBackup(_) => format!(
            "Основной egress ({}) недоступен — трафик переключён на резервный egress ({}).",
            ev.primary,
            ev.active.as_deref().unwrap_or("unknown")
        ),
        EdgeRouteState::Degraded { healthy, total } => format!(
            "Часть узлов egress недоступна в режиме round-robin: доступно {} из {} (последний успешный: {}). Причина: {}",
            healthy,
            total,
            ev.active.as_deref().unwrap_or("нет"),
            ev.reason
        ),
        EdgeRouteState::AllDown => format!(
            "Все узлы egress недоступны (основной: {}). Причина: {}",
            ev.primary, ev.reason
        ),
        EdgeRouteState::PrimaryOk => match ev.strategy {
            EgressStrategy::Ordered => format!(
                "Основной egress ({}) восстановился — трафик вернулся на основной выход.",
                ev.primary
            ),
            EgressStrategy::RoundRobin => {
                "Все узлы egress снова доступны в режиме round-robin.".to_string()
            }
        },
    }
}

pub(crate) fn send_http_alert_webhook(url: &str, payload: &str) -> std::io::Result<()> {
    use std::{
        io::{BufRead, BufReader, Write},
        net::ToSocketAddrs,
    };
    // Minimal stdlib-only HTTP POST for http://host[:port]/path webhooks (no extra crate deps).
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| std::io::Error::other("expected an HTTP webhook URL"))?;
    let (host_port, path) = match rest.find('/') {
        Some(pos) => (&rest[..pos], &rest[pos..]),
        None => (rest, "/"),
    };
    let addr = if host_port.contains(':') {
        host_port.to_string()
    } else {
        format!("{host_port}:80")
    };
    let body = payload.as_bytes();
    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: {host_port}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let endpoint = addr
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| std::io::Error::other("webhook address did not resolve"))?;
    let limit = Duration::from_secs(3);
    let mut stream = std::net::TcpStream::connect_timeout(&endpoint, limit)?;
    stream.set_write_timeout(Some(limit))?;
    stream.set_read_timeout(Some(limit))?;
    stream.write_all(req.as_bytes())?;
    stream.write_all(body)?;
    let mut status = String::new();
    use std::io::Read;
    BufReader::new(stream).take(256).read_line(&mut status)?;
    match status
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok())
    {
        Some(200..=299) => Ok(()),
        _ => Err(std::io::Error::other("webhook did not return HTTP 2xx")),
    }
}

pub(crate) const ALERT_WEBHOOK_QUEUE_CAPACITY: usize = 64;
pub(crate) const ALERT_WEBHOOK_WORKERS: usize = 2;

pub(crate) struct AlertWebhookDispatcher {
    tx: std::sync::mpsc::SyncSender<(String, String)>,
}

impl AlertWebhookDispatcher {
    pub(crate) fn new(capacity: usize, workers: usize) -> Self {
        Self::new_with_handler(capacity, workers, |url, body| {
            for delay in [0, 2, 8] {
                if delay > 0 {
                    std::thread::sleep(Duration::from_secs(delay));
                }
                if send_http_alert_webhook(&url, &body).is_ok() {
                    return;
                }
            }
            telemetry::event("edge_alert_webhook_failed", 0, json!({"attempts": 3}));
        })
    }

    pub(crate) fn new_with_handler<F>(capacity: usize, workers: usize, handler: F) -> Self
    where
        F: Fn(String, String) + Send + Sync + 'static,
    {
        let (tx, rx) = std::sync::mpsc::sync_channel::<(String, String)>(capacity.max(1));
        let rx = Arc::new(std::sync::Mutex::new(rx));
        let handler = Arc::new(handler);
        for _ in 0..workers.max(1) {
            let rx_c = rx.clone();
            let h_c = handler.clone();
            let _ = std::thread::Builder::new()
                .name("mtevil-alert-webhook".into())
                .spawn(move || loop {
                    let item = {
                        let guard = rx_c.lock().unwrap_or_else(|e| e.into_inner());
                        guard.recv()
                    };
                    match item {
                        Ok((url, body)) => h_c(url, body),
                        Err(_) => break,
                    }
                });
        }
        Self { tx }
    }

    pub(crate) fn try_enqueue(
        &self,
        url: String,
        body: String,
        counters: &telemetry::Counters,
    ) -> bool {
        match self.tx.try_send((url, body)) {
            Ok(()) => true,
            Err(_) => {
                counters
                    .alert_webhook_dropped
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                false
            }
        }
    }
}

fn global_alert_webhook_dispatcher() -> &'static AlertWebhookDispatcher {
    static DISPATCHER: std::sync::OnceLock<AlertWebhookDispatcher> = std::sync::OnceLock::new();
    DISPATCHER.get_or_init(|| {
        AlertWebhookDispatcher::new(ALERT_WEBHOOK_QUEUE_CAPACITY, ALERT_WEBHOOK_WORKERS)
    })
}

pub(crate) fn emit_edge_route_alert(state: &State, ev: EdgeAlertEvent) {
    let ts_unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let message = format_edge_alert_message(&ev);
    let payload = json!({
        "ts_unix_ms": ts_unix_ms,
        "event": "edge_route_alert",
        "prev_state": ev.prev.as_str(),
        "state": ev.next.as_str(),
        "primary": ev.primary.clone(),
        "active": ev.active.clone(),
        "reason": ev.reason,
        "message": message,
    });
    telemetry::event("edge_route_alert", 0, payload.clone());

    if let Some(alerts_path) = &state.alerts_file {
        if let Some(parent) = alerts_path.parent() {
            if parent.exists() {
                let line = format!("{payload}\n");
                if let Ok(mut f) = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(alerts_path)
                {
                    use std::io::Write;
                    let _ = f.write_all(line.as_bytes());
                }
            }
        }
    }

    if let Some(url) = state.alert_webhook_url.clone() {
        let body = payload.to_string();
        let _ = global_alert_webhook_dispatcher().try_enqueue(url, body, &state.counters);
    }
}

pub(crate) const BACKGROUND_PROBE_DCS: [i16; 4] = [2, 4, -2, -4];

pub(crate) async fn monitor_edge_egress(state: Arc<State>, period: Duration) {
    let mut previous = None;
    let mut confirmed = None;
    let mut dc_rot: usize = 0;
    let mut first = true;
    let mut next_wait = period;
    loop {
        if !first {
            tokio::time::sleep(next_wait).await;
        }
        first = false;
        let probe_dc = BACKGROUND_PROBE_DCS[dc_rot % BACKGROUND_PROBE_DCS.len()];
        dc_rot = dc_rot.wrapping_add(1);
        let mut probes = tokio::task::JoinSet::new();
        for (idx, endpoint) in state.egress_upstreams.iter().cloned().enumerate() {
            let token = state.egress_token;
            let use_mtv3 = state.egress_use_mtv3;
            let tls_conn = state.ws_pool.as_ref().map(|p| p.tls_connector().clone());
            probes.spawn(async move {
                let limit = Duration::from_secs(4);
                let outcome = match timeout(
                    limit,
                    probe_egress_endpoint_proto(
                        &endpoint,
                        probe_dc,
                        &token,
                        limit,
                        use_mtv3,
                        tls_conn.as_ref(),
                    ),
                )
                .await
                {
                    Ok(probe) if probe.dc_reachable => BackgroundProbeOutcome::PositiveAck,
                    Ok(probe) if probe.tcp_reachable && probe.token_status == "ok" => {
                        BackgroundProbeOutcome::NegativeAck
                    }
                    _ => BackgroundProbeOutcome::TransportFailure,
                };
                (idx, outcome)
            });
        }
        let mut available = vec![false; state.egress_upstreams.len()];
        let mut any_degraded = false;
        while let Some(result) = probes.join_next().await {
            if let Ok((idx, outcome)) = result {
                available[idx] = outcome != BackgroundProbeOutcome::TransportFailure;
                if outcome != BackgroundProbeOutcome::PositiveAck {
                    any_degraded = true;
                }
                EgressHealth::apply_background_probe(
                    &state.egress_health,
                    idx,
                    probe_dc,
                    outcome,
                    state.egress_cooldown,
                    state.egress_cooldown_max,
                );
            }
        }
        let any_down = any_degraded || available.iter().any(|ok| !*ok);
        next_wait = if any_down {
            state.egress_probe_degraded_interval.min(period)
        } else {
            period
        };
        let route = match available.iter().position(|ok| *ok) {
            None => EdgeRouteState::AllDown,
            Some(0) if state.egress_strategy == EgressStrategy::Ordered => {
                EdgeRouteState::PrimaryOk
            }
            Some(idx) if state.egress_strategy == EgressStrategy::Ordered => {
                EdgeRouteState::FailoverBackup(idx)
            }
            Some(_) => {
                let healthy = available.iter().filter(|ok| **ok).count();
                let total = available.len();
                if healthy == total {
                    EdgeRouteState::PrimaryOk
                } else {
                    EdgeRouteState::Degraded { healthy, total }
                }
            }
        };
        // A single transient probe should not trigger an alert; require two consecutive matching observations.
        if previous == Some(route) && confirmed != Some(route) {
            confirmed = Some(route);
            if let Some(event) = EgressHealth::transition_route_state(
                &state.egress_health,
                route,
                &state.egress_upstreams,
                "background_egress_probe_dc2".to_string(),
                state.egress_strategy,
                None,
            ) {
                emit_edge_route_alert(&state, event);
            }
        }
        previous = Some(route);
    }
}
