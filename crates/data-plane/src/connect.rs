use super::*;

pub(crate) const EGRESS_MAGIC: [u8; 4] = *b"MTV2";
pub(crate) const EGRESS_ACK_OK: u8 = 0x00;
pub(crate) const EGRESS_ACK_ERR: u8 = 0x01;

pub(crate) struct EgressProbe {
    pub(crate) tcp_reachable: bool,
    pub(crate) token_status: &'static str,
    pub(crate) dc_reachable: bool,
    pub(crate) detail: String,
}

pub(crate) fn build_egress_wire_preface(
    token: &[u8; 16],
    dc_id: i16,
    dc_header: &[u8; 64],
    use_mtv3: bool,
) -> Result<Vec<u8>> {
    if use_mtv3 {
        use rand::RngCore;
        let now_secs = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let mut nonce = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let preface = wire::build_egress_preface_v3(token, dc_id, now_secs, &nonce, dc_header)?;
        Ok(preface.to_vec())
    } else {
        let mut preface = vec![0u8; wire::EGRESS_PREFACE_V2_LEN];
        preface[..4].copy_from_slice(&EGRESS_MAGIC);
        preface[4..6].copy_from_slice(&dc_id.to_le_bytes());
        preface[8..24].copy_from_slice(token);
        preface[24..88].copy_from_slice(dc_header);
        Ok(preface)
    }
}

#[cfg(test)]
pub(crate) async fn probe_egress_endpoint(
    addr: SocketAddr,
    dc_id: i16,
    token: &[u8; 16],
    limit: Duration,
) -> EgressProbe {
    probe_egress_endpoint_proto(addr, dc_id, token, limit, false).await
}

pub(crate) async fn probe_egress_endpoint_proto(
    addr: SocketAddr,
    dc_id: i16,
    token: &[u8; 16],
    limit: Duration,
    use_mtv3: bool,
) -> EgressProbe {
    let mut stream = match timeout(limit, TcpStream::connect(addr)).await {
        Ok(Ok(s)) => s,
        Ok(Err(err)) => {
            return EgressProbe {
                tcp_reachable: false,
                token_status: "unknown",
                dc_reachable: false,
                detail: format!("tcp_connect_failed: {err}"),
            };
        }
        Err(_) => {
            return EgressProbe {
                tcp_reachable: false,
                token_status: "unknown",
                dc_reachable: false,
                detail: "tcp_connect_timeout".to_string(),
            };
        }
    };
    let dc = match wire::dc_transport() {
        Ok(dc) => dc,
        Err(err) => {
            return EgressProbe {
                tcp_reachable: true,
                token_status: "unknown",
                dc_reachable: false,
                detail: format!("dc_transport_error: {err:#}"),
            };
        }
    };
    let preface = match build_egress_wire_preface(token, dc_id, &dc.header, use_mtv3) {
        Ok(p) => p,
        Err(err) => {
            return EgressProbe {
                tcp_reachable: true,
                token_status: "unknown",
                dc_reachable: false,
                detail: format!("preface_build_error: {err:#}"),
            };
        }
    };
    if let Err(err) = timeout(limit, stream.write_all(&preface)).await {
        return EgressProbe {
            tcp_reachable: true,
            token_status: "unknown",
            dc_reachable: false,
            detail: format!("preface_write_timeout: {err}"),
        };
    }
    let mut ack = [0u8; 1];
    match timeout(limit, stream.read_exact(&mut ack)).await {
        Ok(Ok(_)) if ack[0] == EGRESS_ACK_OK => EgressProbe {
            tcp_reachable: true,
            token_status: "accepted",
            dc_reachable: true,
            detail: format!("dc {dc_id} reachable via egress"),
        },
        Ok(Ok(_)) => EgressProbe {
            tcp_reachable: true,
            token_status: "accepted",
            dc_reachable: false,
            detail: format!("dc {dc_id} unreachable from egress (negative ack)"),
        },
        Ok(Err(err))
            if matches!(
                err.kind(),
                std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::ConnectionReset
            ) =>
        {
            EgressProbe {
                tcp_reachable: true,
                token_status: "unknown",
                dc_reachable: false,
                detail: "connection closed before ACK (token rejected, protocol mismatch, or peer reset)".to_string(),
            }
        }
        Ok(Err(err)) => EgressProbe {
            tcp_reachable: true,
            token_status: "unknown",
            dc_reachable: false,
            detail: format!("ack_read_failed: {err}"),
        },
        Err(_) => EgressProbe {
            tcp_reachable: true,
            token_status: "unknown",
            dc_reachable: false,
            detail: "ack_read_timeout".to_string(),
        },
    }
}

pub(crate) fn build_req_pq_multi_frame(nonce: &[u8; 16]) -> Vec<u8> {
    // MTProto unencrypted message: auth_key_id(8=0) + msg_id(8, unix<<32) + msg_len(4=20) +
    // req_pq_multi#be7e8ef1 (4) + nonce(16) = 40 bytes payload.
    // Wrapped in padded-intermediate frame: len(4 LE = 40) + payload(40) = 44 bytes.
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(1_700_000_000);
    let msg_id = (now_secs << 32) & !3u64;
    let mut frame = Vec::with_capacity(44);
    frame.extend_from_slice(&40u32.to_le_bytes());
    frame.extend_from_slice(&0u64.to_le_bytes());
    frame.extend_from_slice(&msg_id.to_le_bytes());
    frame.extend_from_slice(&20u32.to_le_bytes());
    frame.extend_from_slice(&[0xf1, 0x8e, 0x7e, 0xbe]); // req_pq_multi#be7e8ef1
    frame.extend_from_slice(nonce);
    frame
}

pub(crate) fn validate_res_pq_payload(payload: &[u8], expected_nonce: &[u8; 16]) -> Result<()> {
    // Unencrypted MTProto response: auth_key_id(8=0) + msg_id(8) + msg_len(4) + resPQ#05162463(4) + nonce(16) + ...
    ensure!(
        payload.len() >= 40,
        "Telegram DC reply too short ({} bytes)",
        payload.len()
    );
    ensure!(
        payload[0..8] == [0u8; 8],
        "unexpected non-zero auth_key_id in resPQ"
    );
    ensure!(
        payload[20..24] == [0x63, 0x24, 0x16, 0x05],
        "unexpected MTProto constructor (expected resPQ#05162463)"
    );
    ensure!(&payload[24..40] == expected_nonce, "resPQ nonce mismatch");
    Ok(())
}

pub(crate) async fn read_tls_record_raw(stream: &mut TcpStream) -> Result<(u8, Vec<u8>)> {
    let mut hdr = [0u8; 5];
    stream
        .read_exact(&mut hdr)
        .await
        .context("reading TLS record header")?;
    let n = usize::from(u16::from_be_bytes([hdr[3], hdr[4]]));
    ensure!(n <= wire::MAX_RECORD, "TLS record exceeds bound");
    let mut body = vec![0u8; n];
    stream
        .read_exact(&mut body)
        .await
        .context("reading TLS record body")?;
    let mut raw = Vec::with_capacity(5 + n);
    raw.extend_from_slice(&hdr);
    raw.extend_from_slice(&body);
    Ok((hdr[0], raw))
}

pub(crate) async fn probe_telegram_e2e(
    cfg: &Config,
    addr: SocketAddr,
    dc_id: i16,
    limit: Duration,
) -> Result<u64> {
    use rand::RngCore;
    let started = Instant::now();
    timeout(limit, async {
        let mut nonce = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let mut req_frame = build_req_pq_multi_frame(&nonce);

        if cfg.role == Role::Egress {
            let token = cfg.egress_token()?;
            let mut dc = wire::dc_transport()?;
            let mut stream = TcpStream::connect(addr)
                .await
                .with_context(|| format!("connecting to egress {addr}"))?;
            let preface =
                build_egress_wire_preface(&token, dc_id, &dc.header, cfg.egress_use_mtv3)?;
            stream
                .write_all(&preface)
                .await
                .context("writing egress preface")?;
            let mut ack = [0u8; 1];
            stream
                .read_exact(&mut ack)
                .await
                .context("reading egress ACK")?;
            ensure!(ack[0] == EGRESS_ACK_OK, "egress returned negative ACK for DC {dc_id}");
            wire::crypt(&mut dc.encrypt, &mut req_frame);
            stream.write_all(&req_frame).await.context("sending req_pq_multi")?;

            let mut len_buf = [0u8; 4];
            stream.read_exact(&mut len_buf).await.context("reading DC frame length")?;
            wire::crypt(&mut dc.decrypt, &mut len_buf);
            let frame_len = (u32::from_le_bytes(len_buf) & 0x7fff_ffff) as usize;
            ensure!((40..=4096).contains(&frame_len), "unexpected DC frame length {frame_len}");
            let mut payload = vec![0u8; frame_len];
            stream.read_exact(&mut payload).await.context("reading DC resPQ payload")?;
            wire::crypt(&mut dc.decrypt, &mut payload);
            validate_res_pq_payload(&payload, &nonce)?;
            return Ok(started.elapsed().as_millis() as u64);
        }

        let secrets = cfg.secrets()?;
        let secret = &secrets[0].key;
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let (hello_rec, client_random, client_session) =
            wire::build_client_hello(secret, &cfg.sni, now, &mut rand::rngs::OsRng)?;

        let mut stream = TcpStream::connect(addr)
            .await
            .with_context(|| format!("connecting to proxy {addr}"))?;
        stream.write_all(&hello_rec).await.context("writing FakeTLS ClientHello")?;

        let mut flight = Vec::new();
        for expected_kind in [0x16u8, 0x14u8, 0x17u8] {
            let (kind, raw) = read_tls_record_raw(&mut stream).await?;
            ensure!(
                kind == expected_kind,
                "unexpected ServerHello flight record kind 0x{kind:02x} (expected 0x{expected_kind:02x})"
            );
            flight.extend_from_slice(&raw);
        }
        wire::verify_server_flight(secret, &client_random, &client_session, &flight)?;

        let (init_hdr, mut encrypt, mut decrypt) = wire::build_client_init(secret, dc_id)?;
        wire::crypt(&mut encrypt, &mut req_frame);
        let mut combined = Vec::with_capacity(init_hdr.len() + req_frame.len());
        combined.extend_from_slice(&init_hdr);
        combined.extend_from_slice(&req_frame);
        let app_rec = wire::record(0x17, &combined)?;
        stream.write_all(&app_rec).await.context("writing obfuscated2 init + req_pq_multi")?;

        let mut tls_reader = TlsReader::default();
        let mut len_buf = [0u8; 4];
        let mut off = 0;
        while off < 4 {
            let n = tls_reader.read_into(&mut stream, &mut len_buf[off..]).await?;
            ensure!(n > 0, "EOF before Telegram DC reply length");
            off += n;
        }
        wire::crypt(&mut decrypt, &mut len_buf);
        let frame_len = (u32::from_le_bytes(len_buf) & 0x7fff_ffff) as usize;
        ensure!((40..=4096).contains(&frame_len), "unexpected Telegram reply frame length {frame_len}");
        let mut payload = vec![0u8; frame_len];
        let mut p_off = 0;
        while p_off < frame_len {
            let n = tls_reader.read_into(&mut stream, &mut payload[p_off..]).await?;
            ensure!(n > 0, "EOF before Telegram resPQ payload");
            p_off += n;
        }
        wire::crypt(&mut decrypt, &mut payload);
        validate_res_pq_payload(&payload, &nonce)?;
        Ok(started.elapsed().as_millis() as u64)
    })
    .await
    .context("probe_telegram_timeout")?
}

#[cfg(test)]
pub(crate) fn default_media_override_map() -> HashMap<i16, Vec<SocketAddr>> {
    Config {
        role: Role::Direct,
        listen: SocketAddr::from(([127, 0, 0, 1], 24443)),
        secret_file: None,
        users_file: None,
        replay_file: None,
        sni: String::new(),
        cover: String::new(),
        enable_dd: false,
        proxy_protocol: false,
        dc: Vec::new(),
        egress_upstreams: Vec::new(),
        egress_strategy: EgressStrategy::RoundRobin,
        egress_token_file: None,
        max_connections: 128,
        client_hello_timeout_secs: 5,
        handshake_timeout_secs: 10,
        idle_timeout_secs: 300,
        drain_timeout_secs: 5,
        fake_tls_cert_bytes: wire::DEFAULT_CERT_BYTES,
        fake_tls_cert_jitter: 0,
        flight_shaping: false,
        client_mss: None,
        client_mss_bulk: None,
        alert_webhook_url: None,
        egress_cooldown_base_ms: config::default_egress_cooldown_base_ms(),
        egress_cooldown_max_ms: config::default_egress_cooldown_max_ms(),
        egress_probe_interval_secs: config::default_egress_probe_interval_secs(),
        egress_probe_degraded_interval_secs: config::default_egress_probe_degraded_interval_secs(),
        egress_hedge_ms: config::default_egress_hedge_ms(),
        egress_accept_legacy: config::default_egress_accept_legacy(),
        egress_use_mtv3: config::default_egress_use_mtv3(),
        egress_allow_from: Vec::new(),
        egress_max_failed_per_ip: config::default_egress_max_failed_per_ip(),
        egress_nonce_cache_capacity: None,
        dc_media_override: config::default_dc_media_override(),
        dc_probe_interval_secs: config::default_dc_probe_interval_secs(),
        cover_dns_ttl_secs: config::default_cover_dns_ttl_secs(),
        diagnostics: false,
        metrics_listen: None,
    }
    .dc_media_overrides()
    .unwrap_or_default()
}

#[cfg(test)]
pub(crate) fn lookup_dc_addr(dcs: &HashMap<i16, SocketAddr>, dc_id: i16) -> Option<SocketAddr> {
    lookup_dc_candidates(dcs, dc_id, 0).into_iter().next()
}

#[cfg(test)]
pub(crate) fn lookup_dc_candidates(
    dcs: &HashMap<i16, SocketAddr>,
    dc_id: i16,
    seq: usize,
) -> Vec<SocketAddr> {
    lookup_dc_candidates_with_overrides(dcs, &default_media_override_map(), dc_id, seq)
}

pub(crate) fn lookup_dc_candidates_with_overrides(
    dcs: &HashMap<i16, SocketAddr>,
    overrides: &HashMap<i16, Vec<SocketAddr>>,
    dc_id: i16,
    seq: usize,
) -> Vec<SocketAddr> {
    let std_dc2 = SocketAddr::from(([149, 154, 167, 51], 443));
    let std_dc2_media = SocketAddr::from(([149, 154, 167, 151], 443));
    let std_dc4 = SocketAddr::from(([149, 154, 167, 91], 443));
    let std_dc4_media = SocketAddr::from(([149, 154, 166, 120], 443));

    if let Some(&addr) = dcs.get(&dc_id) {
        let mut out = vec![addr];
        let is_standard_prod = (dc_id == 2 && addr == std_dc2)
            || (dc_id == -2 && addr == std_dc2_media)
            || (dc_id == 4 && addr == std_dc4)
            || (dc_id == -4 && addr == std_dc4_media);
        let apply_ovr = is_standard_prod
            || overrides
                .get(&dc_id)
                .is_some_and(|list| list.contains(&addr));
        if apply_ovr {
            if let Some(ovr_list) = overrides.get(&dc_id) {
                if dc_id < 0 && ovr_list.len() >= 2 && seq % 2 == 1 {
                    let mut rot = Vec::with_capacity(ovr_list.len() + 2);
                    for (i, &cand) in ovr_list.iter().enumerate() {
                        if i > 0 && !rot.contains(&cand) {
                            rot.push(cand);
                        }
                    }
                    if !rot.contains(&addr) {
                        rot.push(addr);
                    }
                    if let Some(&first) = ovr_list.first() {
                        if !rot.contains(&first) {
                            rot.push(first);
                        }
                    }
                    out = rot;
                } else {
                    for &cand in ovr_list {
                        if !out.contains(&cand) {
                            out.push(cand);
                        }
                    }
                }
            }
            if dc_id < 0 {
                if let Some(&base) = dcs.get(&dc_id.abs()) {
                    if !out.contains(&base) {
                        out.push(base);
                    }
                } else if dc_id == -2 && !out.contains(&std_dc2) {
                    out.push(std_dc2);
                } else if dc_id == -4 && !out.contains(&std_dc4) {
                    out.push(std_dc4);
                }
            }
        }
        return out;
    }
    if dc_id < 0 {
        if let Some(ovr_list) = overrides.get(&dc_id).filter(|l| !l.is_empty()) {
            let apply = match dcs.get(&dc_id.abs()) {
                Some(&base) => {
                    (dc_id == -2 && base == std_dc2)
                        || (dc_id == -4 && base == std_dc4)
                        || ovr_list.iter().any(|c| {
                            c.ip() != std_dc2_media.ip()
                                && c.ip() != std_dc4_media.ip()
                                && c.ip() != std::net::IpAddr::from([149, 154, 167, 220])
                                && c.ip() != std::net::IpAddr::from([149, 154, 167, 92])
                        })
                }
                None => false,
            };
            if apply {
                let mut out = if ovr_list.len() >= 2 && seq % 2 == 1 {
                    let mut rot = ovr_list[1..].to_vec();
                    rot.push(ovr_list[0]);
                    rot
                } else {
                    ovr_list.clone()
                };
                if let Some(&base) = dcs.get(&dc_id.abs()) {
                    if !out.contains(&base) {
                        out.push(base);
                    }
                }
                return out;
            }
        }
    }
    let Some(&base) = dcs.get(&dc_id.abs()) else {
        return Vec::new();
    };
    vec![base]
}

pub(crate) async fn run_dc_reachability_check_once(
    dcs: &HashMap<i16, SocketAddr>,
    overrides: &HashMap<i16, Vec<SocketAddr>>,
    counters: &telemetry::Counters,
    per_target_limit: Duration,
) -> (usize, usize) {
    use std::sync::atomic::Ordering::Relaxed;
    let mut targets: Vec<(i16, SocketAddr)> = Vec::new();
    let mut ids: Vec<i16> = dcs.keys().copied().collect();
    for &id in overrides.keys() {
        if !ids.contains(&id) && dcs.contains_key(&id.abs()) {
            ids.push(id);
        }
    }
    ids.sort();
    for id in ids {
        for addr in lookup_dc_candidates_with_overrides(dcs, overrides, id, 0) {
            if !targets.iter().any(|(_, a)| *a == addr) {
                targets.push((id, addr));
            }
        }
    }
    let mut ok_count = 0usize;
    let mut fail_count = 0usize;
    let mut checks = Vec::with_capacity(targets.len());
    for (dc_id, addr) in targets {
        let t0 = Instant::now();
        let reachable = timeout(per_target_limit, TcpStream::connect(addr))
            .await
            .is_ok_and(|res| res.is_ok());
        let rtt_ms = t0.elapsed().as_millis() as u64;
        if reachable {
            ok_count += 1;
            counters.dc_self_check_ok.fetch_add(1, Relaxed);
        } else {
            fail_count += 1;
            counters.dc_self_check_failed.fetch_add(1, Relaxed);
        }
        checks.push(json!({
            "dc": dc_id,
            "address": addr.to_string(),
            "reachable": reachable,
            "rtt_ms": rtt_ms,
        }));
    }
    telemetry::event(
        "dc_self_check",
        0,
        json!({
            "reachable_count": ok_count,
            "unreachable_count": fail_count,
            "checks": checks,
        }),
    );
    (ok_count, fail_count)
}

pub(crate) async fn monitor_dc_reachability(
    dcs: Arc<HashMap<i16, SocketAddr>>,
    overrides: Arc<HashMap<i16, Vec<SocketAddr>>>,
    counters: Arc<telemetry::Counters>,
    period: Duration,
) {
    let mut interval = tokio::time::interval(period);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        interval.tick().await;
        let _ = run_dc_reachability_check_once(&dcs, &overrides, &counters, Duration::from_secs(3))
            .await;
    }
}

pub(crate) async fn connect_dc_candidates(
    candidates: &[SocketAddr],
    handshake: Duration,
) -> Result<TcpStream> {
    ensure!(!candidates.is_empty(), "DC not configured");
    if candidates.len() == 1 {
        let stream = timeout(handshake, TcpStream::connect(candidates[0]))
            .await
            .context("dc_connect_timeout")?
            .context("dc_connect_failed")?;
        configure_tcp_socket(&stream)?;
        return Ok(stream);
    }
    let per_try = (handshake / (candidates.len() as u32))
        .max(Duration::from_millis(200))
        .min(Duration::from_millis(1500));
    timeout(handshake, async {
        let mut last_err = None;
        for &addr in candidates {
            match timeout(per_try, TcpStream::connect(addr)).await {
                Ok(Ok(stream)) => {
                    configure_tcp_socket(&stream)?;
                    return Ok(stream);
                }
                Ok(Err(err)) => last_err = Some(anyhow::Error::from(err)),
                Err(_) => last_err = Some(anyhow::anyhow!("dc_connect_timeout")),
            }
        }
        Err(last_err.unwrap_or_else(|| anyhow::anyhow!("dc_connect_failed")))
            .context("dc_connect_failed")
    })
    .await
    .context("dc_connect_timeout")?
}

pub(crate) enum EgressAttemptErr {
    Node(anyhow::Error),
    Dc(anyhow::Error),
}

pub(crate) async fn dial_egress_candidate(
    state: &State,
    idx: usize,
    dc_id: i16,
    dc_abs: i16,
    dc_header: &[u8; 64],
    per_try: Duration,
) -> std::result::Result<TcpStream, EgressAttemptErr> {
    use std::sync::atomic::Ordering::Relaxed;
    let addr = state.egress_upstreams[idx];
    match timeout(per_try, async {
        let mut upstream = TcpStream::connect(addr)
            .await
            .map_err(|e| EgressAttemptErr::Node(e.into()))?;
        configure_tcp_socket(&upstream).map_err(EgressAttemptErr::Node)?;
        let preface =
            build_egress_wire_preface(&state.egress_token, dc_id, dc_header, state.egress_use_mtv3)
                .map_err(EgressAttemptErr::Node)?;
        upstream
            .write_all(&preface)
            .await
            .map_err(|e| EgressAttemptErr::Node(e.into()))?;
        state
            .counters
            .upstream_tx_bytes
            .fetch_add(preface.len() as u64, Relaxed);
        let mut ack = [0u8; 1];
        upstream
            .read_exact(&mut ack)
            .await
            .map_err(|e| EgressAttemptErr::Node(e.into()))?;
        state
            .counters
            .upstream_rx_bytes
            .fetch_add(ack.len() as u64, Relaxed);
        if ack[0] == EGRESS_ACK_OK {
            Ok(upstream)
        } else if ack[0] == EGRESS_ACK_ERR {
            Err(EgressAttemptErr::Dc(anyhow::anyhow!(
                "egress DC {dc_abs} unreachable (negative ACK)"
            )))
        } else {
            Err(EgressAttemptErr::Node(anyhow::anyhow!(
                "egress upstream invalid ACK byte"
            )))
        }
    })
    .await
    {
        Ok(res) => res,
        Err(_) => Err(EgressAttemptErr::Node(anyhow::anyhow!(
            "egress_connect_timeout"
        ))),
    }
}

pub(crate) fn finalize_egress_success(
    state: &State,
    idx: usize,
    claim: EgressAttemptClaim<'_>,
    ordered: bool,
    last_err: &Option<anyhow::Error>,
    default_backup_reason: &'static str,
) {
    let addr = state.egress_upstreams[idx];
    claim.record_success();
    let (healthy, total) = EgressHealth::set_node_availability(&state.egress_health, idx, true);
    let (next_state, reason, active_override) = if ordered {
        if idx == 0 {
            (
                EdgeRouteState::PrimaryOk,
                "primary_recovered".to_string(),
                Some(addr),
            )
        } else {
            state
                .counters
                .egress_failover_total
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            (
                EdgeRouteState::FailoverBackup(idx),
                last_err
                    .as_ref()
                    .map(|e| format!("{e:#}"))
                    .unwrap_or_else(|| default_backup_reason.to_string()),
                Some(addr),
            )
        }
    } else if healthy == total {
        (
            EdgeRouteState::PrimaryOk,
            "all_egress_recovered".to_string(),
            Some(addr),
        )
    } else {
        (
            EdgeRouteState::Degraded { healthy, total },
            last_err
                .as_ref()
                .map(|e| format!("{e:#}"))
                .unwrap_or_else(|| default_backup_reason.to_string()),
            Some(addr),
        )
    };
    if let Some(ev) = EgressHealth::transition_route_state(
        &state.egress_health,
        next_state,
        &state.egress_upstreams,
        reason,
        state.egress_strategy,
        active_override,
    ) {
        emit_edge_route_alert(state, ev);
    }
}

pub(crate) fn finalize_egress_error(
    state: &State,
    idx: usize,
    claim: EgressAttemptClaim<'_>,
    err: EgressAttemptErr,
) -> anyhow::Error {
    EgressHealth::set_node_availability(&state.egress_health, idx, false);
    match err {
        EgressAttemptErr::Dc(e) => {
            claim.record_dc_failure(state.egress_cooldown, state.egress_cooldown_max);
            e
        }
        EgressAttemptErr::Node(e) => {
            claim.record_node_failure(state.egress_cooldown, state.egress_cooldown_max);
            e
        }
    }
}

pub(crate) async fn connect_upstream(
    state: &State,
    dc_id: i16,
    dc_header: &[u8; 64],
) -> Result<(TcpStream, &'static str)> {
    use std::sync::atomic::Ordering::Relaxed;
    if state.egress_upstreams.is_empty() {
        let seq = state.egress_rr.fetch_add(1, Relaxed);
        let candidates =
            lookup_dc_candidates_with_overrides(&state.dcs, &state.dc_media_overrides, dc_id, seq);
        let mut upstream = connect_dc_candidates(&candidates, state.handshake).await?;
        timeout(state.handshake, upstream.write_all(dc_header)).await??;
        state
            .counters
            .upstream_tx_bytes
            .fetch_add(dc_header.len() as u64, Relaxed);
        return Ok((upstream, "direct"));
    }
    let count = state.egress_upstreams.len();
    let start = match state.egress_strategy {
        EgressStrategy::Ordered => 0,
        EgressStrategy::RoundRobin => state.egress_rr.fetch_add(1, Relaxed),
    };
    let per_try = (state.handshake / (count as u32).max(1))
        .max(Duration::from_millis(150))
        .min(Duration::from_secs(2));
    let dc_abs = dc_id.abs();
    let ordered = state.egress_strategy == EgressStrategy::Ordered;
    let hedge_delay = (ordered && state.egress_hedge_ms > 0)
        .then(|| Duration::from_millis(state.egress_hedge_ms))
        .filter(|d| *d < per_try);
    timeout(state.handshake, async {
        let mut last_err: Option<anyhow::Error> = None;
        let mut attempted_any = false;
        let mut hedged_this_conn = false;
        let mut offset = 0;
        while offset < count {
            let idx = (start + offset) % count;
            offset += 1;
            let Some(claim) =
                EgressHealth::try_claim(&state.egress_health, idx, dc_abs, Instant::now())
            else {
                continue;
            };
            attempted_any = true;
            if let Some(h_delay) = hedge_delay.filter(|_| !hedged_this_conn && offset < count) {
                let fut1 = dial_egress_candidate(state, idx, dc_id, dc_abs, dc_header, per_try);
                tokio::pin!(fut1);
                let early = tokio::select! {
                    biased;
                    res1 = &mut fut1 => Some(res1),
                    () = tokio::time::sleep(h_delay) => None,
                };
                if let Some(res1) = early {
                    match res1 {
                        Ok(upstream) => {
                            finalize_egress_success(
                                state,
                                idx,
                                claim,
                                ordered,
                                &last_err,
                                "primary_in_cooldown",
                            );
                            return Ok((upstream, "egress"));
                        }
                        Err(err1) => {
                            last_err = Some(finalize_egress_error(state, idx, claim, err1));
                            continue;
                        }
                    }
                }
                // Primary did not ACK within hedge_delay: claim next available candidate for hedge (at most 1 per conn).
                let mut backup_claim = None;
                while offset < count {
                    let cand_idx = (start + offset) % count;
                    offset += 1;
                    if let Some(c2) = EgressHealth::try_claim(
                        &state.egress_health,
                        cand_idx,
                        dc_abs,
                        Instant::now(),
                    ) {
                        backup_claim = Some((cand_idx, c2));
                        break;
                    }
                }
                let Some((idx2, claim2)) = backup_claim else {
                    match fut1.await {
                        Ok(upstream) => {
                            finalize_egress_success(
                                state,
                                idx,
                                claim,
                                ordered,
                                &last_err,
                                "primary_in_cooldown",
                            );
                            return Ok((upstream, "egress"));
                        }
                        Err(err1) => {
                            last_err = Some(finalize_egress_error(state, idx, claim, err1));
                            continue;
                        }
                    }
                };
                hedged_this_conn = true;
                state.counters.hedge_started.fetch_add(1, Relaxed);
                let fut2 = dial_egress_candidate(state, idx2, dc_id, dc_abs, dc_header, per_try);
                tokio::pin!(fut2);
                enum HedgeRace {
                    First(std::result::Result<TcpStream, EgressAttemptErr>),
                    Second(std::result::Result<TcpStream, EgressAttemptErr>),
                }
                let first_done = tokio::select! {
                    res1 = &mut fut1 => HedgeRace::First(res1),
                    res2 = &mut fut2 => HedgeRace::Second(res2),
                };
                match first_done {
                    HedgeRace::First(Ok(stream1)) => {
                        drop(claim2);
                        finalize_egress_success(
                            state,
                            idx,
                            claim,
                            ordered,
                            &last_err,
                            "primary_in_cooldown",
                        );
                        return Ok((stream1, "egress"));
                    }
                    HedgeRace::First(Err(err1)) => {
                        last_err = Some(finalize_egress_error(state, idx, claim, err1));
                        match fut2.await {
                            Ok(stream2) => {
                                state.counters.hedge_won_by_backup.fetch_add(1, Relaxed);
                                finalize_egress_success(
                                    state,
                                    idx2,
                                    claim2,
                                    ordered,
                                    &last_err,
                                    "hedged_connect_backup_won",
                                );
                                return Ok((stream2, "egress"));
                            }
                            Err(err2) => {
                                last_err = Some(finalize_egress_error(state, idx2, claim2, err2));
                                continue;
                            }
                        }
                    }
                    HedgeRace::Second(Ok(stream2)) => {
                        state.counters.hedge_won_by_backup.fetch_add(1, Relaxed);
                        last_err = Some(finalize_egress_error(
                            state,
                            idx,
                            claim,
                            EgressAttemptErr::Node(anyhow::anyhow!("hedged_primary_slow_ack")),
                        ));
                        finalize_egress_success(
                            state,
                            idx2,
                            claim2,
                            ordered,
                            &last_err,
                            "hedged_connect_backup_won",
                        );
                        return Ok((stream2, "egress"));
                    }
                    HedgeRace::Second(Err(err2)) => {
                        last_err = Some(finalize_egress_error(state, idx2, claim2, err2));
                        match fut1.await {
                            Ok(stream1) => {
                                finalize_egress_success(
                                    state,
                                    idx,
                                    claim,
                                    ordered,
                                    &last_err,
                                    "primary_in_cooldown",
                                );
                                return Ok((stream1, "egress"));
                            }
                            Err(err1) => {
                                last_err = Some(finalize_egress_error(state, idx, claim, err1));
                                continue;
                            }
                        }
                    }
                }
            }

            match dial_egress_candidate(state, idx, dc_id, dc_abs, dc_header, per_try).await {
                Ok(upstream) => {
                    finalize_egress_success(
                        state,
                        idx,
                        claim,
                        ordered,
                        &last_err,
                        "primary_in_cooldown",
                    );
                    return Ok((upstream, "egress"));
                }
                Err(err) => {
                    last_err = Some(finalize_egress_error(state, idx, claim, err));
                }
            }
        }
        // Fail-open when all nodes were in cooldown: force a single probe on the node
        // whose cooldown expires soonest (at most 1 concurrent forced probe per node).
        if !attempted_any {
            if let Some((idx, claim)) =
                EgressHealth::try_claim_forced_soonest(&state.egress_health, count, dc_abs)
            {
                match dial_egress_candidate(state, idx, dc_id, dc_abs, dc_header, per_try).await {
                    Ok(upstream) => {
                        finalize_egress_success(
                            state,
                            idx,
                            claim,
                            ordered,
                            &last_err,
                            "forced_probe_recovered",
                        );
                        return Ok((upstream, "egress"));
                    }
                    Err(err) => {
                        last_err = Some(finalize_egress_error(state, idx, claim, err));
                    }
                }
            }
        }
        let err = last_err
            .unwrap_or_else(|| anyhow::anyhow!("all egress upstreams in cooldown or unavailable"));
        if let Some(ev) = EgressHealth::transition_route_state(
            &state.egress_health,
            EdgeRouteState::AllDown,
            &state.egress_upstreams,
            format!("{err:#}"),
            state.egress_strategy,
            None,
        ) {
            emit_edge_route_alert(state, ev);
        }
        Err(err).context("egress_connect_failed")
    })
    .await
    .context("egress_budget_timeout")?
}
