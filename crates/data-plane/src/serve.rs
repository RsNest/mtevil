use super::*;

pub(crate) fn parse_proc_self_limits_nofile(text: &str) -> Option<usize> {
    for line in text.lines() {
        let trimmed = line.trim_start();
        if let Some(rest) = trimmed.strip_prefix("Max open files") {
            let first = rest.split_whitespace().next()?;
            if first.eq_ignore_ascii_case("unlimited") {
                return Some(usize::MAX);
            }
            return first.parse::<usize>().ok();
        }
    }
    None
}

pub(crate) fn detect_rlimit_nofile() -> Option<usize> {
    let text = std::fs::read_to_string("/proc/self/limits").ok()?;
    parse_proc_self_limits_nofile(&text)
}

pub(crate) fn detect_fd_used() -> Option<usize> {
    std::fs::read_dir("/proc/self/fd").ok().map(|rd| rd.count())
}

pub(crate) fn spawn_metrics_server(
    listener: TcpListener,
    counters: Arc<telemetry::Counters>,
    breaker_source: Option<Arc<State>>,
    fd_limit: Option<usize>,
    mut stop_rx: tokio::sync::oneshot::Receiver<()>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let accepted = tokio::select! {
                res = listener.accept() => res,
                _ = &mut stop_rx => break,
            };
            let Ok((mut stream, _)) = accepted else {
                continue;
            };
            let counters = counters.clone();
            let breaker_source = breaker_source.clone();
            tokio::spawn(async move {
                let mut req_buf = [0u8; 1024];
                let Ok(Ok(n)) = timeout(Duration::from_secs(2), stream.read(&mut req_buf)).await
                else {
                    return;
                };
                if n == 0 {
                    return;
                }
                let first_line = std::str::from_utf8(&req_buf[..n])
                    .unwrap_or("")
                    .lines()
                    .next()
                    .unwrap_or("");
                let mut parts = first_line.split_whitespace();
                let method = parts.next().unwrap_or("");
                let path = parts.next().unwrap_or("");
                let resp = if method == "GET"
                    && (path == "/metrics" || path.starts_with("/metrics?"))
                {
                    let breaker_states = breaker_source
                        .as_ref()
                        .map(|st| {
                            EgressHealth::snapshot_breaker_states(
                                &st.egress_health,
                                &st.egress_upstreams,
                            )
                        })
                        .unwrap_or_default();
                    let me_snap = breaker_source
                        .as_ref()
                        .and_then(|st| st.me.as_ref().map(|m| m.telemetry_snapshot()));
                    let body = counters.render_prometheus_with_me(
                        &breaker_states,
                        detect_fd_used(),
                        fd_limit,
                        me_snap.as_ref(),
                    );
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    )
                } else {
                    "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        .to_string()
                };
                let _ = timeout(Duration::from_secs(2), stream.write_all(resp.as_bytes())).await;
                let _ = stream.shutdown().await;
            });
        }
    })
}

pub(crate) fn compute_effective_max_connections(
    configured_max: usize,
    rlimit_nofile: Option<usize>,
) -> Result<usize> {
    let effective = match rlimit_nofile {
        Some(nofile) => configured_max.min(nofile.saturating_sub(128) / 2),
        None => configured_max,
    };
    ensure!(
        effective >= 16,
        "effective max_connections ({effective}) is below minimum 16 (configured max_connections={configured_max}, rlimit_nofile={rlimit_nofile:?})"
    );
    Ok(effective)
}

pub(crate) trait Acceptor {
    async fn accept_conn(&mut self) -> std::io::Result<(TcpStream, SocketAddr)>;
}

impl Acceptor for TcpListener {
    async fn accept_conn(&mut self) -> std::io::Result<(TcpStream, SocketAddr)> {
        TcpListener::accept(self).await
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AcceptErrorAction {
    RetryImmediate(&'static str),
    Backoff(&'static str),
    Fatal(&'static str),
}

pub(crate) fn classify_accept_error(err: &std::io::Error) -> AcceptErrorAction {
    use std::io::ErrorKind;
    match err.kind() {
        ErrorKind::ConnectionAborted => {
            return AcceptErrorAction::RetryImmediate("connection_aborted")
        }
        ErrorKind::ConnectionReset => return AcceptErrorAction::RetryImmediate("connection_reset"),
        ErrorKind::Interrupted => return AcceptErrorAction::RetryImmediate("interrupted"),
        ErrorKind::WouldBlock => return AcceptErrorAction::RetryImmediate("would_block"),
        ErrorKind::OutOfMemory => return AcceptErrorAction::Backoff("enomem"),
        ErrorKind::InvalidInput => return AcceptErrorAction::Fatal("fatal"),
        _ => {}
    }
    match err.raw_os_error() {
        // EMFILE (POSIX 24, Winsock WSAEMFILE 10024)
        Some(24 | 10024) => AcceptErrorAction::Backoff("emfile"),
        // ENFILE (POSIX 23)
        Some(23) => AcceptErrorAction::Backoff("enfile"),
        // ENOBUFS (Linux 105, BSD/macOS 55, Winsock WSAENOBUFS 10055)
        Some(105 | 55 | 10055) => AcceptErrorAction::Backoff("enobufs"),
        // ENOMEM (POSIX 12)
        Some(12) => AcceptErrorAction::Backoff("enomem"),
        // ECONNABORTED / ECONNRESET / EINTR / EAGAIN / EPROTO / ENOPROTOOPT / EHOSTUNREACH / ENETUNREACH / ETIMEDOUT
        Some(103 | 10053) => AcceptErrorAction::RetryImmediate("connection_aborted"),
        Some(104 | 10054) => AcceptErrorAction::RetryImmediate("connection_reset"),
        Some(4 | 10004) => AcceptErrorAction::RetryImmediate("interrupted"),
        Some(11 | 10035) => AcceptErrorAction::RetryImmediate("would_block"),
        Some(71 | 92 | 101 | 110 | 112 | 113 | 64) => {
            AcceptErrorAction::RetryImmediate("connection_aborted")
        }
        // EBADF (9 / 10009), EINVAL (22 / 10022), ENOTSOCK (88 / 10038), EOPNOTSUPP (95 / 10045)
        Some(9 | 10009 | 22 | 10022 | 88 | 10038 | 95 | 10045) => AcceptErrorAction::Fatal("fatal"),
        _ => AcceptErrorAction::Backoff("other"),
    }
}

pub(crate) enum AcceptDecision {
    Accepted((TcpStream, SocketAddr)),
    Retry,
    Shutdown,
}

pub(crate) struct AcceptLoopState {
    pub(crate) backoff: Duration,
    pub(crate) last_log: HashMap<&'static str, (Instant, u64)>,
}

impl Default for AcceptLoopState {
    fn default() -> Self {
        Self {
            backoff: Duration::from_millis(10),
            last_log: HashMap::new(),
        }
    }
}

impl AcceptLoopState {
    const MIN_BACKOFF: Duration = Duration::from_millis(10);
    const MAX_BACKOFF: Duration = Duration::from_secs(1);
    const LOG_WINDOW: Duration = Duration::from_secs(1);

    pub(crate) fn log_rate_limited(
        &mut self,
        kind: &'static str,
        action: &'static str,
        backoff_ms: u64,
        err: &std::io::Error,
    ) {
        let now = Instant::now();
        match self.last_log.get_mut(kind) {
            Some((last_at, suppressed)) if now.duration_since(*last_at) < Self::LOG_WINDOW => {
                *suppressed += 1;
            }
            Some((last_at, suppressed)) => {
                let skipped = *suppressed;
                *last_at = now;
                *suppressed = 0;
                telemetry::event(
                    "accept_error",
                    0,
                    json!({
                        "kind": kind,
                        "action": action,
                        "backoff_ms": backoff_ms,
                        "suppressed": skipped,
                        "error": err.to_string(),
                    }),
                );
            }
            None => {
                self.last_log.insert(kind, (now, 0));
                telemetry::event(
                    "accept_error",
                    0,
                    json!({
                        "kind": kind,
                        "action": action,
                        "backoff_ms": backoff_ms,
                        "suppressed": 0,
                        "error": err.to_string(),
                    }),
                );
            }
        }
    }

    pub(crate) async fn handle_result<F: std::future::Future<Output = ()> + Unpin>(
        &mut self,
        accepted: std::io::Result<(TcpStream, SocketAddr)>,
        counters: &telemetry::Counters,
        shutdown: &mut F,
    ) -> Result<AcceptDecision> {
        match accepted {
            Ok(pair) => {
                self.backoff = Self::MIN_BACKOFF;
                Ok(AcceptDecision::Accepted(pair))
            }
            Err(err) => match classify_accept_error(&err) {
                AcceptErrorAction::RetryImmediate(kind) => {
                    counters.accept_errors.record(kind);
                    self.log_rate_limited(kind, "retry_immediate", 0, &err);
                    Ok(AcceptDecision::Retry)
                }
                AcceptErrorAction::Backoff(kind) => {
                    counters.accept_errors.record(kind);
                    let sleep_dur = self.backoff;
                    self.backoff = (self.backoff.saturating_mul(2)).min(Self::MAX_BACKOFF);
                    self.log_rate_limited(kind, "backoff", sleep_dur.as_millis() as u64, &err);
                    tokio::select! {
                        () = tokio::time::sleep(sleep_dur) => Ok(AcceptDecision::Retry),
                        _ = shutdown => Ok(AcceptDecision::Shutdown),
                    }
                }
                AcceptErrorAction::Fatal(kind) => {
                    counters.accept_errors.record(kind);
                    self.log_rate_limited(kind, "fatal", 0, &err);
                    Err(err.into())
                }
            },
        }
    }
}

pub(crate) async fn serve(
    mut listener: impl Acceptor,
    state: Arc<State>,
    max_connections: usize,
    shutdown: impl std::future::Future<Output = ()>,
) -> Result<()> {
    let permits = Arc::new(Semaphore::new(max_connections));
    let mut tasks = tokio::task::JoinSet::new();
    let mut accept_state = AcceptLoopState::default();
    tokio::pin!(shutdown);
    loop {
        // Reap completed tasks before admitting another. A semaphore only bounds
        // live sessions; without reaping, completed JoinSet entries can accumulate.
        while tasks.try_join_next().is_some() {}
        // Acquire before accept: bounded tasks/FDs; overload remains in the kernel backlog.
        let permit = tokio::select! {
            permit = permits.clone().acquire_owned() => permit?,
            _ = &mut shutdown => break,
        };
        let accepted = tokio::select! {
            accepted = listener.accept_conn() => accepted,
            _ = &mut shutdown => break,
        };
        let socket = match accept_state
            .handle_result(accepted, &state.counters, &mut shutdown)
            .await?
        {
            AcceptDecision::Accepted((socket, _)) => socket,
            AcceptDecision::Retry => continue,
            AcceptDecision::Shutdown => break,
        };
        let state = state.clone();
        tasks.spawn(async move {
            let _permit = permit;
            // Deliberately do not log client addresses, secrets or payload bytes.
            let _ = connection(socket, state).await;
        });
    }
    // Stop admission immediately. Drain has its own deadline, independent of a stalled handshake.
    drop(listener);
    telemetry::event(
        "drain_started",
        0,
        json!({"active":state.counters.active.load(std::sync::atomic::Ordering::Relaxed)}),
    );
    if timeout(state.drain, async {
        while tasks.join_next().await.is_some() {}
    })
    .await
    .is_err()
    {
        let remaining = tasks.len() as u64;
        if remaining > 0 {
            state
                .counters
                .forced_close
                .fetch_add(remaining, std::sync::atomic::Ordering::Relaxed);
        }
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
    }
    telemetry::event(
        "shutdown",
        0,
        json!({"active":state.counters.active.load(std::sync::atomic::Ordering::Relaxed)}),
    );
    Ok(())
}

pub(crate) async fn saved_read<R: AsyncRead + Unpin>(
    r: &mut R,
    raw: &mut Vec<u8>,
    end: usize,
) -> Result<()> {
    while raw.len() < end {
        let mut buf = [0u8; 4096];
        let n = (end - raw.len()).min(buf.len());
        let got = r.read(&mut buf[..n]).await?;
        ensure!(got != 0, "EOF during ClientHello");
        raw.extend_from_slice(&buf[..got]);
    }
    Ok(())
}

pub(crate) async fn read_hello<R: AsyncRead + Unpin>(
    r: &mut R,
    raw: &mut Vec<u8>,
) -> Result<Vec<u8>> {
    let mut handshake = Vec::new();
    let mut offset = 0;
    for _ in 0..16 {
        saved_read(r, raw, offset + 1).await?;
        ensure!(raw[offset] == 0x16, "not a handshake record");
        saved_read(r, raw, offset + 5).await?;
        ensure!(
            raw[offset + 1] == 3 && (1..=3).contains(&raw[offset + 2]),
            "TLS version"
        );
        let n = usize::from(u16::from_be_bytes([raw[offset + 3], raw[offset + 4]]));
        ensure!(
            n > 0 && handshake.len() + n <= wire::MAX_HELLO + 4,
            "hello bound"
        );
        let start = offset + 5;
        offset = start + n;
        saved_read(r, raw, offset).await?;
        handshake.extend_from_slice(&raw[start..offset]);
        if handshake.len() >= 4 {
            let expected = wire::handshake_length(&handshake)?;
            ensure!(
                handshake.len() <= expected,
                "coalesced trailing handshake unsupported"
            );
            if handshake.len() == expected {
                return Ok(handshake);
            }
        }
    }
    bail!("too many ClientHello fragments")
}

/// Number of TLS records the ClientHello occupied on the wire.
pub(crate) fn hello_record_count(raw: &[u8]) -> usize {
    let mut offset = 0;
    let mut count = 0;
    while offset + 5 <= raw.len() && raw[offset] == 0x16 {
        let n = usize::from(u16::from_be_bytes([raw[offset + 3], raw[offset + 4]]));
        let next = offset + 5 + n;
        if next > raw.len() {
            break;
        }
        offset = next;
        count += 1;
    }
    count
}

pub(crate) async fn connection(mut client: TcpStream, state: Arc<State>) -> Result<()> {
    let mut session = telemetry::Session::new(&state.counters);
    let result = connection_inner(&mut client, &state, session.id).await;
    session.finish(&result);
    result
}

pub(crate) fn bind_listener(addr: SocketAddr, client_mss: Option<u16>) -> Result<TcpListener> {
    let domain = socket2::Domain::for_address(addr);
    let socket = socket2::Socket::new(domain, socket2::Type::STREAM, Some(socket2::Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    #[cfg(target_os = "linux")]
    if let Some(mss) = client_mss {
        socket
            .set_tcp_mss(u32::from(mss))
            .context("set listener TCP_MAXSEG")?;
    }
    #[cfg(not(target_os = "linux"))]
    let _ = client_mss;
    socket.bind(&addr.into())?;
    socket.listen(1024)?;
    let std_listener: std::net::TcpListener = socket.into();
    Ok(TcpListener::from_std(std_listener)?)
}

pub(crate) fn apply_bulk_mss(stream: &TcpStream, bulk_mss: Option<u16>) {
    #[cfg(target_os = "linux")]
    if let Some(mss) = bulk_mss {
        let _ = socket2::SockRef::from(stream).set_tcp_mss(u32::from(mss));
    }
    #[cfg(not(target_os = "linux"))]
    let _ = (stream, bulk_mss);
}

pub(crate) fn configure_tcp_socket(stream: &TcpStream) -> Result<()> {
    stream.set_nodelay(true)?;
    let keepalive = socket2::TcpKeepalive::new()
        .with_time(Duration::from_secs(60))
        .with_interval(Duration::from_secs(15));
    #[cfg(unix)]
    let keepalive = keepalive.with_retries(3);
    socket2::SockRef::from(stream).set_tcp_keepalive(&keepalive)?;
    Ok(())
}

pub(crate) enum ProxyV2Outcome {
    Header(Option<SocketAddr>),
    EmptyEof,
}

pub(crate) async fn read_proxy_v2<R: AsyncRead + Unpin>(
    r: &mut R,
    limit: Duration,
) -> Result<ProxyV2Outcome> {
    timeout(limit, async {
        let mut hdr = [0u8; wire::PROXY_V2_HEADER_LEN];
        let n = r.read(&mut hdr[..1]).await.context("proxy_v2_eof")?;
        if n == 0 {
            return Ok(ProxyV2Outcome::EmptyEof);
        }
        r.read_exact(&mut hdr[1..]).await.context("proxy_v2_eof")?;
        let parsed = wire::parse_proxy_v2_header(&hdr)?;
        let mut payload = vec![0u8; parsed.payload_len];
        if !payload.is_empty() {
            r.read_exact(&mut payload)
                .await
                .context("proxy_v2_payload_eof")?;
        }
        let client_addr = wire::parse_proxy_v2_payload(&parsed, &payload)?;
        Ok(ProxyV2Outcome::Header(client_addr))
    })
    .await
    .context("proxy_v2_timeout")?
}

pub(crate) async fn connection_inner(
    client: &mut TcpStream,
    state: &State,
    session_id: u64,
) -> Result<()> {
    configure_tcp_socket(client)?;
    let t0 = Instant::now();
    let us = || t0.elapsed().as_micros() as u64;
    let mut proxy_v2_client_addr: Option<SocketAddr> = None;
    if state.proxy_protocol {
        match read_proxy_v2(client, state.client_hello).await {
            Ok(ProxyV2Outcome::Header(addr)) => {
                proxy_v2_client_addr = addr;
            }
            Ok(ProxyV2Outcome::EmptyEof) => {
                telemetry::event(
                    "empty_connection_closed",
                    session_id,
                    json!({"timeout":false,"proxy_protocol":true}),
                );
                return Ok(());
            }
            Err(error) => {
                telemetry::event(
                    "proxy_protocol_failed",
                    session_id,
                    json!({"error": format!("{error:#}")}),
                );
                return Err(error);
            }
        }
    }
    let mut raw = Vec::with_capacity(wire::MAX_HELLO + 84);
    let received = timeout(state.client_hello, async {
        if state.enable_dd {
            saved_read(client, &mut raw, 3).await?;
            if !matches!(raw.as_slice(), [0x16, 3, 1..=3]) {
                saved_read(client, &mut raw, 64).await?;
                return Ok(None);
            }
        }
        read_hello(client, &mut raw).await.map(Some)
    })
    .await;
    if !raw.is_empty() {
        state
            .counters
            .downstream_rx_bytes
            .fetch_add(raw.len() as u64, std::sync::atomic::Ordering::Relaxed);
    }
    if raw.is_empty() {
        telemetry::event(
            "empty_connection_closed",
            session_id,
            json!({"timeout":received.is_err()}),
        );
        return Ok(());
    }
    let hello_read_us = us();
    let hello_records = hello_record_count(&raw);
    let record_version = raw.get(2).copied();
    let indicated_record_bytes = match raw.get(..5) {
        Some([0x16, 3, 1..=3, high, low]) => {
            Some(5 + usize::from(u16::from_be_bytes([*high, *low])))
        }
        _ => None,
    };
    if let Some(size) = indicated_record_bytes.filter(|&size| raw.len() < size) {
        if received.is_err() {
            // The input deadline has expired with an incomplete first record.
            // Starting another upstream exchange would consume another full budget.
            state
                .counters
                .record_client_hello_incomplete(raw.len(), size, true);
            telemetry::event(
                "client_hello_incomplete",
                session_id,
                json!({
                    "received_bytes":raw.len(),
                    "first_tls_record_bytes":indicated_record_bytes,
                }),
            );
            let _ = timeout(DC_EOF_SHUTDOWN_TIMEOUT, async {
                client.shutdown().await?;
                tokio::io::copy(client, &mut tokio::io::sink()).await
            })
            .await;
            return Ok(());
        } else if matches!(received, Ok(Err(_))) {
            state
                .counters
                .record_client_hello_incomplete(raw.len(), size, false);
        }
    }
    if matches!(received, Ok(Ok(None))) {
        let secrets = state.current_secrets();
        let frame: &[u8; 64] = raw.as_slice().try_into()?;
        if let Some((user, transport)) = secrets.iter().find_map(|s| {
            wire::client_transport(frame, &s.key)
                .ok()
                .map(|t| (s.name.clone(), t))
        }) {
            // The first eight bytes do not affect the cipher. Key replays on the
            // wire key/IV so that changing those bytes does not reset the cache.
            let key = Sha256::digest(&frame[8..56]).into();
            let decision = state
                .replay
                .lock()
                .await
                .check_and_insert(key, Instant::now());
            if decision != Decision::Fresh {
                if decision == Decision::Full {
                    state
                        .counters
                        .replay_full
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                telemetry::event(
                    "dd_rejected",
                    session_id,
                    json!({"reason":"replay_or_cache_full"}),
                );
                return Ok(());
            }
            return relay_client(
                client,
                state,
                session_id,
                t0,
                ClientSession {
                    user,
                    transport,
                    tls: None,
                    client_peer: proxy_v2_client_addr,
                    hello_read_us,
                    flight_written_us: None,
                    diag: HelloDiag {
                        client_hello_bytes: raw.len(),
                        client_hello_records: hello_records,
                        record_version,
                        ..HelloDiag::default()
                    },
                },
            )
            .await;
        }
    }
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let record_minor = if let Ok(Ok(Some(ref bytes))) = received {
        if raw.len() == bytes.len() + 5 {
            raw[2]
        } else {
            1
        }
    } else {
        1
    };
    let secrets = state.current_secrets();
    let allowed_snis = state.current_allowed_snis();
    let (auth, failure) = match received {
        Ok(Ok(Some(bytes))) => {
            let mut matched = None;
            let mut last_err = String::new();
            for s in secrets.iter() {
                match wire::authenticate_with_record_version(
                    &bytes,
                    record_minor,
                    &s.key,
                    &allowed_snis,
                    now,
                ) {
                    Ok(hello) => {
                        matched = Some((s, hello));
                        break;
                    }
                    Err(error) => last_err = error.to_string(),
                }
            }
            match matched {
                Some((s, hello)) => (Some((s, hello)), String::new()),
                None => (None, last_err),
            }
        }
        Ok(Ok(None)) => (None, "dd_authentication_failed".to_string()),
        Ok(Err(error)) => (None, error.to_string()),
        Err(_) => (None, "client_hello_timeout".to_string()),
    };
    let Some((matched_secret, hello)) = auth else {
        telemetry::event(
            "cover_selected",
            session_id,
            json!({
                "reason":"unverified_hello",
                "stage_error":failure,
                "received_bytes":raw.len(),
                "first_tls_record_bytes":indicated_record_bytes,
                "client_hello_records":hello_records,
                "record_version":record_version,
            }),
        );
        return bounded_cover(client, raw, state, session_id).await;
    };
    let decision = {
        let mut cache = state.replay.lock().await;
        cache.check_and_insert(hello.replay_key, Instant::now())
    };
    if decision != Decision::Fresh {
        if decision == Decision::Full {
            state
                .counters
                .replay_full
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        telemetry::event(
            "cover_selected",
            session_id,
            json!({"reason":"replay_or_cache_full"}),
        );
        return bounded_cover(client, raw, state, session_id).await;
    }
    let flight_profile = state.flight_profile();
    let flight = wire::server_flight(
        &matched_secret.key,
        &hello,
        &flight_profile,
        &mut rand::rngs::OsRng,
    )?;
    // INV-01: from the first write onwards every error only closes this path.
    // No cover call exists below this boundary, including partial-write failures.
    write_server_flight(client, &flight, state.flight_shaping, state.handshake).await?;
    state
        .counters
        .downstream_tx_bytes
        .fetch_add(flight.len() as u64, std::sync::atomic::Ordering::Relaxed);
    let flight_written_us = us();
    let mut tls = TlsReader::default();
    let mut frame = [0u8; 64];
    let inner = timeout(state.handshake, async {
        let mut off = 0;
        while off < frame.len() {
            let n = tls.read_into(client, &mut frame[off..]).await?;
            ensure!(n > 0, "EOF before inner header");
            off += n;
        }
        Ok::<_, anyhow::Error>(())
    })
    .await;
    state
        .counters
        .downstream_rx_bytes
        .fetch_add(tls.consumed, std::sync::atomic::Ordering::Relaxed);
    let failure = match &inner {
        Ok(Ok(())) => None,
        Ok(Err(error)) => Some(format!("{error:#}")),
        Err(_) => Some("deadline".to_string()),
    };
    if let Some(reason) = failure {
        state
            .counters
            .inner_header_incomplete
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        telemetry::event(
            "inner_header_incomplete",
            session_id,
            json!({
                "reason":reason,
                "flight_bytes":flight.len(),
                "fake_tls_cert_bytes":flight_profile.cert_bytes,
                "client_bytes_after_flight":tls.consumed,
                "client_hello_bytes":raw.len(),
                "client_hello_records":hello_records,
                "record_version":record_version,
                "client_template":hello.template,
                "cipher_suite":hello.cipher_suite,
                "flight_written_us":flight_written_us,
            }),
        );
    }
    inner
        .context("inner_header_timeout")?
        .context("inner_header_invalid")?;
    let transport =
        wire::client_transport(&frame, &matched_secret.key).context("inner_transport_invalid")?;
    relay_client(
        client,
        state,
        session_id,
        t0,
        ClientSession {
            user: matched_secret.name.clone(),
            transport,
            tls: Some(tls),
            client_peer: proxy_v2_client_addr,
            hello_read_us,
            flight_written_us: Some(flight_written_us),
            diag: HelloDiag {
                client_hello_bytes: raw.len(),
                client_hello_records: hello_records,
                record_version,
                client_template: hello.template.clone(),
                cipher_suite: hello.cipher_suite,
                flight_bytes: flight.len(),
                fake_tls_cert_bytes: flight_profile.cert_bytes,
            },
        },
    )
    .await
}

pub(crate) fn ct_eq_16(a: &[u8; 16], b: &[u8; 16]) -> bool {
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

pub(crate) async fn write_server_flight(
    client: &mut TcpStream,
    flight: &[u8],
    shaping: bool,
    handshake: Duration,
) -> Result<()> {
    timeout(handshake, async {
        if !shaping || flight.len() <= 256 {
            client.write_all(flight).await?;
            return Ok::<_, std::io::Error>(());
        }
        use rand::Rng;
        let first_chunk = rand::rngs::OsRng.gen_range(95..=165).min(flight.len());
        client.write_all(&flight[..first_chunk]).await?;
        client.flush().await?;
        if first_chunk < flight.len() {
            let delay_us = rand::rngs::OsRng.gen_range(300..=1000);
            tokio::time::sleep(Duration::from_micros(delay_us)).await;
            client.write_all(&flight[first_chunk..]).await?;
            client.flush().await?;
        }
        Ok(())
    })
    .await
    .context("server_hello_write_timeout")?
    .context("server_hello_write_failed")?;
    Ok(())
}
