use super::*;

// Query TCP_INFO on Linux to measure TCP retransmissions on mtevil's own sockets only,
// excluding unrelated VPS traffic even when running with network_mode: host.
#[cfg(unix)]
#[allow(unsafe_code)]
pub(crate) fn sample_fd_retrans(
    fd: Option<std::os::fd::RawFd>,
    prev: &mut u32,
    acc: &std::sync::atomic::AtomicU64,
) {
    #[cfg(target_os = "linux")]
    {
        let Some(raw_fd) = fd else {
            return;
        };
        #[repr(C)]
        #[derive(Default)]
        struct LinuxTcpInfoPrefix {
            tcpi_state: u8,
            tcpi_ca_state: u8,
            tcpi_retransmits: u8,
            tcpi_probes: u8,
            tcpi_backoff: u8,
            tcpi_options: u8,
            tcpi_snd_rcv_wscale: u8,
            tcpi_delivery_rate_app_limited: u8,
            tcpi_rto: u32,
            tcpi_ato: u32,
            tcpi_snd_mss: u32,
            tcpi_rcv_mss: u32,
            tcpi_unacked: u32,
            tcpi_sacked: u32,
            tcpi_lost: u32,
            tcpi_retrans: u32,
            tcpi_fackets: u32,
            tcpi_last_data_sent: u32,
            tcpi_last_ack_sent: u32,
            tcpi_last_data_recv: u32,
            tcpi_last_ack_recv: u32,
            tcpi_pmtu: u32,
            tcpi_rcv_ssthresh: u32,
            tcpi_rtt: u32,
            tcpi_rttvar: u32,
            tcpi_snd_ssthresh: u32,
            tcpi_snd_cwnd: u32,
            tcpi_advmss: u32,
            tcpi_reordering: u32,
            tcpi_rcv_rtt: u32,
            tcpi_rcv_space: u32,
            tcpi_total_retrans: u32,
        }
        extern "C" {
            fn getsockopt(
                sockfd: i32,
                level: i32,
                optname: i32,
                optval: *mut std::ffi::c_void,
                optlen: *mut u32,
            ) -> i32;
        }
        const IPPROTO_TCP: i32 = 6;
        const TCP_INFO: i32 = 11;
        let mut info = LinuxTcpInfoPrefix::default();
        let mut len = std::mem::size_of::<LinuxTcpInfoPrefix>() as u32;
        let rc = unsafe {
            getsockopt(
                raw_fd,
                IPPROTO_TCP,
                TCP_INFO,
                (&mut info as *mut LinuxTcpInfoPrefix).cast::<std::ffi::c_void>(),
                &mut len,
            )
        };
        if rc == 0 && (len as usize) >= std::mem::size_of::<LinuxTcpInfoPrefix>() {
            let cur = info.tcpi_total_retrans;
            if cur >= *prev {
                let delta = cur - *prev;
                if delta > 0 {
                    acc.fetch_add(u64::from(delta), std::sync::atomic::Ordering::Relaxed);
                }
                *prev = cur;
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (fd, prev, acc);
    }
}

#[cfg(not(unix))]
pub(crate) fn sample_fd_retrans(
    _fd: Option<i32>,
    _prev: &mut u32,
    _acc: &std::sync::atomic::AtomicU64,
) {
}

#[cfg(unix)]
pub(crate) fn stream_raw_fd(stream: &TcpStream) -> Option<std::os::fd::RawFd> {
    use std::os::fd::{AsFd, AsRawFd};
    Some(stream.as_fd().as_raw_fd())
}

#[cfg(not(unix))]
pub(crate) fn stream_raw_fd(_stream: &TcpStream) -> Option<i32> {
    None
}

pub(crate) struct ClientSession {
    pub(crate) user: String,
    pub(crate) transport: wire::ClientTransport,
    pub(crate) tls: Option<TlsReader>,
    /// Client peer address from PROXY protocol v2 when enabled; otherwise `None` (falls back to `TcpStream::peer_addr`).
    pub(crate) client_peer: Option<SocketAddr>,
    pub(crate) hello_read_us: u64,
    pub(crate) flight_written_us: Option<u64>,
    pub(crate) diag: HelloDiag,
}

/// Shape of the accepted ClientHello and of the flight we answered with.
/// It identifies the client template without exposing key material.
#[derive(Default, Clone)]
pub(crate) struct HelloDiag {
    pub(crate) client_hello_bytes: usize,
    pub(crate) client_hello_records: usize,
    pub(crate) record_version: Option<u8>,
    pub(crate) client_template: String,
    pub(crate) cipher_suite: u16,
    pub(crate) flight_bytes: usize,
    pub(crate) fake_tls_cert_bytes: usize,
}

pub(crate) async fn relay_client(
    client: &mut TcpStream,
    state: &State,
    session_id: u64,
    t0: Instant,
    session: ClientSession,
) -> Result<()> {
    let ClientSession {
        user,
        transport,
        tls,
        client_peer,
        hello_read_us,
        flight_written_us,
        diag,
    } = session;
    apply_bulk_mss(client, state.client_mss_bulk);
    if let Some(me_rt) = &state.me {
        let effective_peer = client_peer.or_else(|| client.peer_addr().ok());
        let remote_addr = if me_rt.send_client_ip() {
            me::extract_client_ipv4(effective_peer)
        } else {
            None
        };
        match me_rt.open_session(transport.dc, remote_addr, transport.kind) {
            Ok(me_session) => {
                let ad_tag_configured = me_rt.current_ad_tag().is_some();
                return me::relay_me_session(
                    client,
                    state,
                    session_id,
                    t0,
                    user,
                    transport,
                    tls,
                    hello_read_us,
                    flight_written_us,
                    diag,
                    me_session,
                    ad_tag_configured,
                )
                .await;
            }
            Err(err) => {
                if me_rt.fallback_to_direct() {
                    me_rt.record_fallback_to_direct(session_id, transport.dc, &err.to_string());
                } else {
                    return Err(err.context("me_strict_no_healthy_connection"));
                }
            }
        }
    }
    if let Some(edge_me) = &state.edge_me {
        let effective_peer = client_peer.or_else(|| client.peer_addr().ok());
        let remote_addr = if edge_me.send_client_ip {
            me::extract_client_ipv4(effective_peer)
        } else {
            None
        };
        match connect_upstream_mtv4(state, transport.dc, transport.kind, remote_addr).await {
            Ok((upstream, route)) => {
                return me::relay_edge_mtv4_session(
                    client,
                    upstream,
                    route,
                    state,
                    session_id,
                    t0,
                    user,
                    transport,
                    tls,
                    hello_read_us,
                    flight_written_us,
                    diag,
                )
                .await;
            }
            Err(err) => {
                if edge_me.fallback_to_direct {
                    edge_me.record_fallback_to_direct(
                        &state.counters,
                        session_id,
                        transport.dc,
                        &err.to_string(),
                    );
                } else {
                    return Err(err.context("edge_me_strict_no_healthy_egress"));
                }
            }
        }
    }
    let us = || t0.elapsed().as_micros() as u64;
    let framed = tls.is_some();
    let inner_header_us = us();
    let dc = wire::dc_transport_for(transport.kind)?;
    let (upstream, route) = connect_upstream(state, transport.dc, &dc.header).await?;
    let dc_connected_us = us();
    telemetry::event(
        "authenticated",
        session_id,
        json!({
            "user":user,
            "dc":transport.dc,
            "route":route,
            "transport":transport.kind.as_str(),
            "mode": if framed { "ee" } else { "dd" },
            "hello_read_us":hello_read_us,
            "flight_written_us":flight_written_us,
            "inner_header_us":inner_header_us,
            "dc_connected_us":dc_connected_us,
            "dc_header_written_us":us(),
            "client_hello_bytes":diag.client_hello_bytes,
            "client_hello_records":diag.client_hello_records,
            "record_version":diag.record_version,
            "client_template":diag.client_template,
            "cipher_suite":diag.cipher_suite,
            "flight_bytes":diag.flight_bytes,
            "fake_tls_cert_bytes":diag.fake_tls_cert_bytes,
        }),
    );
    let client_fd = stream_raw_fd(client);
    let upstream_fd = stream_raw_fd(&upstream);
    let (cr, cw) = client.split();
    let (ur, uw) = upstream.into_split();
    let relay = RelayStats {
        counters: Some(state.counters.clone()),
        client_fd,
        upstream_fd,
        diagnostics: state.diagnostics,
        ..RelayStats::default()
    };
    let relay_start_us = us();
    let result = relay_until_end(
        &relay,
        state.idle,
        async {
            upload(
                cr,
                uw,
                tls,
                transport.decrypt,
                dc.encrypt,
                RELAY_WRITE_TIMEOUT,
                &relay,
            )
            .await
            .context("client_to_dc_relay_failed")
        },
        async {
            download(
                ur,
                cw,
                dc.decrypt,
                transport.encrypt,
                framed,
                RELAY_WRITE_TIMEOUT,
                &relay,
            )
            .await
            .context("dc_to_client_relay_failed")
        },
    )
    .await;
    let dc_close_reason = if result.is_ok() {
        // Download already sent FIN. Give the peer a short window to close
        // its write half and consume late bytes without forwarding them.
        Some(
            match timeout(
                DC_EOF_SHUTDOWN_TIMEOUT,
                tokio::io::copy(client, &mut tokio::io::sink()),
            )
            .await
            {
                Ok(Ok(_)) => "dc_eof",
                Ok(Err(_)) => "client_drain_read_error",
                Err(_) => "client_drain_timeout",
            },
        )
    } else {
        None
    };
    let mut summary = relay.summary();
    if let Some(reason) = dc_close_reason {
        summary["final_reason"] = json!(reason);
    }
    summary["relay_start_us"] = json!(relay_start_us);
    telemetry::event("relay_summary", session_id, summary);
    result?;
    Ok(())
}

pub(crate) const NONE_US: u64 = u64::MAX;
pub(crate) const RELAY_WRITE_TIMEOUT: Duration = Duration::from_secs(30);
pub(crate) const DC_EOF_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(1);
pub(crate) const CLIENT_EOF_REPLY_TIMEOUT: Duration = Duration::from_secs(5);

pub(crate) async fn relay_until_end(
    stats: &RelayStats,
    idle: Duration,
    upload: impl std::future::Future<Output = Result<()>>,
    download: impl std::future::Future<Output = Result<()>>,
) -> Result<()> {
    tokio::pin!(upload, download);
    let transfer = async {
        tokio::select! {
            // Download completes only after the last reply has been written
            // and the client's write half has been shut down.
            biased;
            result = &mut download => result,
            result = &mut upload => {
                result?;
                // A client FIN still allows the DC to finish its reply.
                match timeout(CLIENT_EOF_REPLY_TIMEOUT, download).await {
                    Ok(result) => result,
                    Err(error) => stats.failed("dc_reply_drain_timeout", error.into()),
                }
            }
        }
    };
    tokio::select! {
        biased;
        result = transfer => result,
        () = stats.wait_for_idle(idle) => {
            stats.timeline.close("session_idle", "timed_out");
            bail!("session idle timeout")
        }
    }
}

/// Counters here measure bytes handed to a socket or read from it. A
/// successful write does not prove the peer received the data.
pub(crate) struct RelayStats {
    pub(crate) uploaded: std::sync::atomic::AtomicU64,
    pub(crate) downloaded: std::sync::atomic::AtomicU64,
    pub(crate) first_eof: std::sync::atomic::AtomicU64,
    pub(crate) transport_error: std::sync::atomic::AtomicI32,
    pub(crate) client_reads: std::sync::atomic::AtomicU64,
    pub(crate) dc_writes: std::sync::atomic::AtomicU64,
    pub(crate) dc_reads: std::sync::atomic::AtomicU64,
    pub(crate) client_writes: std::sync::atomic::AtomicU64,
    pub(crate) first_up_us: std::sync::atomic::AtomicU64,
    pub(crate) last_up_us: std::sync::atomic::AtomicU64,
    pub(crate) first_dn_us: std::sync::atomic::AtomicU64,
    pub(crate) last_dn_us: std::sync::atomic::AtomicU64,
    pub(crate) last_activity_us: std::sync::atomic::AtomicU64,
    pub(crate) timeline: telemetry::Timeline,
    pub(crate) first_up_kind: std::sync::atomic::AtomicU64,
    pub(crate) first_dn_kind: std::sync::atomic::AtomicU64,
    pub(crate) first_up_frame_len: std::sync::atomic::AtomicU64,
    pub(crate) first_dn_frame_len: std::sync::atomic::AtomicU64,
    pub(crate) counters: Option<Arc<telemetry::Counters>>,
    pub(crate) client_fd: Option<i32>,
    pub(crate) upstream_fd: Option<i32>,
    pub(crate) diagnostics: bool,
}

impl Default for RelayStats {
    fn default() -> Self {
        use std::sync::atomic::{AtomicI32, AtomicU64};
        Self {
            uploaded: AtomicU64::new(0),
            downloaded: AtomicU64::new(0),
            first_eof: AtomicU64::new(0),
            transport_error: AtomicI32::new(0),
            client_reads: AtomicU64::new(0),
            dc_writes: AtomicU64::new(0),
            dc_reads: AtomicU64::new(0),
            client_writes: AtomicU64::new(0),
            first_up_us: AtomicU64::new(NONE_US),
            last_up_us: AtomicU64::new(NONE_US),
            first_dn_us: AtomicU64::new(NONE_US),
            last_dn_us: AtomicU64::new(NONE_US),
            last_activity_us: AtomicU64::new(0),
            timeline: telemetry::Timeline::new(),
            first_up_kind: AtomicU64::new(0),
            first_dn_kind: AtomicU64::new(0),
            first_up_frame_len: AtomicU64::new(0),
            first_dn_frame_len: AtomicU64::new(0),
            counters: None,
            client_fd: None,
            upstream_fd: None,
            diagnostics: false,
        }
    }
}

pub(crate) fn io_kind(error: &anyhow::Error) -> &'static str {
    use std::io::ErrorKind::*;
    match error.downcast_ref::<std::io::Error>().map(|e| e.kind()) {
        None => "protocol",
        Some(ConnectionReset) => "reset",
        Some(BrokenPipe) => "broken_pipe",
        Some(UnexpectedEof) => "unexpected_eof",
        Some(TimedOut) => "timed_out",
        Some(ConnectionAborted) => "aborted",
        Some(_) => "other",
    }
}

impl RelayStats {
    pub(crate) async fn wait_for_idle(&self, idle: Duration) {
        use std::sync::atomic::Ordering::Relaxed;
        let mut wait = idle;
        loop {
            tokio::time::sleep(wait).await;
            let last_activity = self.last_activity_us.load(Relaxed);
            let elapsed =
                Duration::from_micros(self.timeline.now_us().saturating_sub(last_activity));
            wait = idle.saturating_sub(elapsed);
            if wait.is_zero() {
                return;
            }
        }
    }

    pub(crate) fn record_activity(&self) {
        self.last_activity_us
            .store(self.timeline.now_us(), std::sync::atomic::Ordering::Relaxed);
    }

    pub(crate) fn observe_prefix(&self, prefix: &[u8], upload: bool) {
        use std::sync::atomic::Ordering::Relaxed;
        let (kind, length) = if upload {
            (&self.first_up_kind, &self.first_up_frame_len)
        } else {
            (&self.first_dn_kind, &self.first_dn_frame_len)
        };
        if prefix.len() < 4 {
            return;
        }
        let frame_length =
            u32::from_le_bytes([prefix[0], prefix[1], prefix[2], prefix[3]]) & 0x7fff_ffff;
        if !(8..=16 * 1024 * 1024).contains(&frame_length) {
            return;
        }
        length.store(u64::from(frame_length), Relaxed);
        if prefix.len() < 12 {
            return;
        }
        if prefix[4..12] != [0; 8] {
            kind.store(1, Relaxed);
            return;
        }
        kind.store(2, Relaxed);
        if prefix.len() >= 28 {
            let expected = if upload {
                [0xf1, 0x8e, 0x7e, 0xbe]
            } else {
                [0x63, 0x24, 0x16, 0x05]
            };
            if prefix[24..28] == expected {
                kind.store(3, Relaxed);
            }
        }
    }

    pub(crate) fn stamp(
        &self,
        first: &std::sync::atomic::AtomicU64,
        last: &std::sync::atomic::AtomicU64,
    ) {
        use std::sync::atomic::Ordering::Relaxed;
        let now = self.timeline.now_us();
        let _ = first.compare_exchange(NONE_US, now, Relaxed, Relaxed);
        last.store(now, Relaxed);
        self.last_activity_us.store(now, Relaxed);
    }

    pub(crate) fn failed<T>(&self, tag: &'static str, error: anyhow::Error) -> Result<T> {
        let detail = if error.is::<tokio::time::error::Elapsed>() {
            "timed_out"
        } else {
            io_kind(&error)
        };
        self.timeline.close(tag, detail);
        Err(error)
    }

    pub(crate) fn summary(&self) -> serde_json::Value {
        use std::sync::atomic::Ordering::Relaxed;
        let end = self.timeline.now_us();
        let opt = |v: u64| if v == NONE_US { None } else { Some(v) };
        let (first_up, last_up) = (
            opt(self.first_up_us.load(Relaxed)),
            opt(self.last_up_us.load(Relaxed)),
        );
        let (first_dn, last_dn) = (
            opt(self.first_dn_us.load(Relaxed)),
            opt(self.last_dn_us.load(Relaxed)),
        );
        let reply_seen = self.downloaded.load(Relaxed) > 0;
        let closer = self.timeline.closer();
        let class = match closer.map(|c| c.1) {
            Some("client_eof") | Some("client_eof_mid_record") if reply_seen => {
                "client_closed_after_dc_reply"
            }
            Some("client_eof") | Some("client_eof_mid_record") => {
                "client_closed_before_any_dc_reply"
            }
            Some("dc_eof") if reply_seen => "dc_closed_after_reply",
            Some("dc_eof") => "dc_closed_without_reply",
            Some(t) if t.ends_with("_idle") => "idle_timeout",
            Some(t) if t.starts_with("client_") => "client_socket_error",
            Some(t) if t.starts_with("dc_") => "dc_socket_error",
            Some(_) => "other",
            None => "none",
        };
        let error_code = self.transport_error.load(Relaxed);
        json!({
            "uploaded_bytes":self.uploaded.load(Relaxed),
            "downloaded_bytes":self.downloaded.load(Relaxed),
            "client_reads":self.client_reads.load(Relaxed),
            "dc_writes":self.dc_writes.load(Relaxed),
            "dc_reads":self.dc_reads.load(Relaxed),
            "client_writes":self.client_writes.load(Relaxed),
            "first_up_us":first_up,
            "last_up_us":last_up,
            "first_dn_us":first_dn,
            "last_dn_us":last_dn,
            "end_us":end,
            "final_reason":self.timeline.final_reason(),
            "final_at_us":end,
            "idle_since_last_up_us":last_up.map(|t| end.saturating_sub(t)),
            "idle_since_last_dn_us":last_dn.map(|t| end.saturating_sub(t)),
            "first_eof":match self.first_eof.load(Relaxed) {1=>"client",2=>"dc",_=>"none"},
            "initiator":closer.map(|c| c.1),
            "initiator_detail":closer.map(|c| c.2),
            "initiator_at_us":closer.map(|c| c.0),
            "class":class,
            "dc_transport_error":if error_code==0 {None}else{Some(error_code)},
            "first_up_frame_len":self.first_up_frame_len.load(Relaxed),
            "first_dn_frame_len":self.first_dn_frame_len.load(Relaxed),
            "first_up_kind":match self.first_up_kind.load(Relaxed) {1=>"encrypted",2=>"unencrypted_other",3=>"unencrypted_req_pq_multi",_=>"unknown"},
            "first_dn_kind":match self.first_dn_kind.load(Relaxed) {1=>"encrypted",2=>"unencrypted_other",3=>"unencrypted_res_pq",_=>"unknown"},
            "timeline":self.timeline.snapshot(),
        })
    }
}

// Telegram iOS emits FakeTLS application records with up to 16,408 payload bytes.
pub(crate) const MAX_CLIENT_RECORD: usize = 16_408;
pub(crate) const TLS_READER_CHUNK: usize = 5 + MAX_CLIENT_RECORD;

#[derive(Default)]
pub(crate) struct TlsReader {
    pub(crate) pending: Vec<u8>,
    pub(crate) offset: usize,
    pub(crate) raw: Vec<u8>,
    pub(crate) raw_offset: usize,
    /// Wire bytes read from the socket, including TLS headers and partial records.
    pub(crate) consumed: u64,
}
impl TlsReader {
    pub(crate) async fn read_wire_some<R: AsyncRead + Unpin>(
        &mut self,
        r: &mut R,
        dst: &mut [u8],
    ) -> std::io::Result<usize> {
        if self.raw_offset < self.raw.len() {
            let avail = self.raw.len() - self.raw_offset;
            let n = dst.len().min(avail);
            dst[..n].copy_from_slice(&self.raw[self.raw_offset..self.raw_offset + n]);
            self.raw_offset += n;
            if self.raw_offset == self.raw.len() {
                self.raw.clear();
                self.raw_offset = 0;
            }
            return Ok(n);
        }
        if self.raw.capacity() == 0 {
            self.raw.reserve_exact(TLS_READER_CHUNK);
        }
        self.raw.resize(TLS_READER_CHUNK, 0);
        let got = r.read(&mut self.raw).await?;
        self.raw.truncate(got);
        self.raw_offset = 0;
        if got == 0 {
            return Ok(0);
        }
        self.consumed += got as u64;
        let n = dst.len().min(got);
        dst[..n].copy_from_slice(&self.raw[..n]);
        self.raw_offset = n;
        if self.raw_offset == self.raw.len() {
            self.raw.clear();
            self.raw_offset = 0;
        }
        Ok(n)
    }

    pub(crate) async fn read_wire_exact<R: AsyncRead + Unpin>(
        &mut self,
        r: &mut R,
        mut bytes: &mut [u8],
    ) -> std::io::Result<()> {
        while !bytes.is_empty() {
            let n = self.read_wire_some(r, bytes).await?;
            if n == 0 {
                return Err(std::io::ErrorKind::UnexpectedEof.into());
            }
            bytes = &mut bytes[n..];
        }
        Ok(())
    }

    pub(crate) async fn read_into<R: AsyncRead + Unpin>(
        &mut self,
        r: &mut R,
        out: &mut [u8],
    ) -> Result<usize> {
        if self.offset == self.pending.len() {
            self.pending.clear();
            self.offset = 0;
            // Permit only one CCS before an application record. No unbounded empty-record loop.
            for _ in 0..2 {
                let mut h = [0u8; 5];
                let first = self.read_wire_some(r, &mut h).await?;
                if first == 0 {
                    return Ok(0);
                }
                if first < 5 {
                    self.read_wire_exact(r, &mut h[first..]).await?;
                }
                ensure!(h[1..3] == [3, 3], "TLS record version");
                let n = usize::from(u16::from_be_bytes([h[3], h[4]]));
                let limit = if h[0] == 0x17 {
                    MAX_CLIENT_RECORD
                } else {
                    wire::MAX_RECORD
                };
                ensure!(n > 0 && n <= limit, "TLS record limit");
                let mut pending = std::mem::take(&mut self.pending);
                pending.resize(n, 0);
                let read_res = self.read_wire_exact(r, &mut pending).await;
                self.pending = pending;
                read_res?;
                if h[0] == 0x14 {
                    ensure!(self.pending == [1], "invalid CCS");
                    self.pending.clear();
                    continue;
                }
                ensure!(h[0] == 0x17, "unexpected post-commit record");
                break;
            }
            ensure!(!self.pending.is_empty(), "repeated CCS");
        }
        let n = out.len().min(self.pending.len() - self.offset);
        out[..n].copy_from_slice(&self.pending[self.offset..self.offset + n]);
        self.offset += n;
        Ok(n)
    }
}

pub(crate) async fn upload<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    mut r: R,
    mut w: W,
    mut tls: Option<TlsReader>,
    mut decrypt: AesCtr,
    mut encrypt: AesCtr,
    write_timeout: Duration,
    stats: &RelayStats,
) -> Result<()> {
    use std::sync::atomic::Ordering::Relaxed;
    const RETRANS_SAMPLE_INTERVAL: Duration = Duration::from_secs(1);
    let mut buf = [0u8; wire::MAX_RECORD];
    let mut prefix = [0u8; 28];
    let mut prefix_len = 0;
    let mut prev_retrans = 0u32;
    let mut last_retrans_sample = Instant::now();
    loop {
        let prev_consumed = tls.as_ref().map(|t| t.consumed).unwrap_or(0);
        let read = match &mut tls {
            Some(reader) => reader.read_into(&mut r, &mut buf).await,
            None => r.read(&mut buf).await.map_err(Into::into),
        };
        if let (Some(reader), Some(counters)) = (&tls, &stats.counters) {
            let delta = reader.consumed.saturating_sub(prev_consumed);
            if delta > 0 {
                counters.downstream_rx_bytes.fetch_add(delta, Relaxed);
            }
        }
        let n = match read {
            Ok(n) => n,
            Err(error) => {
                let tag = if io_kind(&error) == "unexpected_eof" {
                    "client_eof_mid_record"
                } else {
                    "client_read_error"
                };
                return stats.failed(tag, error);
            }
        };
        if tls.is_none() && n > 0 {
            if let Some(counters) = &stats.counters {
                counters.downstream_rx_bytes.fetch_add(n as u64, Relaxed);
            }
        }
        if n == 0 {
            let _ = stats.first_eof.compare_exchange(0, 1, Relaxed, Relaxed);
            stats.timeline.close("client_eof", "fin");
            let res = match timeout(write_timeout, w.shutdown()).await {
                Ok(Ok(())) => Ok(()),
                Ok(Err(error)) => stats.failed("dc_write_error", error.into()),
                Err(error) => stats.failed("dc_write_idle", error.into()),
            };
            if let Some(counters) = &stats.counters {
                sample_fd_retrans(
                    stats.upstream_fd,
                    &mut prev_retrans,
                    &counters.upstream_retrans_segs,
                );
            }
            return res;
        }
        stats.client_reads.fetch_add(1, Relaxed);
        stats.record_activity();
        if stats.diagnostics {
            stats.timeline.mark("client_read", n as u64);
        }
        wire::crypt(&mut decrypt, &mut buf[..n]);
        let take = n.min(prefix.len() - prefix_len);
        prefix[prefix_len..prefix_len + take].copy_from_slice(&buf[..take]);
        prefix_len += take;
        stats.observe_prefix(&prefix[..prefix_len], true);
        wire::crypt(&mut encrypt, &mut buf[..n]);
        match timeout(write_timeout, w.write_all(&buf[..n])).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                if let Some(counters) = &stats.counters {
                    sample_fd_retrans(
                        stats.upstream_fd,
                        &mut prev_retrans,
                        &counters.upstream_retrans_segs,
                    );
                }
                return stats.failed("dc_write_error", error.into());
            }
            Err(error) => {
                if let Some(counters) = &stats.counters {
                    sample_fd_retrans(
                        stats.upstream_fd,
                        &mut prev_retrans,
                        &counters.upstream_retrans_segs,
                    );
                }
                return stats.failed("dc_write_idle", error.into());
            }
        }
        if let Some(counters) = &stats.counters {
            counters.upstream_tx_bytes.fetch_add(n as u64, Relaxed);
            if last_retrans_sample.elapsed() >= RETRANS_SAMPLE_INTERVAL {
                sample_fd_retrans(
                    stats.upstream_fd,
                    &mut prev_retrans,
                    &counters.upstream_retrans_segs,
                );
                last_retrans_sample = Instant::now();
            }
        }
        stats.uploaded.fetch_add(n as u64, Relaxed);
        stats.dc_writes.fetch_add(1, Relaxed);
        if stats.diagnostics {
            stats.timeline.mark("dc_write", n as u64);
        }
        stats.stamp(&stats.first_up_us, &stats.last_up_us);
    }
}
pub(crate) async fn download<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    mut r: R,
    mut w: W,
    mut decrypt: AesCtr,
    mut encrypt: AesCtr,
    framed: bool,
    write_timeout: Duration,
    stats: &RelayStats,
) -> Result<()> {
    use std::sync::atomic::Ordering::Relaxed;
    const RETRANS_SAMPLE_INTERVAL: Duration = Duration::from_secs(1);
    let mut frame_buf = vec![0u8; 5 + wire::MAX_RECORD];
    frame_buf[0] = 0x17;
    frame_buf[1] = 3;
    frame_buf[2] = 3;
    let mut prefix = [0u8; 28];
    let mut prefix_len = 0;
    let mut prev_retrans = 0u32;
    let mut last_retrans_sample = Instant::now();
    loop {
        let n = match r.read(&mut frame_buf[5..]).await {
            Ok(n) => n,
            Err(error) => return stats.failed("dc_read_error", error.into()),
        };
        if n == 0 {
            let _ = stats.first_eof.compare_exchange(0, 2, Relaxed, Relaxed);
            stats.timeline.close("dc_eof", "fin");
            let res = match timeout(write_timeout.min(DC_EOF_SHUTDOWN_TIMEOUT), w.shutdown()).await
            {
                Ok(Ok(())) => Ok(()),
                Ok(Err(error)) => stats.failed("client_write_error", error.into()),
                Err(error) => stats.failed("client_write_idle", error.into()),
            };
            if let Some(counters) = &stats.counters {
                sample_fd_retrans(
                    stats.client_fd,
                    &mut prev_retrans,
                    &counters.downstream_retrans_segs,
                );
            }
            return res;
        }
        if let Some(counters) = &stats.counters {
            counters.upstream_rx_bytes.fetch_add(n as u64, Relaxed);
        }
        stats.dc_reads.fetch_add(1, Relaxed);
        stats.record_activity();
        if stats.diagnostics {
            stats.timeline.mark("dc_read", n as u64);
        }
        {
            let buf = &mut frame_buf[5..5 + n];
            wire::crypt(&mut decrypt, buf);
            // Transient prefix only: recognize public unencrypted handshake types
            // and transport errors; never emit prefix bytes, key IDs or payload.
            let take = n.min(prefix.len() - prefix_len);
            prefix[prefix_len..prefix_len + take].copy_from_slice(&buf[..take]);
            prefix_len += take;
            stats.observe_prefix(&prefix[..prefix_len], false);
            if prefix_len >= 4 {
                let word = i32::from_le_bytes([prefix[0], prefix[1], prefix[2], prefix[3]]);
                let code = if word == 4 && prefix_len >= 8 {
                    i32::from_le_bytes([prefix[4], prefix[5], prefix[6], prefix[7]])
                } else {
                    word
                };
                if [-404, -429, -444, -500].contains(&code) {
                    stats.transport_error.store(code, Relaxed);
                }
            }
            wire::crypt(&mut encrypt, buf);
        }
        let bytes = if framed {
            let len_bytes = (n as u16).to_be_bytes();
            frame_buf[3] = len_bytes[0];
            frame_buf[4] = len_bytes[1];
            &frame_buf[..5 + n]
        } else {
            &frame_buf[5..5 + n]
        };
        match timeout(write_timeout, w.write_all(bytes)).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                if let Some(counters) = &stats.counters {
                    sample_fd_retrans(
                        stats.client_fd,
                        &mut prev_retrans,
                        &counters.downstream_retrans_segs,
                    );
                }
                return stats.failed("client_write_error", error.into());
            }
            Err(error) => {
                if let Some(counters) = &stats.counters {
                    sample_fd_retrans(
                        stats.client_fd,
                        &mut prev_retrans,
                        &counters.downstream_retrans_segs,
                    );
                }
                return stats.failed("client_write_idle", error.into());
            }
        }
        if let Some(counters) = &stats.counters {
            counters
                .downstream_tx_bytes
                .fetch_add(bytes.len() as u64, Relaxed);
            if last_retrans_sample.elapsed() >= RETRANS_SAMPLE_INTERVAL {
                sample_fd_retrans(
                    stats.client_fd,
                    &mut prev_retrans,
                    &counters.downstream_retrans_segs,
                );
                last_retrans_sample = Instant::now();
            }
        }
        stats.downloaded.fetch_add(n as u64, Relaxed);
        stats.client_writes.fetch_add(1, Relaxed);
        if stats.diagnostics {
            stats.timeline.mark("client_write", n as u64);
        }
        stats.stamp(&stats.first_dn_us, &stats.last_dn_us);
    }
}
pub(crate) async fn plain_copy<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    mut r: R,
    mut w: W,
    idle: Duration,
) -> Result<()> {
    let mut buf = [0; wire::MAX_RECORD];
    loop {
        let n = timeout(idle, r.read(&mut buf)).await??;
        if n == 0 {
            timeout(idle, w.shutdown()).await??;
            return Ok(());
        }
        timeout(idle, w.write_all(&buf[..n])).await??;
    }
}
#[allow(clippy::too_many_arguments)]
pub(crate) async fn counted_copy<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    mut r: R,
    mut w: W,
    idle: Duration,
    session_start: Instant,
    last_activity_ms: &std::sync::atomic::AtomicU64,
    rx_counter: &std::sync::atomic::AtomicU64,
    tx_counter: &std::sync::atomic::AtomicU64,
    write_fd: Option<i32>,
    retrans_counter: &std::sync::atomic::AtomicU64,
) -> Result<()> {
    use std::sync::atomic::Ordering::Relaxed;
    const RETRANS_SAMPLE_INTERVAL: Duration = Duration::from_secs(1);
    let mut buf = [0; wire::MAX_RECORD];
    let mut prev_retrans = 0u32;
    let mut last_retrans_sample = Instant::now();
    let idle_ms = idle.as_millis().min(u128::from(u64::MAX)) as u64;
    loop {
        let n = loop {
            let now_ms = session_start
                .elapsed()
                .as_millis()
                .min(u128::from(u64::MAX)) as u64;
            let last_ms = last_activity_ms.load(Relaxed);
            let since_ms = now_ms.saturating_sub(last_ms);
            if since_ms >= idle_ms {
                bail!("egress_relay_idle_timeout");
            }
            let wait = Duration::from_millis(idle_ms.saturating_sub(since_ms).max(1));
            match timeout(wait, r.read(&mut buf)).await {
                Ok(res) => break res?,
                Err(_) => continue,
            }
        };
        let now_ms = session_start
            .elapsed()
            .as_millis()
            .min(u128::from(u64::MAX)) as u64;
        last_activity_ms.store(now_ms, Relaxed);
        if n == 0 {
            let res = timeout(idle, w.shutdown()).await;
            sample_fd_retrans(write_fd, &mut prev_retrans, retrans_counter);
            res??;
            return Ok(());
        }
        rx_counter.fetch_add(n as u64, Relaxed);
        let res = timeout(idle, w.write_all(&buf[..n])).await;
        if res.is_err()
            || res.as_ref().is_ok_and(|r| r.is_err())
            || last_retrans_sample.elapsed() >= RETRANS_SAMPLE_INTERVAL
        {
            sample_fd_retrans(write_fd, &mut prev_retrans, retrans_counter);
            last_retrans_sample = Instant::now();
        }
        res??;
        let done_ms = session_start
            .elapsed()
            .as_millis()
            .min(u128::from(u64::MAX)) as u64;
        last_activity_ms.store(done_ms, Relaxed);
        tx_counter.fetch_add(n as u64, Relaxed);
    }
}
