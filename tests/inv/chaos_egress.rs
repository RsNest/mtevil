//! Phase 4 / T14 chaos integration tests against the real `mtevil` binary.
//! Test names reference `INV-xx` and `F-NN` from `docs/failure-matrix.md`.

use anyhow::{bail, ensure, Context, Result};
use mtevil_proto as wire;
use std::{
    net::SocketAddr,
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicU64, AtomicU8, AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::timeout,
};

const MODE_HEALTHY: u8 = 0;
const MODE_REFUSE: u8 = 1;
const MODE_BLACKHOLE: u8 = 2;
const MODE_SLOW_ACK: u8 = 3;
const MODE_NEGATIVE_ACK: u8 = 4;
const MODE_FLAP: u8 = 5;
const MODE_KILL_MID_SESSION: u8 = 6;

const EGRESS_ACK_OK: u8 = 0x00;
const EGRESS_ACK_ERR: u8 = 0x01;

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct TempDirGuard(PathBuf);

impl TempDirGuard {
    fn new(prefix: &str) -> Result<Self> {
        let dir = std::env::temp_dir().join(format!(
            "mtevil-{prefix}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir)?;
        Ok(Self(dir))
    }
}

impl Drop for TempDirGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct FakeEgress {
    addr: SocketAddr,
    mode: Arc<AtomicU8>,
    slow_ack_ms: Arc<AtomicU64>,
    hits: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for FakeEgress {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl FakeEgress {
    async fn start(dc_addr: SocketAddr, initial_mode: u8, slow_ack_ms: u64) -> Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let mode = Arc::new(AtomicU8::new(initial_mode));
        let slow = Arc::new(AtomicU64::new(slow_ack_ms));
        let hits = Arc::new(AtomicUsize::new(0));
        let flap_seq = Arc::new(AtomicUsize::new(0));

        let m = mode.clone();
        let s_ms = slow.clone();
        let h = hits.clone();
        let f_seq = flap_seq.clone();
        let task = tokio::spawn(async move {
            while let Ok((mut edge, _)) = listener.accept().await {
                h.fetch_add(1, Ordering::SeqCst);
                let cur_mode = m.load(Ordering::SeqCst);
                let delay = s_ms.load(Ordering::SeqCst);
                let flap_n = f_seq.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    let eff_mode = if cur_mode == MODE_FLAP {
                        if flap_n.is_multiple_of(2) {
                            MODE_NEGATIVE_ACK
                        } else {
                            MODE_HEALTHY
                        }
                    } else {
                        cur_mode
                    };

                    if eff_mode == MODE_REFUSE {
                        let _ = edge.shutdown().await;
                        return;
                    }
                    if eff_mode == MODE_BLACKHOLE {
                        // Accept TCP and hold without ever sending ACK.
                        tokio::time::sleep(Duration::from_secs(30)).await;
                        return;
                    }

                    // Read MTV3 (126 bytes) or MTV2 (88 bytes) preface.
                    let mut magic = [0u8; 4];
                    if edge.read_exact(&mut magic).await.is_err() {
                        return;
                    }
                    let dc_header: [u8; 64] = if &magic == b"MTV3" {
                        let mut rest = [0u8; wire::EGRESS_PREFACE_V3_LEN - 4];
                        if edge.read_exact(&mut rest).await.is_err() {
                            return;
                        }
                        let mut hdr = [0u8; 64];
                        hdr.copy_from_slice(&rest[58..122]);
                        hdr
                    } else if &magic == b"MTV2" {
                        let mut rest = [0u8; wire::EGRESS_PREFACE_V2_LEN - 4];
                        if edge.read_exact(&mut rest).await.is_err() {
                            return;
                        }
                        let mut hdr = [0u8; 64];
                        hdr.copy_from_slice(&rest[20..84]);
                        hdr
                    } else {
                        return;
                    };

                    if eff_mode == MODE_SLOW_ACK && delay > 0 {
                        tokio::time::sleep(Duration::from_millis(delay)).await;
                    }
                    if eff_mode == MODE_NEGATIVE_ACK {
                        let _ = edge.write_all(&[EGRESS_ACK_ERR]).await;
                        let _ = edge.shutdown().await;
                        return;
                    }

                    let Ok(mut dc) = TcpStream::connect(dc_addr).await else {
                        let _ = edge.write_all(&[EGRESS_ACK_ERR]).await;
                        return;
                    };
                    if dc.write_all(&dc_header).await.is_err() {
                        let _ = edge.write_all(&[EGRESS_ACK_ERR]).await;
                        return;
                    }
                    if edge.write_all(&[EGRESS_ACK_OK]).await.is_err() {
                        return;
                    }
                    if eff_mode == MODE_KILL_MID_SESSION {
                        // Drop right after ACK, before relaying payload.
                        drop(edge);
                        drop(dc);
                        return;
                    }
                    let _ = tokio::io::copy_bidirectional(&mut edge, &mut dc).await;
                });
            }
        });
        Ok(Self {
            addr,
            mode,
            slow_ack_ms: slow,
            hits,
            task,
        })
    }

    fn set_mode(&self, mode: u8) {
        self.mode.store(mode, Ordering::SeqCst);
    }

    fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }
}

async fn spawn_mock_telegram_dc() -> Result<(SocketAddr, tokio::task::JoinHandle<()>)> {
    use aes::cipher::KeyIvInit;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let task = tokio::spawn(async move {
        while let Ok((mut peer, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut header = [0u8; 64];
                if peer.read_exact(&mut header).await.is_err() {
                    return;
                }
                let Ok(mut decode) = wire::AesCtr::new_from_slices(&header[8..40], &header[40..56])
                else {
                    return;
                };
                let mut plain = header;
                wire::crypt(&mut decode, &mut plain);

                let mut len_buf = [0u8; 4];
                if peer.read_exact(&mut len_buf).await.is_err() {
                    return;
                }
                wire::crypt(&mut decode, &mut len_buf);
                let req_len = (u32::from_le_bytes(len_buf) & 0x7fff_ffff) as usize;
                if req_len != 40 {
                    return;
                }
                let mut req_payload = vec![0u8; req_len];
                if peer.read_exact(&mut req_payload).await.is_err() {
                    return;
                }
                wire::crypt(&mut decode, &mut req_payload);
                if req_payload[20..24] != [0xf1, 0x8e, 0x7e, 0xbe] {
                    return;
                }
                let Ok(nonce): std::result::Result<[u8; 16], _> = req_payload[24..40].try_into()
                else {
                    return;
                };

                let reversed: Vec<_> = header[8..56].iter().rev().copied().collect();
                let Ok(mut encode) =
                    wire::AesCtr::new_from_slices(&reversed[..32], &reversed[32..])
                else {
                    return;
                };
                let mut resp = Vec::with_capacity(44);
                resp.extend_from_slice(&40u32.to_le_bytes());
                resp.extend_from_slice(&0u64.to_le_bytes());
                resp.extend_from_slice(&1u64.to_le_bytes());
                resp.extend_from_slice(&20u32.to_le_bytes());
                resp.extend_from_slice(&[0x63, 0x24, 0x16, 0x05]);
                resp.extend_from_slice(&nonce);
                wire::crypt(&mut encode, &mut resp);
                let _ = peer.write_all(&resp).await;
                let _ = peer.shutdown().await;
            });
        }
    });
    Ok((addr, task))
}

async fn reserve_local_port() -> Result<SocketAddr> {
    let l = TcpListener::bind("127.0.0.1:0").await?;
    Ok(l.local_addr()?)
}

async fn wait_port_ready(addr: SocketAddr, max_wait: Duration) -> Result<()> {
    let deadline = Instant::now() + max_wait;
    while Instant::now() < deadline {
        if TcpStream::connect(addr).await.is_ok() {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    bail!("proxy listener {addr} did not become ready in {max_wait:?}")
}

fn spawn_mtevil_with_config(cfg_path: &std::path::Path) -> Result<ChildGuard> {
    let bin = env!("CARGO_BIN_EXE_mtevil");
    let child = Command::new(bin)
        .arg("--config")
        .arg(cfg_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("spawning mtevil binary")?;
    Ok(ChildGuard(child))
}

async fn run_probe_telegram(cfg_path: &std::path::Path, proxy_addr: SocketAddr) -> Result<u64> {
    let cfg = cfg_path.to_path_buf();
    tokio::task::spawn_blocking(move || {
        let bin = env!("CARGO_BIN_EXE_mtevil");
        let t0 = Instant::now();
        let out = Command::new(bin)
            .args([
                "probe-telegram",
                "--config",
                &cfg.to_string_lossy(),
                "--address",
                &proxy_addr.to_string(),
                "--dc",
                "2",
                "--timeout-secs",
                "5",
            ])
            .output()
            .context("running mtevil probe-telegram")?;
        ensure!(
            out.status.success(),
            "probe-telegram failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        Ok(t0.elapsed().as_millis() as u64)
    })
    .await?
}

#[tokio::test]
async fn inv10_f23_chaos_ordered_failover_modes_and_failback() -> Result<()> {
    let tmp = TempDirGuard::new("chaos-ordered")?;
    let secret_path = tmp.0.join("secret");
    std::fs::write(&secret_path, "000102030405060708090a0b0c0d0e0f\n")?;
    let token_path = tmp.0.join("token");
    std::fs::write(&token_path, "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a\n")?;

    let (dc_addr, dc_task) = spawn_mock_telegram_dc().await?;
    let primary = FakeEgress::start(dc_addr, MODE_HEALTHY, 0).await?;
    let backup = FakeEgress::start(dc_addr, MODE_HEALTHY, 0).await?;
    let edge_addr = reserve_local_port().await?;

    let cfg_path = tmp.0.join("edge.json");
    let cfg = serde_json::json!({
        "role": "edge",
        "listen": edge_addr.to_string(),
        "secret_file": secret_path.to_string_lossy(),
        "sni": "example.com",
        "cover": dc_addr.to_string(),
        "egress_upstreams": [primary.addr.to_string(), backup.addr.to_string()],
        "egress_strategy": "ordered",
        "egress_token_file": token_path.to_string_lossy(),
        "handshake_timeout_secs": 2,
        "egress_cooldown_base_ms": 500,
        "egress_cooldown_max_ms": 2000,
        "egress_probe_interval_secs": 1,
        "egress_probe_degraded_interval_secs": 1,
        "egress_hedge_ms": 150
    });
    std::fs::write(&cfg_path, serde_json::to_string_pretty(&cfg)?)?;

    let _edge = spawn_mtevil_with_config(&cfg_path)?;
    wait_port_ready(edge_addr, Duration::from_secs(3)).await?;

    // 1. Baseline healthy on primary.
    let _ = run_probe_telegram(&cfg_path, edge_addr).await?;
    assert!(primary.hits() >= 1);

    // 2. Primary enters BLACKHOLE (accept without ACK):
    //    Hedged connect / failover to backup must complete well within per_try(1000ms) + eps!
    primary.set_mode(MODE_BLACKHOLE);
    let failover_ms = run_probe_telegram(&cfg_path, edge_addr).await?;
    assert!(
        failover_ms <= 1600,
        "blackhole failover took {failover_ms}ms (expected <= per_try + eps)"
    );
    // Subsequent 3 client requests must have 0 errors while backup is alive.
    for _ in 0..3 {
        let _ = run_probe_telegram(&cfg_path, edge_addr).await?;
    }

    // 3. Primary enters REFUSE, NEGATIVE_ACK, SLOW_ACK(1200ms), FLAP, KILL_MID_SESSION:
    for mode in [
        MODE_REFUSE,
        MODE_NEGATIVE_ACK,
        MODE_SLOW_ACK,
        MODE_FLAP,
        MODE_KILL_MID_SESSION,
    ] {
        primary.slow_ack_ms.store(1200, Ordering::SeqCst);
        primary.set_mode(mode);
        let res = run_probe_telegram(&cfg_path, edge_addr).await;
        if mode == MODE_KILL_MID_SESSION {
            // Mid-session kill may drop the in-flight request if primary was chosen; next reconnect succeeds.
            if res.is_err() {
                primary.set_mode(MODE_REFUSE);
                let _ = run_probe_telegram(&cfg_path, edge_addr).await?;
            }
        } else {
            res.with_context(|| {
                format!("client failed under primary mode {mode} with healthy backup")
            })?;
        }
    }

    // 4. Failback: restore primary to HEALTHY and wait for background probe (1s) to clear cooldown.
    primary.set_mode(MODE_HEALTHY);
    tokio::time::sleep(Duration::from_millis(1600)).await;
    let p_before = primary.hits();
    let _ = run_probe_telegram(&cfg_path, edge_addr).await?;
    assert!(
        primary.hits() > p_before,
        "expected failback to primary after recovery"
    );

    dc_task.abort();
    Ok(())
}

#[tokio::test]
async fn inv10_f23_chaos_round_robin_with_dead_node_zero_errors() -> Result<()> {
    let tmp = TempDirGuard::new("chaos-rr")?;
    let secret_path = tmp.0.join("secret");
    std::fs::write(&secret_path, "000102030405060708090a0b0c0d0e0f\n")?;
    let token_path = tmp.0.join("token");
    std::fs::write(&token_path, "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a\n")?;

    let (dc_addr, dc_task) = spawn_mock_telegram_dc().await?;
    let dead = FakeEgress::start(dc_addr, MODE_REFUSE, 0).await?;
    let live = FakeEgress::start(dc_addr, MODE_HEALTHY, 0).await?;
    let edge_addr = reserve_local_port().await?;

    let cfg_path = tmp.0.join("edge-rr.json");
    let cfg = serde_json::json!({
        "role": "edge",
        "listen": edge_addr.to_string(),
        "secret_file": secret_path.to_string_lossy(),
        "sni": "example.com",
        "cover": dc_addr.to_string(),
        "egress_upstreams": [dead.addr.to_string(), live.addr.to_string()],
        "egress_strategy": "round-robin",
        "egress_token_file": token_path.to_string_lossy(),
        "handshake_timeout_secs": 2,
        "egress_cooldown_base_ms": 10000,
        "egress_cooldown_max_ms": 30000,
        "egress_probe_interval_secs": 30,
        "egress_probe_degraded_interval_secs": 30
    });
    std::fs::write(&cfg_path, serde_json::to_string_pretty(&cfg)?)?;

    let _edge = spawn_mtevil_with_config(&cfg_path)?;
    wait_port_ready(edge_addr, Duration::from_secs(3)).await?;

    // 6 client connections in round-robin with dead node -> 0 errors, dead node skipped after cooldown.
    for _ in 0..6 {
        let _ = run_probe_telegram(&cfg_path, edge_addr).await?;
    }
    assert!(live.hits() >= 6);
    assert!(
        dead.hits() <= 3,
        "dead node in round-robin should be skipped by circuit breaker (hits={})",
        dead.hits()
    );

    dc_task.abort();
    Ok(())
}

#[tokio::test]
async fn inv10_f24_all_nodes_down_and_recovered_without_15s_gap() -> Result<()> {
    let tmp = TempDirGuard::new("chaos-all-down")?;
    let secret_path = tmp.0.join("secret");
    std::fs::write(&secret_path, "000102030405060708090a0b0c0d0e0f\n")?;
    let token_path = tmp.0.join("token");
    std::fs::write(&token_path, "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a\n")?;

    let (dc_addr, dc_task) = spawn_mock_telegram_dc().await?;
    let n1 = FakeEgress::start(dc_addr, MODE_REFUSE, 0).await?;
    let n2 = FakeEgress::start(dc_addr, MODE_REFUSE, 0).await?;
    let edge_addr = reserve_local_port().await?;

    let cfg_path = tmp.0.join("edge-all-down.json");
    let cfg = serde_json::json!({
        "role": "edge",
        "listen": edge_addr.to_string(),
        "secret_file": secret_path.to_string_lossy(),
        "sni": "example.com",
        "cover": dc_addr.to_string(),
        "egress_upstreams": [n1.addr.to_string(), n2.addr.to_string()],
        "egress_strategy": "ordered",
        "egress_token_file": token_path.to_string_lossy(),
        "handshake_timeout_secs": 2,
        "egress_cooldown_base_ms": 15000,
        "egress_cooldown_max_ms": 60000,
        "egress_probe_interval_secs": 60,
        "egress_probe_degraded_interval_secs": 60
    });
    std::fs::write(&cfg_path, serde_json::to_string_pretty(&cfg)?)?;

    let _edge = spawn_mtevil_with_config(&cfg_path)?;
    wait_port_ready(edge_addr, Duration::from_secs(3)).await?;

    // 1. Both nodes down -> client fails and puts both nodes into 15-second cooldown.
    assert!(run_probe_telegram(&cfg_path, edge_addr).await.is_err());

    // 2. Immediately bring both nodes back up (well before 15s cooldown expires!):
    //    Fail-open forced probe must recover traffic immediately without a 15-second hole,
    //    regardless of which node got a slightly shorter ±20% jittered cooldown.
    n1.set_mode(MODE_HEALTHY);
    n2.set_mode(MODE_HEALTHY);
    let rec_ms = run_probe_telegram(&cfg_path, edge_addr).await?;
    assert!(
        rec_ms < 3000,
        "expected immediate fail-open recovery without 15s gap, got {rec_ms}ms"
    );

    dc_task.abort();
    Ok(())
}

#[tokio::test]
async fn inv10_f15_f29_process_survives_aborted_accepts_and_metrics_live() -> Result<()> {
    let tmp = TempDirGuard::new("chaos-f15-f29")?;
    let secret_path = tmp.0.join("secret");
    std::fs::write(&secret_path, "000102030405060708090a0b0c0d0e0f\n")?;

    let (dc_addr, dc_task) = spawn_mock_telegram_dc().await?;
    let proxy_addr = reserve_local_port().await?;
    let metrics_addr = reserve_local_port().await?;

    let cfg_path = tmp.0.join("direct.json");
    let cfg = serde_json::json!({
        "role": "direct",
        "listen": proxy_addr.to_string(),
        "secret_file": secret_path.to_string_lossy(),
        "sni": "example.com",
        "cover": dc_addr.to_string(),
        "dc": [format!("2={dc_addr}")],
        "drain_timeout_secs": 1,
        "metrics_listen": metrics_addr.to_string()
    });
    std::fs::write(&cfg_path, serde_json::to_string_pretty(&cfg)?)?;

    let _proc = spawn_mtevil_with_config(&cfg_path)?;
    wait_port_ready(proxy_addr, Duration::from_secs(3)).await?;

    // Burst of immediate connect+drop (simulating client aborts / scanner noise).
    for _ in 0..16 {
        if let Ok(s) = TcpStream::connect(proxy_addr).await {
            drop(s);
        }
    }

    // Real Telegram client probe still succeeds cleanly.
    let _ = run_probe_telegram(&cfg_path, proxy_addr).await?;

    // Prometheus /metrics endpoint on localhost responds with HTTP 200.
    let mut m = TcpStream::connect(metrics_addr).await?;
    m.write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await?;
    let mut resp = String::new();
    timeout(Duration::from_secs(2), m.read_to_string(&mut resp)).await??;
    assert!(resp.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(resp.contains("mtevil_forced_close_total "));
    assert!(resp.contains("mtevil_accept_errors_total{kind=\"emfile\"}"));

    dc_task.abort();
    Ok(())
}
