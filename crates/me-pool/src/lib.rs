pub mod config;
pub mod conn;
pub mod crypto;
pub mod pool;
pub mod wire;

pub use config::{is_global_ipv4, parse_ad_tag_hex, MeConfigBundle, MeDiskCache, ProxyMultiConfig};
pub use conn::{MeConnOptions, MeConnection, MeSession};
pub use crypto::{derive_me_aes_key_iv, KdfPurpose, MeCbcDecryptor, MeCbcEncryptor};
pub use pool::{MePool, MePoolConfig, MePoolHealth};
pub use wire::{
    build_req_pq_multi, decode_rpc_frame, encode_close_ext, encode_handshake, encode_nonce,
    encode_ping, encode_pong, encode_proxy_req, ipv4_mapped_16, pack_rpc_frame, parse_rpc_message,
    tl_encode_bytes, validate_res_pq, RpcMessage,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conn::SESSION_INBOUND_QUEUE_CAP;
    use crate::wire::{
        CRYPTO_AES, FLAG_HAS_AD_TAG, RPC_CLOSE_EXT, RPC_HANDSHAKE, RPC_PING, RPC_PROXY_ANS,
        RPC_PROXY_REQ,
    };
    use anyhow::{Context, Result};
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::time::timeout;

    struct MockMeObservation {
        flags: u32,
        remote_ip_bytes: [u8; 16],
        remote_port: u32,
        ad_tag_seen: Option<[u8; 16]>,
    }

    struct MockMeServer {
        addr: SocketAddrV4,
        observed: Arc<Mutex<Vec<MockMeObservation>>>,
        closed_conns: Arc<Mutex<Vec<u64>>>,
        pings_seen: Arc<AtomicUsize>,
        drop_pongs: Arc<AtomicBool>,
        burst_count: Arc<AtomicUsize>,
        task: tokio::task::JoinHandle<()>,
    }

    impl Drop for MockMeServer {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    async fn spawn_mock_me_server(proxy_secret: Vec<u8>) -> Result<MockMeServer> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let SocketAddr::V4(addr) = listener.local_addr()? else {
            anyhow::bail!("expected IPv4 listener");
        };
        let observed = Arc::new(Mutex::new(Vec::new()));
        let closed_conns = Arc::new(Mutex::new(Vec::new()));
        let pings_seen = Arc::new(AtomicUsize::new(0));
        let drop_pongs = Arc::new(AtomicBool::new(false));
        let burst_count = Arc::new(AtomicUsize::new(1));

        let obs_cl = observed.clone();
        let cls_cl = closed_conns.clone();
        let ping_cl = pings_seen.clone();
        let dp_cl = drop_pongs.clone();
        let bc_cl = burst_count.clone();

        let task = tokio::spawn(async move {
            loop {
                let Ok((mut s, peer)) = listener.accept().await else {
                    break;
                };
                let SocketAddr::V4(peer_v4) = peer else {
                    continue;
                };
                let secret = proxy_secret.clone();
                let obs = obs_cl.clone();
                let cls = cls_cl.clone();
                let pings = ping_cl.clone();
                let dp = dp_cl.clone();
                let bc = bc_cl.clone();
                tokio::spawn(async move {
                    let mut plain_buf = Vec::new();
                    let mut tmp = [0u8; 256];
                    let (seq, payload) = loop {
                        if let Ok(Some(f)) = decode_rpc_frame(&mut plain_buf) {
                            break f;
                        }
                        let Ok(n) = s.read(&mut tmp).await else {
                            return;
                        };
                        if n == 0 {
                            return;
                        }
                        plain_buf.extend_from_slice(&tmp[..n]);
                    };
                    if seq != -2 {
                        return;
                    }
                    let Ok(RpcMessage::Nonce {
                        key_selector,
                        schema,
                        ts: clt_ts,
                        nonce: clt_nonce,
                    }) = parse_rpc_message(&payload)
                    else {
                        return;
                    };
                    if schema != CRYPTO_AES || secret.get(..4) != Some(&key_selector[..]) {
                        return;
                    }
                    let srv_nonce = [0x5a; 16];
                    let srv_nonce_msg = encode_nonce(key_selector, clt_ts, &srv_nonce);
                    let Ok(resp) = pack_rpc_frame(-2, &srv_nonce_msg, false) else {
                        return;
                    };
                    if s.write_all(&resp).await.is_err() {
                        return;
                    }

                    // Server decrypts with CLIENT key, encrypts with SERVER key.
                    let (dec_key, dec_iv) = derive_me_aes_key_iv(
                        &srv_nonce,
                        &clt_nonce,
                        clt_ts,
                        *addr.ip(),
                        peer_v4.port(),
                        KdfPurpose::Client,
                        *peer_v4.ip(),
                        addr.port(),
                        &secret,
                    );
                    let (enc_key, enc_iv) = derive_me_aes_key_iv(
                        &srv_nonce,
                        &clt_nonce,
                        clt_ts,
                        *addr.ip(),
                        peer_v4.port(),
                        KdfPurpose::Server,
                        *peer_v4.ip(),
                        addr.port(),
                        &secret,
                    );
                    let mut dec = MeCbcDecryptor::new(&dec_key, &dec_iv);
                    let mut enc = MeCbcEncryptor::new(&enc_key, &enc_iv);
                    let mut enc_buf = Vec::new();
                    let mut blk = [0u8; 16];
                    let mut next_seq: i32 = 0;

                    loop {
                        let (rseq, rpay) = loop {
                            if let Ok(Some(f)) = decode_rpc_frame(&mut enc_buf) {
                                break f;
                            }
                            if s.read_exact(&mut blk).await.is_err() {
                                return;
                            }
                            if dec.decrypt_in_place(&mut blk).is_err() {
                                return;
                            }
                            enc_buf.extend_from_slice(&blk);
                        };
                        if rpay.len() < 4 {
                            return;
                        }
                        let op = u32::from_le_bytes([rpay[0], rpay[1], rpay[2], rpay[3]]);
                        match op {
                            RPC_HANDSHAKE if rseq == -1 && rpay.len() >= 32 => {
                                let hs = encode_handshake(0, &[0x11; 12], &[0x22; 12]);
                                let Ok(mut f) = pack_rpc_frame(-1, &hs, true) else {
                                    return;
                                };
                                if enc.encrypt_in_place(&mut f).is_err()
                                    || s.write_all(&f).await.is_err()
                                {
                                    return;
                                }
                            }
                            RPC_PING if rpay.len() >= 12 => {
                                pings.fetch_add(1, Ordering::Relaxed);
                                if dp.load(Ordering::Relaxed) {
                                    continue;
                                }
                                let pid = i64::from_le_bytes([
                                    rpay[4], rpay[5], rpay[6], rpay[7], rpay[8], rpay[9], rpay[10],
                                    rpay[11],
                                ]);
                                let pong = encode_pong(pid);
                                let Ok(mut f) = pack_rpc_frame(next_seq, &pong, true) else {
                                    return;
                                };
                                next_seq = next_seq.wrapping_add(1);
                                if enc.encrypt_in_place(&mut f).is_err()
                                    || s.write_all(&f).await.is_err()
                                {
                                    return;
                                }
                            }
                            RPC_CLOSE_EXT if rpay.len() >= 12 => {
                                let cid = u64::from_le_bytes([
                                    rpay[4], rpay[5], rpay[6], rpay[7], rpay[8], rpay[9], rpay[10],
                                    rpay[11],
                                ]);
                                cls.lock().unwrap_or_else(|e| e.into_inner()).push(cid);
                            }
                            RPC_PROXY_REQ if rpay.len() >= 56 => {
                                let flags =
                                    u32::from_le_bytes([rpay[4], rpay[5], rpay[6], rpay[7]]);
                                let cid = u64::from_le_bytes([
                                    rpay[8], rpay[9], rpay[10], rpay[11], rpay[12], rpay[13],
                                    rpay[14], rpay[15],
                                ]);
                                let mut rip = [0u8; 16];
                                rip.copy_from_slice(&rpay[16..32]);
                                let rport =
                                    u32::from_le_bytes([rpay[32], rpay[33], rpay[34], rpay[35]]);
                                let (ad_tag_seen, body_off) = if flags & FLAG_HAS_AD_TAG != 0 {
                                    // TL short bytes: [len=16][16 bytes][3 pad bytes] = 20 bytes
                                    if rpay.len() < 56 + 20 || rpay[56] != 16 {
                                        return;
                                    }
                                    let mut tag = [0u8; 16];
                                    tag.copy_from_slice(&rpay[57..73]);
                                    (Some(tag), 76)
                                } else {
                                    (None, 56)
                                };
                                let body = rpay[body_off..].to_vec();
                                obs.lock().unwrap_or_else(|e| e.into_inner()).push(
                                    MockMeObservation {
                                        flags,
                                        remote_ip_bytes: rip,
                                        remote_port: rport,
                                        ad_tag_seen,
                                    },
                                );
                                // Echo payload back `burst_count` times as RPC_PROXY_ANS.
                                let n_burst = bc.load(Ordering::Relaxed).max(1);
                                for _ in 0..n_burst {
                                    let mut ans = Vec::with_capacity(16 + body.len());
                                    ans.extend_from_slice(&RPC_PROXY_ANS.to_le_bytes());
                                    ans.extend_from_slice(&0u32.to_le_bytes());
                                    ans.extend_from_slice(&cid.to_le_bytes());
                                    ans.extend_from_slice(&body);
                                    let Ok(mut f) = pack_rpc_frame(next_seq, &ans, true) else {
                                        return;
                                    };
                                    next_seq = next_seq.wrapping_add(1);
                                    if enc.encrypt_in_place(&mut f).is_err()
                                        || s.write_all(&f).await.is_err()
                                    {
                                        return;
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                });
            }
        });

        Ok(MockMeServer {
            addr,
            observed,
            closed_conns,
            pings_seen,
            drop_pongs,
            burst_count,
            task,
        })
    }

    #[test]
    fn kdf_and_rpc_frame_roundtrip_and_padding() -> Result<()> {
        let secret = vec![0xaa; 128];
        let (k_c, iv_c) = derive_me_aes_key_iv(
            &[0x11; 16],
            &[0x22; 16],
            1_700_000_000,
            Ipv4Addr::new(149, 154, 167, 51),
            44444,
            KdfPurpose::Client,
            Ipv4Addr::new(203, 0, 113, 10),
            8888,
            &secret,
        );
        let (k_s, iv_s) = derive_me_aes_key_iv(
            &[0x11; 16],
            &[0x22; 16],
            1_700_000_000,
            Ipv4Addr::new(149, 154, 167, 51),
            44444,
            KdfPurpose::Server,
            Ipv4Addr::new(203, 0, 113, 10),
            8888,
            &secret,
        );
        assert_ne!(k_c, k_s);
        assert_ne!(iv_c, iv_s);

        let mut enc = MeCbcEncryptor::new(&k_c, &iv_c);
        let mut dec = MeCbcDecryptor::new(&k_c, &iv_c);
        let hs = encode_handshake(0, b"IPIPPRPDTIME", &[0u8; 12]);
        let mut wire = pack_rpc_frame(-1, &hs, true)?;
        assert_eq!(wire.len() % 16, 0);
        enc.encrypt_in_place(&mut wire)?;
        dec.decrypt_in_place(&mut wire)?;
        let (seq, decoded) = decode_rpc_frame(&mut wire)?.context("decoded frame")?;
        assert_eq!(seq, -1);
        assert_eq!(decoded, hs);
        // Trailing 4-byte padding word (0x00000004) must be stripped cleanly on next call.
        assert!(decode_rpc_frame(&mut wire)?.is_none());
        assert!(wire.is_empty());
        Ok(())
    }

    #[test]
    fn proxy_multi_conf_parser_and_lkg_disk_cache() -> Result<()> {
        let conf_text = "\
            # Telegram proxy config\n\
            default 2;\n\
            proxy_for 1 149.154.175.50:8888;\n\
            proxy_for 2 149.154.167.51:8888;\n\
            proxy_for -2 149.154.167.151:8888;\n\
            proxy_for 2 [2001:b28:f23d:f001::a]:8888;\n\
            timeout 10 30;\n";
        let parsed = ProxyMultiConfig::parse(conf_text)?;
        assert_eq!(parsed.default_dc, Some(2));
        assert_eq!(parsed.endpoints_for(2).len(), 1);
        assert_eq!(parsed.endpoints_for(-2).len(), 1);
        assert_eq!(parsed.endpoints_for(4), parsed.endpoints_for(2)); // falls back to default_dc

        assert!(parse_ad_tag_hex("0123456789abcdef0123456789abcdef").is_ok());
        assert!(parse_ad_tag_hex("too_short").is_err());
        assert!(parse_ad_tag_hex("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz").is_err());

        // Last-known-good disk cache must never overwrite valid cache with corrupted input.
        let dir = std::env::temp_dir().join(format!("mtevil-me-cache-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let cache = MeDiskCache::new(&dir);
        let secret = vec![0x42; 128];
        let saved = cache.save_validated(&secret, conf_text)?;
        assert_eq!(saved.key_selector()?, [0x42; 4]);
        assert!(cache.save_validated(&[1, 2], conf_text).is_err());
        assert!(cache.save_validated(&secret, "garbage only").is_err());
        let loaded = cache.load()?;
        assert_eq!(loaded, saved);
        let _ = std::fs::remove_dir_all(&dir);
        Ok(())
    }

    #[tokio::test]
    async fn mock_me_multiplex_50_sessions_ad_tag_and_zero_remote_ip() -> Result<()> {
        let secret = vec![0x77; 128];
        let srv = spawn_mock_me_server(secret.clone()).await?;
        let conn = MeConnection::connect(
            srv.addr,
            &secret,
            MeConnOptions {
                handshake_timeout: Duration::from_secs(3),
                ping_interval: Duration::ZERO,
                ping_timeout: Duration::from_secs(2),
                public_ipv4: None,
            },
        )
        .await?;

        let ad_tag = parse_ad_tag_hex("00112233445566778899aabbccddeeff")?;
        let mut handles = Vec::with_capacity(50);
        for i in 0..50u32 {
            let c = conn.clone();
            let remote = if i % 2 == 0 {
                None // me.send_client_ip = false -> 0.0.0.0:0
            } else {
                Some(SocketAddrV4::new(
                    Ipv4Addr::new(198, 51, 100, (i as u8) + 1),
                    40000 + i as u16,
                ))
            };
            let tag = if i % 3 == 0 { Some(ad_tag) } else { None };
            handles.push(tokio::spawn(async move {
                let mut sess = c.open_session(remote, tag)?;
                let mut msg = [0u8; 16];
                msg[0..4].copy_from_slice(&i.to_le_bytes());
                sess.send_frame(&msg).await?;
                let reply = timeout(Duration::from_secs(3), sess.recv_frame())
                    .await
                    .context("recv reply timeout")?
                    .context("session closed prematurely")?;
                assert_eq!(reply, msg);
                sess.close();
                Ok::<_, anyhow::Error>(())
            }));
        }
        for h in handles {
            h.await??;
        }
        tokio::time::sleep(Duration::from_millis(80)).await;
        let obs = srv.observed.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(obs.len(), 50);
        assert!(obs.iter().any(
            |o| o.remote_ip_bytes == ipv4_mapped_16(Ipv4Addr::UNSPECIFIED) && o.remote_port == 0
        ));
        assert!(obs
            .iter()
            .any(|o| o.ad_tag_seen == Some(ad_tag) && (o.flags & FLAG_HAS_AD_TAG) != 0));
        let closed = srv.closed_conns.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(closed.len(), 50, "all 50 sessions must emit RPC_CLOSE_EXT");
        conn.close();
        Ok(())
    }

    #[tokio::test]
    async fn inv03_slow_client_backpressure_drops_only_slow_session() -> Result<()> {
        let secret = vec![0x88; 128];
        let srv = spawn_mock_me_server(secret.clone()).await?;
        let conn = MeConnection::connect(
            srv.addr,
            &secret,
            MeConnOptions {
                handshake_timeout: Duration::from_secs(3),
                ping_interval: Duration::ZERO,
                ping_timeout: Duration::from_secs(2),
                public_ipv4: None,
            },
        )
        .await?;

        // Slow session never reads; trigger > SESSION_INBOUND_QUEUE_CAP replies for it.
        let _slow = conn.open_session(None, None)?;
        srv.burst_count
            .store(SESSION_INBOUND_QUEUE_CAP + 8, Ordering::Relaxed);
        _slow.send_frame(&[0xaa; 16]).await?;
        tokio::time::sleep(Duration::from_millis(120)).await;
        assert_eq!(
            conn.backpressure_drops(),
            1,
            "slow session overflow must be dropped and counted"
        );
        assert!(
            conn.is_alive(),
            "ME connection must stay alive for other sessions"
        );

        // Healthy session on the SAME ME connection must still work cleanly.
        srv.burst_count.store(1, Ordering::Relaxed);
        let mut fast = conn.open_session(None, None)?;
        fast.send_frame(&[0xbb; 16]).await?;
        let reply = timeout(Duration::from_secs(2), fast.recv_frame())
            .await?
            .context("fast session reply")?;
        assert_eq!(reply, vec![0xbb; 16]);
        conn.close();
        Ok(())
    }

    #[tokio::test]
    async fn chaos_me_pool_reconnect_hot_swap_and_ping_timeout() -> Result<()> {
        let secret = vec![0x99; 128];
        let srv1 = spawn_mock_me_server(secret.clone()).await?;
        let srv2 = spawn_mock_me_server(secret.clone()).await?;

        let conf1 = format!("default 2;\nproxy_for 2 {};\n", srv1.addr);
        let bundle1 = MeConfigBundle::from_raw(secret.clone(), &conf1)?;
        let pool = MePool::start(
            bundle1,
            MePoolConfig {
                conns_per_dc: 1,
                reconnect_base: Duration::from_millis(50),
                reconnect_max: Duration::from_millis(200),
                conn_opts: MeConnOptions {
                    handshake_timeout: Duration::from_secs(2),
                    ping_interval: Duration::from_millis(80),
                    ping_timeout: Duration::from_millis(150),
                    public_ipv4: None,
                },
            },
        );

        // Wait for initial connection to srv1.
        for _ in 0..40 {
            if !pool.health().degraded {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert!(!pool.health().degraded);

        // Wait for at least one RPC_PING/RPC_PONG keepalive cycle.
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(srv1.pings_seen.load(Ordering::Relaxed) >= 1);

        // Hot config swap to srv2: sessions switch cleanly to srv2.
        let conf2 = format!("default 2;\nproxy_for 2 {};\n", srv2.addr);
        let bundle2 = MeConfigBundle::from_raw(secret.clone(), &conf2)?;
        pool.update_config(bundle2);
        for _ in 0..40 {
            if !pool.health().degraded {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        let mut sess = pool.open_session(2, None, None)?;
        sess.send_frame(&[0x55; 16]).await?;
        let rep = timeout(Duration::from_secs(2), sess.recv_frame())
            .await?
            .context("srv2 reply")?;
        assert_eq!(rep, vec![0x55; 16]);
        assert!(!srv2
            .observed
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_empty());

        // Simulate hung ME server (drops pongs): ping timeout closes dead socket and marks pool degraded.
        srv2.drop_pongs.store(true, Ordering::Relaxed);
        let mut became_degraded = false;
        for _ in 0..40 {
            if pool.health().degraded {
                became_degraded = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
        assert!(became_degraded, "ping timeout must detect hung ME socket");

        pool.shutdown();
        Ok(())
    }

    #[tokio::test]
    #[ignore = "live Telegram ME test: requires network access to Telegram ME and MTEVIL_ME_SECRET_FILE/MTEVIL_ME_CONF_FILE"]
    async fn live_me_req_pq_multi_roundtrip() -> Result<()> {
        let secret_path = std::env::var("MTEVIL_ME_SECRET_FILE")
            .context("set MTEVIL_ME_SECRET_FILE to downloaded proxy-secret")?;
        let conf_path = std::env::var("MTEVIL_ME_CONF_FILE")
            .context("set MTEVIL_ME_CONF_FILE to downloaded proxy-multi.conf")?;
        let secret = std::fs::read(&secret_path)?;
        let conf_text = std::fs::read_to_string(&conf_path)?;
        let bundle = MeConfigBundle::from_raw(secret, &conf_text)?;
        let ep = *bundle
            .proxy_conf
            .endpoints_for(2)
            .first()
            .context("no DC 2 endpoint in proxy-multi.conf")?;
        let public_ipv4 = std::env::var("MTEVIL_ME_PUBLIC_IPV4")
            .ok()
            .and_then(|s| s.parse::<Ipv4Addr>().ok());

        let conn = MeConnection::connect(
            ep,
            &bundle.proxy_secret,
            MeConnOptions {
                handshake_timeout: Duration::from_secs(10),
                ping_interval: Duration::ZERO,
                ping_timeout: Duration::from_secs(5),
                public_ipv4,
            },
        )
        .await?;
        let mut sess = conn.open_session(None, None)?;
        let mut nonce = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce);
        let now_secs = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let req = build_req_pq_multi(&nonce, now_secs);
        sess.send_frame(&req).await?;
        let reply = timeout(Duration::from_secs(10), sess.recv_frame())
            .await
            .context("live resPQ timeout")?
            .context("live ME session closed before resPQ")?;
        validate_res_pq(&reply, &nonce)?;
        conn.close();
        Ok(())
    }
}
