//! Pure-Rust, constant-time RFC 7748 X25519 scalar multiplication (no `unsafe`),
//! using 51-bit limbs modulo 2^255 - 19 for fast debug and release execution.

use rand::RngCore;

type Fe = [u64; 5];

const MASK51: u64 = (1u64 << 51) - 1;
const FE_ZERO: Fe = [0; 5];
const FE_ONE: Fe = [1, 0, 0, 0, 0];
const BASEPOINT_U: [u8; 32] = [
    9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

#[inline]
fn fe_add(a: &Fe, b: &Fe) -> Fe {
    [
        a[0] + b[0],
        a[1] + b[1],
        a[2] + b[2],
        a[3] + b[3],
        a[4] + b[4],
    ]
}

/// Subtract `b` from `a` modulo p by adding `2*p` before subtracting to avoid underflow.
#[inline]
fn fe_sub(a: &Fe, b: &Fe) -> Fe {
    // 2 * p in radix 2^51:
    // 2*(2^51 - 19) = 0xfffffffffffda, 2*(2^51 - 1) = 0xffffffffffffe
    let mut o = [
        a[0] + 0x000f_ffff_ffff_ffda - b[0],
        a[1] + 0x000f_ffff_ffff_fffe - b[1],
        a[2] + 0x000f_ffff_ffff_fffe - b[2],
        a[3] + 0x000f_ffff_ffff_fffe - b[3],
        a[4] + 0x000f_ffff_ffff_fffe - b[4],
    ];
    fe_carry(&mut o);
    o
}

#[inline]
fn fe_carry(h: &mut Fe) {
    let c0 = h[0] >> 51;
    h[1] += c0;
    h[0] &= MASK51;
    let c1 = h[1] >> 51;
    h[2] += c1;
    h[1] &= MASK51;
    let c2 = h[2] >> 51;
    h[3] += c2;
    h[2] &= MASK51;
    let c3 = h[3] >> 51;
    h[4] += c3;
    h[3] &= MASK51;
    let c4 = h[4] >> 51;
    h[0] += c4 * 19;
    h[4] &= MASK51;
}

fn fe_mul(a: &Fe, b: &Fe) -> Fe {
    let a0 = u128::from(a[0]);
    let a1 = u128::from(a[1]);
    let a2 = u128::from(a[2]);
    let a3 = u128::from(a[3]);
    let a4 = u128::from(a[4]);

    let b0 = u128::from(b[0]);
    let b1 = u128::from(b[1]);
    let b2 = u128::from(b[2]);
    let b3 = u128::from(b[3]);
    let b4 = u128::from(b[4]);

    let b1_19 = b1 * 19;
    let b2_19 = b2 * 19;
    let b3_19 = b3 * 19;
    let b4_19 = b4 * 19;

    let mut t0 = a0 * b0 + a1 * b4_19 + a2 * b3_19 + a3 * b2_19 + a4 * b1_19;
    let mut t1 = a0 * b1 + a1 * b0 + a2 * b4_19 + a3 * b3_19 + a4 * b2_19;
    let mut t2 = a0 * b2 + a1 * b1 + a2 * b0 + a3 * b4_19 + a4 * b3_19;
    let mut t3 = a0 * b3 + a1 * b2 + a2 * b1 + a3 * b0 + a4 * b4_19;
    let mut t4 = a0 * b4 + a1 * b3 + a2 * b2 + a3 * b1 + a4 * b0;

    t1 += t0 >> 51;
    t0 &= u128::from(MASK51);
    t2 += t1 >> 51;
    t1 &= u128::from(MASK51);
    t3 += t2 >> 51;
    t2 &= u128::from(MASK51);
    t4 += t3 >> 51;
    t3 &= u128::from(MASK51);
    t0 += (t4 >> 51) * 19;
    t4 &= u128::from(MASK51);
    t1 += t0 >> 51;
    t0 &= u128::from(MASK51);

    [t0 as u64, t1 as u64, t2 as u64, t3 as u64, t4 as u64]
}

#[inline]
fn fe_sq(a: &Fe) -> Fe {
    fe_mul(a, a)
}

#[inline]
fn fe_mul_121665(a: &Fe) -> Fe {
    let k = 121_665u128;
    let mut t0 = u128::from(a[0]) * k;
    let mut t1 = u128::from(a[1]) * k;
    let mut t2 = u128::from(a[2]) * k;
    let mut t3 = u128::from(a[3]) * k;
    let mut t4 = u128::from(a[4]) * k;

    t1 += t0 >> 51;
    t0 &= u128::from(MASK51);
    t2 += t1 >> 51;
    t1 &= u128::from(MASK51);
    t3 += t2 >> 51;
    t2 &= u128::from(MASK51);
    t4 += t3 >> 51;
    t3 &= u128::from(MASK51);
    t0 += (t4 >> 51) * 19;
    t4 &= u128::from(MASK51);
    t1 += t0 >> 51;
    t0 &= u128::from(MASK51);

    [t0 as u64, t1 as u64, t2 as u64, t3 as u64, t4 as u64]
}

#[inline]
fn fe_cswap(a: &mut Fe, b: &mut Fe, swap: u64) {
    let mask = 0u64.wrapping_sub(swap);
    for i in 0..5 {
        let t = mask & (a[i] ^ b[i]);
        a[i] ^= t;
        b[i] ^= t;
    }
}

fn fe_from_bytes(s: &[u8; 32]) -> Fe {
    let load8 = |off: usize| -> u64 {
        u64::from_le_bytes([
            s[off],
            s[off + 1],
            s[off + 2],
            s[off + 3],
            s[off + 4],
            s[off + 5],
            s[off + 6],
            s[off + 7],
        ])
    };
    let h0 = load8(0) & MASK51;
    let h1 = (load8(6) >> 3) & MASK51;
    let h2 = (load8(12) >> 6) & MASK51;
    let h3 = (load8(19) >> 1) & MASK51;
    let h4 = (load8(24) >> 12) & MASK51;
    [h0, h1, h2, h3, h4]
}

fn fe_to_bytes(h: &Fe) -> [u8; 32] {
    let mut t = *h;
    fe_carry(&mut t);
    fe_carry(&mut t);

    // Canonical reduction mod p = 2^255 - 19
    let mut q = (t[0] + 19) >> 51;
    q = (t[1] + q) >> 51;
    q = (t[2] + q) >> 51;
    q = (t[3] + q) >> 51;
    q = (t[4] + q) >> 51;

    t[0] += 19 * q;
    let c0 = t[0] >> 51;
    t[0] &= MASK51;
    t[1] += c0;
    let c1 = t[1] >> 51;
    t[1] &= MASK51;
    t[2] += c1;
    let c2 = t[2] >> 51;
    t[2] &= MASK51;
    t[3] += c2;
    let c3 = t[3] >> 51;
    t[3] &= MASK51;
    t[4] += c3;
    t[4] &= MASK51;

    let mut out = [0u8; 32];
    let w0 = t[0] | (t[1] << 51);
    let w1 = (t[1] >> 13) | (t[2] << 38);
    let w2 = (t[2] >> 26) | (t[3] << 25);
    let w3 = (t[3] >> 39) | (t[4] << 12);
    out[0..8].copy_from_slice(&w0.to_le_bytes());
    out[8..16].copy_from_slice(&w1.to_le_bytes());
    out[16..24].copy_from_slice(&w2.to_le_bytes());
    out[24..32].copy_from_slice(&w3.to_le_bytes());
    out
}

fn fe_inv(z: &Fe) -> Fe {
    let z2 = fe_sq(z);
    let z9 = fe_mul(&fe_sq(&fe_sq(&z2)), z);
    let z11 = fe_mul(&z9, &z2);
    let z_5_0 = fe_mul(&fe_sq(&z11), &z9);

    let mut t = z_5_0;
    for _ in 0..5 {
        t = fe_sq(&t);
    }
    let z_10_0 = fe_mul(&t, &z_5_0);

    t = z_10_0;
    for _ in 0..10 {
        t = fe_sq(&t);
    }
    let z_20_0 = fe_mul(&t, &z_10_0);

    t = z_20_0;
    for _ in 0..20 {
        t = fe_sq(&t);
    }
    let mut z_40_0 = fe_mul(&t, &z_20_0);

    t = z_40_0;
    for _ in 0..10 {
        t = fe_sq(&t);
    }
    let z_50_0 = fe_mul(&t, &z_10_0);

    t = z_50_0;
    for _ in 0..50 {
        t = fe_sq(&t);
    }
    let z_100_0 = fe_mul(&t, &z_50_0);

    t = z_100_0;
    for _ in 0..100 {
        t = fe_sq(&t);
    }
    t = fe_mul(&t, &z_100_0);

    for _ in 0..50 {
        t = fe_sq(&t);
    }
    z_40_0 = fe_mul(&t, &z_50_0);

    for _ in 0..5 {
        z_40_0 = fe_sq(&z_40_0);
    }
    fe_mul(&z_40_0, &z11)
}

/// Compute `X25519(k, u)` per RFC 7748 §5.
pub fn x25519(scalar: &[u8; 32], u_coord: &[u8; 32]) -> [u8; 32] {
    let mut k = *scalar;
    k[0] &= 248;
    k[31] = (k[31] & 127) | 64;

    let x1 = fe_from_bytes(u_coord);
    let mut x2 = FE_ONE;
    let mut z2 = FE_ZERO;
    let mut x3 = x1;
    let mut z3 = FE_ONE;
    let mut swap = 0u64;

    for t in (0..=254).rev() {
        let k_t = u64::from((k[t >> 3] >> (t & 7)) & 1);
        swap ^= k_t;
        fe_cswap(&mut x2, &mut x3, swap);
        fe_cswap(&mut z2, &mut z3, swap);
        swap = k_t;

        let a = fe_add(&x2, &z2);
        let aa = fe_sq(&a);
        let b = fe_sub(&x2, &z2);
        let bb = fe_sq(&b);
        let e = fe_sub(&aa, &bb);
        let c = fe_add(&x3, &z3);
        let d = fe_sub(&x3, &z3);
        let da = fe_mul(&d, &a);
        let cb = fe_mul(&c, &b);

        x3 = fe_sq(&fe_add(&da, &cb));
        z3 = fe_mul(&x1, &fe_sq(&fe_sub(&da, &cb)));
        x2 = fe_mul(&aa, &bb);
        z2 = fe_mul(&e, &fe_add(&aa, &fe_mul_121665(&e)));
    }

    fe_cswap(&mut x2, &mut x3, swap);
    fe_cswap(&mut z2, &mut z3, swap);

    let out = fe_mul(&x2, &fe_inv(&z2));
    fe_to_bytes(&out)
}

/// Compute an X25519 public key `X25519(secret, 9)` from a 32-byte scalar.
pub fn public_from_secret(secret: &[u8; 32]) -> [u8; 32] {
    x25519(secret, &BASEPOINT_U)
}

/// Generate a fresh ephemeral X25519 public key using `rng`.
pub fn generate_public_key<R: RngCore + ?Sized>(rng: &mut R) -> [u8; 32] {
    let mut secret = [0u8; 32];
    rng.fill_bytes(&mut secret);
    public_from_secret(&secret)
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use rand::rngs::OsRng;
    use std::collections::HashSet;

    fn hex32(s: &str) -> Result<[u8; 32]> {
        let bytes = hex::decode(s)?;
        Ok(bytes.as_slice().try_into()?)
    }

    #[test]
    fn rfc7748_section5_and_section6_vectors() -> Result<()> {
        let k1 = hex32("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")?;
        let u1 = hex32("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")?;
        let exp1 = hex32("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552")?;
        assert_eq!(x25519(&k1, &u1), exp1);

        let alice_sk = hex32("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")?;
        let alice_pk_exp =
            hex32("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")?;
        let bob_sk = hex32("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")?;
        let bob_pk_exp = hex32("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")?;
        let shared_exp = hex32("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")?;

        let alice_pk = public_from_secret(&alice_sk);
        let bob_pk = public_from_secret(&bob_sk);
        assert_eq!(alice_pk, alice_pk_exp);
        assert_eq!(bob_pk, bob_pk_exp);
        assert_eq!(x25519(&alice_sk, &bob_pk), shared_exp);
        assert_eq!(x25519(&bob_sk, &alice_pk), shared_exp);
        Ok(())
    }

    #[test]
    fn x25519_key_generation_unique_across_10000_calls() {
        let mut seen = HashSet::with_capacity(10_000);
        for _ in 0..10_000 {
            let pk = generate_public_key(&mut OsRng);
            assert!(seen.insert(pk), "duplicate X25519 public key generated");
        }
        assert_eq!(seen.len(), 10_000);
    }

    #[test]
    fn x25519_matches_x25519_dalek_across_10000_random_scalars() {
        use rand::RngCore;
        for _ in 0..10_000 {
            let mut sk = [0u8; 32];
            OsRng.fill_bytes(&mut sk);
            let ours = public_from_secret(&sk);
            let dalek_sk = x25519_dalek::StaticSecret::from(sk);
            let dalek_pk = x25519_dalek::PublicKey::from(&dalek_sk);
            assert_eq!(ours, *dalek_pk.as_bytes());
        }
    }

    #[test]
    #[ignore = "manual CPU cost benchmark for 10,000 X25519 key generations"]
    fn bench_x25519_10000_keys_cpu_cost() {
        let t0 = std::time::Instant::now();
        let mut acc = 0u8;
        for _ in 0..10_000 {
            let pk = generate_public_key(&mut OsRng);
            acc ^= pk[0];
        }
        let elapsed = t0.elapsed();
        println!(
            "x25519_10000_keys: total={:?}, per_key_us={:.2}, guard={}",
            elapsed,
            elapsed.as_secs_f64() * 1_000_000.0 / 10_000.0,
            acc
        );
    }
}
