#![no_main]

use libfuzzer_sys::fuzz_target;
use mtevil_proto::{
    verify_egress_preface_v3, EGRESS_PREFACE_V3_LEN, EGRESS_V3_MAX_SKEW_SECS,
};

const DEFAULT_TOKEN: [u8; 16] = [
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
    0x1f,
];

fuzz_target!(|data: &[u8]| {
    if data.len() < EGRESS_PREFACE_V3_LEN {
        return;
    }
    let mut preface = [0u8; EGRESS_PREFACE_V3_LEN];
    preface.copy_from_slice(&data[..EGRESS_PREFACE_V3_LEN]);
    let token = if data.len() >= EGRESS_PREFACE_V3_LEN + 16 {
        let mut t = [0u8; 16];
        t.copy_from_slice(&data[EGRESS_PREFACE_V3_LEN..EGRESS_PREFACE_V3_LEN + 16]);
        t
    } else {
        DEFAULT_TOKEN
    };
    let _ = verify_egress_preface_v3(&preface, &token, 1_700_000_000, EGRESS_V3_MAX_SKEW_SECS);
});
