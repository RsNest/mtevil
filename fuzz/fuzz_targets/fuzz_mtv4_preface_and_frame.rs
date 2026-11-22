#![no_main]

use libfuzzer_sys::fuzz_target;
use mtevil_proto::{
    decode_mtv4_frame_from_slice, verify_egress_preface_v4, EGRESS_PREFACE_V4_LEN,
    EGRESS_V3_MAX_SKEW_SECS,
};

fuzz_target!(|data: &[u8]| {
    let token = [0x42u8; 16];
    if data.len() >= EGRESS_PREFACE_V4_LEN {
        if let Ok(arr) = <[u8; EGRESS_PREFACE_V4_LEN]>::try_from(&data[..EGRESS_PREFACE_V4_LEN]) {
            let _ = verify_egress_preface_v4(&arr, &token, 1_700_000_000, EGRESS_V3_MAX_SKEW_SECS);
        }
    }
    let mut buf = data.to_vec();
    while let Ok(Some(_)) = decode_mtv4_frame_from_slice(&mut buf) {}
});
