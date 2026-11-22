#![no_main]

use libfuzzer_sys::fuzz_target;
use mtevil_me_pool::{decode_rpc_frame, parse_rpc_message};

fuzz_target!(|data: &[u8]| {
    let mut buf = data.to_vec();
    while let Ok(Some((_seq, payload))) = decode_rpc_frame(&mut buf) {
        let _ = parse_rpc_message(&payload);
    }
    let _ = parse_rpc_message(data);
});
