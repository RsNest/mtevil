#![no_main]

use libfuzzer_sys::fuzz_target;
use mtevil_proto::{parse_proxy_v2_header, parse_proxy_v2_payload, PROXY_V2_HEADER_LEN};

fuzz_target!(|data: &[u8]| {
    if data.len() < PROXY_V2_HEADER_LEN {
        return;
    }
    let mut header_bytes = [0u8; PROXY_V2_HEADER_LEN];
    header_bytes.copy_from_slice(&data[..PROXY_V2_HEADER_LEN]);
    if let Ok(header) = parse_proxy_v2_header(&header_bytes) {
        let payload = &data[PROXY_V2_HEADER_LEN..];
        let _ = parse_proxy_v2_payload(&header, payload);
        if payload.len() >= header.payload_len {
            let _ = parse_proxy_v2_payload(&header, &payload[..header.payload_len]);
        }
    }
});
