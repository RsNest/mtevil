#![no_main]

use libfuzzer_sys::fuzz_target;
use mtevil_proto::{parse_ws_upgrade_request, parse_ws_upgrade_response};

fuzz_target!(|data: &[u8]| {
    let _ = parse_ws_upgrade_request(data, true);
    let _ = parse_ws_upgrade_request(data, false);
    let _ = parse_ws_upgrade_response(data, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
});
