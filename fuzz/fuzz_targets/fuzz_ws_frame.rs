#![no_main]

use libfuzzer_sys::fuzz_target;
use mtevil_proto::parse_ws_frame_header;

fuzz_target!(|data: &[u8]| {
    let _ = parse_ws_frame_header(data, true);
    let _ = parse_ws_frame_header(data, false);
});
