#![no_main]

use libfuzzer_sys::fuzz_target;
use mtevil_proto::{authenticate, authenticate_with_record_version, handshake_length};

const SECRET: [u8; 16] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
    0x0f,
];

fuzz_target!(|data: &[u8]| {
    let _ = handshake_length(data);
    let _ = authenticate(data, &SECRET, "example.com", 1_700_000_000);
    if let Some((&minor, rest)) = data.split_first() {
        let _ = authenticate_with_record_version(rest, minor, &SECRET, "example.com", 1_700_000_000);
    }
    if data.len() > 5 && data[0] == 0x16 {
        let _ = authenticate_with_record_version(
            &data[5..],
            data[2],
            &SECRET,
            "example.com",
            1_700_000_000,
        );
    }
});
