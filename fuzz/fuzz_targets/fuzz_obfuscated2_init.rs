#![no_main]

use libfuzzer_sys::fuzz_target;
use mtevil_proto::client_transport;

const DEFAULT_SECRET: [u8; 16] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
    0x0f,
];

fuzz_target!(|data: &[u8]| {
    if data.len() < 64 {
        return;
    }
    let mut wire = [0u8; 64];
    wire.copy_from_slice(&data[..64]);
    let secret = if data.len() >= 80 {
        let mut s = [0u8; 16];
        s.copy_from_slice(&data[64..80]);
        s
    } else {
        DEFAULT_SECRET
    };
    let _ = client_transport(&wire, &secret);
});
