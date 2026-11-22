#![no_main]

use libfuzzer_sys::fuzz_target;
use mtevil_proto::{decode_client_frame, ClientProtoKind};

fuzz_target!(|data: &[u8]| {
    for kind in [
        ClientProtoKind::Abridged,
        ClientProtoKind::Intermediate,
        ClientProtoKind::PaddedIntermediate,
    ] {
        let mut buf = data.to_vec();
        while let Ok(Some(_frame)) = decode_client_frame(kind, &mut buf) {}
    }
});
