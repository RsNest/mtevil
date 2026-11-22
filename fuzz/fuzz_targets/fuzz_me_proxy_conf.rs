#![no_main]

use libfuzzer_sys::fuzz_target;
use mtevil_me_pool::ProxyMultiConfig;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = ProxyMultiConfig::parse(text);
    }
});
