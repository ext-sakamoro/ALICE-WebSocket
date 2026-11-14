//! `OsMask`: mask keys and nonces from the operating system's random source.
#![cfg(feature = "rng")]

use alice_websocket::{client_key, Frame, MaskSource, OsMask};

#[test]
fn two_os_mask_fills_differ() {
    let mut m = OsMask::new();
    let (mut a, mut b) = ([0u8; 32], [0u8; 32]);
    m.fill(&mut a);
    m.fill(&mut b);
    // 2^-256 chance of a false failure
    assert_ne!(a, b);
    assert_ne!(a, [0u8; 32]);
}

#[test]
fn os_mask_keys_and_nonces_differ_per_use() {
    let mut m = OsMask::new();
    assert_ne!(client_key(&mut m), client_key(&mut m));
    let f = Frame::binary(vec![0; 16]);
    let (a, b) = (f.serialize_client(&mut m), f.serialize_client(&mut m));
    // 4-byte keys: a 2^-32 chance of a false failure, so compare the masked payloads as well
    assert!(a[2..] != b[2..]);
}

#[test]
fn os_mask_try_fill_reports_success() {
    let mut buf = [0u8; 64];
    OsMask::new()
        .try_fill(&mut buf)
        .expect("the OS source is available");
    assert_ne!(buf, [0u8; 64]);
}
