//! `OsMask`: mask keys and nonces from the operating system's random source.
#![cfg(feature = "rng")]

use alice_websocket::{client_key, Frame, MaskSource, OsMask};

#[test]
fn two_os_mask_fills_differ() {
    let mut m = OsMask::new();
    let (mut a, mut b) = ([0u8; 32], [0u8; 32]);
    m.fill(&mut a).expect("the OS source is available");
    m.fill(&mut b).expect("the OS source is available");
    // 2^-256 chance of a false failure
    assert_ne!(a, b);
    assert_ne!(a, [0u8; 32]);
}

#[test]
fn os_mask_keys_and_nonces_differ_per_use() {
    let mut m = OsMask::new();
    assert_ne!(client_key(&mut m).unwrap(), client_key(&mut m).unwrap());
    let f = Frame::binary(vec![0; 16]);
    let (a, b) = (
        f.serialize_client(&mut m).unwrap(),
        f.serialize_client(&mut m).unwrap(),
    );
    // 4-byte keys: a 2^-32 chance of a false failure, so compare the masked payloads as well
    assert!(a[2..] != b[2..]);
}

/// A 4-byte mask key on success, different across calls: 16 keys, at least 2 distinct
/// (all equal by chance: 2^-480).
#[test]
fn os_mask_four_byte_keys_vary_across_calls() {
    let mut m = OsMask::new();
    let keys: Vec<[u8; 4]> = (0..16)
        .map(|_| {
            let bytes = Frame::binary(vec![0; 4]).serialize_client(&mut m).unwrap();
            // header: 0x82, 0x80 | 4, then the 4-byte key, then the masked payload (= the key, payload 0)
            assert_eq!(bytes.len(), 2 + 4 + 4);
            assert_eq!(bytes[1], 0x80 | 4, "mask bit and length 4");
            assert_eq!(
                bytes[2..6],
                bytes[6..10],
                "a zero payload masked is the key"
            );
            [bytes[2], bytes[3], bytes[4], bytes[5]]
        })
        .collect();
    assert_eq!(keys.len(), 16, "compared > 0");
    assert!(keys.iter().any(|k| *k != keys[0]), "keys vary: {keys:?}");
}
