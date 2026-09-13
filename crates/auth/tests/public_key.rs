//! Tests for public-key rendering.

use turnkey_auth::ssh::encode_public_key_line;

#[test]
fn encode_public_key_line_matches_openssh_format() {
    let public_key = [0x66; 32];

    let line = encode_public_key_line(&public_key);

    assert_eq!(
        line,
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZm"
    );
}
