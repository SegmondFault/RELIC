//! Interoperability with keys produced by the real OpenSSH `ssh-keygen`.
//!
//! `docs/analyst-keys.md` tells analysts to create their RELIC identity with
//! `ssh-keygen`. These tests generate fresh keys with that exact tool at test
//! time (no private key is committed) and check that `SystemSigner` loads them,
//! rejects unsafe or wrong input, and signs verifiably with the matching public
//! key.
//!
//! `ssh-keygen` must be on `PATH`; the tests fail rather than silently skip.

#![cfg(unix)]

use std::{
    fs,
    os::unix::fs::{PermissionsExt as _, symlink},
    path::{Path, PathBuf},
    process::Command,
};

use relic_crypto::{KeyLoadError, SystemSigner, read_secret_file, sha256, verify_digest_signature};
use ssh_key::PublicKey;
use tempfile::{TempDir, tempdir};

const PASSPHRASE: &str = "correct horse battery staple";
const DOMAIN: &[u8] = b"RELIC:openssh-interop-test:v1";

/// Run `ssh-keygen` as documented for analysts, with a fixed passphrase so the
/// test is non-interactive. `-a 16` (instead of the documented `-a 100`) keeps
/// the test fast; the key format and cipher are the same.
fn ssh_keygen(directory: &TempDir, key_type: &str, passphrase: &str) -> PathBuf {
    let path = directory.path().join(format!("id_{key_type}"));
    let output = Command::new("ssh-keygen")
        .args([
            "-q",
            "-t",
            key_type,
            "-a",
            "16",
            "-C",
            "relic-test",
            "-N",
            passphrase,
            "-f",
        ])
        .arg(&path)
        .output()
        .expect("ssh-keygen must be installed to run the OpenSSH interop tests");
    assert!(
        output.status.success(),
        "ssh-keygen failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    path
}

fn public_key_bytes(private_path: &Path) -> [u8; 32] {
    let encoded = fs::read_to_string(private_path.with_extension("pub")).unwrap();
    let public = PublicKey::from_openssh(&encoded).unwrap();
    public.key_data().ed25519().expect("Ed25519 public key").0
}

#[test]
fn encrypted_ssh_keygen_key_loads_and_signs_verifiably() {
    let directory = tempdir().unwrap();
    let key = ssh_keygen(&directory, "ed25519", PASSPHRASE);

    let signer = SystemSigner::from_openssh_file(&key, Some(PASSPHRASE.as_bytes())).unwrap();
    let public = public_key_bytes(&key);
    assert_eq!(signer.verifying_key(), public);

    let digest = sha256(b"submission");
    let signature = signer.sign_digest(DOMAIN, &digest);
    assert!(verify_digest_signature(&public, DOMAIN, &digest, &signature).is_ok());
    assert!(verify_digest_signature(&public, b"RELIC:other:v1", &digest, &signature).is_err());
}

#[test]
fn passphrase_file_with_trailing_newline_unlocks_key() {
    let directory = tempdir().unwrap();
    let key = ssh_keygen(&directory, "ed25519", PASSPHRASE);
    let passphrase_path = directory.path().join("passphrase");
    fs::write(&passphrase_path, format!("{PASSPHRASE}\n")).unwrap();
    fs::set_permissions(&passphrase_path, fs::Permissions::from_mode(0o600)).unwrap();

    let passphrase = read_secret_file(&passphrase_path).unwrap();
    let signer = SystemSigner::from_openssh_file(&key, Some(&passphrase)).unwrap();
    assert_eq!(signer.verifying_key(), public_key_bytes(&key));
}

#[test]
fn encrypted_key_requires_the_correct_passphrase() {
    let directory = tempdir().unwrap();
    let key = ssh_keygen(&directory, "ed25519", PASSPHRASE);

    assert!(matches!(
        SystemSigner::from_openssh_file(&key, None),
        Err(KeyLoadError::PassphraseRequired)
    ));
    assert!(matches!(
        SystemSigner::from_openssh_file(&key, Some(b"wrong passphrase")),
        Err(KeyLoadError::Decrypt(_))
    ));
}

#[test]
fn unencrypted_ssh_keygen_key_loads() {
    let directory = tempdir().unwrap();
    let key = ssh_keygen(&directory, "ed25519", "");

    let signer = SystemSigner::from_openssh_file(&key, None).unwrap();
    assert_eq!(signer.verifying_key(), public_key_bytes(&key));
}

#[test]
fn non_ed25519_ssh_keygen_key_is_rejected() {
    let directory = tempdir().unwrap();
    let key = ssh_keygen(&directory, "ecdsa", "");

    assert!(matches!(
        SystemSigner::from_openssh_file(&key, None),
        Err(KeyLoadError::NotEd25519)
    ));
}

#[test]
fn group_or_other_readable_key_is_rejected() {
    let directory = tempdir().unwrap();
    let key = ssh_keygen(&directory, "ed25519", PASSPHRASE);

    for mode in [0o640, 0o604, 0o660] {
        fs::set_permissions(&key, fs::Permissions::from_mode(mode)).unwrap();
        assert!(
            matches!(
                SystemSigner::from_openssh_file(&key, Some(PASSPHRASE.as_bytes())),
                Err(KeyLoadError::UnsafePermissions { .. })
            ),
            "mode {mode:o} must be rejected"
        );
    }
}

#[test]
fn symlinked_key_is_rejected() {
    let directory = tempdir().unwrap();
    let key = ssh_keygen(&directory, "ed25519", PASSPHRASE);
    let link = directory.path().join("link");
    symlink(&key, &link).unwrap();

    assert!(matches!(
        SystemSigner::from_openssh_file(&link, Some(PASSPHRASE.as_bytes())),
        Err(KeyLoadError::NotPrivateRegularFile(_))
    ));
}
