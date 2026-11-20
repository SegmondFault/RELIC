import os
import stat

import pytest

from cryptography.hazmat.primitives import serialization

from relic_identity import (
    IdentityError,
    generate_keypair,
    load_private_key,
    load_public_key,
    sign_bytes,
    verify_bytes,
)


TEST_PASSPHRASE = "correct horse battery staple"


def test_generate_keypair(tmp_path):
    paths = generate_keypair(
        tmp_path,
        TEST_PASSPHRASE,
    )

    assert paths.private_key.exists()
    assert paths.public_key.exists()


def test_public_key_has_correct_size(tmp_path):
    paths = generate_keypair(
        tmp_path,
        TEST_PASSPHRASE,
    )

    public_hex = paths.public_key.read_text().strip()

    assert len(public_hex) == 64

    public_raw = bytes.fromhex(public_hex)

    assert len(public_raw) == 32


def test_private_key_is_encrypted(tmp_path):
    paths = generate_keypair(
        tmp_path,
        TEST_PASSPHRASE,
    )

    private_pem = paths.private_key.read_bytes()

    with pytest.raises((TypeError, ValueError)):
        serialization.load_pem_private_key(
            private_pem,
            password=None,
        )


def test_private_key_has_restrictive_permissions(tmp_path):
    paths = generate_keypair(
        tmp_path,
        TEST_PASSPHRASE,
    )

    if os.name == "posix":
        permissions = stat.S_IMODE(
            paths.private_key.stat().st_mode
        )

        assert permissions == 0o600


def test_load_private_and_public_keys(tmp_path):
    paths = generate_keypair(
        tmp_path,
        TEST_PASSPHRASE,
    )

    private_key = load_private_key(
        paths.private_key,
        TEST_PASSPHRASE,
    )

    public_key = load_public_key(
        paths.public_key,
    )

    assert private_key is not None
    assert public_key is not None


def test_sign_and_verify(tmp_path):
    paths = generate_keypair(
        tmp_path,
        TEST_PASSPHRASE,
    )

    private_key = load_private_key(
        paths.private_key,
        TEST_PASSPHRASE,
    )

    public_key = load_public_key(
        paths.public_key,
    )

    message = b"RELIC Ed25519 test message"

    signature = sign_bytes(
        private_key,
        message,
    )

    assert len(signature) == 64

    assert verify_bytes(
        public_key,
        message,
        signature,
    )


def test_modified_message_is_rejected(tmp_path):
    paths = generate_keypair(
        tmp_path,
        TEST_PASSPHRASE,
    )

    private_key = load_private_key(
        paths.private_key,
        TEST_PASSPHRASE,
    )

    public_key = load_public_key(
        paths.public_key,
    )

    signature = sign_bytes(
        private_key,
        b"Original message",
    )

    assert not verify_bytes(
        public_key,
        b"Modified message",
        signature,
    )


def test_wrong_passphrase_is_rejected(tmp_path):
    paths = generate_keypair(
        tmp_path,
        TEST_PASSPHRASE,
    )

    with pytest.raises(IdentityError):
        load_private_key(
            paths.private_key,
            "this is an incorrect passphrase",
        )


def test_existing_identity_is_never_overwritten(tmp_path):
    paths = generate_keypair(
        tmp_path,
        TEST_PASSPHRASE,
    )

    original_private_key = paths.private_key.read_bytes()
    original_public_key = paths.public_key.read_bytes()

    with pytest.raises(IdentityError):
        generate_keypair(
            tmp_path,
            TEST_PASSPHRASE,
        )

    assert paths.private_key.read_bytes() == original_private_key
    assert paths.public_key.read_bytes() == original_public_key
