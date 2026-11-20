from __future__ import annotations

import argparse
import getpass
import os
import sys

from pathlib import Path
from typing import NamedTuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


DEFAULT_IDENTITY_DIR = (
    Path.home() / ".config" / "relic" / "identity"
)

MIN_PASSPHRASE_LENGTH = 12
ED25519_PUBLIC_KEY_SIZE = 32
ED25519_SIGNATURE_SIZE = 64


class IdentityError(Exception):
    """Raised when an identity operation fails."""


class KeyPaths(NamedTuple):
    private_key: Path
    public_key: Path


def _validate_passphrase(passphrase: str) -> bytes:
    if not isinstance(passphrase, str):
        raise IdentityError("Passphrase must be a string.")

    encoded = passphrase.encode("utf-8")

    if len(passphrase) < MIN_PASSPHRASE_LENGTH:
        raise IdentityError(
            f"Passphrase must contain at least "
            f"{MIN_PASSPHRASE_LENGTH} characters."
        )

    return encoded


def _prepare_identity_directory(directory: Path) -> None:
    directory = Path(directory)

    if directory.is_symlink():
        raise IdentityError(
            "Identity directory must not be a symbolic link."
        )

    directory.mkdir(
        parents=True,
        exist_ok=True,
        mode=0o700,
    )

    if not directory.is_dir():
        raise IdentityError(
            "Identity path is not a directory."
        )

    if os.name == "posix":
        os.chmod(directory, 0o700)


def _write_new_file(
    path: Path,
    content: bytes,
    mode: int,
) -> None:
    """
    Create a new file without overwriting an existing one.
    """

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL

    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY

    descriptor = os.open(path, flags, mode)

    try:
        with os.fdopen(descriptor, "wb") as file:
            file.write(content)
            file.flush()
            os.fsync(file.fileno())

    except Exception:
        path.unlink(missing_ok=True)
        raise

    if os.name == "posix":
        os.chmod(path, mode)


def generate_keypair(
    directory: Path,
    passphrase: str,
) -> KeyPaths:
    """
    Generate an Ed25519 keypair.

    The private key is encrypted using PKCS#8.
    The public key is exported as 64 hexadecimal characters.

    Existing keys are never overwritten.
    """

    password = _validate_passphrase(passphrase)

    directory = Path(directory)

    _prepare_identity_directory(directory)

    private_path = directory / "ed25519_private.pem"
    public_path = directory / "ed25519_public.hex"

    if private_path.exists() or public_path.exists():
        raise IdentityError(
            "An identity already exists in this directory. "
            "Refusing to overwrite existing keys."
        )

    private_key = Ed25519PrivateKey.generate()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(
            password
        ),
    )

    public_raw = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    public_hex = public_raw.hex().encode("ascii") + b"\n"

    private_created = False

    try:
        _write_new_file(
            private_path,
            private_pem,
            0o600,
        )

        private_created = True

        _write_new_file(
            public_path,
            public_hex,
            0o644,
        )

    except Exception:
        if private_created:
            private_path.unlink(missing_ok=True)
        raise

    return KeyPaths(
        private_key=private_path,
        public_key=public_path,
    )


def load_private_key(
    path: Path,
    passphrase: str,
) -> Ed25519PrivateKey:
    """
    Load an encrypted Ed25519 private key.
    """

    password = _validate_passphrase(passphrase)

    try:
        private_key = serialization.load_pem_private_key(
            Path(path).read_bytes(),
            password=password,
        )

    except (ValueError, TypeError) as exc:
        raise IdentityError(
            "Unable to load private key. "
            "Check the passphrase and key format."
        ) from exc

    if not isinstance(private_key, Ed25519PrivateKey):
        raise IdentityError(
            "The provided key is not an Ed25519 private key."
        )

    return private_key


def load_public_key(path: Path) -> Ed25519PublicKey:
    """
    Load an Ed25519 public key from hexadecimal format.
    """

    try:
        public_hex = Path(path).read_text(
            encoding="ascii"
        ).strip()

        public_raw = bytes.fromhex(public_hex)

    except (OSError, UnicodeError, ValueError) as exc:
        raise IdentityError(
            "Unable to read public key."
        ) from exc

    if len(public_raw) != ED25519_PUBLIC_KEY_SIZE:
        raise IdentityError(
            "Invalid Ed25519 public key size. Expected 32 bytes."
        )

    return Ed25519PublicKey.from_public_bytes(public_raw)


def sign_bytes(
    private_key: Ed25519PrivateKey,
    message: bytes,
) -> bytes:
    """
    Sign an exact sequence of bytes using Ed25519.
    """

    if not isinstance(message, bytes):
        raise TypeError("Message must be bytes.")

    return private_key.sign(message)


def verify_bytes(
    public_key: Ed25519PublicKey,
    message: bytes,
    signature: bytes,
) -> bool:
    """
    Verify an Ed25519 signature.

    Returns False if the signature is invalid.
    """

    if not isinstance(message, bytes):
        raise TypeError("Message must be bytes.")

    if not isinstance(signature, bytes):
        raise TypeError("Signature must be bytes.")

    if len(signature) != ED25519_SIGNATURE_SIZE:
        return False

    try:
        public_key.verify(signature, message)
        return True

    except InvalidSignature:
        return False


def _generate_command(args: argparse.Namespace) -> int:
    passphrase = getpass.getpass("Choose a passphrase: ")
    confirmation = getpass.getpass("Confirm passphrase: ")

    if passphrase != confirmation:
        print("Passphrases do not match.", file=sys.stderr)
        return 1

    paths = generate_keypair(
        directory=args.directory,
        passphrase=passphrase,
    )

    print("\nEd25519 identity generated successfully.\n")

    print(f"Private key: {paths.private_key}")
    print(f"Public key:  {paths.public_key}")

    print("\nPublic key:")

    print(
        paths.public_key.read_text(
            encoding="ascii"
        ).strip()
    )

    print(
        "\nKeep your private key and passphrase secret."
    )

    return 0


def _sign_command(args: argparse.Namespace) -> int:
    passphrase = getpass.getpass("Private key passphrase: ")

    private_key = load_private_key(
        args.private_key,
        passphrase,
    )

    message = args.input.read_bytes()

    signature = sign_bytes(
        private_key,
        message,
    )

    _write_new_file(
        args.signature_out,
        signature.hex().encode("ascii") + b"\n",
        0o644,
    )

    print(f"Signature saved to: {args.signature_out}")

    return 0


def _verify_command(args: argparse.Namespace) -> int:
    public_key = load_public_key(args.public_key)

    message = args.input.read_bytes()

    try:
        signature_hex = args.signature.read_text(
            encoding="ascii"
        ).strip()

        signature = bytes.fromhex(signature_hex)

    except (OSError, UnicodeError, ValueError) as exc:
        raise IdentityError(
            "Unable to read signature."
        ) from exc

    if verify_bytes(public_key, message, signature):
        print("Signature is VALID.")
        return 0

    print("Signature is INVALID.")
    return 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="RELIC Ed25519 identity utility"
    )

    commands = parser.add_subparsers(
        dest="command",
        required=True,
    )

    generate = commands.add_parser(
        "generate",
        help="Generate an Ed25519 identity",
    )

    generate.add_argument(
        "--directory",
        type=Path,
        default=DEFAULT_IDENTITY_DIR,
    )

    generate.set_defaults(handler=_generate_command)

    sign = commands.add_parser(
        "sign",
        help="Sign the exact bytes of a file",
    )

    sign.add_argument(
        "--private-key",
        type=Path,
        required=True,
    )

    sign.add_argument(
        "--input",
        type=Path,
        required=True,
    )

    sign.add_argument(
        "--signature-out",
        type=Path,
        required=True,
    )

    sign.set_defaults(handler=_sign_command)

    verify = commands.add_parser(
        "verify",
        help="Verify a file signature",
    )

    verify.add_argument(
        "--public-key",
        type=Path,
        required=True,
    )

    verify.add_argument(
        "--input",
        type=Path,
        required=True,
    )

    verify.add_argument(
        "--signature",
        type=Path,
        required=True,
    )

    verify.set_defaults(handler=_verify_command)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    try:
        return args.handler(args)

    except (IdentityError, OSError, FileExistsError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
