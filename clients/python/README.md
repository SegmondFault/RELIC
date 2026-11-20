# RELIC Python Identity Utility

A local Ed25519 identity management utility for RELIC analysts.

## Features

- Generate Ed25519 keypairs.
- Encrypt private keys using PKCS#8.
- Export public keys as hexadecimal strings.
- Sign exact byte sequences.
- Verify Ed25519 signatures.
- Prevent accidental key overwrites.

## Requirements

- Python 3.9+
- cryptography

## Installation

From the RELIC repository root:

```bash
python3 -m venv .venv
source .venv/bin/activate

python -m pip install --upgrade pip
python -m pip install -r clients/python/requirements.txt
