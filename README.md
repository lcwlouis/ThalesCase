# ThalesCase

Local-only web proof of concept for:

1. SHA-256 hashing of UTF-8 plain text, displayed as lowercase HEX.
2. ECDSA P-256 key generation, signing, and verification, with keys and signatures displayed as lowercase HEX.

The implementation is in `app/` and uses Vite, React, TypeScript, Vitest, and the browser Web Crypto API. It does not require a backend, database, account, cloud service, or network service at runtime.

## Setup

From the repository root:

```bash
cd app
npm install
```

## Run Locally

```bash
cd app
npm run dev
```

Open the local URL printed by Vite, usually:

```text
http://localhost:5173/
```

For a production build:

```bash
cd app
npm run build
npm run preview
```

## Run Tests

```bash
cd app
npm test
```

The automated tests cover SHA-256 known vectors, HEX validation, P-256 key generation/export, raw/DER signature conversion, signing, verification failure cases, and the fixture in `app/settings.example.json`.

## How To Use The UI

### SHA-256

1. Enter text in the SHA-256 plain-text field.
2. Click `Hash`.
3. Copy the lowercase HEX digest from the output field.

Known values:

- Empty input: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`
- `abc`: `ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad`

### ECDSA P-256

1. Click `Generate Keypair`.
2. The public key appears as SPKI DER HEX.
3. The private key appears as PKCS#8 DER HEX for assignment transparency.
4. Enter a message and click `Sign`.
5. Choose a signature format: raw ECDSA `r || s` HEX or DER HEX.
6. The signature appears in the selected HEX format.
7. Click `Verify` to verify the signature against the message and public key.
8. Change the verify message or signature to confirm verification returns `Invalid signature`.

### Reviewer Import

Use the `Reviewer Import` controls to paste external or fixture keys:

- Public key import expects P-256 SPKI DER HEX.
- Private key import expects P-256 PKCS#8 DER HEX.
- Invalid HEX is rejected before Web Crypto import runs.

`app/settings.example.json` contains non-secret sample values for copy/paste verification. These values are local fixtures only and should not be treated as confidential key material.

## Local ECDSA Verification Helper

Use `tools/ecdsa_p256_tool.py` to verify P-256 signatures locally instead of pasting private keys into online tools.

Convert a DER signature HEX to raw `r || s` HEX if you want to use the app's raw mode:

```bash
python3 tools/ecdsa_p256_tool.py der-to-raw 3045022018e35c212f695e8c2b2b41c521e681d06bf26a5720942be7447ece47863eb29f022100c1341fb738065b620fb4f89b5be40703e9862cc6b79daeb0ccab0dccb0d27f71
```

Convert PEM keys to the DER HEX formats expected by the app:

```bash
python3 tools/ecdsa_p256_tool.py pem-to-hex --kind public --pem-file public.pem
python3 tools/ecdsa_p256_tool.py pem-to-hex --kind private --pem-file private.pem
```

Verify a raw app signature:

```bash
python3 tools/ecdsa_p256_tool.py verify --public-key-hex <spki-der-hex> --message "hello world" --signature-hex <raw-rs-hex> --signature-format raw
```

Verify an online-tool DER signature directly:

```bash
python3 tools/ecdsa_p256_tool.py verify --public-key-hex <spki-der-hex> --message "hello world" --signature-hex <der-signature-hex> --signature-format der
```

## Security Notes

- Crypto operations run locally in the browser through Web Crypto.
- The app does not send messages, keys, hashes, or signatures to any service.
- Keys are kept in browser memory for the current session only.
- The app does not write keys to localStorage, sessionStorage, IndexedDB, cookies, or files.
