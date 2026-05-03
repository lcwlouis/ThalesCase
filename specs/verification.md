# Verification Plan

This document defines the verification work to run after implementation. Pre-build status: not executed because the app source has not been created yet.

## SHA-256 Known Vectors

Vector 1:

- Input: empty string
- Expected lowercase HEX: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`
- Required result after implementation: Pass

Vector 2:

- Input: `abc`
- Expected lowercase HEX: `ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad`
- Required result after implementation: Pass

## ECDSA Sample Fixture

`app/settings.example.json` contains an optional, non-secret sample P-256 keypair and signature for copy/paste verification if the optional import flow is implemented.

- Message: `hello world`
- Private key format: PKCS#8 DER HEX
- Public key format: SPKI DER HEX
- Signature format: raw ECDSA `r || s` HEX
- Expected verification result: Valid

The signature is a fixed sample generated from the included private key. Future signatures for the same message may differ because ECDSA signing is randomized.

## Automated Test Scenarios

If automated tests are included, they should cover:

- `sha256Hex("")` returns the empty-string SHA-256 vector.
- `sha256Hex("abc")` returns the standard `abc` SHA-256 vector.
- HEX parser accepts uppercase or lowercase HEX and normalizes output to lowercase.
- HEX parser rejects odd-length strings and non-HEX characters.
- P-256 key generation exports non-empty PKCS#8 private key HEX and SPKI public key HEX.
- Optional import path: imported sample private key can sign `hello world`.
- Optional import path: imported sample public key verifies the sample `hello world` signature.
- Verification fails when the message is changed to `hello world!`.
- Verification fails when one byte of the signature is changed.
- Verification fails when the signature is checked with a different generated public key.

## Manual Crypto Flow Verification

Run these checks in a browser after starting the local app from the README.

1. Hash `abc`.
   - Expected: `ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad`.

2. Hash an empty input.
   - Expected: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.

3. Generate a P-256 keypair.
   - Expected: public key and private key fields contain lowercase HEX.

4. Sign `hello world` with the generated private key.
   - Expected: signature field contains 128 lowercase HEX characters.

5. Verify the generated signature against `hello world` and the matching public key.
   - Expected: Valid.

6. Change the verify message to `hello world!` without changing the signature.
   - Expected: Invalid signature.

7. If optional copy/paste import is implemented, paste the sample message, public key, and signature from `app/settings.example.json`.
   - Expected: Valid.

8. If optional copy/paste import is implemented, change one HEX character in the pasted signature.
   - Expected: Invalid signature or validation error, depending on whether the modified signature remains valid HEX.

9. If optional copy/paste import is implemented, paste invalid HEX into a key field, such as `xyz`.
   - Expected: clear validation error before import.

## Manual UI Usability Verification

Run these checks during the same browser walkthrough:

1. Confirm the page has separate SHA-256 and ECDSA P-256 sections.
   - Expected: the two workflows are easy to distinguish.

2. Confirm action buttons are explicit.
   - Expected: visible controls for `Hash`, `Generate Keypair`, `Sign`, and `Verify`.

3. Confirm outputs are selectable text.
   - Expected: hash, key, and signature HEX can be selected/copied from the page.

4. Confirm long HEX outputs do not break the layout.
   - Expected: long values wrap or scroll within their output areas.

5. Trigger at least one validation error, such as signing before generating a keypair.
   - Expected: the error appears near the relevant action.

6. Resize to a normal laptop-width browser window.
   - Expected: the app remains usable without overlapping controls or unreadable output.

## Evidence to Record After Implementation

After implementation, update this document with:

- The exact test command that was run.
- The test result summary.
- The browser and version used for manual verification.
- Any known limitations or deviations from this plan.
