# Verification

This document records the verification work for the implemented local web app.

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

`app/settings.example.json` contains a non-secret sample P-256 keypair and signature for copy/paste verification. Key import was originally listed as an optional stretch goal in the brief and is included in this implementation.

- Message: `hello world`
- Private key format: PKCS#8 DER HEX
- Public key format: SPKI DER HEX
- Signature formats: raw ECDSA `r || s` HEX in the fixture; DER HEX can be derived from the raw signature and verified through the app's DER mode.
- Expected verification result: Valid

The signature is a fixed sample generated from the included private key. Future signatures for the same message may differ because ECDSA signing is randomized.

## Automated Test Scenarios

Automated tests cover:

- `sha256Hex("")` returns the empty-string SHA-256 vector.
- `sha256Hex("abc")` returns the standard `abc` SHA-256 vector.
- HEX parser accepts uppercase or lowercase HEX and normalizes output to lowercase.
- HEX parser rejects odd-length strings and non-HEX characters.
- P-256 key generation exports non-empty PKCS#8 private key HEX and SPKI public key HEX.
- Imported sample private key can sign `hello world`.
- Imported sample public key verifies the sample `hello world` signature.
- Raw P-256 signatures convert to DER HEX and back.
- DER signatures with positive integer padding convert to raw P-256 HEX.
- DER-format signatures verify when DER mode is selected.
- Verification fails when the message is changed to `hello world!`.
- Verification fails when one byte of the signature is changed.
- Verification fails when the signature is checked with a different generated public key.

Executed command:

```bash
cd app
npm test
```

Result on 2026-05-04:

```text
Test Files  3 passed (3)
Tests       11 passed (11)
```

Result on 2026-05-06 after adding DER/raw signature format support:

```text
Test Files  3 passed (3)
Tests       14 passed (14)
```

Production build check:

```bash
cd app
npm run build
```

Result on 2026-05-04:

```text
✓ 32 modules transformed.
✓ built in 358ms
```

Result on 2026-05-06 after adding DER/raw signature format support:

```text
✓ 32 modules transformed.
✓ built in 331ms
```

## Manual Crypto Flow Verification

Run these checks in a browser after starting the local app from the README.

Manual browser used on 2026-05-03:

```text
HeadlessChrome/147.0.0.0 on macOS, driven by Playwright CLI
Local URL: http://127.0.0.1:5173/
```

1. Hash `abc`.
   - Expected: `ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad`.
   - Result: Pass.

2. Hash an empty input.
   - Expected: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.
   - Result: Covered by automated test.

3. Generate a P-256 keypair.
   - Expected: public key and private key fields contain lowercase HEX.
   - Result: Pass.

4. Sign `hello world` with the generated private key.
   - Expected: signature field contains 128 lowercase HEX characters.
   - Result: Pass.

5. Verify the generated signature against `hello world` and the matching public key.
   - Expected: Valid.
   - Result: Pass.

6. Change the verify message to `hello world!` without changing the signature.
   - Expected: Invalid signature.
   - Result: Pass.

7. Paste the sample message, public key, and signature from `app/settings.example.json`.
   - Expected: Valid.
   - Result: Pass.

8. Change one HEX character in the pasted signature.
   - Expected: Invalid signature or validation error, depending on whether the modified signature remains valid HEX.
   - Result: Covered by automated test.

9. Paste invalid HEX into a key field, such as `xyz`.
   - Expected: clear validation error before import.
   - Result: Pass with `HEX input contains non-HEX characters.`

10. Select DER signature format, sign `hello world`, and verify without changing the message.
    - Expected: Valid.
    - Result: Pass in Codex in-app browser on 2026-05-06.

11. Paste a DER ECDSA P-256/SHA-256 signature and select DER signature format.
    - Expected: Valid when the public key and message match.
    - Result: Pass using the DER-encoded fixture signature in Codex in-app browser on 2026-05-06.

## Manual UI Usability Verification

Run these checks during the same browser walkthrough:

1. Confirm the page has separate SHA-256 and ECDSA P-256 sections.
   - Expected: the two workflows are easy to distinguish.
   - Result: Pass.

2. Confirm action buttons are explicit.
   - Expected: visible controls for `Hash`, `Generate Keypair`, `Sign`, and `Verify`.
   - Result: Pass.

3. Confirm outputs are selectable text.
   - Expected: hash, key, and signature HEX can be selected/copied from the page.
   - Result: Pass; outputs are text areas.

4. Confirm long HEX outputs do not break the layout.
   - Expected: long values wrap or scroll within their output areas.
   - Result: Pass in desktop browser smoke test.

5. Trigger at least one validation error, such as signing before generating a keypair.
   - Expected: the error appears near the relevant action.
   - Result: Pass for invalid reviewer HEX import.

6. Resize to a normal laptop-width browser window.
   - Expected: the app remains usable without overlapping controls or unreadable output.
   - Result: Pass in default Playwright desktop viewport.

## Evidence to Record After Implementation

Additional checks on 2026-05-03:

- Browser console errors after smoke test: 0.
- localStorage entries after smoke test: none.
- sessionStorage entries after smoke test: none.
- Screenshot artifact captured during verification: `.playwright-cli/page-2026-05-03T14-42-58-443Z.png` (ignored by git).

Known limitations:

- ECDSA signatures are intentionally randomized by Web Crypto, so generated signatures are verified by behavior rather than deterministic byte equality.
- DER signature support is an interoperability layer; Web Crypto still signs and verifies raw `r || s` internally.
