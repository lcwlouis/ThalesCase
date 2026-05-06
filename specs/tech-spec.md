# Technical Specification

## Application Stack

- Frontend: Vite, React, TypeScript.
- Cryptography: Browser Web Crypto API.
- Tests: Vitest for unit tests and browser-compatible crypto behavior.
- Runtime: local static page or local Vite dev server. No backend or cloud service is required.

## Architecture

The app will keep crypto behavior in small, testable TypeScript modules and keep React components focused on UI state and user actions.

- Hashing module: accepts strings, encodes them with `TextEncoder`, computes SHA-256, and returns lowercase HEX.
- HEX module: converts `ArrayBuffer`/`Uint8Array` to lowercase HEX and validates/parses pasted HEX.
- ECDSA module: generates, imports, exports, signs, verifies, and converts P-256 signatures between raw `r || s` and DER HEX.
- Reviewer fixture: committed non-secret sample values for manual copy/paste verification.
- UI layer: provides text inputs, key fields, signature field, action buttons, and success/error messages.

## UI Design

- Build a single-page React UI; routing is not needed.
- Use two primary sections: SHA-256 Hashing and ECDSA P-256.
- Keep controls explicit and close to their outputs: hash input/button/output together; key generation, signing, and verification controls grouped in the ECDSA section.
- Show validation and operation results inline near the related control.
- Render long HEX values in selectable, wrapped text areas or preformatted blocks so users can copy them and the layout remains stable.
- Place reviewer import controls after or below the generated-key flow so the required assignment path remains the primary path.
- Do not add visual polish that changes the scope, such as animations, routing, dashboards, persistence, or multi-screen workflows.

## Cryptographic Decisions

- SHA-256 input encoding: UTF-8 via `TextEncoder`.
- SHA-256 output format: 32-byte digest displayed as 64 lowercase HEX characters.
- ECDSA algorithm: P-256 with SHA-256.
- Private key display format: PKCS#8 DER HEX.
- Public key display format: SPKI DER HEX.
- Signature display formats: raw ECDSA `r || s` HEX and ASN.1 DER signature HEX.
- Web Crypto signs and verifies raw `r || s` signatures internally; DER support is implemented as conversion at the UI/input boundary for external tool interoperability.
- ECDSA signing is expected to be randomized. Verification behavior, not byte-for-byte signature equality, is the stable acceptance target.

## Key Import and Reviewer Fixture

The core assignment requires key generation, signing, verification, and HEX display. The brief listed key export/import as an optional stretch goal; this implementation includes copy/paste import for reviewer-provided key material.

- Private key import uses `crypto.subtle.importKey("pkcs8", ..., { name: "ECDSA", namedCurve: "P-256" }, true, ["sign"])`.
- Public key import uses `crypto.subtle.importKey("spki", ..., { name: "ECDSA", namedCurve: "P-256" }, true, ["verify"])`.
- Generated keys are exported with `crypto.subtle.exportKey("pkcs8", privateKey)` and `crypto.subtle.exportKey("spki", publicKey)`.

The repository includes `app/settings.example.json` as a committed test fixture. It is not a secret store. It exists so a reviewer can request testing against a specific key, message, or signature.

The repo may ignore local `.env*` files for safety, but Vite exposes frontend environment variables with the `VITE_` prefix to browser JavaScript. Any private key placed in frontend settings or `.env` must be documented as visible test data, not confidential secret material.

## Error Handling

- Unsupported Web Crypto: show a blocking error explaining that the browser does not support required crypto APIs.
- Invalid HEX: reject invalid pasted values before cryptographic operations and identify the field with invalid input.
- Invalid key import: show a clear message that the key must be P-256 in the documented DER HEX format.
- Invalid DER signature: show a clear message that the DER signature cannot be parsed as an ECDSA P-256 signature.
- Missing private key on sign: ask the user to generate a keypair or paste a private key.
- Missing public key or signature on verify: ask the user to provide the missing value.
- Verification failure is not an exception state; display it as a valid `Invalid signature` result.

## Security and Privacy Notes

- The app is local-only and does not send key material, messages, hashes, or signatures to any service.
- Keys are kept in browser memory for the current session only.
- Displaying generated private keys is acceptable for this assignment because the app is a local cryptography PoC.
- Pasted private keys are local test fixtures and not confidential secret material.
- The app must not persist private keys to local storage, session storage, IndexedDB, cookies, or files in v1.

## Implementation Constraints

- Keep cryptographic operations in browser-compatible TypeScript; do not use Node-only crypto APIs in app code.
- Keep outputs lowercase and whitespace-free.
- Treat pasted HEX case-insensitively during parsing, then normalize displayed values to lowercase.
- Do not add backend services, database storage, authentication, or cloud dependencies.
