# Functional Requirements

## Scope

The application is a local-only web proof of concept for SHA-256 hashing and ECDSA P-256 signing/verification. It must run without any cloud service, backend service, external account, or network dependency after dependencies are installed.

## SHA-256 Hashing

- User can enter plain text in a text input area.
- User can compute the SHA-256 digest of the exact entered text encoded as UTF-8.
- App displays the digest as lowercase HEX.
- App displays a clear validation or error message if hashing cannot be performed.

Acceptance criteria:

- Given input `abc`, output must equal `ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad`.
- Given empty input, output must equal `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.
- Hash output must always be 64 lowercase HEX characters.

## ECDSA P-256 Key Management

- User can generate an ECDSA P-256 keypair in the browser.
- App displays the generated public key as SPKI DER HEX.
- App displays the generated private key as PKCS#8 DER HEX for assignment transparency.

Acceptance criteria:

- After generating a keypair, both public and private key fields are populated with lowercase HEX.

## ECDSA P-256 Signing

- User can enter a message to sign.
- User can sign the message with the current private key using ECDSA P-256 with SHA-256.
- App displays the signature as raw ECDSA `r || s` HEX.
- App displays a clear error when signing is requested without a private key.

Acceptance criteria:

- A valid sign operation produces a 128-character lowercase HEX signature.
- Signing the same message more than once may produce different signatures because ECDSA signing is randomized.
- The app does not require a deterministic ECDSA signature vector.

## ECDSA P-256 Verification

- User can enter a message, public key, and signature.
- User can verify a raw ECDSA `r || s` signature with the generated public key.
- App displays whether verification succeeded or failed.
- App displays a clear error when verification is requested without a public key or valid signature.

Acceptance criteria:

- A signature created by the app verifies successfully against the same message and matching public key.
- The same signature fails verification if the message changes.
- The same signature fails verification if any signature byte changes.
- The same signature fails verification with a mismatched public key.

## User Interface

- App provides a simple single-page UI with separate SHA-256 and ECDSA P-256 sections.
- Each section shows its inputs, action buttons, outputs, and status/error messages clearly.
- Crypto actions are explicit and user-triggered: `Hash`, `Generate Keypair`, `Sign`, and `Verify`.
- HEX outputs are visible as selectable text so users can copy them for verification.
- The UI is usable in a normal desktop browser window.
- Optional reviewer test/import controls, if implemented, are visually secondary to the core hash/generate/sign/verify flow.

Acceptance criteria:

- User can complete the SHA-256 flow without interacting with ECDSA controls.
- User can complete the ECDSA generate/sign/verify flow without interacting with SHA-256 controls.
- Status and error messages appear close to the action that produced them.
- Long HEX values remain readable and do not break the page layout.

## Optional Reviewer Test Support

- Copy/paste key import may be included as an optional stretch feature so reviewers can test other keys.
- If included, user can paste/import a public key as SPKI DER HEX.
- If included, user can paste/import a private key as PKCS#8 DER HEX.
- If included, imported keys are used only in the local browser session.
- If included, invalid HEX input is rejected before cryptographic import is attempted.
- If included, valid HEX with unsupported or malformed key data produces a clear import failure message.
- The repository includes `app/settings.example.json` as an optional non-secret fixture that reviewers can use for copy/paste verification.
