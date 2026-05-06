import { useMemo, useState } from "react";
import {
  derSignatureHexToRawP256Hex,
  generateP256KeyPair,
  importP256PrivateKeyFromPkcs8Hex,
  importP256PublicKeyFromSpkiHex,
  rawP256SignatureHexToDerHex,
  type SignatureFormat,
  signP256Sha256,
  verifyP256Sha256
} from "./crypto/ecdsa";
import { sha256Hex } from "./crypto/sha256";

type Status = {
  type: "idle" | "success" | "error" | "result";
  message: string;
};

const idleStatus: Status = { type: "idle", message: "" };

function getErrorMessage(error: unknown): string {
  return error instanceof Error ? error.message : "Unexpected error.";
}

export default function App() {
  const [hashInput, setHashInput] = useState("abc");
  const [hashOutput, setHashOutput] = useState("");
  const [hashStatus, setHashStatus] = useState<Status>(idleStatus);

  const [publicKey, setPublicKey] = useState<CryptoKey | null>(null);
  const [privateKey, setPrivateKey] = useState<CryptoKey | null>(null);
  const [publicKeyHex, setPublicKeyHex] = useState("");
  const [privateKeyHex, setPrivateKeyHex] = useState("");
  const [keyStatus, setKeyStatus] = useState<Status>(idleStatus);

  const [signMessage, setSignMessage] = useState("hello world");
  const [signatureHex, setSignatureHex] = useState("");
  const [signStatus, setSignStatus] = useState<Status>(idleStatus);

  const [verifyMessage, setVerifyMessage] = useState("hello world");
  const [verifyStatus, setVerifyStatus] = useState<Status>(idleStatus);
  const [signatureFormat, setSignatureFormat] = useState<SignatureFormat>("raw");

  const [importPublicHex, setImportPublicHex] = useState("");
  const [importPrivateHex, setImportPrivateHex] = useState("");
  const [importStatus, setImportStatus] = useState<Status>(idleStatus);

  const cryptoAvailable = useMemo(() => Boolean(globalThis.crypto?.subtle), []);

  async function handleHash() {
    try {
      setHashOutput(await sha256Hex(hashInput));
      setHashStatus({ type: "success", message: "Hash computed." });
    } catch (error) {
      setHashStatus({ type: "error", message: getErrorMessage(error) });
    }
  }

  async function handleGenerateKeys() {
    try {
      const keypair = await generateP256KeyPair();
      setPublicKey(keypair.publicKey);
      setPrivateKey(keypair.privateKey);
      setPublicKeyHex(keypair.publicKeyHex);
      setPrivateKeyHex(keypair.privateKeyHex);
      setKeyStatus({ type: "success", message: "P-256 keypair generated." });
    } catch (error) {
      setKeyStatus({ type: "error", message: getErrorMessage(error) });
    }
  }

  async function handleImportPublicKey() {
    try {
      const importedPublicKey = await importP256PublicKeyFromSpkiHex(importPublicHex);
      const normalized = importPublicHex.trim().replace(/\s+/g, "").toLowerCase();
      setPublicKey(importedPublicKey);
      setPublicKeyHex(normalized);
      setImportPublicHex(normalized);
      setImportStatus({ type: "success", message: "Public key imported for verification." });
    } catch (error) {
      setImportStatus({ type: "error", message: getErrorMessage(error) });
    }
  }

  async function handleImportPrivateKey() {
    try {
      const importedPrivateKey = await importP256PrivateKeyFromPkcs8Hex(importPrivateHex);
      const normalized = importPrivateHex.trim().replace(/\s+/g, "").toLowerCase();
      setPrivateKey(importedPrivateKey);
      setPrivateKeyHex(normalized);
      setImportPrivateHex(normalized);
      setImportStatus({ type: "success", message: "Private key imported for signing." });
    } catch (error) {
      setImportStatus({ type: "error", message: getErrorMessage(error) });
    }
  }

  async function handleSign() {
    if (!privateKey) {
      setSignStatus({ type: "error", message: "Generate or import a private key before signing." });
      return;
    }

    try {
      const rawSignature = await signP256Sha256(privateKey, signMessage);
      setSignatureHex(formatSignatureForDisplay(rawSignature, signatureFormat));
      setVerifyMessage(signMessage);
      setSignStatus({ type: "success", message: "Message signed." });
    } catch (error) {
      setSignStatus({ type: "error", message: getErrorMessage(error) });
    }
  }

  async function handleVerify() {
    if (!publicKeyHex.trim()) {
      setVerifyStatus({ type: "error", message: "Provide a public key before verification." });
      return;
    }

    if (!signatureHex.trim()) {
      setVerifyStatus({ type: "error", message: `Provide a ${signatureFormatLabel(signatureFormat)} signature before verification.` });
      return;
    }

    try {
      const keyForVerification = publicKey ?? (await importP256PublicKeyFromSpkiHex(publicKeyHex));
      const valid = await verifyP256Sha256(keyForVerification, verifyMessage, signatureHex, signatureFormat);
      setPublicKey(keyForVerification);
      setVerifyStatus({
        type: "result",
        message: valid ? "Valid signature." : "Invalid signature."
      });
    } catch (error) {
      setVerifyStatus({ type: "error", message: getErrorMessage(error) });
    }
  }

  function handleSignatureFormatChange(nextFormat: SignatureFormat) {
    if (nextFormat === signatureFormat) {
      return;
    }

    try {
      setSignatureHex(convertSignatureFormat(signatureHex, signatureFormat, nextFormat));
      setSignatureFormat(nextFormat);
      setVerifyStatus(idleStatus);
    } catch (error) {
      setSignatureFormat(nextFormat);
      setVerifyStatus({
        type: "error",
        message: `Signature format changed, but the existing signature could not be converted: ${getErrorMessage(error)}`
      });
    }
  }

  return (
    <main className="app-shell">
      <header className="page-header">
        <div>
          <p className="eyebrow">Local Web Crypto PoC</p>
          <h1>SHA-256 Hashing and ECDSA P-256</h1>
        </div>
      </header>

      {!cryptoAvailable ? (
        <section className="notice error" role="alert">
          This browser does not support the Web Crypto API required by this app.
        </section>
      ) : null}

      <section className="panel" aria-labelledby="hash-title">
        <div className="section-heading">
          <h2 id="hash-title">SHA-256 Hashing</h2>
          <button type="button" onClick={handleHash} disabled={!cryptoAvailable}>
            Hash
          </button>
        </div>
        <label htmlFor="hash-input">Plain text</label>
        <textarea id="hash-input" value={hashInput} onChange={(event) => setHashInput(event.target.value)} />
        <label htmlFor="hash-output">Lowercase HEX digest</label>
        <textarea id="hash-output" readOnly value={hashOutput} className="hex-output" />
        <StatusMessage status={hashStatus} />
      </section>

      <section className="panel" aria-labelledby="ecdsa-title">
        <div className="section-heading">
          <h2 id="ecdsa-title">ECDSA P-256</h2>
          <button type="button" onClick={handleGenerateKeys} disabled={!cryptoAvailable}>
            Generate Keypair
          </button>
        </div>

        <div className="grid two-columns">
          <div>
            <label htmlFor="public-key">Public key SPKI DER HEX</label>
            <textarea
              id="public-key"
              value={publicKeyHex}
              onChange={(event) => {
                setPublicKeyHex(event.target.value);
                setPublicKey(null);
              }}
              className="hex-output tall"
            />
          </div>
          <div>
            <label htmlFor="private-key">Private key PKCS#8 DER HEX</label>
            <textarea id="private-key" readOnly value={privateKeyHex} className="hex-output tall" />
          </div>
        </div>
        <StatusMessage status={keyStatus} />

        <div className="format-control">
          <label htmlFor="signature-format">Signature format</label>
          <select
            id="signature-format"
            value={signatureFormat}
            onChange={(event) => handleSignatureFormatChange(event.target.value as SignatureFormat)}
          >
            <option value="raw">Raw r||s HEX</option>
            <option value="der">DER HEX</option>
          </select>
        </div>

        <div className="workflow">
          <div>
            <h3>Sign</h3>
            <label htmlFor="sign-message">Message</label>
            <textarea id="sign-message" value={signMessage} onChange={(event) => setSignMessage(event.target.value)} />
            <button type="button" onClick={handleSign} disabled={!cryptoAvailable}>
              Sign
            </button>
            <StatusMessage status={signStatus} />
          </div>

          <div>
            <h3>Verify</h3>
            <label htmlFor="verify-message">Message</label>
            <textarea
              id="verify-message"
              value={verifyMessage}
              onChange={(event) => setVerifyMessage(event.target.value)}
            />
            <label htmlFor="signature">{signatureFormatLabel(signatureFormat)} signature</label>
            <textarea
              id="signature"
              value={signatureHex}
              onChange={(event) => setSignatureHex(event.target.value)}
              className="hex-output"
            />
            <button type="button" onClick={handleVerify} disabled={!cryptoAvailable}>
              Verify
            </button>
            <StatusMessage status={verifyStatus} />
          </div>
        </div>

        <div className="secondary-panel" aria-labelledby="import-title">
          <h3 id="import-title">Reviewer Import</h3>
          <div className="grid two-columns">
            <div>
              <label htmlFor="import-public">Import public key SPKI DER HEX</label>
              <textarea
                id="import-public"
                value={importPublicHex}
                onChange={(event) => setImportPublicHex(event.target.value)}
                className="hex-output"
              />
              <button type="button" onClick={handleImportPublicKey} disabled={!cryptoAvailable}>
                Import Public Key
              </button>
            </div>
            <div>
              <label htmlFor="import-private">Import private key PKCS#8 DER HEX</label>
              <textarea
                id="import-private"
                value={importPrivateHex}
                onChange={(event) => setImportPrivateHex(event.target.value)}
                className="hex-output"
              />
              <button type="button" onClick={handleImportPrivateKey} disabled={!cryptoAvailable}>
                Import Private Key
              </button>
            </div>
          </div>
          <StatusMessage status={importStatus} />
        </div>
      </section>
    </main>
  );
}

function formatSignatureForDisplay(rawSignatureHex: string, signatureFormat: SignatureFormat): string {
  return signatureFormat === "der" ? rawP256SignatureHexToDerHex(rawSignatureHex) : rawSignatureHex;
}

function convertSignatureFormat(
  signatureHex: string,
  currentFormat: SignatureFormat,
  nextFormat: SignatureFormat
): string {
  if (!signatureHex.trim() || currentFormat === nextFormat) {
    return signatureHex;
  }
  return nextFormat === "der" ? rawP256SignatureHexToDerHex(signatureHex) : derSignatureHexToRawP256Hex(signatureHex);
}

function signatureFormatLabel(signatureFormat: SignatureFormat): string {
  return signatureFormat === "der" ? "DER HEX" : "Raw r||s HEX";
}

function StatusMessage({ status }: { status: Status }) {
  if (!status.message) {
    return null;
  }

  return (
    <p className={`status ${status.type}`} role={status.type === "error" ? "alert" : "status"}>
      {status.message}
    </p>
  );
}
