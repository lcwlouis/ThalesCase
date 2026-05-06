import { describe, expect, it } from "vitest";
import fixture from "../../settings.example.json";
import {
  derSignatureHexToRawP256Hex,
  generateP256KeyPair,
  importP256PrivateKeyFromPkcs8Hex,
  importP256PublicKeyFromSpkiHex,
  rawP256SignatureHexToDerHex,
  signP256Sha256,
  verifyP256Sha256
} from "./ecdsa";

const isLowerHex = (value: string) => /^[0-9a-f]+$/.test(value);

describe("ECDSA P-256 helpers", () => {
  it("generates exportable P-256 keys as lowercase DER HEX", async () => {
    const keypair = await generateP256KeyPair();

    expect(keypair.privateKeyHex.length).toBeGreaterThan(0);
    expect(keypair.publicKeyHex.length).toBeGreaterThan(0);
    expect(isLowerHex(keypair.privateKeyHex)).toBe(true);
    expect(isLowerHex(keypair.publicKeyHex)).toBe(true);
  });

  it("signs messages as 128-character raw r||s lowercase HEX", async () => {
    const keypair = await generateP256KeyPair();
    const signature = await signP256Sha256(keypair.privateKey, "hello world");

    expect(signature).toMatch(/^[0-9a-f]{128}$/);
  });

  it("converts raw P-256 signatures to DER HEX and back", () => {
    const rawSignature =
      "5a1bd1a580a0f4af434071f4336fc50811e18fae30651d67ab4fa97e43cfd768" +
      "4f8e7f2854ba13a2500a589838cc50079624118fc3cfb2dc3dbc94a4791624ea";

    const derSignature = rawP256SignatureHexToDerHex(rawSignature);

    expect(derSignature).toBe(
      "304402205a1bd1a580a0f4af434071f4336fc50811e18fae30651d67ab4fa97e43cfd768" +
        "02204f8e7f2854ba13a2500a589838cc50079624118fc3cfb2dc3dbc94a4791624ea"
    );
    expect(derSignatureHexToRawP256Hex(derSignature)).toBe(rawSignature);
  });

  it("converts DER signatures with positive integer padding to raw P-256 HEX", () => {
    const derSignature =
      "3045022018e35c212f695e8c2b2b41c521e681d06bf26a5720942be7447ece47863eb29f" +
      "022100c1341fb738065b620fb4f89b5be40703e9862cc6b79daeb0ccab0dccb0d27f71";

    expect(derSignatureHexToRawP256Hex(derSignature)).toBe(
      "18e35c212f695e8c2b2b41c521e681d06bf26a5720942be7447ece47863eb29f" +
        "c1341fb738065b620fb4f89b5be40703e9862cc6b79daeb0ccab0dccb0d27f71"
    );
  });

  it("verifies generated signatures and rejects changed messages, changed signatures, and mismatched keys", async () => {
    const keypair = await generateP256KeyPair();
    const mismatch = await generateP256KeyPair();
    const signature = await signP256Sha256(keypair.privateKey, "hello world");
    const tamperedSignature = `${signature.slice(0, -2)}${signature.endsWith("00") ? "01" : "00"}`;

    await expect(verifyP256Sha256(keypair.publicKey, "hello world", signature)).resolves.toBe(true);
    await expect(verifyP256Sha256(keypair.publicKey, "hello world!", signature)).resolves.toBe(false);
    await expect(verifyP256Sha256(keypair.publicKey, "hello world", tamperedSignature)).resolves.toBe(false);
    await expect(verifyP256Sha256(mismatch.publicKey, "hello world", signature)).resolves.toBe(false);
  });

  it("verifies fixture signatures supplied as DER HEX", async () => {
    const publicKey = await importP256PublicKeyFromSpkiHex(fixture.ecdsaP256.publicKeySpkiDerHex);
    const derSignature = rawP256SignatureHexToDerHex(fixture.ecdsaP256.signatureRawRsHex);

    await expect(verifyP256Sha256(publicKey, fixture.ecdsaP256.message, derSignature, "der")).resolves.toBe(true);
  });

  it("imports the fixture public key and verifies the fixture signature", async () => {
    const publicKey = await importP256PublicKeyFromSpkiHex(fixture.ecdsaP256.publicKeySpkiDerHex);

    await expect(
      verifyP256Sha256(publicKey, fixture.ecdsaP256.message, fixture.ecdsaP256.signatureRawRsHex)
    ).resolves.toBe(true);
  });

  it("imports the fixture private key and signs the fixture message", async () => {
    const privateKey = await importP256PrivateKeyFromPkcs8Hex(fixture.ecdsaP256.privateKeyPkcs8DerHex);
    const publicKey = await importP256PublicKeyFromSpkiHex(fixture.ecdsaP256.publicKeySpkiDerHex);
    const signature = await signP256Sha256(privateKey, fixture.ecdsaP256.message);

    expect(signature).toMatch(/^[0-9a-f]{128}$/);
    await expect(verifyP256Sha256(publicKey, fixture.ecdsaP256.message, signature)).resolves.toBe(true);
  });
});
