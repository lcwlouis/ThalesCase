import { describe, expect, it } from "vitest";
import fixture from "../../settings.example.json";
import {
  generateP256KeyPair,
  importP256PrivateKeyFromPkcs8Hex,
  importP256PublicKeyFromSpkiHex,
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
