import { bytesToHex, parseHex } from "./hex";
import { requireSubtleCrypto } from "./sha256";

const ECDSA_P256 = { name: "ECDSA", namedCurve: "P-256" } as const;
const ECDSA_SHA256 = { name: "ECDSA", hash: "SHA-256" } as const;
const RAW_P256_SIGNATURE_BYTES = 64;

export type ExportedP256KeyPair = {
  publicKey: CryptoKey;
  privateKey: CryptoKey;
  publicKeyHex: string;
  privateKeyHex: string;
};

export async function generateP256KeyPair(): Promise<ExportedP256KeyPair> {
  const keypair = await requireSubtleCrypto().generateKey(ECDSA_P256, true, ["sign", "verify"]);

  if (keypair instanceof CryptoKey) {
    throw new Error("Expected an ECDSA key pair, but Web Crypto returned a single key.");
  }

  const [publicKeyHex, privateKeyHex] = await Promise.all([
    exportP256PublicKeyToSpkiHex(keypair.publicKey),
    exportP256PrivateKeyToPkcs8Hex(keypair.privateKey)
  ]);

  return {
    publicKey: keypair.publicKey,
    privateKey: keypair.privateKey,
    publicKeyHex,
    privateKeyHex
  };
}

export async function exportP256PublicKeyToSpkiHex(publicKey: CryptoKey): Promise<string> {
  return bytesToHex(await requireSubtleCrypto().exportKey("spki", publicKey));
}

export async function exportP256PrivateKeyToPkcs8Hex(privateKey: CryptoKey): Promise<string> {
  return bytesToHex(await requireSubtleCrypto().exportKey("pkcs8", privateKey));
}

export async function importP256PublicKeyFromSpkiHex(hex: string): Promise<CryptoKey> {
  try {
    return await requireSubtleCrypto().importKey("spki", toArrayBuffer(parseHex(hex)), ECDSA_P256, true, ["verify"]);
  } catch (error) {
    if (error instanceof Error && error.message.startsWith("HEX input")) {
      throw error;
    }
    throw new Error("Public key import failed. Use P-256 SPKI DER HEX.");
  }
}

export async function importP256PrivateKeyFromPkcs8Hex(hex: string): Promise<CryptoKey> {
  try {
    return await requireSubtleCrypto().importKey("pkcs8", toArrayBuffer(parseHex(hex)), ECDSA_P256, true, ["sign"]);
  } catch (error) {
    if (error instanceof Error && error.message.startsWith("HEX input")) {
      throw error;
    }
    throw new Error("Private key import failed. Use P-256 PKCS#8 DER HEX.");
  }
}

export async function signP256Sha256(privateKey: CryptoKey, message: string): Promise<string> {
  const signature = await requireSubtleCrypto().sign(ECDSA_SHA256, privateKey, new TextEncoder().encode(message));
  const signatureBytes = new Uint8Array(signature);

  if (signatureBytes.byteLength !== RAW_P256_SIGNATURE_BYTES) {
    throw new Error("ECDSA P-256 signing did not return a raw 64-byte signature.");
  }

  return bytesToHex(signatureBytes);
}

export async function verifyP256Sha256(
  publicKey: CryptoKey,
  message: string,
  rawSignatureHex: string
): Promise<boolean> {
  const signature = parseHex(rawSignatureHex);
  if (signature.byteLength !== RAW_P256_SIGNATURE_BYTES) {
    throw new Error("ECDSA P-256 signatures must be 64 bytes (128 HEX characters).");
  }

  return requireSubtleCrypto().verify(ECDSA_SHA256, publicKey, toArrayBuffer(signature), new TextEncoder().encode(message));
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}
