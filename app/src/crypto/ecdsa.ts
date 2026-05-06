import { bytesToHex, parseHex } from "./hex";
import { requireSubtleCrypto } from "./sha256";

const ECDSA_P256 = { name: "ECDSA", namedCurve: "P-256" } as const;
const ECDSA_SHA256 = { name: "ECDSA", hash: "SHA-256" } as const;
const RAW_P256_SIGNATURE_BYTES = 64;
const P256_SCALAR_BYTES = 32;

export type SignatureFormat = "raw" | "der";

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

export function rawP256SignatureHexToDerHex(rawSignatureHex: string): string {
  const rawSignature = parseHex(rawSignatureHex);
  if (rawSignature.byteLength !== RAW_P256_SIGNATURE_BYTES) {
    throw new Error("Raw ECDSA P-256 signatures must be 64 bytes (128 HEX characters).");
  }

  const r = encodeDerInteger(rawSignature.slice(0, P256_SCALAR_BYTES));
  const s = encodeDerInteger(rawSignature.slice(P256_SCALAR_BYTES));
  const sequenceLength = r.length + s.length;

  if (sequenceLength > 0x7f) {
    throw new Error("ECDSA P-256 DER signature is unexpectedly long.");
  }

  return bytesToHex(new Uint8Array([0x30, sequenceLength, ...r, ...s]));
}

export function derSignatureHexToRawP256Hex(derSignatureHex: string): string {
  const derSignature = parseHex(derSignatureHex);
  let offset = 0;

  if (readByte(derSignature, offset) !== 0x30) {
    throw new Error("DER ECDSA signatures must start with an ASN.1 sequence.");
  }
  offset += 1;

  const sequenceLength = readDerLength(derSignature, offset);
  offset = sequenceLength.nextOffset;
  if (sequenceLength.value !== derSignature.byteLength - offset) {
    throw new Error("DER ECDSA signature sequence length is invalid.");
  }

  const r = readDerInteger(derSignature, offset);
  offset = r.nextOffset;
  const s = readDerInteger(derSignature, offset);
  offset = s.nextOffset;

  if (offset !== derSignature.byteLength) {
    throw new Error("DER ECDSA signature contains trailing data.");
  }

  return bytesToHex(concatBytes(toFixedP256Scalar(r.value), toFixedP256Scalar(s.value)));
}

export async function verifyP256Sha256(
  publicKey: CryptoKey,
  message: string,
  signatureHex: string,
  signatureFormat: SignatureFormat = "raw"
): Promise<boolean> {
  const signature = parseHex(
    signatureFormat === "der" ? derSignatureHexToRawP256Hex(signatureHex) : signatureHex
  );
  if (signature.byteLength !== RAW_P256_SIGNATURE_BYTES) {
    throw new Error("Raw ECDSA P-256 signatures must be 64 bytes (128 HEX characters).");
  }

  return requireSubtleCrypto().verify(ECDSA_SHA256, publicKey, toArrayBuffer(signature), new TextEncoder().encode(message));
}

function encodeDerInteger(integer: Uint8Array): Uint8Array {
  let start = 0;
  while (start < integer.length - 1 && integer[start] === 0x00) {
    start += 1;
  }

  const trimmed = integer.slice(start);
  const needsPositivePadding = (trimmed[0] & 0x80) !== 0;
  const value = needsPositivePadding ? concatBytes(new Uint8Array([0x00]), trimmed) : trimmed;
  return concatBytes(new Uint8Array([0x02, value.length]), value);
}

function readDerInteger(bytes: Uint8Array, offset: number): { value: Uint8Array; nextOffset: number } {
  if (readByte(bytes, offset) !== 0x02) {
    throw new Error("DER ECDSA signature is missing an integer.");
  }

  const length = readDerLength(bytes, offset + 1);
  const valueStart = length.nextOffset;
  const valueEnd = valueStart + length.value;
  if (length.value === 0 || valueEnd > bytes.byteLength) {
    throw new Error("DER ECDSA signature integer length is invalid.");
  }

  return { value: bytes.slice(valueStart, valueEnd), nextOffset: valueEnd };
}

function readDerLength(bytes: Uint8Array, offset: number): { value: number; nextOffset: number } {
  const firstLengthByte = readByte(bytes, offset);
  if ((firstLengthByte & 0x80) === 0) {
    return { value: firstLengthByte, nextOffset: offset + 1 };
  }

  const lengthByteCount = firstLengthByte & 0x7f;
  if (lengthByteCount === 0 || lengthByteCount > 2 || offset + 1 + lengthByteCount > bytes.byteLength) {
    throw new Error("DER ECDSA signature length is invalid.");
  }

  let value = 0;
  for (let index = 0; index < lengthByteCount; index += 1) {
    value = value * 256 + readByte(bytes, offset + 1 + index);
  }

  return { value, nextOffset: offset + 1 + lengthByteCount };
}

function toFixedP256Scalar(integer: Uint8Array): Uint8Array {
  let value = integer;
  if (value.length > 1 && value[0] === 0x00) {
    value = value.slice(1);
  }

  if (value.byteLength > P256_SCALAR_BYTES) {
    throw new Error("DER ECDSA signature integer is too large for P-256.");
  }

  const padded = new Uint8Array(P256_SCALAR_BYTES);
  padded.set(value, P256_SCALAR_BYTES - value.byteLength);
  return padded;
}

function readByte(bytes: Uint8Array, offset: number): number {
  const byte = bytes[offset];
  if (byte === undefined) {
    throw new Error("DER ECDSA signature is truncated.");
  }
  return byte;
}

function concatBytes(...chunks: Uint8Array[]): Uint8Array {
  const result = new Uint8Array(chunks.reduce((total, chunk) => total + chunk.byteLength, 0));
  let offset = 0;
  for (const chunk of chunks) {
    result.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return result;
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}
