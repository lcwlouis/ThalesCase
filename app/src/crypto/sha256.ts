import { bytesToHex } from "./hex";

export async function sha256Hex(input: string): Promise<string> {
  const digest = await requireSubtleCrypto().digest("SHA-256", new TextEncoder().encode(input));
  return bytesToHex(digest);
}

export function requireSubtleCrypto(): SubtleCrypto {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) {
    throw new Error("This browser does not support the Web Crypto API required by this app.");
  }
  return subtle;
}
