export function bytesToHex(bytes: ArrayBuffer | Uint8Array): string {
  const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  return Array.from(view, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function parseHex(input: string): Uint8Array {
  const normalized = input.trim().replace(/\s+/g, "").toLowerCase();

  if (normalized.length % 2 !== 0) {
    throw new Error("HEX input must contain an even number of characters.");
  }

  if (!/^[0-9a-f]*$/.test(normalized)) {
    throw new Error("HEX input contains non-HEX characters.");
  }

  const bytes = new Uint8Array(normalized.length / 2);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(normalized.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
}
