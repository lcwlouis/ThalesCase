import { describe, expect, it } from "vitest";
import { bytesToHex, parseHex } from "./hex";

describe("HEX helpers", () => {
  it("formats bytes as lowercase HEX", () => {
    expect(bytesToHex(new Uint8Array([0, 10, 15, 16, 255]))).toBe("000a0f10ff");
  });

  it("accepts uppercase or lowercase HEX and normalizes parsed output", () => {
    expect(bytesToHex(parseHex("Aa10FF"))).toBe("aa10ff");
  });

  it("rejects odd-length HEX strings", () => {
    expect(() => parseHex("abc")).toThrow("HEX input must contain an even number of characters.");
  });

  it("rejects non-HEX characters", () => {
    expect(() => parseHex("zz")).toThrow("HEX input contains non-HEX characters.");
  });
});
