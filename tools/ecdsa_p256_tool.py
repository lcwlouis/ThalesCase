#!/usr/bin/env python3
"""Local ECDSA P-256 helper for assignment verification.

This tool avoids pasting private keys into online tools. It accepts the same
formats used by the app spec:
- public key: SPKI DER HEX
- private key: PKCS#8 DER HEX
- raw signature: P-256 r||s HEX
"""

from __future__ import annotations

import argparse
import base64
import re
import sys
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils


P256_SIZE_BYTES = 32


def normalize_hex(value: str) -> str:
    cleaned = re.sub(r"[\s:_-]", "", value).lower()
    if cleaned.startswith("0x"):
        cleaned = cleaned[2:]
    if len(cleaned) % 2 != 0:
        raise ValueError("HEX input must have an even number of characters")
    if not re.fullmatch(r"[0-9a-f]*", cleaned):
        raise ValueError("Input contains non-HEX characters")
    return cleaned


def hex_to_bytes(value: str) -> bytes:
    return bytes.fromhex(normalize_hex(value))


def bytes_to_hex(value: bytes) -> str:
    return value.hex()


def der_signature_to_raw_p256(signature_hex: str) -> str:
    r, s = utils.decode_dss_signature(hex_to_bytes(signature_hex))
    return _int_to_fixed_hex(r) + _int_to_fixed_hex(s)


def raw_p256_to_der_signature(signature_hex: str) -> str:
    raw = hex_to_bytes(signature_hex)
    if len(raw) != P256_SIZE_BYTES * 2:
        raise ValueError("Raw P-256 signatures must be 64 bytes / 128 HEX characters")
    r = int.from_bytes(raw[:P256_SIZE_BYTES], "big")
    s = int.from_bytes(raw[P256_SIZE_BYTES:], "big")
    return bytes_to_hex(utils.encode_dss_signature(r, s))


def sign_p256_sha256(
    *,
    private_key_hex: str,
    message: str,
    signature_format: str,
) -> str:
    private_key = serialization.load_der_private_key(hex_to_bytes(private_key_hex), password=None)
    if not isinstance(private_key, ec.EllipticCurvePrivateKey):
        raise ValueError("Private key is not an elliptic-curve private key")
    if private_key.curve.name != "secp256r1":
        raise ValueError(f"Private key curve must be P-256, got {private_key.curve.name}")

    der_signature = private_key.sign(message.encode("utf-8"), ec.ECDSA(hashes.SHA256()))
    der_hex = bytes_to_hex(der_signature)
    if signature_format == "der":
        return der_hex
    if signature_format == "raw":
        return der_signature_to_raw_p256(der_hex)
    raise ValueError("signature_format must be raw or der")


def verify_p256_sha256(
    *,
    public_key_hex: str,
    message: str,
    signature_hex: str,
    signature_format: str,
) -> bool:
    public_key = serialization.load_der_public_key(hex_to_bytes(public_key_hex))
    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        raise ValueError("Public key is not an elliptic-curve public key")
    if public_key.curve.name != "secp256r1":
        raise ValueError(f"Public key curve must be P-256, got {public_key.curve.name}")

    der_hex = (
        raw_p256_to_der_signature(signature_hex)
        if signature_format == "raw"
        else normalize_hex(signature_hex)
    )
    try:
        public_key.verify(hex_to_bytes(der_hex), message.encode("utf-8"), ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


def pem_to_der_hex(*, pem_path: str, key_kind: str) -> str:
    pem = Path(pem_path).read_bytes()
    if key_kind == "public":
        key = serialization.load_pem_public_key(pem)
        return bytes_to_hex(
            key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
    if key_kind == "private":
        key = serialization.load_pem_private_key(pem, password=None)
        return bytes_to_hex(
            key.private_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    raise ValueError("key_kind must be public or private")


def _int_to_fixed_hex(value: int) -> str:
    raw = value.to_bytes(P256_SIZE_BYTES, "big")
    return raw.hex()


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="ECDSA P-256 verification helper")
    subcommands = parser.add_subparsers(dest="command", required=True)

    der_to_raw = subcommands.add_parser("der-to-raw", help="Convert DER signature HEX to raw r||s HEX")
    der_to_raw.add_argument("signature_hex")

    raw_to_der = subcommands.add_parser("raw-to-der", help="Convert raw r||s HEX to DER signature HEX")
    raw_to_der.add_argument("signature_hex")

    pem_to_hex_parser = subcommands.add_parser("pem-to-hex", help="Convert PEM key file to DER HEX")
    pem_to_hex_parser.add_argument("--kind", choices=["public", "private"], required=True)
    pem_to_hex_parser.add_argument("--pem-file", required=True)

    sign = subcommands.add_parser("sign", help="Sign a UTF-8 message with PKCS#8 private key DER HEX")
    sign.add_argument("--private-key-hex", required=True)
    sign.add_argument("--message", required=True)
    sign.add_argument("--signature-format", choices=["raw", "der"], default="raw")

    verify = subcommands.add_parser("verify", help="Verify a UTF-8 message with SPKI public key DER HEX")
    verify.add_argument("--public-key-hex", required=True)
    verify.add_argument("--message", required=True)
    verify.add_argument("--signature-hex", required=True)
    verify.add_argument("--signature-format", choices=["raw", "der"], default="raw")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "der-to-raw":
            print(der_signature_to_raw_p256(args.signature_hex))
        elif args.command == "raw-to-der":
            print(raw_p256_to_der_signature(args.signature_hex))
        elif args.command == "pem-to-hex":
            print(pem_to_der_hex(pem_path=args.pem_file, key_kind=args.kind))
        elif args.command == "sign":
            print(
                sign_p256_sha256(
                    private_key_hex=args.private_key_hex,
                    message=args.message,
                    signature_format=args.signature_format,
                )
            )
        elif args.command == "verify":
            ok = verify_p256_sha256(
                public_key_hex=args.public_key_hex,
                message=args.message,
                signature_hex=args.signature_hex,
                signature_format=args.signature_format,
            )
            print("VALID" if ok else "INVALID")
            return 0 if ok else 1
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
