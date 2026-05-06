import json
from pathlib import Path

from ecdsa_p256_tool import (
    der_signature_to_raw_p256,
    raw_p256_to_der_signature,
    sign_p256_sha256,
    verify_p256_sha256,
)


def test_der_signature_to_raw_p256_removes_positive_integer_padding():
    der_hex = (
        "3045022018e35c212f695e8c2b2b41c521e681d06bf26a5720942be7447ece47863eb29f"
        "022100c1341fb738065b620fb4f89b5be40703e9862cc6b79daeb0ccab0dccb0d27f71"
    )

    assert der_signature_to_raw_p256(der_hex) == (
        "18e35c212f695e8c2b2b41c521e681d06bf26a5720942be7447ece47863eb29f"
        "c1341fb738065b620fb4f89b5be40703e9862cc6b79daeb0ccab0dccb0d27f71"
    )


def test_raw_p256_to_der_signature_round_trips_raw_signature():
    raw_hex = (
        "5a1bd1a580a0f4af434071f4336fc50811e18fae30651d67ab4fa97e43cfd768"
        "4f8e7f2854ba13a2500a589838cc50079624118fc3cfb2dc3dbc94a4791624ea"
    )

    assert der_signature_to_raw_p256(raw_p256_to_der_signature(raw_hex)) == raw_hex


def test_sample_fixture_signature_verifies_and_tampered_message_fails():
    fixture = json.loads(Path("app/settings.example.json").read_text())["ecdsaP256"]

    assert verify_p256_sha256(
        public_key_hex=fixture["publicKeySpkiDerHex"],
        message=fixture["message"],
        signature_hex=fixture["signatureRawRsHex"],
        signature_format="raw",
    )

    assert not verify_p256_sha256(
        public_key_hex=fixture["publicKeySpkiDerHex"],
        message=fixture["tamperedMessage"],
        signature_hex=fixture["signatureRawRsHex"],
        signature_format="raw",
    )


def test_sample_fixture_private_key_can_sign_der_and_verify():
    fixture = json.loads(Path("app/settings.example.json").read_text())["ecdsaP256"]
    der_signature = sign_p256_sha256(
        private_key_hex=fixture["privateKeyPkcs8DerHex"],
        message=fixture["message"],
        signature_format="der",
    )

    assert verify_p256_sha256(
        public_key_hex=fixture["publicKeySpkiDerHex"],
        message=fixture["message"],
        signature_hex=der_signature,
        signature_format="der",
    )
