import base64
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from credential_crypto import (
    create_login_challenge,
    decrypt_credentials,
    get_public_key_pem,
    validate_login_challenge,
)


def _make_keypair(tmp_path: Path):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_path = tmp_path / "login_private.pem"
    public_path = tmp_path / "login_public.pem"
    private_path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    public_path.write_bytes(
        private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    return private_key, private_path, public_path


def test_public_key_pem_is_read_from_configured_path(tmp_path):
    _, _, public_path = _make_keypair(tmp_path)
    pem = get_public_key_pem(public_path)
    assert pem.startswith("-----BEGIN PUBLIC KEY-----")
    assert pem.endswith("-----END PUBLIC KEY-----\n")


def test_decrypt_credentials_round_trip_rsa_oaep_sha256(tmp_path):
    private_key, private_path, _ = _make_keypair(tmp_path)
    expected = {"password": "S3cret!", "challenge": "signed-challenge-123"}
    plaintext = json.dumps(expected).encode("utf-8")
    ciphertext = private_key.public_key().encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    encoded = base64.b64encode(ciphertext).decode("ascii")

    assert decrypt_credentials(encoded, private_path) == expected


def test_decrypt_credentials_rejects_invalid_base64(tmp_path):
    _, private_path, _ = _make_keypair(tmp_path)
    with pytest.raises(ValueError):
        decrypt_credentials("%%%not-base64%%%", private_path)


def test_decrypt_credentials_rejects_non_object_json(tmp_path):
    private_key, private_path, _ = _make_keypair(tmp_path)
    ciphertext = private_key.public_key().encrypt(
        json.dumps(["wrong-shape"]).encode("utf-8"),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    encoded = base64.b64encode(ciphertext).decode("ascii")
    with pytest.raises(ValueError):
        decrypt_credentials(encoded, private_path)


def test_signed_login_challenge_round_trip():
    token = create_login_challenge("test-secret", nonce="nonce-123")
    payload = validate_login_challenge(token, "test-secret", max_age=120)
    assert payload == {"nonce": "nonce-123"}


def test_signed_login_challenge_rejects_tampering():
    token = create_login_challenge("test-secret", nonce="nonce-123")
    tampered = token[:-1] + ("A" if token[-1] != "A" else "B")
    with pytest.raises(ValueError, match="Invalid or expired login challenge"):
        validate_login_challenge(tampered, "test-secret", max_age=120)


def test_signed_login_challenge_rejects_expired_token():
    token = create_login_challenge("test-secret", nonce="nonce-123")
    with pytest.raises(ValueError, match="Invalid or expired login challenge"):
        validate_login_challenge(token, "test-secret", max_age=-1)


def test_multiple_login_pages_do_not_invalidate_each_others_challenges():
    first = create_login_challenge("test-secret", nonce="page-one")
    second = create_login_challenge("test-secret", nonce="page-two")

    assert validate_login_challenge(first, "test-secret", max_age=120) == {"nonce": "page-one"}
    assert validate_login_challenge(second, "test-secret", max_age=120) == {"nonce": "page-two"}
