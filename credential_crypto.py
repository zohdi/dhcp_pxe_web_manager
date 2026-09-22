"""RSA-OAEP helpers for the AD login credential envelope.

This module protects the AD password from appearing as plaintext in the
browser's submitted form payload. It is defense-in-depth and does not replace
HTTPS/TLS. V1.3.1 uses a bundled pure-JavaScript RSA-OAEP implementation so the
credential envelope can be created on ordinary HTTP pages. The browser encrypts
password + a signed short-lived login challenge with the public key; the server
decrypts with the private key and validates the challenge immediately before
PAM/VAS auth.
"""
from __future__ import annotations

import base64
import binascii
import json
import secrets
from pathlib import Path
from typing import Any, Dict, Union

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from itsdangerous import BadData, URLSafeTimedSerializer

PathLike = Union[str, Path]



LOGIN_CHALLENGE_SALT = "dhcp-manager-ad-login-v1"


def create_login_challenge(secret_key: str, *, nonce: str | None = None) -> str:
    """Create a signed timestamped challenge for an AD login page."""
    if not isinstance(secret_key, str) or not secret_key:
        raise ValueError("Invalid login challenge configuration")
    value = nonce if nonce is not None else secrets.token_urlsafe(32)
    if not isinstance(value, str) or not value:
        raise ValueError("Invalid login challenge configuration")
    serializer = URLSafeTimedSerializer(secret_key, salt=LOGIN_CHALLENGE_SALT)
    return serializer.dumps({"nonce": value})


def validate_login_challenge(token: str, secret_key: str, *, max_age: int = 120) -> Dict[str, Any]:
    """Validate a signed timestamped challenge and return its payload."""
    if not isinstance(token, str) or not token:
        raise ValueError("Invalid or expired login challenge")
    if not isinstance(secret_key, str) or not secret_key:
        raise ValueError("Invalid or expired login challenge")
    try:
        serializer = URLSafeTimedSerializer(secret_key, salt=LOGIN_CHALLENGE_SALT)
        payload = serializer.loads(token, max_age=max_age)
    except (BadData, ValueError, TypeError) as exc:
        raise ValueError("Invalid or expired login challenge") from exc
    if not isinstance(payload, dict) or not isinstance(payload.get("nonce"), str) or not payload["nonce"]:
        raise ValueError("Invalid or expired login challenge")
    return payload

def get_public_key_pem(public_key_path: PathLike) -> str:
    """Read and validate an RSA public key, returning normalized PEM text."""
    path = Path(public_key_path)
    raw = path.read_bytes()
    try:
        key = serialization.load_pem_public_key(raw)
    except Exception as exc:
        raise ValueError("Invalid login public key") from exc
    if not isinstance(key, rsa.RSAPublicKey):
        raise ValueError("Login public key must be RSA")
    return key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")


def decrypt_credentials(ciphertext_b64: str, private_key_path: PathLike) -> Dict[str, Any]:
    """Decrypt a base64 RSA-OAEP/SHA-256 login envelope.

    Returns a dict containing exactly the browser-provided JSON fields. Errors
    are normalized so callers never need to expose cryptographic details.
    """
    if not isinstance(ciphertext_b64, str) or not ciphertext_b64:
        raise ValueError("Invalid encrypted credential payload")

    try:
        ciphertext = base64.b64decode(ciphertext_b64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("Invalid encrypted credential payload") from exc

    try:
        raw_key = Path(private_key_path).read_bytes()
        private_key = serialization.load_pem_private_key(raw_key, password=None)
        if not isinstance(private_key, rsa.RSAPrivateKey):
            raise ValueError("Login private key must be RSA")
        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        data = json.loads(plaintext.decode("utf-8"))
        if not isinstance(data, dict):
            raise ValueError("Credential payload must be a JSON object")
        if not isinstance(data.get("password"), str) or not isinstance(data.get("challenge"), str):
            raise ValueError("Credential payload is missing required fields")
        return data
    except ValueError:
        raise
    except Exception as exc:
        raise ValueError("Unable to decrypt credential payload") from exc
    finally:
        try:
            plaintext = None
        except UnboundLocalError:
            pass
