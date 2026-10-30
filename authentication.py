
"""Handle JSON messages and signatures."""

import json
import re
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)

PROTOCOL_LABEL = "DH-CLASSROOM-AUTH-v1"
MAX_MESSAGE_BYTES = 4096
INIT_KEYS = frozenset({"protocol", "message_type", "initiator", "responder",
                       "p", "g", "A", "nonce_A"})
TRANSCRIPT_KEYS = frozenset({"protocol", "initiator", "responder", "p", "g",
                             "A", "B", "nonce_A", "nonce_B"})
FOLLOWUP_KEYS = frozenset({"message_type", "transcript"})


class ProtocolError(ValueError):
    """Error for invalid messages."""


def canonical_bytes(payload: dict) -> bytes:
    """Convert data into JSON bytes."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("utf-8")


def sign_message(payload: dict, signing_key: Ed25519PrivateKey) -> bytes:
    """Sign a message."""
    signature_hex = signing_key.sign(canonical_bytes(payload)).hex()
    message = canonical_bytes({"payload": payload, "signature": signature_hex})
    if len(message) > MAX_MESSAGE_BYTES:
        raise ProtocolError("message exceeds 4096 bytes")
    return message


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ProtocolError("duplicate JSON key")
        result[key] = value
    return result


def parse_message(raw: bytes) -> tuple[dict, bytes]:
    """Check and read JSON messages."""
    if type(raw) is not bytes or len(raw) > MAX_MESSAGE_BYTES:
        raise ProtocolError("message must be bytes no larger than 4096 bytes")
    try:
        message = json.loads(raw.decode("utf-8"),
                             object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeDecodeError, ValueError, TypeError) as exc:
        raise ProtocolError("invalid JSON") from exc
    if type(message) is not dict or set(message) != {"payload", "signature"}:
        raise ProtocolError("wrong message envelope")
    payload, signature = message["payload"], message["signature"]
    if type(payload) is not dict:
        raise ProtocolError("payload must be an object")
    if type(signature) is not str or re.fullmatch(r"[0-9a-f]{128}", signature) is None:
        raise ProtocolError("signature must be 64 bytes of lowercase hex")
    try:
        if canonical_bytes(message) != raw:
            raise ProtocolError("message must use canonical JSON encoding")
    except (ValueError, TypeError) as exc:
        raise ProtocolError("invalid JSON value") from exc
    return payload, bytes.fromhex(signature)


def verify_message(payload: dict, signature: bytes,
                   trusted_key: Ed25519PublicKey) -> None:
    """Verify the signature."""
    try:
        trusted_key.verify(signature, canonical_bytes(payload))
    except InvalidSignature as exc:
        raise ProtocolError("INVALID signature: exchange aborted") from exc


def _nonce_valid(value: object) -> bool:
    return type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _check_common(payload: dict, fixture_mode: bool) -> None:
    """Check message values."""
    if payload["protocol"] != PROTOCOL_LABEL:
        raise ProtocolError("wrong protocol label")
    if payload["initiator"] != "Alice" or payload["responder"] != "Bob":
        raise ProtocolError("wrong identity labels")
    p = payload["p"]
    if type(p) is not int or p <= 2 or (p.bit_length() not in range(16, 33)
                                        and not (fixture_mode and p == 23)):
        raise ProtocolError("invalid modulus size or type")
    for key in ("g", "A", "B"):
        if key in payload:
            value = payload[key]
            if type(value) is not int or not (2 <= value <= p - 2):
                raise ProtocolError(f"invalid {key} value or type")
    for key in ("nonce_A", "nonce_B"):
        if key in payload and not _nonce_valid(payload[key]):
            raise ProtocolError(f"invalid {key}")


def check_initiation(payload: dict, *, fixture_mode: bool) -> None:
    if type(payload) is not dict or set(payload) != INIT_KEYS:
        raise ProtocolError("wrong initiation schema")
    if payload["message_type"] != "init":
        raise ProtocolError("wrong message type")
    _check_common(payload, fixture_mode)


def check_followup(payload: dict, kind: str, *, fixture_mode: bool) -> dict:
    if type(payload) is not dict or set(payload) != FOLLOWUP_KEYS:
        raise ProtocolError("wrong response/finish schema")
    if payload["message_type"] != kind:
        raise ProtocolError("wrong message type or order")
    transcript = payload["transcript"]
    if type(transcript) is not dict or set(transcript) != TRANSCRIPT_KEYS:
        raise ProtocolError("wrong transcript schema")
    _check_common(transcript, fixture_mode)
    return transcript
