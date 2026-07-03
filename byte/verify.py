"""Subscriber-side hash verification for BYTE Library r2 payloads.

THIS IS THE POST-MORTEM-DEFENSIBILITY WEDGE FOR BYTE LIBRARY v1.

The on-chain DataStreamed / BroadcastStreamed event certifies that the
publisher SIGNED an EIP-712 attestation over
(publisher, payloadHash, payloadLength, deadline). That proves the
publisher attested *to a payload with the given hash* — but it does
NOT prove the bytes you received in your delivery channel match.

A corrupted archive, a man-in-the-middle on the off-chain transport,
or a publisher misconfig could feed you different bytes while the
on-chain attestation still verifies (because the hash in the event
is what the publisher signed for, not necessarily what you received).

`verify_payload()` closes that gap. Call it on every payload before
acting on the data. If it raises HashMismatchError, the bytes you
received do NOT match what the publisher attested to on-chain — do
not consume them; treat it as a publisher-side or transport incident.

This is the function a risk committee can point at in a post-mortem:
"every byte we relied on was hash-verified against the publisher's
on-chain attestation; here is the tx hash and here is the verifier."
"""

from typing import Union
import json
import urllib.request
import urllib.error

from web3 import Web3

from byte.canonical import canonical_bytes


class HashMismatchError(Exception):
    """Received payload bytes do not match the on-chain attested hash."""

    def __init__(self, expected: str, actual: str):
        self.expected = expected
        self.actual = actual
        super().__init__(
            f"payload hash mismatch: expected {expected}, got {actual}"
        )


class CanonicalFormMismatchError(Exception):
    """Raised by fetch_and_verify when a JSON-envelope payload matches the
    attested hash under NO known canonical form (raw response bytes, sorted-
    canonical, insertion-order with/without ASCII escaping).

    Deliberately NOT a HashMismatchError: once a payload has been re-serialized,
    a hash mismatch cannot distinguish tampering from a canonical-form
    difference, so this error alleges neither — fetch the exact delivered bytes
    and use verify_payload() (byte-exact), the only path that can prove
    tampering. Fail closed either way: do not consume the payload.

    Background: the SDK publishers hash SORTED-key canonical bytes
    (byte/canonical.py); the first-party live feeds sign INSERTION-ORDER compact
    bytes (a frozen hash-compatibility surface). See
    ops/plans/TICKET_CANONICAL_FORMS_2026-07-03.md.
    """

    def __init__(self, expected: str, candidates: dict):
        self.expected = expected
        self.candidates = dict(candidates)
        forms = ", ".join(f"{k}={v}" for k, v in self.candidates.items())
        super().__init__(
            f"payload matched the attested hash {expected} under no known "
            f"canonical form ({forms}). A re-serialized JSON envelope cannot "
            f"distinguish tampering from a canonical-form mismatch — fetch the "
            f"exact delivered bytes and verify them with verify_payload() "
            f"(byte-exact). Do not consume this payload."
        )


def _normalize_hash(h: Union[str, bytes]) -> str:
    """Return a lowercased 0x-prefixed 32-byte hex hash string."""
    if isinstance(h, (bytes, bytearray)):
        return "0x" + bytes(h).hex().lower()
    h = h.lower()
    return h if h.startswith("0x") else "0x" + h


def verify_payload(
    payload_bytes: bytes,
    expected_hash: Union[str, bytes],
) -> None:
    """Verify keccak256(payload_bytes) matches the on-chain attested hash.

    Raises HashMismatchError on mismatch. Returns None on success.

    Usage:
        from byte.verify import verify_payload, HashMismatchError

        async for event in subscriber.stream():
            payload_bytes = fetch_from_my_archive(event["payload_hash"])
            try:
                verify_payload(payload_bytes, event["payload_hash"])
            except HashMismatchError as e:
                log_incident(e)
                continue  # do NOT consume mismatched bytes
            consume(payload_bytes)
    """
    actual_hex = Web3.keccak(payload_bytes).hex()
    actual = actual_hex if actual_hex.startswith("0x") else "0x" + actual_hex
    actual = actual.lower()
    expected = _normalize_hash(expected_hash)
    if actual != expected:
        raise HashMismatchError(expected=expected, actual=actual)


def verify_event_payload(event, payload_bytes: bytes) -> bool:
    """Verify a payload against a stream event's attestation, ONLY if the
    event carries an r2 attestation. Legacy pre-r2 events have no attestation
    field; for those this is a no-op and returns False so the caller can
    decide policy (fail-closed vs. allow legacy).

    Returns True if the attestation was present and bytes verified.
    Raises HashMismatchError if attestation present and bytes don't match.

    Accepts either a dict (as yielded by Subscriber.stream()) or any object
    exposing the same field names via attribute access.
    """
    if isinstance(event, dict):
        payload_hash = event.get("payload_hash") or event.get("payloadHash")
        attestation = event.get("attestation")
    else:
        payload_hash = getattr(event, "payload_hash", None) or getattr(event, "payloadHash", None)
        attestation = getattr(event, "attestation", None)

    if not attestation:
        return False  # legacy pre-r2 event — wedge does not apply
    if isinstance(attestation, (bytes, bytearray)) and len(attestation) == 0:
        return False
    if isinstance(attestation, str) and (attestation in ("", "0x", "0X")):
        return False

    verify_payload(payload_bytes, payload_hash)
    return True


def fetch_and_verify(
    payload_hash: Union[str, bytes],
    discovery_url: str,
    timeout: float = 3.0,
) -> bytes:
    """Fetch a payload from a discovery-api-style archive and verify its
    hash against the on-chain attested hash. Returns the raw bytes on
    success.

    Raises HashMismatchError if the archive's bytes don't match the
    attestation. Raises ValueError if the archive misses the payload.

    Convenience wrapper around verify_payload. If your archive lives
    elsewhere or uses a non-standard envelope, fetch the bytes yourself
    and call verify_payload directly.
    """
    h_hex = _normalize_hash(payload_hash).removeprefix("0x")
    base = discovery_url.rstrip("/")
    # discovery-api's route is GET /payload/:hash (singular — discovery-api
    # src/index.ts:222). Earlier SDK versions fetched /payloads/<hash>, which
    # that API never served; keep it as a fallback for archives that adopted
    # the old SDK convention.
    raw = None
    for path in (f"{base}/payload/{h_hex}", f"{base}/payloads/{h_hex}"):
        try:
            with urllib.request.urlopen(path, timeout=timeout) as resp:
                raw = resp.read()
            break
        except urllib.error.HTTPError as e:
            if e.code == 404:
                continue
            raise
    if raw is None:
        raise ValueError(f"archive miss for payload {h_hex}")

    # discovery-api wraps payloads as {"payload": {...}, ...}. TWO publisher
    # populations hash DIFFERENT bytes for the same logical payload:
    #   - SDK publishers (publisher.py / publisher.ts): SORTED-key canonical form.
    #   - First-party live feeds (data-feeds/*/server.py): INSERTION-ORDER
    #     compact form via json.dumps(separators=(",",":")) — default
    #     ensure_ascii=True — a FROZEN hash-compatibility surface (never re-sort).
    # A re-serialized envelope therefore has to be tried against every known
    # form; a keccak256 match under ANY form proves those bytes are the attested
    # preimage. If NONE match we raise CanonicalFormMismatchError — NOT
    # HashMismatchError, because after re-serialization a mismatch cannot
    # distinguish tampering from a form difference. This envelope re-wrap is the
    # only place the SDK re-serializes; verify_payload itself hashes the raw
    # bytes it is handed (byte-exact, real tamper semantics).
    envelope = None
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, dict) and "payload" in parsed:
            envelope = parsed
    except (json.JSONDecodeError, UnicodeDecodeError):
        pass

    if envelope is None:
        verify_payload(raw, payload_hash)  # byte-exact: HashMismatchError = real tamper signal
        return raw

    payload = envelope["payload"]
    expected = _normalize_hash(payload_hash)
    candidates = (
        ("raw-response", raw),
        ("sorted-canonical", canonical_bytes(payload)),
        # json.loads preserves the document's key order, so a compact re-dump
        # reproduces the feeds' insertion-order signer bytes (ensure_ascii=True
        # matches their json.dumps default; the =False variant covers non-ASCII
        # payloads written without escaping).
        ("insertion-order", json.dumps(payload, separators=(",", ":")).encode("utf-8")),
        ("insertion-order-utf8", json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")),
    )
    seen = {}
    for form, candidate in candidates:
        h = Web3.keccak(candidate).hex()
        h = (h if h.startswith("0x") else "0x" + h).lower()
        seen[form] = h
        if h == expected:
            return candidate  # attested preimage found
    raise CanonicalFormMismatchError(expected=expected, candidates=seen)
