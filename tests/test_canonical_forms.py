"""Cross-canonical-form boundary tests — ops/plans/TICKET_CANONICAL_FORMS_2026-07-03.md.

Documents the two canonical-JSON forms in the stack (SDK sorted vs live-feed
insertion-order), proves byte-exact verification is form-agnostic, and pins the
fetch_and_verify contract: a keccak match under ANY known form verifies; no
match on a re-serialized envelope raises CanonicalFormMismatchError (loud,
correct) — never a false HashMismatchError tamper alarm. Raw-bytes paths keep
real tamper semantics.

Run: python -m pytest tests/test_canonical_forms.py -q  (from sdk/python/)
"""

import json
from unittest import mock

import pytest
from web3 import Web3

from byte.canonical import canonical_bytes
from byte.verify import (
    CanonicalFormMismatchError,
    HashMismatchError,
    fetch_and_verify,
    verify_payload,
)

# Insertion order deliberately NOT sorted ("b" before "a").
PAYLOAD = {"b": 1, "a": {"d": 2, "c": 3}, "list": [{"z": 9, "y": 8}]}


def insertion_order_bytes(value) -> bytes:
    """The live feeds' form (data-feeds/*/server.py): compact, insertion order,
    default ensure_ascii=True."""
    return json.dumps(value, separators=(",", ":")).encode("utf-8")


def hash_of(data: bytes) -> str:
    h = Web3.keccak(data).hex()
    return (h if h.startswith("0x") else "0x" + h).lower()


class _FakeResponse:
    def __init__(self, body: bytes):
        self._body = body

    def read(self) -> bytes:
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _archive(body: bytes):
    return mock.patch("byte.verify.urllib.request.urlopen", return_value=_FakeResponse(body))


# ─── the documented boundary ─────────────────────────────────────────────────

def test_two_forms_diverge_for_unsorted_payload():
    insertion = insertion_order_bytes(PAYLOAD)
    sorted_form = canonical_bytes(PAYLOAD)
    assert insertion != sorted_form
    assert hash_of(insertion) != hash_of(sorted_form)


def test_already_sorted_payloads_coincide():
    # Why the bug hid: ASCII payloads whose keys happen to be sorted agree.
    already_sorted = {"a": 1, "b": 2}
    assert hash_of(insertion_order_bytes(already_sorted)) == hash_of(canonical_bytes(already_sorted))


def test_non_ascii_diverges_even_when_sorted():
    # ensure_ascii=True (feeds) escapes; ensure_ascii=False (SDK canonical) does not.
    payload = {"a": "café"}
    assert insertion_order_bytes(payload) != canonical_bytes(payload)


# ─── byte-exact verification is form-agnostic ────────────────────────────────

def test_verify_payload_passes_on_delivered_insertion_order_bytes():
    delivered = insertion_order_bytes(PAYLOAD)
    verify_payload(delivered, hash_of(delivered))  # must not raise


def test_verify_payload_real_tamper_still_raises_hash_mismatch():
    delivered = insertion_order_bytes(PAYLOAD)
    tampered = insertion_order_bytes({**PAYLOAD, "b": 2})
    with pytest.raises(HashMismatchError):
        verify_payload(tampered, hash_of(delivered))


# ─── fetch_and_verify is form-aware ──────────────────────────────────────────

URL = "https://archive.example"


def test_envelope_insertion_order_form_verifies():
    attested = hash_of(insertion_order_bytes(PAYLOAD))
    body = json.dumps({"payload": PAYLOAD, "meta": "x"}).encode()
    with _archive(body):
        got = fetch_and_verify(attested, URL)
    assert hash_of(got) == attested


def test_envelope_insertion_order_non_ascii_verifies():
    payload = {"b": "café", "a": 1}
    attested = hash_of(json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
    body = json.dumps({"payload": payload}, ensure_ascii=False).encode("utf-8")
    with _archive(body):
        got = fetch_and_verify(attested, URL)
    assert hash_of(got) == attested


def test_envelope_sorted_form_verifies():
    attested = hash_of(canonical_bytes(PAYLOAD))
    body = json.dumps({"payload": PAYLOAD, "meta": "x"}).encode()
    with _archive(body):
        got = fetch_and_verify(attested, URL)
    assert hash_of(got) == attested


def test_raw_bytes_archive_verifies_byte_exact():
    delivered = insertion_order_bytes(PAYLOAD)
    with _archive(delivered):
        got = fetch_and_verify(hash_of(delivered), URL)
    assert got == delivered


def test_no_form_matches_raises_canonical_form_mismatch_not_hash_mismatch():
    # Attested hash belongs to bytes no re-serialization of this envelope can
    # reproduce — indistinguishable from tampering after re-serialization, so
    # the error must allege neither and point at byte-exact verify.
    attested = hash_of(b"unreachable-preimage")
    body = json.dumps({"payload": PAYLOAD}).encode()
    with _archive(body):
        with pytest.raises(CanonicalFormMismatchError) as exc_info:
            fetch_and_verify(attested, URL)
    err = exc_info.value
    assert not isinstance(err, HashMismatchError)
    assert set(err.candidates) == {
        "raw-response",
        "sorted-canonical",
        "insertion-order",
        "insertion-order-utf8",
    }
    assert "verify_payload" in str(err)
    assert "Do not consume" in str(err)


def test_raw_bytes_archive_keeps_real_tamper_semantics():
    delivered = b"not-json-raw-bytes"
    with _archive(delivered):
        with pytest.raises(HashMismatchError):
            fetch_and_verify(hash_of(b"the-real-bytes"), URL)


def test_url_singular_first_with_plural_fallback():
    # discovery-api serves GET /payload/:hash (singular); the old SDK path
    # /payloads/<hash> stays as a fallback.
    delivered = insertion_order_bytes(PAYLOAD)
    calls = []

    def fake_urlopen(url, timeout=None):
        calls.append(url)
        if "/payload/" in url and "/payloads/" not in url:
            raise __import__("urllib.error", fromlist=["HTTPError"]).HTTPError(
                url, 404, "not found", None, None
            )
        return _FakeResponse(delivered)

    with mock.patch("byte.verify.urllib.request.urlopen", side_effect=fake_urlopen):
        got = fetch_and_verify(hash_of(delivered), URL)
    assert got == delivered
    assert "/payload/" in calls[0] and "/payloads/" not in calls[0]
    assert "/payloads/" in calls[1]
