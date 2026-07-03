"""Shared canonical-JSON helper — the SDK's definition of canonical bytes,
used by the SDK publish-side hash (publisher.py) AND the verify-side envelope
wrap (verify.py) so the same logical payload always produces the same keccak256
across the publish/verify boundary AND across the TypeScript and Python SDKs.

WARNING — NOT THE ONLY CANONICAL FORM IN THE STACK. The first-party live feeds
(data-feeds/*/server.py) sign INSERTION-ORDER compact JSON
(json.dumps(separators=(",",":")), no sort_keys) — a frozen hash-compatibility
surface that must never be re-sorted. A payload signed there will NOT
hash-match this sorted form. fetch_and_verify is form-aware (tries both + raw
bytes) and raises CanonicalFormMismatchError rather than a false tamper alarm
when re-serialization cannot reproduce the attested bytes. See
ops/plans/TICKET_CANONICAL_FORMS_2026-07-03.md.

Canonical form = UTF-8 of JSON with recursively lexicographically-sorted object
keys and no insignificant whitespace (separators ',' and ':'). This is NOT full
RFC-8785/JCS: floats are emitted in each language's default repr (JS Number vs
Python float may differ for some values), and very large integers / NaN /
Infinity / -0 are out of scope. Keep payload values to strings, bools, and
integers that round-trip identically in JS and Python, or pre-stringify floats,
to guarantee keccak256 parity across SDKs. Array element order is significant
and preserved; only object keys are sorted.

Parity note: the TypeScript side (canonical.ts) rebuilds objects with
Object.keys().sort() then JSON.stringify (no spaces); this Python side uses
json.dumps(sort_keys=True, separators=(',',':'), ensure_ascii=False). Both sort
keys ascending by Unicode code unit and emit no whitespace, so they yield
IDENTICAL bytes for the same logical object. ensure_ascii=False is REQUIRED so
non-ASCII characters emit as raw UTF-8 bytes (matching TS TextEncoder, which
never escapes); the default ensure_ascii=True would emit \\uXXXX escapes and
diverge from TS on any non-ASCII payload.
"""

import json


def canonicalize(value) -> str:
    """Return the canonical JSON string for ``value``.

    Keys are sorted recursively (sort_keys=True); whitespace is stripped
    (separators=(',', ':')); non-ASCII is emitted as UTF-8, not escaped
    (ensure_ascii=False) so the output matches the TS canonicalizer byte-for-byte.
    """
    return json.dumps(value, separators=(",", ":"), sort_keys=True, ensure_ascii=False)


def canonical_bytes(value) -> bytes:
    """Return the UTF-8 canonical bytes for ``value`` — the exact bytes hashed
    with keccak256 on both the publish side and the verify side."""
    return canonicalize(value).encode("utf-8")
