"""Cross-form divergence diff — ops/plans/TICKET_CANONICAL_FORMS_2026-07-03.md item 3.

Feeds one adversarial vector set through the stack's canonical forms and diffs
bytes + keccak256:

  Form A — the FROZEN live-feed signer: json.dumps(payload, separators=(",",":"))
           (insertion order, ensure_ascii=True). Byte-identical replica of
           data-feeds/broadcast_helper.py:187 (canonical_payload_bytes) —
           replicated here instead of imported so this diff never triggers
           that module's import-time side effects.
  Form B — the SDK canonicalizer: byte.canonical.canonical_bytes
           (sort_keys=True, ensure_ascii=False).
  JCS    — OPTIONAL third leg via MarkovianProtocol/canoncheck, ONLY when
           CANONCHECK_DIR is set (founder-gated: external code; reviewed
           SAFE-TO-RUN-SANDBOXED at pinned SHA 2c2bdd7, review 2026-07-03 —
           run from a pinned checkout, never pip install, skip demo/).

Usage:
  python3 tests/crossform_diff.py                      # A vs B (our code only)
  CANONCHECK_DIR=/path/to/canoncheck python3 tests/crossform_diff.py   # + JCS
"""

import json
import os
import sys

from web3 import Web3

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from byte.canonical import canonical_bytes  # noqa: E402  (Form B)


def form_a(payload) -> bytes:
    """Replica of data-feeds/broadcast_helper.py:187 — the frozen signer form."""
    return json.dumps(payload, separators=(",", ":")).encode("utf-8")


def keccak(data: bytes) -> str:
    h = Web3.keccak(data).hex()
    return (h if h.startswith("0x") else "0x" + h).lower()


VECTORS = [
    ("unsorted-keys", {"b": 1, "a": 2}),
    ("nested-unsorted", {"b": {"d": 1, "c": 2}, "a": [{"z": 1, "y": 2}]}),
    ("sorted-keys-ascii", {"a": 1, "b": 2}),
    ("non-ascii-sorted", {"a": "café"}),
    ("emoji-and-accents", {"k": "café😀"}),
    ("floats", {"a": 1.0, "b": 1e20, "c": 1e-7}),
    ("negative-zero", {"x": -0.0}),
    ("big-int-wei", {"wei": 10**24}),
    ("int-float-identity", {"a": 1.0, "b": 1e2, "c": 100}),
    ("nfc-e-acute", {"s": "é"}),
    ("nfd-e-acute", {"s": "é"}),
    ("non-bmp-key-sort", {"\U0001f600": 1, "ﬀ": 2}),
]


def jcs_fn():
    cc_dir = os.environ.get("CANONCHECK_DIR")
    if not cc_dir:
        return None
    sys.path.insert(0, cc_dir)
    import canoncheck  # type: ignore

    def jcs(payload) -> bytes:
        out = canoncheck.canonicalize(payload)
        return out if isinstance(out, bytes) else str(out).encode("utf-8")

    return jcs


def main() -> None:
    jcs = jcs_fn()
    legs = ["A(insertion)", "B(sorted)"] + (["JCS"] if jcs else [])
    print(f"legs: {legs}   (JCS leg {'ON' if jcs else 'OFF — set CANONCHECK_DIR to enable'})\n")
    rows = []
    for name, payload in VECTORS:
        out = {}
        for leg, fn in (("A", form_a), ("B", canonical_bytes)) + ((("JCS", jcs),) if jcs else ()):
            try:
                b = fn(payload)
                out[leg] = (b, keccak(b))
            except Exception as e:  # a leg REJECTING a vector is itself a result
                out[leg] = (None, f"REJECTED: {type(e).__name__}: {e}")
        verdict_ab = (
            "A==B" if out["A"][1] == out["B"][1] else "A!=B"
        )
        rows.append((name, verdict_ab, out))
        print(f"── {name}: {verdict_ab}")
        for leg, (b, h) in out.items():
            shown = b.decode("utf-8", "backslashreplace") if b is not None else "-"
            print(f"   {leg:3} {h}  {shown[:90]}")
    diverging = [r[0] for r in rows if r[1] == "A!=B"]
    print(f"\nA vs B diverge on {len(diverging)}/{len(VECTORS)} vectors: {diverging}")
    # NFC vs NFD are distinct vectors on purpose: no form normalizes unicode,
    # so the two hash differently under EVERY leg (JCS does not fix this).
    nfc = [r for r in rows if r[0] == "nfc-e-acute"][0][2]
    nfd = [r for r in rows if r[0] == "nfd-e-acute"][0][2]
    assert nfc["A"][1] != nfd["A"][1] and nfc["B"][1] != nfd["B"][1]
    print("unicode-normalization: NFC and NFD hash differently in every form (as documented)")


if __name__ == "__main__":
    main()
