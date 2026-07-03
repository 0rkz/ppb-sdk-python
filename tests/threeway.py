"""Three-way canonical-form diff — Form A vs Form B vs JCS (Node-native leg).

Adopted from the ephemeral scratchpad runner behind the 2026-07-03 evidence run
(ops/plans/TICKET_CANONICAL_FORMS_JCS_RUN_2026-07-03.txt, appendix). Extends
tests/crossform_diff.py with a JCS leg that runs the REAL cross-language
round-trip: each vector's Form-A bytes are fed as text to Node (jcs_leg.mjs),
which JSON.parses them (the "naive JS round-trip" — silently corrupts
10**24 to 1e+24 BEFORE hashing) and re-serializes per RFC 8785 (UTF-16
code-unit key sort + ES number repr).

Legs:
  Form A — the FROZEN live-feed signer: json.dumps(payload, separators=(",",":"))
           (insertion order, ensure_ascii=True). Byte-identical replica of
           data-feeds/broadcast_helper.py:187 (canonical_payload_bytes).
  Form B — the SDK canonicalizer: byte.canonical.canonical_bytes
           (sort_keys=True, ensure_ascii=False).
  JCS    — Node-native (tests/jcs_leg.mjs, our code — always on).
  CC-JCS — OPTIONAL 4th leg via MarkovianProtocol/canoncheck, ONLY when
           CANONCHECK_DIR is set (founder-gated: external code; reviewed
           SAFE-TO-RUN-SANDBOXED at pinned SHA 2c2bdd7, review 2026-07-03 —
           run from a pinned checkout, never pip install, skip demo/). When on,
           the summary reports Node-native vs canoncheck JCS conformance
           (2026-07-03 run: hash-identical 11/12; sole split = big-int-wei,
           where canoncheck REJECTS fail-closed and the naive JS round-trip
           hashes the corrupted 1e+24).

Usage:
  python3 tests/threeway.py                                  # A / B / JCS(node)
  CANONCHECK_DIR=/path/to/canoncheck python3 tests/threeway.py   # + CC-JCS leg

Exits non-zero if the 12-vector results drift from the frozen 2026-07-03
evidence expectations (A==B 5/12, A==JCS 1/12, B==JCS 7/12).
"""

import json
import os
import subprocess
import sys

from web3 import Web3

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from byte.canonical import canonical_bytes  # noqa: E402  (Form B)

HERE = os.path.dirname(os.path.abspath(__file__))
JCS_LEG = os.path.join(HERE, "jcs_leg.mjs")

# Frozen expectations from the 2026-07-03 evidence run (appendix).
EXPECT = {"A==B": 5, "A==JCS": 1, "B==JCS": 7, "vectors": 12}


def form_a(payload) -> bytes:
    """Replica of data-feeds/broadcast_helper.py:187 — the frozen signer form."""
    return json.dumps(payload, separators=(",", ":")).encode("utf-8")


def keccak(data: bytes) -> str:
    h = Web3.keccak(data).hex()
    return (h if h.startswith("0x") else "0x" + h).lower()


# Non-ASCII characters are spelled as escapes ON PURPOSE: editors/tooling can
# silently NFC-normalize source text, which corrupts the nfc-vs-nfd pair (the
# evidence file's own display caveat). Escapes make the vectors normalization-proof.
VECTORS = [
    ("unsorted-keys", {"b": 1, "a": 2}),
    ("nested-unsorted", {"b": {"d": 1, "c": 2}, "a": [{"z": 1, "y": 2}]}),
    ("sorted-keys-ascii", {"a": 1, "b": 2}),
    ("non-ascii-sorted", {"a": "caf\u00e9"}),
    ("emoji-and-accents", {"k": "caf\u00e9\U0001f600"}),
    ("floats", {"a": 1.0, "b": 1e20, "c": 1e-7}),
    ("negative-zero", {"x": -0.0}),
    ("big-int-wei", {"wei": 10**24}),
    ("int-float-identity", {"a": 1.0, "b": 1e2, "c": 100}),
    ("nfc-e-acute", {"s": "\u00e9"}),
    ("nfd-e-acute", {"s": "e\u0301"}),
    ("non-bmp-key-sort", {"\U0001f600": 1, "\ufb00": 2}),
]

# Conformance-nit probe (NOT part of the 12-vector table): a lone surrogate,
# legal in JSON text (\ud800 escape) but not encodable as well-formed UTF-8.
# Form A hashes it (ensure_ascii keeps it as ASCII escape text); Form B
# REJECTS (UnicodeEncodeError at .encode("utf-8") — fail-closed); Node's
# JSON.stringify (ES2019 well-formed mode) re-escapes it as \ud800.
# canoncheck's Python leg raises on it per source review at 2c2bdd7 —
# NOT yet exercised in a run (the founder-gate applies).
LONE_SURROGATE = ("lone-surrogate", '{"s":"\\ud800"}')


def node_jcs(form_a_texts: list) -> list:
    """Feed Form-A texts through jcs_leg.mjs; return per-line (bytes|None, note)."""
    proc = subprocess.run(
        ["node", JCS_LEG],
        input=("\n".join(form_a_texts) + "\n").encode("utf-8"),
        capture_output=True,
        check=True,
    )
    out = []
    for raw in proc.stdout.split(b"\n"):
        if not raw:
            continue
        if raw.startswith(b"OK "):
            out.append((raw[3:], None))
        else:
            out.append((None, raw.decode("utf-8", "replace")))
    return out


def canoncheck_fn():
    cc_dir = os.environ.get("CANONCHECK_DIR")
    if not cc_dir:
        return None
    sys.path.insert(0, cc_dir)
    import canoncheck  # type: ignore

    def cc(payload) -> bytes:
        out = canoncheck.canonicalize(payload)
        return out if isinstance(out, bytes) else str(out).encode("utf-8")

    return cc


def main() -> None:
    cc = canoncheck_fn()
    a_texts = [form_a(p).decode("ascii") for _, p in VECTORS]
    jcs_rows = node_jcs(a_texts)
    assert len(jcs_rows) == len(VECTORS), "jcs_leg.mjs row count mismatch"

    legs = "A(insertion) / B(sorted) / JCS(node-native)" + (" / CC-JCS(canoncheck)" if cc else "")
    print(f"legs: {legs}\n")
    print(f"{'vector':22} {'A==B':5} {'A==JCS':6} {'B==JCS':6}")
    print("-" * 42)

    counts = {"A==B": 0, "A==JCS": 0, "B==JCS": 0}
    cc_agree = 0
    cc_total = 0
    for (name, payload), (jcs_bytes, jcs_note) in zip(VECTORS, jcs_rows):
        a = form_a(payload)
        b = canonical_bytes(payload)
        ha, hb = keccak(a), keccak(b)
        hj = keccak(jcs_bytes) if jcs_bytes is not None else f"REJECTED: {jcs_note}"
        eq_ab, eq_aj, eq_bj = ha == hb, ha == hj, hb == hj
        counts["A==B"] += eq_ab
        counts["A==JCS"] += eq_aj
        counts["B==JCS"] += eq_bj
        print(f"{name:22} {str(eq_ab):5} {str(eq_aj):6} {str(eq_bj):6}")
        print(f"   A   {ha}  {a.decode('utf-8', 'backslashreplace')[:90]}")
        print(f"   B   {hb}  {b.decode('utf-8', 'backslashreplace')[:90]}")
        shown = jcs_bytes.decode("utf-8", "backslashreplace")[:90] if jcs_bytes is not None else "-"
        print(f"   JCS {hj}  {shown}")
        if cc:
            cc_total += 1
            try:
                cb = cc(payload)
                hc = keccak(cb)
                print(f"   CC  {hc}  {cb.decode('utf-8', 'backslashreplace')[:90]}")
                cc_agree += hc == hj
            except Exception as e:  # canoncheck REJECTING a vector is itself a result
                print(f"   CC  REJECTED: {type(e).__name__}: {e}  -")
                # agreement only if node leg also rejected
                cc_agree += jcs_bytes is None

    print(
        f"\nA==B  on {counts['A==B']}/{len(VECTORS)};  "
        f"A==JCS on {counts['A==JCS']}/{len(VECTORS)};  "
        f"B==JCS on {counts['B==JCS']}/{len(VECTORS)}"
    )
    if cc:
        print(f"JCS conformance: node-native vs canoncheck hash-identical on {cc_agree}/{cc_total}")

    # Conformance-nit probe (separate from the 12-vector table on purpose).
    name, text = LONE_SURROGATE
    print(f"\n── {name} (conformance probe, not in the table): {text}")
    payload = json.loads(text)
    a = form_a(payload)
    print(f"   A   {keccak(a)}  {a.decode('ascii')}   (ASCII escape text — hashes fine)")
    try:
        b = canonical_bytes(payload)
        print(f"   B   {keccak(b)}  {b.decode('utf-8', 'backslashreplace')}")
    except UnicodeEncodeError as e:
        print(f"   B   REJECTED: UnicodeEncodeError: {e}   (fail-closed at UTF-8 encode)")
    (jcs_bytes, jcs_note) = node_jcs([text])[0]
    if jcs_bytes is not None:
        print(f"   JCS {keccak(jcs_bytes)}  {jcs_bytes.decode('utf-8', 'backslashreplace')}   (ES2019 re-escapes)")
    else:
        print(f"   JCS REJECTED: {jcs_note}")
    if cc:
        try:
            cb = cc(payload)
            print(f"   CC  {keccak(cb)}  {cb.decode('utf-8', 'backslashreplace')}")
        except Exception as e:
            print(f"   CC  REJECTED: {type(e).__name__}: {e}")

    drift = {k: counts[k] for k in ("A==B", "A==JCS", "B==JCS") if counts[k] != EXPECT[k]}
    if drift:
        print(f"\nDRIFT from frozen 2026-07-03 evidence expectations {EXPECT}: {drift}")
        sys.exit(1)
    print("\nmatches frozen 2026-07-03 evidence expectations (A==B 5/12, A==JCS 1/12, B==JCS 7/12)")


if __name__ == "__main__":
    main()
