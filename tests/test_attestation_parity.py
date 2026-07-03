"""
SHIP-GATE: cross-language EIP-712 parity vector for the Python signer-leg port.

A REAL viem-signed X-BYTE-Attestation receipt + the TS SDK's own
`verifyFromGatewayResponse` verdicts are produced by
`sdk/typescript/scripts/produce-parity-vector.cjs` into `parity_vector.json`.
This test asserts the Python `verify_from_gateway_response` reproduces those
verdicts FIELD-FOR-FIELD across the full attack matrix — which can only hold if
the EIP-712 digest (viem ⇄ eth_account) is byte-identical.

Run directly (`python3 tests/test_attestation_parity.py`) or under pytest.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

# Make `byte` importable when run as a bare script (tests/ is under sdk/python).
SDK_ROOT = Path(__file__).resolve().parent.parent
if str(SDK_ROOT) not in sys.path:
    sys.path.insert(0, str(SDK_ROOT))

from byte.networks import ARBITRUM_SEPOLIA, NetworkConfig  # noqa: E402
from byte import (  # noqa: E402
    verify, verify_from_gateway_response, attestation_domain,
    PAYLOAD_ATTESTATION_TYPES, Verdict,
)
from byte.attestation import _to_bigint_or  # noqa: E402

VECTOR = json.loads((SDK_ROOT / "tests" / "parity_vector.json").read_text())
META = VECTOR["meta"]
NOW = META["now_seconds"]
ATTESTER = META["attester"]


class Counter:
    def __init__(self) -> None:
        self.passed = 0

    def ok(self, cond: bool, label: str) -> None:
        assert cond, f"FAIL: {label}"
        self.passed += 1
        print(f"  pass: {label}")


def _net_for(chain_id: int) -> NetworkConfig:
    if chain_id == ARBITRUM_SEPOLIA.chain_id:
        return ARBITRUM_SEPOLIA
    return NetworkConfig(
        chain_id=chain_id, rpc_url=ARBITRUM_SEPOLIA.rpc_url,
        contracts=dict(ARBITRUM_SEPOLIA.contracts), indexer_url=ARBITRUM_SEPOLIA.indexer_url,
    )


def _header_arg(header_input):
    return None if header_input == "__NULL__" else header_input


def _norm_reason(r: str) -> str:
    # The one intentional cross-language divergence: TS names the camelCase param
    # `expectedAttester`; the Python API param is snake_case.
    return r.replace("expectedAttester", "expected_attester")


def _addr_eq(a, b) -> bool:
    if a is None or b is None:
        return a is None and b is None
    return a.lower() == b.lower()


def _genuine_header() -> dict:
    for c in VECTOR["cases"]:
        if c["name"] == "genuine":
            return json.loads(c["header_input"])
    raise AssertionError("no 'genuine' case in vector")


def run() -> int:
    c = Counter()

    # ── 0. consensus-critical constants are byte-identical ──
    dom = attestation_domain(ARBITRUM_SEPOLIA)
    c.ok(dom["name"] == "BYTE Library", "domain name is 'BYTE Library' (consensus-critical)")
    c.ok(dom["version"] == "1", "domain version is '1'")
    c.ok(dom["chainId"] == 421614, "domain chainId is 421614 (ARBITRUM_SEPOLIA)")
    c.ok(dom["verifyingContract"].lower() == META["data_stream"].lower(),
         "domain verifyingContract == DataStream address")
    c.ok([t["type"] for t in PAYLOAD_ATTESTATION_TYPES["PayloadAttestation"]]
         == ["address", "bytes32", "uint256", "uint256"],
         "PAYLOAD_ATTESTATION_TYPES field types match the typehash")

    # ── 1. the parity matrix: Python verdict must match the TS verdict ──
    for case in VECTOR["cases"]:
        name = case["name"]
        net = _net_for(case["net_chain_id"])
        verdict: Verdict = verify_from_gateway_response(
            case["body"], _header_arg(case["header_input"]), net,
            case["expected_attester"], now_seconds=NOW,
        )
        tv = case["ts_verdict"]
        c.ok(verdict.verified == tv["verified"], f"[{name}] verified == TS ({tv['verified']})")
        c.ok(verdict.hash_match == tv["hashMatch"], f"[{name}] hash_match == TS ({tv['hashMatch']})")
        c.ok(verdict.signer_match == tv["signerMatch"], f"[{name}] signer_match == TS ({tv['signerMatch']})")
        c.ok(_addr_eq(verdict.recovered, tv["recovered"]), f"[{name}] recovered == TS ({tv['recovered']})")
        c.ok(verdict.expired == tv["expired"], f"[{name}] expired == TS ({tv['expired']})")
        c.ok(verdict.reason == _norm_reason(tv["reason"]), f"[{name}] reason matches TS")

    # ── 2. header as a parsed dict matches the JSON-string path ──
    gh = _genuine_header()
    as_dict = verify_from_gateway_response(
        '{"asset":"BTC","price":64000,"sanctioned":true}', gh, ARBITRUM_SEPOLIA, ATTESTER, now_seconds=NOW
    )
    c.ok(as_dict.verified is True, "dict-form header verifies identically to JSON-string form")

    # ── 3. body passed as BYTES matches body passed as the equivalent str ──
    body_str = '{"asset":"BTC","price":64000,"sanctioned":true}'
    as_bytes = verify_from_gateway_response(
        body_str.encode("utf-8"), gh, ARBITRUM_SEPOLIA, ATTESTER, now_seconds=NOW
    )
    c.ok(as_bytes.verified is True, "bytes-form body verifies identically to str-form (EXACT-bytes rule)")

    # ── 4. FIX: odd-length payloadHash → Python rejects (stricter/safer than TS,
    #         which recovers a wrong address). Decision fields are fail-closed. ──
    odd = dict(gh)
    odd["payloadHash"] = "0x" + "ab" * 31 + "a"  # 63 hex chars (odd)
    v_odd = verify_from_gateway_response(body_str, odd, ARBITRUM_SEPOLIA, ATTESTER, now_seconds=NOW)
    c.ok(v_odd.verified is False, "odd-length payloadHash -> verified False")
    c.ok(v_odd.signer_match is False, "odd-length payloadHash -> signer_match False (32-byte guard)")
    c.ok(v_odd.recovered is None, "odd-length payloadHash -> recovered None (no bogus recovery)")

    # ── 5. FIX: verify()/verify_attestation are THROW-FREE on a non-int deadline ──
    for bad_deadline in (None, "abc"):
        v = verify(
            payload_bytes=body_str, attestation="0x" + "11" * 65, expected_publisher=ATTESTER,
            payload_hash="0x" + "00" * 32, payload_length=1, deadline=bad_deadline,
            net=ARBITRUM_SEPOLIA, now_seconds=NOW,
        )
        c.ok(isinstance(v, Verdict) and v.verified is False,
             f"verify(): non-int deadline {bad_deadline!r} -> Verdict (no throw), verified False")

    # ── 6. FIX/coverage: non-object JSON header fails closed (decision fields) ──
    for bad_header in ("[1,2,3]", "123", '"hi"', "true"):
        v = verify_from_gateway_response(body_str, bad_header, ARBITRUM_SEPOLIA, ATTESTER, now_seconds=NOW)
        c.ok(v.verified is False and v.signer_match is None,
             f"non-object header {bad_header!r} -> fail-closed (verified False, signer_match None)")

    # ── 7. _to_bigint_or fail-closed edge cases (mirror TS toBigIntOr) ──
    c.ok(_to_bigint_or(5) == 5 and _to_bigint_or(5.0) == 5 and _to_bigint_or("123") == 123 and _to_bigint_or(0) == 0,
         "to_bigint_or: accepts non-negative integers / integral floats / digit strings")
    for bad in [None, -1, 1.5, "1.5", "-5", "", "0x5", True, False, [1], {"a": 1}, "12a"]:
        c.ok(_to_bigint_or(bad) is None, f"to_bigint_or: {bad!r} -> None (fail-closed)")

    print(f"\nALL TESTS PASSED ({c.passed} assertions)")
    return c.passed


def test_attestation_parity():
    assert run() > 0


if __name__ == "__main__":
    try:
        n = run()
    except AssertionError as e:
        print(f"\n{e}")
        sys.exit(1)
    sys.exit(0)
