"""
SHIP-GATE #1 (live leg): verify a REAL gateway X-BYTE-Attestation receipt with the
Python port, against the pinned attester from /.well-known/agent.json.

A live receipt requires a PAID x402 call (an unpaid GET → 402), so this can't run
unattended. Capture a real receipt once, then run this:

  # 1. Make a paid call to a feed and save the EXACT body + the header value:
  #    (e.g. via byte.GatewayClient, or curl after settling payment)
  #      body   -> /tmp/receipt.body         (raw bytes the gateway returned)
  #      header -> /tmp/receipt.header        (the X-BYTE-Attestation header string)
  # 2. python3 tests/verify_live_receipt.py --body /tmp/receipt.body --header /tmp/receipt.header

Expected: verified=True, recovered == 0x77c86a5367d941091a31BC97104609F2Db33C472.

The attestation domain is anchored at chainId 421614 (BYTE Library / ARBITRUM_SEPOLIA)
regardless of the x402 settlement network (Base) — so we verify with ARBITRUM_SEPOLIA.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

SDK_ROOT = Path(__file__).resolve().parent.parent
if str(SDK_ROOT) not in sys.path:
    sys.path.insert(0, str(SDK_ROOT))

from byte import verify_from_gateway_response, ARBITRUM_SEPOLIA  # noqa: E402

# Pinned attester from https://x402.payperbyte.io/.well-known/agent.json (receipt.attester).
PINNED_ATTESTER = "0x77c86a5367d941091a31BC97104609F2Db33C472"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--body", required=True, help="file with the EXACT response body bytes")
    ap.add_argument("--header", required=True, help="file with the X-BYTE-Attestation header value (JSON)")
    ap.add_argument("--attester", default=PINNED_ATTESTER, help="pinned attester address")
    args = ap.parse_args()

    body = Path(args.body).read_bytes()
    header = Path(args.header).read_text().strip()

    verdict = verify_from_gateway_response(body, header, ARBITRUM_SEPOLIA, args.attester)
    print(f"verified     : {verdict.verified}")
    print(f"hash_match   : {verdict.hash_match}")
    print(f"signer_match : {verdict.signer_match}")
    print(f"recovered    : {verdict.recovered}")
    print(f"expired      : {verdict.expired}")
    print(f"reason       : {verdict.reason}")

    ok = verdict.verified and (verdict.recovered or "").lower() == args.attester.lower()
    print(f"\nLIVE SHIP-GATE: {'PASS ✅' if ok else 'FAIL ❌'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
