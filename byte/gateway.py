"""Keyless x402 gateway client for the BYTE Library.

This client mirrors the REAL BYTE x402 gateway (x402-gateway/src/index.ts) and
its reference agent-client (x402-gateway/examples/agent-client/python/
pay_and_fetch.py). It is KEYLESS: a wallet signs the payment (EIP-3009
``transferWithAuthorization``, gasless — the facilitator broadcasts and pays
gas). There is NO API key anywhere.

Flow per paid request (mirrors the gateway's x402 v2 "exact" EVM scheme):
  1. GET/POST the resource.
  2. Gateway answers HTTP 402 with PaymentRequirements (accepts[] naming the
     CAIP-2 network, payTo, USDC asset, and atomic amount).
  3. The wallet SIGNS an EIP-3009 authorization for the advertised amount.
  4. The request is retried with the X-PAYMENT header; the facilitator
     verifies + settles on-chain; the gateway returns the data.
The x402 ``requests`` session (``x402_requests``) performs steps 2-4
transparently. The settlement SettleResponse {success, payer, transaction} is
decoded from the X-PAYMENT-RESPONSE header.

BOUNDARY — two distinct USDC flows, keep them separate:
  (A) On-chain settlement leg (Publisher / Subscriber, see
      subscriber.subscribe): the subscriber registers in DataRegistry and grants
      DataStream a direct USDC allowance; DataStream pulls per-message fees via
      transferFrom. No escrow contract is involved.
  (B) The x402 gateway EIP-3009 payment leg (THIS client), signed at fetch
      time against whatever the 402 names.
They are INDEPENDENT. The live pay-per-call feeds — including the POST verdict
oracles (address-reputation, sanctions-screen, pkg-verdict, reasoning-verdict,
positioning-snapshot, liquidation-stream, evidence-pack) — need only flow (B):
the paid 200 returns the answer in-body with an embedded EIP-712 attestation,
no prior on-chain subscribe required. Flow (A) is for the on-chain
publish/subscribe streaming path, not for x402 fetches.

DEPENDENCIES (optional/peer — the heavy x402 stack is NOT a hard install_requires
of the core SDK; import it lazily here so ``import byte`` works without it):
    x402[evm,requests]==2.12.0   (the gateway's @x402 v2 line)
    eth-account==0.13.7
    web3==7.16.0
    requests==2.34.2
Install with:  pip install "x402[evm,requests]==2.12.0" eth-account web3 requests
"""

import json
from typing import Any, Optional

# Default gateway base URLs.
#   prod : x402-gateway openapi.ts servers[].url / the /.well-known/x402.json
#          resource prefix / the /feeds catalog URL.
#   local: x402-gateway lib/config.ts default port 3402.
PROD_BASE_URL = "https://x402.payperbyte.io"
LOCAL_BASE_URL = "http://127.0.0.1:3402"

# Feeds the SDK sends over POST-with-a-JSON-body BY DEFAULT — the POST-only
# verdict/pack oracles. Regenerated 2026-07-03 from the live catalog
# (GET x402.payperbyte.io/feeds, method==["POST"]) after the feed cut;
# empirically confirmed (POST-only feeds 405 on GET, 402 on POST).
# NOT included: the dual GET-digest/POST-verdict feeds `runtime-eol` and
# `threat-intel` — they answer GET (a digest, no body) AND POST (a verdict,
# needs input), so they default to GET; pass method="POST" + body for the
# verdict. GET-only feeds (weather, earthquakes) are also absent. Everything
# not listed defaults to GET.
POST_ORACLES = frozenset({
    "address-reputation",
    "sanctions-screen",
    "pkg-verdict",
    "reasoning-verdict",
    "positioning-snapshot",
    "liquidation-stream",
    "evidence-pack",
})

# Response header carrying the per-feed disclaimer category (index.ts §14).
DISCLAIMER_HEADER = "X-BYTE-Disclaimer-Category"


def _missing_x402(exc: Exception):
    return ImportError(
        "The x402 client stack is an optional dependency of payperbyte-sdk and is not "
        "installed. Install it with:\n"
        '    pip install "x402[evm,requests]==2.12.0" eth-account web3 requests\n'
        f"(original import error: {exc})"
    )


class GatewayClient:
    """Keyless x402 client for the BYTE Library gateway.

    A wallet (``eth_account`` LocalAccount) signs each payment; no API key is
    used. Construct with the account and an optional baseUrl (defaults to prod)
    and optional rpcUrl (enables on-chain nonce/allowance reads via
    ``EthAccountSignerWithRPC``; sign-only ``EthAccountSigner`` otherwise — both
    are sufficient for the gasless EIP-3009 "exact" USDC path).

    Example:
        from eth_account import Account
        from byte import GatewayClient

        account = Account.from_key(private_key)          # NEVER hardcode
        gw = GatewayClient(account=account)              # prod gateway
        catalog = gw.discover()                          # GET /feeds
        result = gw.fetch_feed("weather")                # GET feed, pays via x402
        verdict = gw.fetch_feed("address-reputation",    # POST verdict oracle
                                body={"domain": "example.com",
                                      "address": "0x1111111111111111111111111111111111111111",
                                      "chain": "base"})
        print(result["data"], verdict["data"], verdict["settlement"])
    """

    def __init__(
        self,
        account,
        base_url: str = PROD_BASE_URL,
        rpc_url: Optional[str] = None,
    ):
        # Lazy-import the optional x402 stack so the core SDK imports without it.
        try:
            import requests  # noqa: F401
            from x402.client import x402ClientSync
            from x402.http.clients.requests import x402_requests
            from x402.mechanisms.evm.exact.register import register_exact_evm_client
            from x402.mechanisms.evm.signers import (
                EthAccountSigner,
                EthAccountSignerWithRPC,
            )
        except ImportError as exc:  # pragma: no cover - depends on optional deps
            raise _missing_x402(exc)

        self.account = account
        self.address = account.address
        self.base_url = base_url.rstrip("/")
        self.rpc_url = rpc_url

        # EthAccountSigner is sign-only (sufficient for gasless EIP-3009 — the
        # facilitator broadcasts). EthAccountSignerWithRPC adds nonce/allowance
        # reads when an RPC URL is supplied.
        signer = (
            EthAccountSignerWithRPC(account, rpc_url)
            if rpc_url
            else EthAccountSigner(account)
        )

        # No networks= arg -> registers the eip155:* wildcard, which covers any
        # eip155 chain the gateway's 402 names (Arbitrum Sepolia eip155:421614,
        # Base, etc.). The gateway's 402 names the concrete network + USDC asset
        # via accepts[]; the client pays whatever it asks. An optional Solana
        # accept appended by the gateway is tolerated (this exact-EVM client
        # simply does not select it).
        client = x402ClientSync()
        register_exact_evm_client(client, signer)
        self._session = x402_requests(client)

    # -- Discovery (free, no payment) ------------------------------------------

    def discover(self) -> dict:
        """GET {base_url}/feeds — the feed catalog.

        Returns the parsed catalog object:
          { protocol, version, networks[], facilitator, asset (usdcAddress),
            pricing{model:'per-byte', pricePerKB, floor, note},
            disclaimers{header, note, text}, feeds[] }
        Each feed: { id, name, description, price ('$x.xxx'),
          priceAtomic (atomic 6-decimal USDC string), expectedSizeBytes,
          provenance ('eip712-attested'|'first-party'), updateFrequency,
          endpoint ('/feeds/<id>'), disclaimerCategory, publisher? }.
        The SDK READS feed.priceAtomic — it never recomputes the price.
        """
        import requests

        resp = requests.get(f"{self.base_url}/feeds", timeout=30)
        resp.raise_for_status()
        return resp.json()

    def discover_resources(self) -> dict:
        """GET {base_url}/.well-known/x402.json — the x402 resource manifest.

        Returns { x402Version: 1, name: 'BYTE Library', facilitator, catalog,
        resources[] } where each resource =
          { resource, method ('GET'|'POST'), name, description, category, price,
            accepts:[...], metadata:{expectedSizeBytes, updateFrequency} }
        so the caller gets per-resource accepts[] WITHOUT probing a 402.
        """
        import requests

        resp = requests.get(f"{self.base_url}/.well-known/x402.json", timeout=30)
        resp.raise_for_status()
        return resp.json()

    # -- Paid retrieval (wallet signs the x402 payment) ------------------------

    def fetch_feed(
        self,
        feed_id_or_path: str,
        method: Optional[str] = None,
        body: Optional[dict] = None,
        timeout: float = 60.0,
    ) -> dict:
        """Fetch a (typically paid) feed. The wrapped x402 session transparently
        does request -> 402 -> sign EIP-3009 USDC payment -> retry -> paid
        response. NO API key; the wallet signs.

        ``feed_id_or_path`` may be a feed id ('address-reputation') or a full
        path ('/feeds/address-reputation'). The POST-only verdict/pack oracles
        (see ``POST_ORACLES``) default to POST with the supplied JSON ``body``;
        the dual GET-digest/POST-verdict feeds (``runtime-eol``, ``threat-intel``)
        and all other feeds default to GET. Pass ``method`` to override — e.g.
        ``method="POST", body={...}`` to pull a verdict from a dual feed.

        Verdict-oracle body shape (e.g. address-reputation, per gateway
        index.ts): { domain | url, address (0x), amount? (int atomic), chain?
        ('base' | 'arbitrum-one') }. The paid 200 embeds an EIP-712
        PayloadAttestation over the exact answer bytes — recompute keccak256 and
        recover the signer before acting. Body shapes vary per oracle; see each
        feed's 402 challenge (its `bazaar.info.input` schema).

        Returns:
          { 'data': <parsed body>,
            'settlement': { 'success', 'payer', 'transaction' } | None,
            'disclaimerCategory': <X-BYTE-Disclaimer-Category header or None> }
        """
        feed_id, path = self._resolve(feed_id_or_path)
        if method is None:
            method = "POST" if feed_id in POST_ORACLES else "GET"
        method = method.upper()
        url = f"{self.base_url}{path}"

        if method == "POST":
            resp = self._session.post(url, json=(body or {}), timeout=timeout)
        else:
            resp = self._session.get(url, timeout=timeout)

        if resp.status_code != 200:
            raise RuntimeError(
                f"gateway returned {resp.status_code} for {method} {url}: {resp.text}"
            )

        try:
            data: Any = resp.json()
        except ValueError:
            data = resp.text

        return {
            "data": data,
            "settlement": self._extract_settlement(resp),
            "disclaimerCategory": resp.headers.get(DISCLAIMER_HEADER),
        }

    # -- Internals -------------------------------------------------------------

    @staticmethod
    def _resolve(feed_id_or_path: str) -> tuple:
        """Return (feed_id, path) for a feed id or a '/feeds/...' path."""
        s = feed_id_or_path.strip()
        if s.startswith("/"):
            feed_id = s.rstrip("/").rsplit("/", 1)[-1]
            return feed_id, s
        return s, f"/feeds/{s}"

    @staticmethod
    def _extract_settlement(resp) -> Optional[dict]:
        """Decode the settlement SettleResponse from the response headers
        (v2 PAYMENT_RESPONSE_HEADER, then v1 X_PAYMENT_RESPONSE_HEADER).
        Returns { 'success', 'payer', 'transaction' } or None on a free/already-
        paid route. Mirrors pay_and_fetch.py:extract_settlement."""
        try:
            from x402.http.constants import (
                PAYMENT_RESPONSE_HEADER,
                X_PAYMENT_RESPONSE_HEADER,
            )
            from x402.http.utils import decode_payment_response_header
        except ImportError as exc:  # pragma: no cover
            raise _missing_x402(exc)

        raw = resp.headers.get(PAYMENT_RESPONSE_HEADER) or resp.headers.get(
            X_PAYMENT_RESPONSE_HEADER
        )
        if not raw:
            return None
        try:
            settle = decode_payment_response_header(raw)
        except Exception:  # noqa: BLE001 - malformed header -> no settlement
            return None
        return {
            "success": getattr(settle, "success", None),
            "payer": getattr(settle, "payer", None),
            "transaction": getattr(settle, "transaction", None),
        }


# Re-export for callers that prefer json-shaped helpers.
__all__ = ["GatewayClient", "PROD_BASE_URL", "LOCAL_BASE_URL"]
