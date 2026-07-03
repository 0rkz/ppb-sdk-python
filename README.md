# payperbyte-sdk — PayPerByte Python SDK

Python SDK for PayPerByte — the cryptographically attested, provenance-verifiable data layer for AI agents. Discover first-party feeds, pay per call, subscribe, stream payloads, and verify every payload against its EIP-712 attestation (authenticity + tamper-evidence — who signed these exact bytes — not a correctness guarantee). No token; x402 USDC payments settle on **Base mainnet** (the on-chain subscribe + EIP-712 attestation rail is Arbitrum Sepolia, testnet, pre-audit).

## Installation

```bash
pip install payperbyte-sdk
```

Keyless x402 pay-per-call support (the `GatewayClient`) needs the optional x402 stack:

```bash
pip install "payperbyte-sdk[x402]"
```

## Quick Start

```python
from eth_account import Account
from byte import (
    Publisher,
    Subscriber,
    Mercat,
    GatewayClient,
    verify_payload,
    HashMismatchError,
    CanonicalFormMismatchError,
    ARBITRUM_SEPOLIA,
)

# 1. Discover — browse first-party feeds via the keyless x402 gateway catalog.
gw = GatewayClient(account=Account.from_key("0x..."))   # a wallet, NOT an API key
catalog = gw.discover()                                  # GET /feeds
for feed in catalog["feeds"]:
    print(feed["id"], feed["price"], feed["provenance"])

# Or discover publishers via the indexer (Mercat).
mercat = Mercat(ARBITRUM_SEPOLIA.indexer_url)
publishers = await mercat.search(topic="eth-price")

# 2. Subscribe — register in the social registry and approve DataStream to pull
#    per-message fees directly. No escrow, no deposit: your USDC stays in your
#    wallet until a message is actually settled. allowance_usdc is a 6-decimal
#    spend ceiling sized to cover the fees you expect to pay.
#    (This leg is on Arbitrum Sepolia — testnet, pre-audit.)
subscriber = Subscriber("0x...private_key...", ARBITRUM_SEPOLIA)
subscriber.subscribe(publishers[0]["address"], allowance_usdc=10.0)

# 3. Stream — receive payload events as the publisher broadcasts.
async for msg in subscriber.stream():
    payload = fetch_from_my_archive(msg["payload_hash"])

    # 4. Verify — keccak256 of the EXACT delivered bytes vs the attested hash.
    #    Throws HashMismatchError if the bytes don't match what was attested.
    try:
        verify_payload(payload, msg["payload_hash"])
    except HashMismatchError:
        continue  # do NOT consume mismatched bytes
    consume(payload)
```

## Keyless x402 (pay-per-call)

The `GatewayClient` mirrors the PayPerByte x402 gateway. It is **keyless**: a wallet signs
the payment (EIP-3009 `transferWithAuthorization`, gasless — the facilitator broadcasts and
pays gas), settled in USDC on Base mainnet. There is **no API key** anywhere.

```python
from eth_account import Account
from byte import GatewayClient

gw = GatewayClient(account=Account.from_key("0x..."))    # defaults to https://x402.payperbyte.io
result = gw.fetch_feed("weather")                        # GET -> 402 -> sign USDC -> retry -> data
print(result["data"])
print(result["settlement"])        # {"success", "payer", "transaction"} (on-chain settle tx) or None
print(result["disclaimerCategory"])
```

Verdict oracles are POST feeds that take a JSON body and answer BEFORE you act — a signed
ALLOW/WARN/BLOCK with an embedded EIP-712 receipt over the exact answer bytes:

```python
result = gw.fetch_feed("address-reputation", body={
    "domain": "example.com",                              # the payee's web domain
    "address": "0x1111111111111111111111111111111111111111",  # receiving address
    "chain": "base",
})
# result["data"]["answer"]["verdict"]  -> "ALLOW" | "WARN" | "BLOCK"
# result["data"]["attestation"]        -> EIP-712 receipt: recompute keccak256(answer),
#                                         recover the signer, THEN act
```

(`pkg-verdict` does the same for software packages.) The verdict is a screening signal —
the receipt proves who signed these exact bytes, not that the verdict is correct.

> **Two distinct USDC flows.** The on-chain settlement leg (`Subscriber.subscribe` →
> register in DataRegistry + approve DataStream as a direct USDC spender, Arbitrum
> Sepolia) is independent of the x402 gateway payment (`GatewayClient` → EIP-3009 USDC
> on Base at fetch time). Pay-per-call feeds need only the x402 leg.

## Features

- **Feed discovery** — browse the x402 gateway catalog (`GatewayClient.discover`) or search publishers via the indexer (`Mercat`)
- **Subscription management** — subscribe, unsubscribe, check status (direct-allowance USDC settlement; the SDK approves DataStream as a direct spender)
- **Data streaming** — publish and receive payloads via DataStream
- **Payload verification** — byte-exact `keccak256` against the EIP-712 attested hash, plus a form-aware archive path that fails closed (`CanonicalFormMismatchError`) instead of raising a tamper alarm it cannot prove
- **Keyless x402** — pay-per-call feed access with a wallet (EIP-3009, USDC on Base), no API key
- **Provenance** — read publisher status, subscriber/message counts, and revenue from the on-chain registry

## Network Support

| Network | Chain ID | Role | Status |
|---------|----------|------|--------|
| Base | 8453 | x402 USDC payment settlement (`GatewayClient`) | **Live (mainnet)** |
| Arbitrum Sepolia | 421614 | On-chain subscribe + EIP-712 attestation anchor | Live (testnet, pre-audit) |
| Arbitrum One | 42161 | Attestation mainnet re-anchor | Planned (audit-gated) |

## PayPerByte contracts

PayPerByte is a lean 3-contract core. No token; all settlement is in external USDC. Subscriptions are a direct ERC-20 allowance — there is no escrow contract. A subscriber registers in DataRegistry and grants DataStream a USDC allowance; DataStream pulls the exact per-message fee with `transferFrom` at publish time, so funds stay in the subscriber's wallet until a message is settled. Each payload carries an EIP-712 `PayloadAttestation` so subscribers can confirm exactly what they received and from whom.

| Contract | Role |
|----------|------|
| DataRegistry | Publisher registration; subscriber social registry (`subscribe` / `unsubscribe` / `isSubscribed`) |
| DataStream | Per-message payload settlement; pulls fees via direct USDC allowance |
| SchemaRegistry | Feed schema + methodology references |

Contract and settlement-USDC addresses are resolved per-network by the SDK (`ARBITRUM_SEPOLIA`, `LOCAL_ANVIL`).

## Canonical payload bytes — two forms, and why byte-exact verification wins

The primary verify path is **byte-exact**: hash the exact bytes you received
(`verify_payload`) against the attested hash. That path needs no canonicalization at all
and is the strongest tamper evidence the SDK offers. Prefer it whenever you hold the
delivered bytes.

Canonicalization only enters when a payload is *re-serialized* (e.g. re-deriving bytes from
a parsed archive envelope) — and the stack has **two canonical-JSON forms there, not one**:

- **SDK publish path** (`byte.canonical`): recursively key-sorted, no whitespace,
  `ensure_ascii=False`. Matches the TypeScript SDK for payloads that keep values to
  strings/bools/ints; floats, huge ints, and non-BMP keys are explicitly out of scope
  (this is NOT full RFC 8785/JCS).
- **First-party live feeds** (`data-feeds`): INSERTION-ORDER compact JSON — a frozen
  hash-compatibility surface that must never be re-sorted.

A payload signed under one form will not hash-match a re-derivation under the other, so
`fetch_and_verify` is **form-aware**: it tries the raw response bytes and every known form,
and if none reproduces the attested hash it raises `CanonicalFormMismatchError` —
deliberately NOT `HashMismatchError`, because a failed re-serialization cannot distinguish
tampering from a form mismatch. Fail closed either way: don't consume the payload; fetch
the exact delivered bytes and use byte-exact `verify_payload`.

## Modules

- `ByteClient` — low-level client holding the web3 contract instances (used by `Publisher`/`Subscriber`)
- `Publisher` — register a feed, publish data, sign EIP-712 PayloadAttestations
- `Subscriber` — subscribe (register in DataRegistry + approve DataStream as a direct USDC spender), receive payloads, stream events
- `GatewayClient` — keyless x402 pay-per-call client (a wallet, not an API key)
- `verify_payload` / `verify_event_payload` — byte-exact payload verification against attestations
- `fetch_and_verify` — archive fetch + form-aware verification (fails closed with `CanonicalFormMismatchError`)
- `Mercat` — feed search and discovery (connects to the indexer API)

## Related

- [ppb-sdk](https://github.com/0rkz/ppb-sdk) — the TypeScript sibling of this SDK
- [byte-mcp-server](https://github.com/0rkz/byte-mcp-server) — MCP server for AI agent integration
- [byte-x402-gateway](https://github.com/0rkz/byte-x402-gateway) — keyless x402 payment gateway (a wallet, not an API key)
- [byte-discovery-api](https://github.com/0rkz/byte-discovery-api) — agent discovery endpoint

## License

MIT
