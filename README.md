# payperbyte-sdk — PayPerByte Python SDK

Python SDK for PayPerByte (the BYTE Library data layer) — the verified, provenance-first data layer for AI agents. Discover first-party feeds, subscribe, stream payloads, and verify every payload against its on-chain EIP-712 attestation. No token; direct-allowance USDC settlement on Arbitrum.

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
subscriber = Subscriber("0x...private_key...", ARBITRUM_SEPOLIA)
subscriber.subscribe(publishers[0]["address"], allowance_usdc=10.0)

# 3. Stream — receive payload events as the publisher broadcasts.
async for msg in subscriber.stream():
    payload = fetch_from_my_archive(msg["payload_hash"])

    # 4. Verify — keccak256(canonical bytes) vs the on-chain attested hash.
    #    Throws HashMismatchError if the bytes don't match what was attested.
    try:
        verify_payload(payload, msg["payload_hash"])
    except HashMismatchError:
        continue  # do NOT consume mismatched bytes
    consume(payload)
```

## Keyless x402 (pay-per-call)

The `GatewayClient` mirrors the BYTE x402 gateway. It is **keyless**: a wallet signs the
payment (EIP-3009 `transferWithAuthorization`, gasless — the facilitator broadcasts and
pays gas). There is **no API key** anywhere.

```python
from eth_account import Account
from byte import GatewayClient

gw = GatewayClient(account=Account.from_key("0x..."))    # defaults to https://x402.payperbyte.io
result = gw.fetch_feed("crypto-top100")                  # GET -> 402 -> sign USDC -> retry -> data
print(result["data"])
print(result["settlement"])        # {"success", "payer", "transaction"} (on-chain settle tx) or None
print(result["disclaimerCategory"])
```

POST oracle feeds (`fact-oracle`, `evidence-pack`, `usc-statute`) take a JSON body:

```python
result = gw.fetch_feed("fact-oracle", body={
    "question": "What is the current US federal funds rate?",
    "subscriber_address": "0x...",   # REQUIRED — must already be registered on-chain with a DataStream USDC allowance
})
```

> **Two distinct USDC flows.** The on-chain settlement leg (Subscriber.subscribe →
> register in DataRegistry + approve DataStream as a direct USDC spender) is
> independent of the x402 gateway payment (GatewayClient → EIP-3009 at fetch time).
> For `fact-oracle`, the subscriber must already be registered with a DataStream
> allowance *before* the x402 POST succeeds.

## Features

- **Feed discovery** — browse the x402 gateway catalog (`GatewayClient.discover`) or search publishers via the indexer (`Mercat`)
- **Subscription management** — subscribe, unsubscribe, check status (direct-allowance USDC settlement; the SDK approves DataStream as a direct spender)
- **Data streaming** — publish and receive payloads via DataStream
- **Payload verification** — every payload carries an EIP-712 PayloadAttestation; verify `keccak256(canonical bytes)` against the on-chain hash before acting on the data
- **Keyless x402** — pay-per-call feed access with a wallet (EIP-3009), no API key
- **Provenance** — read publisher status, subscriber/message counts, and revenue from the on-chain registry

## Network Support

| Network | Chain ID | Status |
|---------|----------|--------|
| Arbitrum Sepolia | 421614 | Live (testnet) |
| Arbitrum One | 42161 | Planned (mainnet, audit-gated) |

## PayPerByte contracts

PayPerByte is a lean 3-contract core. No token; all settlement is in external USDC. Subscriptions are a direct ERC-20 allowance — there is no escrow contract. A subscriber registers in DataRegistry and grants DataStream a USDC allowance; DataStream pulls the exact per-message fee with `transferFrom` at publish time, so funds stay in the subscriber's wallet until a message is settled. Each payload carries an EIP-712 `PayloadAttestation` so subscribers can confirm exactly what they received and from whom.

| Contract | Role |
|----------|------|
| DataRegistry | Publisher registration; subscriber social registry (`subscribe` / `unsubscribe` / `isSubscribed`) |
| DataStream | Per-message payload settlement; pulls fees via direct USDC allowance |
| SchemaRegistry | Feed schema + methodology references |

Contract and settlement-USDC addresses are resolved per-network by the SDK (`ARBITRUM_SEPOLIA`, `LOCAL_ANVIL`).

## Canonical payload bytes

Publish-side and verify-side hashing both use the same canonical form (`byte.canonical`):
UTF-8 of JSON with recursively lexicographically-sorted object keys and no insignificant
whitespace. This guarantees `keccak256` parity across the publish/verify boundary **and**
between the Python and TypeScript SDKs. Keep payload values to strings, bools, and integers
that round-trip identically across languages (or pre-stringify floats); full RFC-8785/JCS
float/large-integer normalization is out of scope.

## Modules

- `ByteClient` — low-level client holding the web3 contract instances (used by `Publisher`/`Subscriber`)
- `Publisher` — register a feed, publish data, sign EIP-712 PayloadAttestations
- `Subscriber` — subscribe (register in DataRegistry + approve DataStream as a direct USDC spender), receive payloads, stream events
- `GatewayClient` — keyless x402 pay-per-call client (a wallet, not an API key)
- `verify_payload` / `verify_event_payload` / `fetch_and_verify` — subscriber-side payload verification against on-chain attestations
- `Mercat` — feed search and discovery (connects to the indexer API)

## Related

- [byte-mcp-server](https://github.com/0rkz/byte-mcp-server) — MCP server for AI agent integration
- [byte-x402-gateway](https://github.com/0rkz/byte-x402-gateway) — keyless x402 payment gateway (a wallet, not an API key)
- [byte-discovery-api](https://github.com/0rkz/byte-discovery-api) — agent discovery endpoint

## License

MIT
