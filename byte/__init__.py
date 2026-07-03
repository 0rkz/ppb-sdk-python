"""
payperbyte-sdk — Python SDK for PayPerByte (the BYTE Library data layer).

Verified, provenance-first data for AI agents. No token; settlement is in
external USDC on Arbitrum. Three on-chain contracts: DataRegistry (publisher /
subscriber social registry), SchemaRegistry (feed schemas), and DataStream
(per-message settlement). Subscribers approve DataStream as a direct USDC
spender — there is no escrow contract. Keyless x402 payments (a wallet, not an
API key) for pay-per-call feed access via the gateway.

Usage:
    from byte import (
        Publisher, Subscriber, GatewayClient,
        verify_payload, HashMismatchError, ARBITRUM_SEPOLIA,
    )

    # Publisher: register a schema + publisher (no token stake), then publish.
    publisher = Publisher(private_key, ARBITRUM_SEPOLIA)
    publisher.register("eth-price", schema)
    publisher.publish(subscriber_addr, {"signal": "short"})

    # Subscriber: register in the social registry + approve DataStream to pull
    # per-message fees directly (no escrow / no deposit), then stream payloads.
    subscriber = Subscriber(private_key, ARBITRUM_SEPOLIA)
    subscriber.subscribe(publisher_addr, allowance_usdc=10.0)
    async for msg in subscriber.stream():
        payload = fetch_from_archive(msg["payload_hash"])
        try:
            verify_payload(payload, msg["payload_hash"])  # keccak256 vs attested hash
        except HashMismatchError:
            continue  # do NOT consume mismatched bytes
        consume(payload)

    # Gateway: keyless x402 pay-per-call (a wallet signs EIP-3009; no API key).
    from eth_account import Account
    gw = GatewayClient(account=Account.from_key(private_key))
    result = gw.fetch_feed("crypto-top100")
"""

from byte.publisher import Publisher
from byte.subscriber import Subscriber
from byte.mercat import Mercat
from byte.client import ByteClient
from byte.gateway import GatewayClient
from byte.networks import ARBITRUM_SEPOLIA, ARBITRUM_ONE, LOCAL_ANVIL
from byte.verify import (
    verify_payload, verify_event_payload, fetch_and_verify, HashMismatchError,
    CanonicalFormMismatchError,
)
from byte.attestation import (
    verify, verify_attestation, verify_from_gateway_response,
    attestation_domain, PAYLOAD_ATTESTATION_TYPES, Verdict,
)

__all__ = ["Publisher", "Subscriber", "Mercat", "ByteClient", "GatewayClient",
           "ARBITRUM_SEPOLIA", "ARBITRUM_ONE", "LOCAL_ANVIL",
           "verify_payload", "verify_event_payload", "fetch_and_verify",
           "HashMismatchError", "CanonicalFormMismatchError",
           # verify-before-act signer leg (Trust Kit)
           "verify", "verify_attestation", "verify_from_gateway_response",
           "attestation_domain", "PAYLOAD_ATTESTATION_TYPES", "Verdict"]
