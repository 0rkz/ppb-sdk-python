"""Publisher SDK — register, publish, broadcast.

r2 (2026-05-23): publish/broadcast now sign an EIP-712 PayloadAttestation that
the on-chain DataStreamLib verifies and emits in the settlement event.
Subscribers verify received bytes against the emitted attestation — see
byte.verify.verify_payload.

Settlement note (r2 direct-allowance model): per-message fees are pulled by
DataStreamLib straight from the subscriber's wallet via usdc.transferFrom at
publish time. The subscriber must hold a DataStreamLib USDC allowance >= the fee
(set once via usdc.approve(dataStream, cap); see byte.subscriber.subscribe).
There is no escrow contract and no pre-deposited budget.
"""

import time
from eth_account import Account
from eth_account.messages import encode_typed_data
from web3 import Web3
from byte.client import ByteClient
from byte.networks import NetworkConfig
from byte.canonical import canonical_bytes


CLASS_MAP = {"MACHINE": 0, "HUMAN": 1}
VTYPE_MAP = {"RTD": 0, "TIME_DELAYED": 1, "UNVERIFIABLE": 2}
STATUS_MAP = {0: "NONE", 1: "SANDBOX", 2: "ACTIVE", 3: "SUSPENDED", 4: "BANNED"}

ATTESTATION_TTL_S = 300  # 5-minute attestation freshness window.


class Publisher:
    def __init__(self, private_key: str, network: NetworkConfig):
        self.client = ByteClient(private_key, network)

    def register(self, topic: str, schema: dict):
        """Register schema + register as publisher (no token stake)."""
        w3 = self.client.w3
        methodology_hash = w3.keccak(text=schema.get("methodology", f"byte-{topic}"))
        topic_hash = w3.keccak(text=topic)

        # 1. Register schema
        self.client._send_tx(
            self.client.schema_registry.functions.registerSchema,
            schema["expected_size"], schema["max_size"], schema["frequency"],
            CLASS_MAP[schema.get("class", "MACHINE")],
            VTYPE_MAP[schema.get("verification", "RTD")],
            methodology_hash, topic_hash, schema["price_per_kb"],
        )

        # 2. Register publisher. No token stake in v1: the on-chain
        # registerPublisher(uint256 amount, bytes32 publicKey) signature is
        # called with amount=0 (no economic stake; USDC is the only asset).
        pub_key_hash = w3.keccak(text=f"{self.client.address}-{topic}")
        return self.client._send_tx(
            self.client.data_registry.functions.registerPublisher,
            0,
            pub_key_hash,
        )

    def _sign_attestation(self, payload_hash: bytes, payload_length: int, deadline: int) -> bytes:
        """Sign an EIP-712 PayloadAttestation for the active client's chain
        and DataStream contract.

        PAY_TO-class defense: refuse to sign against a placeholder DataStream
        address. Otherwise every attestation would revert
        InvalidAttestationSignature on the live r2 contract with no useful
        error trail.
        """
        addr = (self.client.network.contracts.get("data_stream") or "").strip().lower()
        if not addr or addr == "0x0000000000000000000000000000000000000000":
            raise RuntimeError(
                "Publisher._sign_attestation: network.contracts['data_stream'] "
                "is unset or zero-address — refusing to sign with a placeholder."
            )
        typed = {
            "types": {
                "EIP712Domain": [
                    {"name": "name", "type": "string"},
                    {"name": "version", "type": "string"},
                    {"name": "chainId", "type": "uint256"},
                    {"name": "verifyingContract", "type": "address"},
                ],
                "PayloadAttestation": [
                    {"name": "publisher", "type": "address"},
                    {"name": "payloadHash", "type": "bytes32"},
                    {"name": "payloadLength", "type": "uint256"},
                    {"name": "deadline", "type": "uint256"},
                ],
            },
            "primaryType": "PayloadAttestation",
            "domain": {
                "name": "BYTE Library",
                "version": "1",
                "chainId": self.client.network.chain_id,
                "verifyingContract": Web3.to_checksum_address(
                    self.client.network.contracts["data_stream"]
                ),
            },
            "message": {
                "publisher": Web3.to_checksum_address(self.client.address),
                "payloadHash": payload_hash,
                "payloadLength": payload_length,
                "deadline": deadline,
            },
        }
        signable = encode_typed_data(full_message=typed)
        # client.account is a LocalAccount built from the private key in __init__;
        # signing through it avoids re-passing the raw key.
        signed = self.client.account.sign_message(signable)
        return signed.signature

    def publish(self, subscriber: str, data: dict, max_fee: int = 0):
        """Publish data to a single subscriber (r2: signs PayloadAttestation)."""
        # Hash the SHARED canonical bytes (recursively key-sorted, no whitespace)
        # so the publish-side hash matches verify-side and the TS SDK byte-for-byte.
        payload = canonical_bytes(data)
        payload_hash = self.client.w3.keccak(payload)
        deadline = int(time.time()) + ATTESTATION_TTL_S
        signature = self._sign_attestation(payload_hash, len(payload), deadline)

        return self.client._send_tx(
            self.client.data_stream.functions.streamData,
            Web3.to_checksum_address(subscriber),
            payload_hash, len(payload), max_fee,
            (deadline, signature),
        )

    def broadcast(self, subscribers: list[str], data: dict, max_fee_per_sub: int = 0):
        """Broadcast data to multiple subscribers (r2: signs PayloadAttestation)."""
        # Same shared canonical-bytes hash as publish() — see canonical_bytes.
        payload = canonical_bytes(data)
        payload_hash = self.client.w3.keccak(payload)
        deadline = int(time.time()) + ATTESTATION_TTL_S
        signature = self._sign_attestation(payload_hash, len(payload), deadline)
        addrs = [Web3.to_checksum_address(s) for s in subscribers]

        return self.client._send_tx(
            self.client.data_stream.functions.streamBroadcast,
            addrs, payload_hash, len(payload), max_fee_per_sub,
            (deadline, signature),
        )

    def get_info(self, address: str = None):
        """Get publisher info from DataRegistry."""
        addr = Web3.to_checksum_address(address or self.client.address)
        raw = self.client.data_registry.functions.getPublisher(addr).call()

        # r2 DataRegistryLib.Publisher struct order:
        # 0 status, 1 tier, 2 stakedAmount, 3 sandboxStartTime, 4 registeredAt,
        # 5 subscriberCount, 6 messageCount, 7 totalRevenue, 8 lastActiveTimestamp,
        # 9 publicKey, 10 slashCount
        return {
            "address": addr,
            "status": STATUS_MAP.get(raw[0], "NONE"),
            "subscriber_count": raw[5],
            "message_count": raw[6],
            "total_revenue": raw[7],
        }

    def estimate_fee(self, payload_length: int):
        """Estimate the subscriber fee for a given payload size.

        r2 DataStreamLib.estimateFee returns a SINGLE subscriberFee — the
        v0.5/v0.6 per-message publishing fee is removed in BYTE Library r2.
        """
        addr = Web3.to_checksum_address(self.client.address)
        subscriber_fee = self.client.data_stream.functions.estimateFee(addr, payload_length).call()
        return {"subscriber_fee": subscriber_fee}

    def graduate(self):
        """Graduate from sandbox."""
        return self.client._send_tx(
            self.client.data_registry.functions.graduateFromSandbox,
        )
