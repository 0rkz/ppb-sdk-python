"""Subscriber SDK — subscribe (r2 direct-allowance), stream."""

import asyncio
from web3 import Web3
from byte.client import ByteClient
from byte.networks import NetworkConfig


class Subscriber:
    def __init__(self, private_key: str, network: NetworkConfig):
        self.client = ByteClient(private_key, network)

    def subscribe(self, publisher: str, allowance_usdc: float = 10.0):
        """Subscribe to a publisher (PayPerByte r2 direct-allowance model).

        There is NO escrow contract. The two on-chain steps are:

          1. dataRegistry.subscribe(publisher) — the social/registry side. It
             flips subscriptions[subscriber][publisher] = true (read back via
             isSubscribed) and bumps the publisher's subscriberCount. Settlement
             reverts SubscriberNotRegistered without it.
          2. usdc.approve(dataStream, allowanceCap) — sets a DIRECT ERC-20
             allowance from the subscriber to DataStreamLib. At publish time
             streamData / streamBroadcast pull the exact per-message fee with
             usdc.transferFrom(subscriber, ...). The cap is a spend ceiling, not
             a deposit — no funds move at subscribe time, and the subscriber's
             USDC stays in their own wallet until a message is actually settled.

        `allowance_usdc` is the approval cap in 6-decimal USDC; size it to cover
        the fees you expect to pay (refresh it with a fresh subscribe() call when
        it runs low). Pass 0 to register in the social registry only and approve
        DataStreamLib separately.
        """
        pub = Web3.to_checksum_address(publisher)
        allowance_cap = int(allowance_usdc * 1e6)

        data_stream_addr = Web3.to_checksum_address(
            self.client.network.contracts["data_stream"]
        )

        # 1. Cross-check DataStreamLib's settlement-USDC getter matches our
        # config — eliminates settlement-USDC address drift before we approve.
        on_chain_usdc = Web3.to_checksum_address(
            self.client.data_stream.functions.usdc().call()
        )
        cfg_usdc = Web3.to_checksum_address(self.client.network.contracts["usdc"])
        if on_chain_usdc != cfg_usdc:
            raise RuntimeError(
                "USDC address drift: DataStream.usdc()="
                f"{on_chain_usdc} != NetworkConfig usdc={cfg_usdc}. "
                "Refusing to approve against a mismatched token."
            )

        # 2. Register in DataRegistry (social/registry side, bumps subscriberCount).
        try:
            self.client._send_tx(
                self.client.data_registry.functions.subscribe, pub,
            )
        except Exception:
            pass  # Already subscribed (AlreadySubscribed) — registry state stands.

        # 3. Approve DataStreamLib as a direct spender if the allowance is short.
        if allowance_cap > 0:
            current = self.client.usdc.functions.allowance(
                self.client.address, data_stream_addr
            ).call()
            if current < allowance_cap:
                return self.client._send_tx(
                    self.client.usdc.functions.approve,
                    data_stream_addr, allowance_cap,
                )
        return None

    def unsubscribe(self, publisher: str):
        """Unsubscribe from the social registry.

        This clears subscriptions[subscriber][publisher] via
        dataRegistry.unsubscribe(publisher). It does NOT touch the USDC
        allowance — there is no escrow to withdraw. To stop DataStreamLib being
        able to pull fees, set the allowance to 0 with revoke_allowance().
        """
        pub = Web3.to_checksum_address(publisher)
        return self.client._send_tx(
            self.client.data_registry.functions.unsubscribe, pub,
        )

    def revoke_allowance(self):
        """Set the DataStreamLib USDC allowance to 0 (revoke spend authority)."""
        data_stream_addr = Web3.to_checksum_address(
            self.client.network.contracts["data_stream"]
        )
        return self.client._send_tx(
            self.client.usdc.functions.approve, data_stream_addr, 0,
        )

    def is_subscribed(self, publisher: str) -> bool:
        """True if registered in the social registry (dataRegistry.isSubscribed)."""
        pub = Web3.to_checksum_address(publisher)
        return self.client.data_registry.functions.isSubscribed(
            self.client.address, pub
        ).call()

    def allowance(self) -> int:
        """Current USDC allowance (6-decimal) granted to DataStreamLib."""
        data_stream_addr = Web3.to_checksum_address(
            self.client.network.contracts["data_stream"]
        )
        return self.client.usdc.functions.allowance(
            self.client.address, data_stream_addr
        ).call()

    def get_subscription(self, publisher: str) -> dict:
        """Combined subscription view for a publisher (r2 direct-allowance).

        Returns the social-registry membership plus the spend ceiling the
        subscriber has granted DataStreamLib. There is no per-publisher budget /
        spent / duration — fees are pulled per-message against the single
        DataStreamLib allowance shared across all of this subscriber's feeds.
        """
        return {
            "subscribed": self.is_subscribed(publisher),
            "data_stream_allowance": self.allowance(),
        }

    async def stream(self, publisher: str = None, poll_interval: float = 2.0):
        """Async generator yielding incoming DataStreamed events."""
        w3 = self.client.w3
        addr = self.client.address
        last_block = w3.eth.block_number

        event_abi = self.client.data_stream.events.DataStreamed
        event_filter_args = {"subscriber": addr}
        if publisher:
            event_filter_args["publisher"] = Web3.to_checksum_address(publisher)

        while True:
            await asyncio.sleep(poll_interval)
            current_block = w3.eth.block_number
            if current_block <= last_block:
                continue

            logs = event_abi.get_logs(
                fromBlock=last_block + 1,
                toBlock=current_block,
                argument_filters=event_filter_args,
            )

            for log in logs:
                # r2: events carry attestationDeadline + attestation. Both are
                # absent on legacy pre-r2 events — surface as None so the caller
                # (or verify_event_payload) can no-op gracefully.
                args = log.args
                yield {
                    "publisher": args.publisher,
                    "subscriber": args.subscriber,
                    "payload_hash": args.payloadHash.hex(),
                    "payload_length": args.payloadLength,
                    "fee": args.subscriberFee,
                    "timestamp": args.timestamp,
                    "attestation_deadline": getattr(args, "attestationDeadline", None),
                    "attestation": (
                        getattr(args, "attestation", None).hex()
                        if getattr(args, "attestation", None) else None
                    ),
                }

            last_block = current_block
