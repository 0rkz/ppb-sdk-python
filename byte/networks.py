from dataclasses import dataclass, field


@dataclass
class NetworkConfig:
    chain_id: int
    rpc_url: str
    contracts: dict[str, str] = field(default_factory=dict)
    indexer_url: str = ""


ZERO = "0x0000000000000000000000000000000000000000"

# `usdc` is the Arbitrum SETTLEMENT USDC — the ERC-20 the subscriber approves
# DIRECTLY to DataStreamLib so that streamData / streamBroadcast can
# transferFrom the per-message fee at publish time (r2 direct-allowance model;
# there is no escrow contract). It is SEPARATE from the x402 gateway USDC, which
# comes from the 402 accepts[] at runtime (see byte.gateway). It lives under
# `contracts` so the ERC-20 handle resolves the same way the core contracts do.
_DEFAULT_CONTRACTS = {
    "data_registry": ZERO, "schema_registry": ZERO,
    "data_stream": ZERO, "usdc": ZERO,
}

LOCAL_ANVIL = NetworkConfig(
    chain_id=31337, rpc_url="http://localhost:8545",
    # usdc: deploy a local MockUSDC and set this to its address before running
    # subscribe(). TODO(deploy-time): replace ZERO with the local USDC address.
    contracts=dict(_DEFAULT_CONTRACTS), indexer_url="http://localhost:8080",
)

ARBITRUM_SEPOLIA = NetworkConfig(
    chain_id=421614, rpc_url="https://sepolia-rollup.arbitrum.io/rpc",
    contracts={
        # r2 byte-library contracts — cited from
        # contracts/deployments/arbitrum-sepolia.json "byte-library" block
        # (deployed 2026-05-22) + "r2_redeploy" (DataStreamLib 2026-05-24).
        # The r2 DataRegistryLib / DataStreamLib supersede the dead v0.5
        # token-era DataRegistry / DataStream / StreamSubscription.
        "data_registry": "0x086990937Cf931e36E01487CD63407f281f1Fc6A",  # DataRegistryLib
        "schema_registry": "0x4102BA342A3e9f495bD553D99D1590470C32EE88",  # SchemaRegistry (byte-library)
        "data_stream": "0x44729bB148F46d8Db509E47b0453edc271e06e95",  # DataStreamLib (r2)
        # Settlement USDC — MockUSDC3009 (EIP-3009). Cited from
        # contracts/deployments/arbitrum-sepolia.json "byte-library".USDC
        # (line 88) and x402-gateway/src/lib/config.ts usdcAddress default.
        "usdc": "0x1c16659aeb3aE28467E90348fAAB8874a0D3A4d3",
    },
    indexer_url="http://localhost:8080",
)

ARBITRUM_ONE = NetworkConfig(
    chain_id=42161, rpc_url="https://arb1.arbitrum.io/rpc",
    contracts={
        "data_registry": ZERO, "schema_registry": ZERO,
        "data_stream": ZERO,
        # Circle-published native USDC on Arbitrum One. Not yet referenced by
        # any repo deploy config (mainnet is audit-gated / not deployed). This
        # is Circle's official address — CONFIRM-TODO before mainnet use.
        # https://developers.circle.com/stablecoins/usdc-contract-addresses
        "usdc": "0xaf88d065e77c8cC2239327C5EDb3A432268e5831",  # TODO: confirm at mainnet deploy
    },
)
