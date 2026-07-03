"""Core client — wraps web3.py contract instances."""

import json
from pathlib import Path
from web3 import Web3, AsyncWeb3
from web3.middleware import ExtraDataToPOAMiddleware
from byte.networks import NetworkConfig, ZERO

ABI_DIR = Path(__file__).parent / "abis"

# Minimal ERC-20 ABI for the settlement USDC handle — only the methods the SDK
# needs to approve DataStreamLib as a direct spender and to read the resulting
# allowance (the r2 direct-allowance model; per-message fees are pulled by
# DataStreamLib via transferFrom, so there is no escrow contract to approve).
ERC20_ABI = [
    {"type": "function", "name": "approve", "stateMutability": "nonpayable",
     "inputs": [{"name": "spender", "type": "address"}, {"name": "amount", "type": "uint256"}],
     "outputs": [{"name": "", "type": "bool"}]},
    {"type": "function", "name": "allowance", "stateMutability": "view",
     "inputs": [{"name": "owner", "type": "address"}, {"name": "spender", "type": "address"}],
     "outputs": [{"name": "", "type": "uint256"}]},
    {"type": "function", "name": "decimals", "stateMutability": "view",
     "inputs": [], "outputs": [{"name": "", "type": "uint8"}]},
]


def _load_abi(name: str) -> list:
    path = ABI_DIR / f"{name}.json"
    if path.exists():
        return json.loads(path.read_text())
    return []


class ByteClient:
    def __init__(self, private_key: str, network: NetworkConfig):
        self.network = network
        self.w3 = Web3(Web3.HTTPProvider(network.rpc_url))
        self.w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)
        self.account = self.w3.eth.account.from_key(private_key)
        self.address = self.account.address

        c = network.contracts
        self.data_registry = self.w3.eth.contract(address=c["data_registry"], abi=_load_abi("DataRegistry"))
        self.schema_registry = self.w3.eth.contract(address=c["schema_registry"], abi=_load_abi("SchemaRegistry"))
        self.data_stream = self.w3.eth.contract(address=c["data_stream"], abi=_load_abi("DataStream"))
        # Settlement USDC ERC-20 handle. The subscriber approves DataStreamLib
        # directly as a spender; DataStreamLib transferFroms the per-message fee
        # at publish time (r2 direct-allowance model — no escrow contract).
        self.usdc = self.w3.eth.contract(address=c.get("usdc", ZERO), abi=ERC20_ABI)

    def _send_tx(self, tx_func, *args, **kwargs):
        """Build, sign, and send a transaction."""
        tx = tx_func(*args).build_transaction({
            "from": self.address,
            "nonce": self.w3.eth.get_transaction_count(self.address),
            "gas": kwargs.get("gas", 500_000),
            "maxFeePerGas": self.w3.eth.gas_price * 2,
            "maxPriorityFeePerGas": self.w3.to_wei(0.1, "gwei"),
        })
        signed = self.account.sign_transaction(tx)
        tx_hash = self.w3.eth.send_raw_transaction(signed.raw_transaction)
        receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
        return {"hash": tx_hash.hex(), "status": "success" if receipt.status == 1 else "reverted",
                "block": receipt.blockNumber, "gas_used": receipt.gasUsed}
