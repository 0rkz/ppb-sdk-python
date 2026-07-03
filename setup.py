import os
from setuptools import setup

_here = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(_here, "README.md"), encoding="utf-8") as _f:
    _long_description = _f.read()

setup(
    name="payperbyte-sdk",
    version="0.2.0",
    description="Python SDK for PayPerByte — verified, provenance-first data for AI agents. No token; x402 USDC pay-per-call on Base mainnet, EIP-712 attestation verification (authenticity + tamper-evidence, not correctness).",
    long_description=_long_description,
    long_description_content_type="text/markdown",
    packages=["byte"],
    python_requires=">=3.10",
    install_requires=[
        # web3 7+: byte.client uses ExtraDataToPOAMiddleware (a 7.x symbol) and
        # the verify-before-act signer leg (byte.attestation) needs
        # eth_account.encode_typed_data, which web3 7 pulls (eth-account>=0.13.6).
        "web3>=7.0",
        # Declared directly: byte.attestation imports eth_account symbols and
        # encode_typed_data(full_message=...) first exists in eth-account 0.10;
        # 0.13.6 is the tested/known-good (digest byte-identical to viem) line.
        "eth-account>=0.13.6",
        "aiohttp>=3.9",
    ],
    extras_require={
        # Keyless x402 GatewayClient (byte.gateway). Heavy x402 stack kept
        # optional so `import byte` works without it. Pinned to the gateway's
        # @x402 v2 line (x402-gateway/examples/agent-client/python/requirements.txt).
        "x402": [
            "x402[evm,requests]==2.12.0",
            "eth-account==0.13.7",
            "web3==7.16.0",
            "requests==2.34.2",
        ],
    },
    package_data={"byte": ["abis/*.json"]},
)
