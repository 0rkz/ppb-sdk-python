"""
Trust Kit (signer leg) — verify-before-act provenance for the BYTE Library.

Faithful Python port of ``sdk/typescript/src/attestation.ts``. The shipped
``verify_payload()`` does the HASH leg only (keccak256(bytes) == attested hash).
This module adds the MISSING signer leg — EIP-712 recovery of the publisher /
gateway attester — and composes both into a single :class:`Verdict`:

  1. HASH leg   — keccak256(received_bytes) == the attested payload_hash.
  2. SIGNER leg — recover_typed_data(...) == the pinned attester address.

``verified`` is the AND of both legs.

CONSENSUS-CRITICAL: the EIP-712 domain ``name="BYTE Library"`` (version ``"1"``,
chainId, verifyingContract = the DataStream contract) is the signing constant
shared BYTE-IDENTICALLY across the on-chain DataStreamLib verifier, the gateway
producer, the MCP verifier, the TypeScript SDK, and this module. It is NEVER
renamed — a different name produces a different EIP-712 digest and silently
breaks every existing verifier and every emitted settlement receipt. It is the
signing constant, not a brand.

Throws nothing — every path returns a :class:`Verdict` (recovery failures become
``signer_match=False`` rather than exceptions), exactly mirroring the TS contract.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass
from typing import Optional, Union

from web3 import Web3
from eth_account import Account
from eth_account.messages import encode_typed_data

from byte.networks import NetworkConfig

# ─── EIP-712 type + domain (consensus-critical; mirror attestation.ts exactly) ──

#: Must match DataStreamLib.PAYLOAD_ATTESTATION_TYPEHASH literally:
#:   PayloadAttestation(address publisher,bytes32 payloadHash,uint256 payloadLength,uint256 deadline)
PAYLOAD_ATTESTATION_TYPES = {
    "PayloadAttestation": [
        {"name": "publisher", "type": "address"},
        {"name": "payloadHash", "type": "bytes32"},
        {"name": "payloadLength", "type": "uint256"},
        {"name": "deadline", "type": "uint256"},
    ],
}

_DIGITS = re.compile(r"[0-9]+")  # ASCII-only, to mirror JS /^\d+$/ exactly
# A valid 0x-hex byte string: "0x" + an EVEN number of hex digits ("0x" == empty).
_HEX_BODY = re.compile(r"0x([0-9a-fA-F]{2})*")
# A bytes32 value: exactly 32 bytes == 64 hex digits after "0x".
_BYTES32 = re.compile(r"0x[0-9a-fA-F]{64}")


def _is_hex_str(s: str) -> bool:
    """True iff ``s`` is "0x" + an even number of hex digits (a well-formed
    byte string). Mirrors the only case where viem's hex path is well-defined."""
    return bool(_HEX_BODY.fullmatch(s))


def _is_bytes32(s) -> bool:
    """True iff ``s`` is exactly a 32-byte hex value (66 chars incl. 0x)."""
    return isinstance(s, str) and bool(_BYTES32.fullmatch(s))


def attestation_domain(net: NetworkConfig) -> dict:
    """The EIP-712 domain for a PayloadAttestation. ``name`` is CONSENSUS-CRITICAL
    — NEVER change it. Identical across the contract, gateway, MCP, and TS SDK."""
    return {
        "name": "BYTE Library",
        "version": "1",
        "chainId": net.chain_id,
        "verifyingContract": net.contracts["data_stream"],
    }


@dataclass
class Verdict:
    """The verify-before-act verdict. ``verified == hash_match and signer_match``;
    everything else is the evidence that produced it (for logs / post-mortems)."""

    #: hash_match AND signer_match. The single "safe to act?" boolean.
    verified: bool
    #: keccak256(payload_bytes) == payload_hash.
    hash_match: bool
    #: recovered == expected attester. ``None`` means there was nothing to verify
    #: (empty/missing attestation, or no pinned attester) — fail-closed, never
    #: "pass on the hash alone".
    signer_match: Optional[bool]
    #: The recovered EIP-712 signer address (checksummed), or ``None``.
    recovered: Optional[str]
    #: deadline < now. ADVISORY ONLY — does NOT affect ``verified``.
    expired: bool
    #: Human-readable verdict for logs / post-mortem.
    reason: str


# ─── helpers (mirror toBytesHex / normalizeHash / hasAttestation / toBigIntOr) ──


def _keccak_of_body(payload_bytes: Union[bytes, bytearray, str]) -> str:
    """keccak256 of the EXACT body → lowercased 0x-hex. Mirrors TS ``toBytesHex``:
    bytes → hash the bytes; str ``"0x.."`` → hash the hex bytes; other str → hash
    its UTF-8 encoding. (The gateway signs the exact response bytes.)"""
    if isinstance(payload_bytes, (bytes, bytearray)):
        digest = Web3.keccak(bytes(payload_bytes))
    elif isinstance(payload_bytes, str):
        # A 0x-prefixed VALID-hex string is the bytes it encodes (matches viem's
        # toBytesHex). A 0x-prefixed string that is NOT valid hex is treated as
        # UTF-8 text — `Web3.keccak(hexstr=...)` would raise on non-hex; this
        # keeps the hash leg throw-free and matches viem for all non-hex text.
        if payload_bytes.startswith("0x") and _is_hex_str(payload_bytes):
            digest = Web3.keccak(hexstr=payload_bytes)
        else:
            digest = Web3.keccak(text=payload_bytes)
    else:
        raise TypeError("payload_bytes must be bytes or str")
    h = digest.hex()
    return (h if h.startswith("0x") else "0x" + h).lower()


def _normalize_hash(h: Union[str, bytes, bytearray]) -> str:
    """Lowercased 0x-prefixed hex hash string."""
    if isinstance(h, (bytes, bytearray)):
        return "0x" + bytes(h).hex().lower()
    low = h.lower()
    return low if low.startswith("0x") else "0x" + low


def _has_attestation(att) -> bool:
    """An attestation is "present" only if it is a non-empty hex string (len > 2 —
    i.e. more than just ``"0x"``)."""
    return isinstance(att, str) and len(att) > 2


def _to_bigint_or(value) -> Optional[int]:
    """Coerce an attested numeric field (payload_length / deadline) to a
    non-negative int, or ``None`` if missing / fractional / negative / malformed.
    A ``None`` routes the caller into the fail-closed path rather than throwing —
    these fields arrive over an untrusted transport. Mirrors TS ``toBigIntOr``.

    NOTE: ``bool`` is an ``int`` subclass in Python; reject it explicitly so a JSON
    boolean fails closed exactly as it does in TS (where ``true.trim()`` throws)."""
    if value is None or isinstance(value, bool):
        return None
    try:
        if isinstance(value, int):
            return value if value >= 0 else None
        if isinstance(value, float):
            return int(value) if value.is_integer() and value >= 0 else None
        if isinstance(value, str):
            s = value.strip()
            return int(s) if _DIGITS.fullmatch(s) else None
    except Exception:
        return None
    return None


# ─── verify_attestation() — hash + signer recovery (the core) ───────────────────


def verify_attestation(
    *,
    payload_bytes: Union[bytes, str],
    attestation: Optional[str],
    expected_publisher: str,
    payload_hash: str,
    payload_length: int,
    deadline: int,
    net: NetworkConfig,
    now_seconds: Optional[int] = None,
) -> Verdict:
    """Verify both legs: the received bytes hash to ``payload_hash`` AND the
    signature recovers to ``expected_publisher``.

    Edge cases (these ARE the spec — see PHASE0_TRUST_KIT_SDK_SPEC "Behavior"):
      - Tampered bytes      → hash_match=False, verified=False.
      - Wrong/forged signer → signer_match=False, verified=False.
      - Empty/missing att   → signer_match=None, verified=False (FAIL-CLOSED;
                              never pass on the hash alone).
      - Expired deadline    → expired=True, but verified is UNAFFECTED (staleness
                              is a freshness axis, not a provenance verdict).

    Throws nothing — recovery failures become signer_match=False, not exceptions.
    """
    now = now_seconds if now_seconds is not None else int(time.time())
    # Throw-free: a non-int deadline (None/str off an untrusted transport) must
    # not raise from the public verify()/verify_attestation() — mirror the TS
    # contract (returns a Verdict, never throws). Advisory only.
    try:
        expired = deadline < now
    except TypeError:
        expired = False

    # ── HASH leg (throw-free) ──
    hash_match = False
    try:
        hash_match = _keccak_of_body(payload_bytes) == _normalize_hash(payload_hash)
    except Exception:
        hash_match = False

    # ── Empty / missing attestation → FAIL-CLOSED (do not pass on hash alone) ──
    if not _has_attestation(attestation):
        return Verdict(
            verified=False,
            hash_match=hash_match,
            signer_match=None,
            recovered=None,
            expired=expired,
            reason=(
                "no attestation signature to verify — fail-closed (the bytes hash-match, "
                "but provenance is unproven without the publisher signature)"
                if hash_match
                else "no attestation signature, and the bytes do not match the attested hash — fail-closed"
            ),
        )

    # ── SIGNER leg ──
    recovered: Optional[str] = None
    signer_match = False
    try:
        # A bytes32 payloadHash MUST be exactly 32 bytes. viem rejects any other
        # length (throws → caught → signer_match False); eth_account would instead
        # silently pad/truncate and recover a bogus signer. Reject explicitly so
        # both verifiers converge on signer_match=False / recovered=None for any
        # malformed-length hash.
        if not _is_bytes32(payload_hash):
            raise ValueError("payloadHash is not a 32-byte value")
        signable = encode_typed_data(
            full_message={
                "domain": attestation_domain(net),
                # Declare EIP712Domain EXPLICITLY in viem's canonical field order
                # (name, version, chainId, verifyingContract). viem derives this
                # same type from the domain object; stating it here makes the
                # domain separator deterministic across eth_account versions
                # instead of relying on auto-derivation (proven byte-identical to
                # viem by the cross-language parity vector).
                "types": {
                    "EIP712Domain": [
                        {"name": "name", "type": "string"},
                        {"name": "version", "type": "string"},
                        {"name": "chainId", "type": "uint256"},
                        {"name": "verifyingContract", "type": "address"},
                    ],
                    **PAYLOAD_ATTESTATION_TYPES,
                },
                "primaryType": "PayloadAttestation",
                "message": {
                    "publisher": expected_publisher,
                    "payloadHash": payload_hash,
                    "payloadLength": payload_length,
                    "deadline": deadline,
                },
            }
        )
        rec = Account.recover_message(signable, signature=attestation)
        recovered = Web3.to_checksum_address(rec)
        signer_match = recovered.lower() == expected_publisher.lower()
    except Exception:
        # Malformed signature / bad recovery → signer mismatch, not a throw.
        recovered = None
        signer_match = False

    verified = bool(hash_match and signer_match)
    return Verdict(
        verified=verified,
        hash_match=hash_match,
        signer_match=signer_match,
        recovered=recovered,
        expired=expired,
        reason=(
            "received bytes hash-match the attested hash AND the attestation recovers to "
            "the named publisher — safe to act"
            + (" (note: deadline elapsed; advisory only, provenance is immutable)" if expired else "")
            if verified
            else "HASH MISMATCH — the received bytes are NOT what the publisher attested; do not act"
            if not hash_match
            else "attestation signature did not recover to the named publisher; do not act"
        ),
    )


def verify(**kwargs) -> Verdict:
    """The headline verify-before-act call — a thin alias for
    :func:`verify_attestation` (same keyword arguments)."""
    return verify_attestation(**kwargs)


# ─── verify_from_gateway_response() — the gateway X-BYTE-Attestation adapter ────


def _safe_parse(raw: str) -> Optional[dict]:
    # Narrow to a dict: a valid-JSON-but-non-object header (array/number/bool)
    # routes to the same fail-closed path as an unparseable one. This is an
    # intentional, throw-safety-driven divergence from the TS port — JS can
    # duck-type `att.payloadHash` on any value, but Python `list.get(...)` would
    # raise, breaking the "throws nothing" contract. Decision fields are
    # identical to TS in every case (all fail closed); only the advisory reason
    # text differs for the (pathological, non-object) header.
    try:
        v = json.loads(raw)
        return v if isinstance(v, dict) else None
    except Exception:
        return None


def _fail_closed(
    payload_bytes: Union[bytes, str],
    attested_hash: Optional[str],
    reason: str,
) -> Verdict:
    """A fail-closed Verdict that still reports an honest hash leg over the body
    when an attested hash is available. ``signer_match`` is ``None`` — there was
    nothing trustworthy to recover against."""
    hash_match = False
    if attested_hash is not None:
        try:
            hash_match = _keccak_of_body(payload_bytes) == _normalize_hash(attested_hash)
        except Exception:
            hash_match = False
    return Verdict(
        verified=False,
        hash_match=hash_match,
        signer_match=None,
        recovered=None,
        expired=False,
        reason=reason,
    )


def verify_from_gateway_response(
    response_body: Union[bytes, str],
    attestation_header: Union[str, dict, None],
    net: NetworkConfig,
    expected_attester: Optional[str] = None,
    now_seconds: Optional[int] = None,
) -> Verdict:
    """Verify a gateway response: parse the ``X-BYTE-Attestation`` header, hash the
    EXACT body bytes, and recover the gateway attester. The gateway publishes its
    attester address out-of-band (agent card / well-known); pass it as
    ``expected_attester`` so a forged header can't self-certify.

    FAIL-CLOSED on a self-asserted header: the header's ``publisher`` field is
    attacker-controlled over an untrusted transport, so a forged body+header could
    otherwise self-certify (sign with key X, claim publisher X). With no pinned
    ``expected_attester`` we therefore return verified=False / signer_match=None —
    provenance is unproven. (This is ADVERSARIAL_REVIEW HIGH #1.)

    :param response_body: the EXACT bytes the gateway returned (``bytes`` or ``str``).
    :param attestation_header: the raw ``X-BYTE-Attestation`` header value (JSON
        string), the already-parsed dict, or ``None`` if absent.
    :param expected_attester: the gateway attester address (out-of-band). REQUIRED
        for a meaningful verdict; omitting it fails closed.
    """
    att: Optional[dict] = None
    if attestation_header:
        if isinstance(attestation_header, str):
            att = _safe_parse(attestation_header)
        elif isinstance(attestation_header, dict):
            att = attestation_header

    if not att:
        return _fail_closed(
            response_body,
            None,
            "no X-BYTE-Attestation header (missing or unparseable) — provenance unproven; fail-closed",
        )

    # HIGH-FIX: a self-asserted header cannot prove provenance without a pin.
    if not expected_attester:
        ph = att.get("payloadHash")
        return _fail_closed(
            response_body,
            ph if isinstance(ph, str) else None,
            "no expected_attester pinned — a self-asserted X-BYTE-Attestation header "
            "(its `publisher` field is attacker-controlled) cannot prove provenance; "
            "pass the gateway attester address. Fail-closed.",
        )

    # Coerce numeric fields defensively (untrusted transport).
    payload_length = _to_bigint_or(att.get("payloadLength"))
    deadline = _to_bigint_or(att.get("deadline"))
    payload_hash = att.get("payloadHash")
    signature = att.get("signature")
    if (
        not isinstance(payload_hash, str)
        or not _has_attestation(signature)
        or payload_length is None
        or deadline is None
    ):
        return _fail_closed(
            response_body,
            payload_hash if isinstance(payload_hash, str) else None,
            "malformed or incomplete attestation header "
            "(signature/payloadHash/payloadLength/deadline not well-formed) — fail-closed",
        )

    return verify_attestation(
        payload_bytes=response_body,
        attestation=signature,
        expected_publisher=expected_attester,
        payload_hash=payload_hash,
        payload_length=payload_length,
        deadline=deadline,
        net=net,
        now_seconds=now_seconds,
    )
