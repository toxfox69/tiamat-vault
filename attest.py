"""On-chain attestation module for TIAMAT VAULT.

Calls VaultAttestation contract on Base mainnet to record PII scrub receipts.
"""

import json
import os
import time

from eth_account import Account
from web3 import Web3

CONTRACT_ADDRESS = "0x47a6a776c79a7187a4fa7f7edf0a5511b034025e"
BASE_RPC = "https://mainnet.base.org"
AGENT_ID = 29931
CHAIN_ID = 8453

ABI = [
    {
        "type": "function",
        "name": "attest",
        "inputs": [
            {"name": "agentId", "type": "uint256"},
            {"name": "receiptHash", "type": "bytes32"},
            {"name": "policyHash", "type": "bytes32"},
            {"name": "ipfsCid", "type": "string"},
        ],
        "outputs": [],
        "stateMutability": "nonpayable",
    },
    {
        "type": "function",
        "name": "verify",
        "inputs": [{"name": "receiptHash", "type": "bytes32"}],
        "outputs": [
            {
                "name": "",
                "type": "tuple",
                "components": [
                    {"name": "agentId", "type": "uint256"},
                    {"name": "receiptHash", "type": "bytes32"},
                    {"name": "policyHash", "type": "bytes32"},
                    {"name": "timestamp", "type": "uint256"},
                    {"name": "attester", "type": "address"},
                    {"name": "ipfsCid", "type": "string"},
                ],
            }
        ],
        "stateMutability": "view",
    },
    {
        "type": "function",
        "name": "isAttested",
        "inputs": [{"name": "receiptHash", "type": "bytes32"}],
        "outputs": [{"name": "", "type": "bool"}],
        "stateMutability": "view",
    },
    {
        "type": "function",
        "name": "getAgentScore",
        "inputs": [{"name": "agentId", "type": "uint256"}],
        "outputs": [{"name": "", "type": "uint256"}],
        "stateMutability": "view",
    },
    {
        "type": "function",
        "name": "totalAttestations",
        "inputs": [],
        "outputs": [{"name": "", "type": "uint256"}],
        "stateMutability": "view",
    },
]


def load_wallet():
    """Load wallet from TIAMAT_WALLET_KEY env var."""
    key = os.environ.get("TIAMAT_WALLET_KEY")
    if not key:
        raise RuntimeError("TIAMAT_WALLET_KEY not set")
    w3 = Web3(Web3.HTTPProvider(BASE_RPC))
    if not w3.is_connected():
        raise RuntimeError(f"Cannot connect to {BASE_RPC}")
    account = Account.from_key(key)
    return w3, account


def receipt_hash(receipt: dict) -> bytes:
    """Compute keccak256 of canonical JSON receipt."""
    canonical = json.dumps(receipt, sort_keys=True, separators=(",", ":"))
    return Web3.keccak(text=canonical)


def policy_hash(policy: dict) -> bytes:
    """Compute keccak256 of canonical JSON policy."""
    canonical = json.dumps(policy, sort_keys=True, separators=(",", ":"))
    return Web3.keccak(text=canonical)


def attest_on_chain(agent_id: int, r_hash: bytes, p_hash: bytes, ipfs_cid: str = "") -> str:
    """Submit attestation to Base mainnet. Returns tx hash."""
    w3, account = load_wallet()
    contract = w3.eth.contract(address=Web3.to_checksum_address(CONTRACT_ADDRESS), abi=ABI)

    nonce = w3.eth.get_transaction_count(account.address)
    base_fee = w3.eth.get_block("latest")["baseFeePerGas"]
    max_priority = w3.to_wei(0.001, "gwei")

    tx = contract.functions.attest(agent_id, r_hash, p_hash, ipfs_cid).build_transaction(
        {
            "from": account.address,
            "nonce": nonce,
            "maxFeePerGas": base_fee * 2 + max_priority,
            "maxPriorityFeePerGas": max_priority,
            "chainId": CHAIN_ID,
            "type": 2,
        }
    )

    gas_estimate = w3.eth.estimate_gas(tx)
    tx["gas"] = int(gas_estimate * 1.2)

    signed = account.sign_transaction(tx)
    try:
        tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    except Exception as e:
        # Retry once on failure
        time.sleep(2)
        nonce = w3.eth.get_transaction_count(account.address)
        tx["nonce"] = nonce
        signed = account.sign_transaction(tx)
        tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)

    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=60)
    if receipt["status"] != 1:
        raise RuntimeError(f"Attestation tx reverted: {tx_hash.hex()}")

    return tx_hash.hex()


def is_attested(r_hash: bytes) -> bool:
    """Check if a receipt hash has been attested."""
    w3, _ = load_wallet()
    contract = w3.eth.contract(address=Web3.to_checksum_address(CONTRACT_ADDRESS), abi=ABI)
    return contract.functions.isAttested(r_hash).call()


def verify_attestation(r_hash: bytes) -> dict:
    """Look up attestation on-chain by receipt hash. Returns None-like dict if not found."""
    w3, _ = load_wallet()
    contract = w3.eth.contract(address=Web3.to_checksum_address(CONTRACT_ADDRESS), abi=ABI)
    # Use isAttested first to avoid revert on verify()
    if not contract.functions.isAttested(r_hash).call():
        return {"attested": False, "timestamp": 0}
    result = contract.functions.verify(r_hash).call()
    return {
        "agentId": result[0],
        "receiptHash": "0x" + result[1].hex(),
        "policyHash": "0x" + result[2].hex(),
        "timestamp": result[3],
        "attester": result[4],
        "ipfsCid": result[5],
        "attested": True,
    }


def get_agent_score(agent_id: int = AGENT_ID) -> int:
    """Get total attestation count for an agent."""
    w3, _ = load_wallet()
    contract = w3.eth.contract(address=Web3.to_checksum_address(CONTRACT_ADDRESS), abi=ABI)
    return contract.functions.getAgentScore(agent_id).call()


def get_total_attestations() -> int:
    """Get total attestations across all agents."""
    w3, _ = load_wallet()
    contract = w3.eth.contract(address=Web3.to_checksum_address(CONTRACT_ADDRESS), abi=ABI)
    return contract.functions.totalAttestations().call()


if __name__ == "__main__":
    from dotenv import load_dotenv

    load_dotenv("/root/.env")

    print("=== TIAMAT VAULT — Attestation Test ===")
    print(f"Contract: {CONTRACT_ADDRESS}")
    print(f"Agent ID: {AGENT_ID}")

    # Check current score
    score = get_agent_score()
    total = get_total_attestations()
    print(f"Current agent score: {score}")
    print(f"Total attestations: {total}")

    # Submit test attestation
    test_receipt = {
        "agent_id": AGENT_ID,
        "action": "pii_scrub",
        "pii_types_found": ["email", "phone"],
        "pii_types_redacted": ["email", "phone"],
        "text_length": 142,
        "timestamp": int(time.time()),
        "test": True,
    }
    test_policy = {"redact": ["email", "phone", "ssn"], "version": "1.0"}

    r_h = receipt_hash(test_receipt)
    p_h = policy_hash(test_policy)

    print(f"\nReceipt hash: 0x{r_h.hex()}")
    print(f"Policy hash:  0x{p_h.hex()}")
    print("Submitting attestation...")

    tx = attest_on_chain(AGENT_ID, r_h, p_h, "test-attestation")
    print(f"TX hash: 0x{tx}")
    print(f"BaseScan: https://basescan.org/tx/0x{tx}")

    # Verify it (wait for RPC to sync)
    time.sleep(3)
    att = verify_attestation(r_h)
    print(f"\nVerified on-chain:")
    print(f"  Agent ID:  {att['agentId']}")
    print(f"  Attester:  {att['attester']}")
    print(f"  Timestamp: {att['timestamp']}")
    print(f"  IPFS CID:  {att['ipfsCid']}")

    new_score = get_agent_score()
    print(f"\nAgent score after: {new_score}")
    print("=== TEST PASSED ===")
