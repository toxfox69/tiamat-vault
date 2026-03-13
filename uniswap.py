"""Uniswap Trading API module for TIAMAT VAULT.

Uses Uniswap Trading API (v1) on Base for token swaps.
Safety: max 5 USDC per swap, whitelist tokens only.

API flow: check_approval → quote → sign Permit2 → swap → broadcast tx
"""

import json
import os
import time
import urllib.request

from eth_account import Account
from web3 import Web3

BASE_RPC = "https://mainnet.base.org"
CHAIN_ID = 8453
UNISWAP_API_BASE = "https://trade-api.gateway.uniswap.org/v1"

# Token addresses on Base
TOKENS = {
    "USDC": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
    "WETH": "0x4200000000000000000000000000000000000006",
    "ETH": "0x0000000000000000000000000000000000000000",
}

TOKEN_WHITELIST = set(TOKENS.values())
MAX_SWAP_USDC = 5_000_000  # 5 USDC (6 decimals)

PERMIT2_ADDRESS = "0x000000000022D473030F116dDEE9F6B43aC78BA3"

ERC20_ABI = [
    {
        "type": "function",
        "name": "allowance",
        "inputs": [
            {"name": "owner", "type": "address"},
            {"name": "spender", "type": "address"},
        ],
        "outputs": [{"name": "", "type": "uint256"}],
        "stateMutability": "view",
    },
    {
        "type": "function",
        "name": "approve",
        "inputs": [
            {"name": "spender", "type": "address"},
            {"name": "amount", "type": "uint256"},
        ],
        "outputs": [{"name": "", "type": "bool"}],
        "stateMutability": "nonpayable",
    },
]


def _load():
    """Load wallet and API key."""
    key = os.environ.get("TIAMAT_WALLET_KEY")
    api_key = os.environ.get("UNISWAP_API_KEY")
    if not key:
        raise RuntimeError("TIAMAT_WALLET_KEY not set")
    if not api_key:
        raise RuntimeError("UNISWAP_API_KEY not set")
    w3 = Web3(Web3.HTTPProvider(BASE_RPC))
    account = Account.from_key(key)
    return w3, account, api_key


def _api_request(method: str, endpoint: str, api_key: str, data: dict = None) -> dict:
    """Make authenticated request to Uniswap Trading API."""
    url = f"{UNISWAP_API_BASE}/{endpoint}"
    headers = {
        "Content-Type": "application/json",
        "x-api-key": api_key,
        "Origin": "https://app.uniswap.org",
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
    }

    if method == "GET":
        req = urllib.request.Request(url, headers=headers)
    else:
        body = json.dumps(data).encode() if data else None
        req = urllib.request.Request(url, data=body, headers=headers, method=method)

    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read())


def resolve_token(token: str) -> str:
    """Resolve token name or address to checksummed address."""
    upper = token.upper()
    if upper in TOKENS:
        return Web3.to_checksum_address(TOKENS[upper])
    addr = Web3.to_checksum_address(token)
    if addr.lower() not in {t.lower() for t in TOKEN_WHITELIST}:
        raise ValueError(f"Token {token} not in whitelist. Allowed: {list(TOKENS.keys())}")
    return addr


def check_and_approve(token_in: str, amount: int, w3, account, api_key: str) -> str | None:
    """Check approval via API, submit on-chain if needed. Returns approval tx hash or None."""
    if token_in.lower() == TOKENS["ETH"].lower():
        return None

    # Use Uniswap's check_approval endpoint
    resp = _api_request("POST", "check_approval", api_key, {
        "token": token_in,
        "amount": str(amount),
        "walletAddress": account.address,
        "chainId": CHAIN_ID,
    })

    approval_tx = resp.get("approval")
    if not approval_tx:
        return None

    # Broadcast the approval tx
    tx = {
        "to": Web3.to_checksum_address(approval_tx["to"]),
        "data": approval_tx["data"],
        "value": int(approval_tx.get("value", "0x0"), 16),
        "from": account.address,
        "nonce": w3.eth.get_transaction_count(account.address),
        "chainId": CHAIN_ID,
        "type": 2,
    }
    base_fee = w3.eth.get_block("latest")["baseFeePerGas"]
    max_priority = w3.to_wei(0.001, "gwei")
    tx["maxFeePerGas"] = base_fee * 2 + max_priority
    tx["maxPriorityFeePerGas"] = max_priority
    gas = w3.eth.estimate_gas(tx)
    tx["gas"] = int(gas * 1.2)

    signed = account.sign_transaction(tx)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    w3.eth.wait_for_transaction_receipt(tx_hash, timeout=60)
    time.sleep(2)
    return "0x" + tx_hash.hex()


def get_quote(token_in: str, token_out: str, amount: str, wallet: str, api_key: str) -> dict:
    """Get swap quote from Uniswap Trading API. Returns full response with quote + permitData."""
    return _api_request("POST", "quote", api_key, {
        "type": "EXACT_INPUT",
        "tokenInChainId": CHAIN_ID,
        "tokenOutChainId": CHAIN_ID,
        "tokenIn": token_in,
        "tokenOut": token_out,
        "amount": str(amount),
        "swapper": wallet,
        "slippageTolerance": 0.5,
    })


def build_swap(quote_response: dict, account) -> dict:
    """Sign Permit2 data and call /swap to get the transaction. Returns swap response."""
    permit_data = quote_response.get("permitData")
    signature = None

    if permit_data:
        types_copy = dict(permit_data["types"])
        types_copy.pop("EIP712Domain", None)
        signed = account.sign_typed_data(
            permit_data["domain"],
            types_copy,
            permit_data["values"],
        )
        signature = "0x" + signed.signature.hex()

    api_key = os.environ.get("UNISWAP_API_KEY")
    payload = {
        "quote": quote_response["quote"],
        "signature": signature,
        "permitData": permit_data,
    }

    return _api_request("POST", "swap", api_key, payload)


def execute_swap(swap_response: dict, w3, account) -> str:
    """Sign and broadcast the swap transaction from /swap response. Returns tx hash."""
    swap_tx = swap_response.get("swap")
    if not swap_tx:
        raise RuntimeError(f"No 'swap' in response: {json.dumps(swap_response)[:500]}")

    value_raw = swap_tx.get("value", "0x00")
    if isinstance(value_raw, str) and value_raw.startswith("0x"):
        value = int(value_raw, 16)
    else:
        value = int(value_raw)

    tx = {
        "to": Web3.to_checksum_address(swap_tx["to"]),
        "data": swap_tx["data"],
        "value": value,
        "from": account.address,
        "nonce": w3.eth.get_transaction_count(account.address),
        "chainId": CHAIN_ID,
    }

    # Use gas info from Uniswap response if available
    if "gasPrice" in swap_tx:
        tx["gasPrice"] = int(swap_tx["gasPrice"])
        tx["gas"] = int(int(swap_tx.get("gasLimit", 300000)) * 1.2)
    else:
        base_fee = w3.eth.get_block("latest")["baseFeePerGas"]
        max_priority = w3.to_wei(0.001, "gwei")
        tx["maxFeePerGas"] = base_fee * 2 + max_priority
        tx["maxPriorityFeePerGas"] = max_priority
        tx["type"] = 2
        gas = w3.eth.estimate_gas(tx)
        tx["gas"] = int(gas * 1.2)

    signed = account.sign_transaction(tx)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=60)

    if receipt["status"] != 1:
        raise RuntimeError(f"Swap tx reverted: 0x{tx_hash.hex()}")

    return "0x" + tx_hash.hex()


def full_swap(token_in: str, token_out: str, amount: str, confirm: bool = False) -> dict:
    """Full swap orchestrator. Returns quote or executed swap."""
    w3, account, api_key = _load()

    token_in_addr = resolve_token(token_in)
    token_out_addr = resolve_token(token_out)

    # Safety: max 5 USDC
    if token_in_addr.lower() == TOKENS["USDC"].lower():
        if int(amount) > MAX_SWAP_USDC:
            raise ValueError(f"Amount {amount} exceeds max {MAX_SWAP_USDC} (5 USDC)")

    # Step 1: Check/set approval
    approval_hash = check_and_approve(token_in_addr, int(amount), w3, account, api_key)

    # Step 2: Get quote
    quote_response = get_quote(token_in_addr, token_out_addr, amount, account.address, api_key)

    amount_out = (
        quote_response.get("quote", {}).get("output", {}).get("amount")
        or quote_response.get("amountOut", "unknown")
    )

    result = {
        "token_in": token_in_addr,
        "token_out": token_out_addr,
        "amount_in": amount,
        "amount_out": amount_out,
        "gas_fee_usd": quote_response.get("quote", {}).get("gasFeeUSD"),
        "approval_tx": approval_hash,
    }

    if not confirm:
        result["status"] = "dry_run"
        result["message"] = "Quote only. Pass confirm=true to execute."
        return result

    # Step 3: Sign permit and get swap tx
    swap_response = build_swap(quote_response, account)

    # Step 4: Broadcast
    tx_hash = execute_swap(swap_response, w3, account)

    result["tx_hash"] = tx_hash
    result["basescan_url"] = f"https://basescan.org/tx/{tx_hash}"
    result["status"] = "executed"
    return result


if __name__ == "__main__":
    from dotenv import load_dotenv

    load_dotenv("/root/.env")

    print("=== TIAMAT VAULT — Uniswap Swap Test ===")

    # Dry run: get a quote for 0.10 USDC -> WETH
    amount = "100000"  # 0.10 USDC (6 decimals)
    print(f"\nGetting quote: {amount} USDC ({int(amount)/1e6} USDC) -> WETH...")

    result = full_swap("USDC", "WETH", amount, confirm=False)
    print(f"Status: {result['status']}")
    print(f"Amount out: {result['amount_out']}")
    print(f"Gas fee: ${result.get('gas_fee_usd', 'unknown')}")

    if result.get("approval_tx"):
        print(f"Approval TX: {result['approval_tx']}")

    print(json.dumps({k: v for k, v in result.items()}, indent=2, default=str))
