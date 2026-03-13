"""VAULT Encrypted Receipts — ECIES encryption for privacy attestation receipts.

Encrypts scrub receipts with the data owner's public key so only they
can decrypt and verify what was scrubbed. The encrypted blob is stored
locally and its content hash goes on-chain in the attestation's ipfsCid field.

Flow:
  1. Scrub PII → build receipt dict
  2. Encrypt receipt JSON with owner's ETH public key (ECIES)
  3. Store encrypted blob at /vault/receipts/<content_hash>
  4. content_hash goes on-chain as ipfsCid in attestation
  5. Owner fetches blob, decrypts with their private key → verifies receipt

Crypto: secp256k1 ECIES (same curve as Ethereum)
"""

import hashlib
import json
import os

import ecies
from eth_account import Account

RECEIPT_DIR = "/root/vault/encrypted_receipts"
os.makedirs(RECEIPT_DIR, exist_ok=True)


def _public_key_from_private(private_key_hex: str) -> str:
    """Derive the uncompressed public key hex from a private key."""
    acct = Account.from_key(private_key_hex)
    # eth_account stores the key object; get raw public key bytes
    # The public key is 64 bytes (uncompressed, without 04 prefix)
    pk_bytes = acct._key_obj.public_key.to_bytes()
    # eciespy expects hex string of uncompressed public key (with 04 prefix)
    return "04" + pk_bytes.hex()


def _content_hash(data: bytes) -> str:
    """Compute content-addressed hash (sha256) for the encrypted blob."""
    return "0x" + hashlib.sha256(data).hexdigest()


def encrypt_receipt(receipt: dict, owner_public_key_hex: str) -> tuple[str, bytes]:
    """Encrypt a receipt dict with the owner's public key.

    Args:
        receipt: The scrub receipt (clean_text, detected_pii, policy, etc.)
        owner_public_key_hex: Uncompressed public key hex (with 04 prefix)
                              OR compressed (02/03 prefix)

    Returns:
        (content_hash, encrypted_bytes)
    """
    # Canonicalize the receipt JSON
    receipt_json = json.dumps(receipt, sort_keys=True, separators=(",", ":"))
    plaintext = receipt_json.encode("utf-8")

    # Encrypt with ECIES (secp256k1)
    encrypted = ecies.encrypt(owner_public_key_hex, plaintext)

    # Content-addressed hash
    c_hash = _content_hash(encrypted)

    return c_hash, encrypted


def decrypt_receipt(encrypted_bytes: bytes, owner_private_key_hex: str) -> dict:
    """Decrypt an encrypted receipt blob with the owner's private key.

    Args:
        encrypted_bytes: The encrypted blob
        owner_private_key_hex: The owner's private key (hex, with or without 0x)

    Returns:
        The decrypted receipt dict
    """
    key = owner_private_key_hex.replace("0x", "")
    plaintext = ecies.decrypt(key, encrypted_bytes)
    return json.loads(plaintext.decode("utf-8"))


def store_encrypted_receipt(receipt: dict, owner_public_key_hex: str) -> str:
    """Encrypt and store a receipt. Returns the content hash.

    The content hash is what goes on-chain in the attestation's ipfsCid field.
    """
    c_hash, encrypted = encrypt_receipt(receipt, owner_public_key_hex)

    # Store blob
    filename = c_hash.replace("0x", "") + ".enc"
    filepath = os.path.join(RECEIPT_DIR, filename)
    with open(filepath, "wb") as f:
        f.write(encrypted)

    return c_hash


def load_encrypted_receipt(content_hash: str) -> bytes | None:
    """Load an encrypted receipt blob by its content hash."""
    filename = content_hash.replace("0x", "") + ".enc"
    filepath = os.path.join(RECEIPT_DIR, filename)
    if os.path.exists(filepath):
        with open(filepath, "rb") as f:
            return f.read()
    return None


def verify_receipt(content_hash: str, owner_private_key_hex: str) -> dict | None:
    """Load, decrypt, and return a receipt. Returns None if not found."""
    encrypted = load_encrypted_receipt(content_hash)
    if encrypted is None:
        return None
    return decrypt_receipt(encrypted, owner_private_key_hex)


# Also detect crypto-sensitive PII (private keys, seed phrases, etc.)
# These patterns catch the most dangerous data types

import re

CRYPTO_PII_PATTERNS = {
    "eth_private_key": re.compile(
        r"(?:0x)?[0-9a-fA-F]{64}(?=\s|$|[^0-9a-fA-F])",
    ),
    "seed_phrase": re.compile(
        # 12 or 24 word mnemonic (BIP-39) — detect sequences of 12+ lowercase words
        r"\b(?:[a-z]{3,8}\s+){11,23}[a-z]{3,8}\b",
    ),
    "btc_private_key_wif": re.compile(
        # WIF format: starts with 5, K, or L, base58, 51-52 chars
        r"\b[5KL][1-9A-HJ-NP-Za-km-z]{50,51}\b",
    ),
    "api_key_generic": re.compile(
        # Common API key patterns: sk-, pk-, key-, api- prefixed
        r"\b(?:sk|pk|api|key|secret|token)[-_][A-Za-z0-9_\-]{20,}\b",
        re.IGNORECASE,
    ),
    "jwt_token": re.compile(
        r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",
    ),
}

CRYPTO_REDACT_LABELS = {
    "eth_private_key": "[PRIVATE_KEY_REDACTED]",
    "seed_phrase": "[SEED_PHRASE_REDACTED]",
    "btc_private_key_wif": "[PRIVATE_KEY_REDACTED]",
    "api_key_generic": "[API_KEY_REDACTED]",
    "jwt_token": "[JWT_REDACTED]",
}


if __name__ == "__main__":
    import sys

    # Test encryption round-trip
    print("=== VAULT Encrypted Receipt Test ===\n")

    # Generate a test keypair
    test_acct = Account.create()
    pub_key = _public_key_from_private(test_acct.key.hex())
    print(f"Test address: {test_acct.address}")
    print(f"Public key:   {pub_key[:20]}...{pub_key[-8:]}")

    test_receipt = {
        "clean_text": "My email is [EMAIL_REDACTED], SSN [SSN_REDACTED]",
        "detected_pii": {"email": ["alice@company.com"], "ssn": ["987-65-4321"]},
        "pii_types_found": ["email", "ssn"],
        "pii_types_redacted": ["email", "ssn"],
        "redaction_count": 2,
        "agent_id": 29931,
        "timestamp": 1710000000,
    }

    # Encrypt & store
    print("\nEncrypting receipt...")
    content_hash = store_encrypted_receipt(test_receipt, pub_key)
    print(f"Content hash: {content_hash}")

    # Verify file exists
    enc_data = load_encrypted_receipt(content_hash)
    print(f"Encrypted blob: {len(enc_data)} bytes")

    # Decrypt
    print("\nDecrypting with owner's private key...")
    decrypted = verify_receipt(content_hash, test_acct.key.hex())
    print(f"Decrypted: {json.dumps(decrypted, indent=2)}")

    # Verify match
    assert decrypted == test_receipt, "MISMATCH!"
    print("\n✓ Round-trip encryption verified")

    # Test crypto PII detection
    print("\n=== Crypto PII Detection Test ===")
    test_text = "my key is 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 and my seed is abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    for name, pattern in CRYPTO_PII_PATTERNS.items():
        matches = pattern.findall(test_text)
        if matches:
            print(f"  {name}: {len(matches)} match(es)")
            for m in matches:
                print(f"    → {m[:30]}...")
