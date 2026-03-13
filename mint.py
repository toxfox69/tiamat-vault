"""VAULTPRINTS — Mint pipeline via Rare Protocol CLI.

Deploys collection and mints vaultprint NFTs from attestation hashes.
Rare CLI handles IPFS upload internally.
"""

import json
import os
import subprocess
import tempfile

from vaultart import generate_vaultprint, save_vaultprint

COLLECTION_FILE = "/root/vault/.collection_address"
CHAIN = os.environ.get("RARE_CHAIN", "sepolia")
AGENT_ID = 29931


def _run_rare(args: list[str], timeout: int = 120) -> str:
    """Run a rare CLI command. Returns stdout."""
    cmd = ["rare"] + args + ["--chain", CHAIN]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if result.returncode != 0:
        raise RuntimeError(f"rare {' '.join(args)} failed: {result.stderr}")
    return result.stdout.strip()


def get_collection_address() -> str | None:
    """Get the deployed collection address."""
    if os.path.exists(COLLECTION_FILE):
        with open(COLLECTION_FILE) as f:
            return f.read().strip()
    return None


def deploy_collection(name: str = "VAULTPRINTS", symbol: str = "VPRINT") -> str:
    """Deploy a new ERC-721 collection via Rare Protocol. Returns contract address."""
    existing = get_collection_address()
    if existing:
        return existing

    output = _run_rare(["deploy", "erc721", name, symbol])

    # Parse contract address from output
    for line in output.split("\n"):
        line = line.strip()
        if line.startswith("0x") and len(line) == 42:
            address = line
            with open(COLLECTION_FILE, "w") as f:
                f.write(address)
            return address
        if "deployed" in line.lower() or "contract" in line.lower():
            # Try to extract address from the line
            for word in line.split():
                if word.startswith("0x") and len(word) >= 42:
                    address = word[:42]
                    with open(COLLECTION_FILE, "w") as f:
                        f.write(address)
                    return address

    # If we can't parse it, save the full output for debugging
    raise RuntimeError(f"Could not parse contract address from: {output}")


def mint_vaultprint(
    receipt_hash_hex: str,
    pii_types_found: list[str],
    pii_types_redacted: list[str],
    redaction_count: int,
    tx_hash: str = "",
) -> dict:
    """Generate vaultprint art and mint as NFT.

    Returns dict with token_id, contract, tx_hash, etc.
    """
    contract = get_collection_address()
    if not contract:
        raise RuntimeError("No collection deployed. Run deploy_collection() first.")

    # Generate the art
    img = generate_vaultprint(
        receipt_hash_hex,
        pii_types_found=pii_types_found,
        pii_types_redacted=pii_types_redacted,
        redaction_count=redaction_count,
        agent_id=AGENT_ID,
    )

    # Save to temp file
    with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as f:
        save_vaultprint(img, f.name)
        image_path = f.name

    try:
        # Build description
        pii_str = ", ".join(t.upper() for t in pii_types_redacted)
        description = (
            f"VAULTPRINT — Generative privacy art by TIAMAT (Agent #{AGENT_ID}). "
            f"This artwork was autonomously generated from the on-chain attestation of a PII scrub operation. "
            f"PII types redacted: {pii_str or 'none'}. "
            f"Redaction count: {redaction_count}. "
            f"Receipt hash: {receipt_hash_hex}. "
            f"Attestation TX: {tx_hash or 'pending'}. "
            f"Every pixel is deterministic from the keccak256 hash — the art IS the proof of data protection."
        )

        # Build mint command
        args = [
            "mint",
            "--contract", contract,
            "--name", f"VAULTPRINT #{receipt_hash_hex[:10]}",
            "--description", description,
            "--image", image_path,
            "--tag", "privacy",
            "--tag", "generative",
            "--tag", "ai-agent",
            "--tag", "vault",
        ]

        # Add attributes
        for pii_type in pii_types_redacted:
            args.extend(["--attribute", f"pii_type={pii_type}"])
        args.extend(["--attribute", f"redaction_count={redaction_count}"])
        args.extend(["--attribute", f"agent_id={AGENT_ID}"])
        args.extend(["--attribute", f"receipt_hash={receipt_hash_hex}"])
        if tx_hash:
            args.extend(["--attribute", f"attestation_tx={tx_hash}"])

        output = _run_rare(args, timeout=180)

        return {
            "status": "minted",
            "contract": contract,
            "chain": CHAIN,
            "receipt_hash": receipt_hash_hex,
            "raw_output": output,
        }
    finally:
        os.unlink(image_path)


if __name__ == "__main__":
    print("=== VAULTPRINTS — Mint Test ===")
    print(f"Chain: {CHAIN}")

    addr = get_collection_address()
    if addr:
        print(f"Collection already deployed: {addr}")
    else:
        print("No collection deployed yet.")
        print("To deploy: python3 mint.py deploy")

    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "deploy":
        print("Deploying VAULTPRINTS collection...")
        addr = deploy_collection()
        print(f"Deployed: {addr}")
    elif len(sys.argv) > 1 and sys.argv[1] == "test-mint":
        test_hash = "0x3ba9dfab9400fd38c6946b0ad1667d452c8e710f725e2fb400b1f142e8e00a74"
        print(f"Minting test vaultprint for {test_hash[:16]}...")
        result = mint_vaultprint(
            test_hash,
            pii_types_found=["email", "phone", "ssn"],
            pii_types_redacted=["email", "phone", "ssn"],
            redaction_count=3,
            tx_hash="0x1864bd1e3aa9a344f7b391d621ba5b26c0ce3b5f4135603e79a6b121a6194f9f",
        )
        print(json.dumps(result, indent=2))
