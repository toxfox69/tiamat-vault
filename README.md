# TIAMAT VAULT — Antivirus for AI Agents

VAULT is a privacy firewall for AI agents. It monitors outbound data, catches sensitive information before it leaks, scrubs it, and creates an immutable on-chain proof that the protection happened.

**The user experience is one notification:** *"Threat caught. 2 items scrubbed. You're safe."*

No decryption. No blockchain knowledge. No tech literacy required. Just protection.

## Live Demo

- **Landing Page**: https://tiamat.live/vault/
- **Health Dashboard**: https://tiamat.live/vault/health
- **VAULTPRINT Gallery**: https://tiamat.live/vault/gallery
- **Safety Deposit Box**: https://tiamat.live/vault/deposits
- **MetaMask Delegation**: https://tiamat.live/vault/delegate
- **Tech Deck**: https://tiamat.live/vault/deck

## What It Catches

**13 PII types** across two tiers:

| Category | Types |
|----------|-------|
| Traditional PII | Email, phone, SSN, credit card, IP address, date of birth, US address, passport |
| Crypto Secrets (highest tier) | ETH private keys, BIP-39 seed phrases, BTC private keys (WIF), API keys, JWT tokens |

## How It Works

```
AI Agent (outbound message)
  |
  v
VAULT FIREWALL (background middleware)
  |-- 13 PII regex detectors
  |-- Policy-based selective redaction
  |-- Rate limiting + safety caps
  |
  +---> Attest on-chain (Base mainnet)
  +---> Encrypt receipt (ECIES secp256k1)
  +---> Generate VAULTPRINT art (1200x1200)
  +---> Store in Safety Deposit Box
```

1. Agent processes text containing PII
2. VAULT detects sensitive data in real-time
3. PII is scrubbed, receipt encrypted with owner's key
4. Attestation recorded on Base mainnet
5. User gets notification: "Threat caught. You're safe."

## API

```bash
# Scrub PII and attest on-chain
curl -X POST https://tiamat.live/vault/scrub \
  -H "Content-Type: application/json" \
  -d '{"text": "Contact john@acme.com, SSN 123-45-6789"}'

# Verify attestation
curl https://tiamat.live/vault/verify/0x<receipt_hash>

# Safety deposit box
curl -X POST https://tiamat.live/vault/store \
  -H "Content-Type: application/json" \
  -d '{"data": "encrypted_hex", "owner": "0x...", "label": "my secrets"}'

# Uniswap swap (dry run)
curl -X POST https://tiamat.live/vault/swap \
  -H "Content-Type: application/json" \
  -d '{"token_in": "USDC", "token_out": "WETH", "amount": "100000"}'
```

## Bounty Track Integrations

### MetaMask Delegation (ERC-7710)
Scoped delegation via Smart Accounts Kit v0.4.0-beta.1. VAULT agent can ONLY call `attest()` — zero ETH transfers, single contract, single function. Three on-chain enforcers: AllowedTargets + AllowedMethods + ValueLte. Instantly revocable.

- **E2E verified on Sepolia**: [Delegation TX](https://sepolia.etherscan.io/tx/0x44dbe631c677e353f33affa0ffffdddc52459ebbb9547f4efa6310bb67b50b3a)
- **Pimlico bundler** for smart account deployment (free, no API key)

### Uniswap Trading API
Full swap flow: check_approval -> quote -> Permit2 EIP-712 sign -> broadcast. Safety-capped at 5 USDC.

- **Real swap on Base mainnet**: [BaseScan TX](https://basescan.org/tx/0x3b40735427271201ef429a3eedbe866a0edecb7e75b6c00334b9d22e49179f2c)

### SuperRare / Rare Protocol
VAULTPRINTS — generative art (1200x1200, 5 layers) deterministically derived from attestation hashes. Each scrub creates unique art. Minted as ERC-721 via Rare Protocol CLI.

- **Collection**: `0x716cC4dD2d66A68c65EAD83Cf630C819260e92F7` (Sepolia)

### Status Network
Gasless deployment and attestation on Status Network Sepolia (Chain ID: 1660990954). Contract deployed and attestation executed with `effectiveGasPrice: 0`.

- **Contract**: `0xb5D88A14ee40C4835Ea2C6c864EFD2Ce40959DA9`
- **Deploy TX**: [Status Explorer](https://sepoliascan.status.network/tx/0xa4113282fb1479b7bdf829a363ce1c5980c110149384a5f310cf9a506ffa8710)
- **Gasless Attest TX**: [Status Explorer](https://sepoliascan.status.network/tx/0xab8d80ca1bf57bde5db306f6dc7dfd8900ad2bd9ab999508b1857919c40aec1f)

## Contracts

| Contract | Chain | Address |
|----------|-------|---------|
| VaultAttestation | Base mainnet | `0x47a6a776c79a7187a4fa7f7edf0a5511b034025e` |
| VaultAttestation | Status Network | `0xb5D88A14ee40C4835Ea2C6c864EFD2Ce40959DA9` |
| VAULTPRINTS (ERC-721) | Sepolia | `0x716cC4dD2d66A68c65EAD83Cf630C819260e92F7` |
| DelegationManager | Sepolia | `0xdb9B1e94B5b69Df7e401DDbedE43491141047dB3` |

## Tech Stack

| Component | Technology |
|-----------|-----------|
| API | Python / Flask / Gunicorn |
| On-chain | Solidity / Foundry / web3.py / viem |
| Delegation | @metamask/smart-accounts-kit v0.4.0-beta.1 |
| Encryption | ECIES (eciespy, secp256k1) |
| Art | Pillow (PIL), deterministic from hash |
| NFTs | Rare Protocol CLI, ERC-721 |
| Swaps | Uniswap Trading API v1, Permit2 EIP-712 |
| Agent | TypeScript / Node.js / Claude API |

## Security

- PII is never stored in plaintext
- Encrypted receipts (ECIES secp256k1) — only owner can decrypt
- API binds to 127.0.0.1 only (nginx proxy with TLS)
- Error messages sanitized — no internal state leaks
- Rate limiting: 10 requests/min/IP
- Swap safety cap: 5 USDC max
- Delegation scope: attest() only, 0 ETH value cap

## Agent Identity

- **Agent ID**: 29931 (ERC-8004 on Base)
- **Wallet**: `0xdc118c4e1284e61e4d5277936a64B9E08Ad9e7EE`
- **Operator**: ENERGENAI LLC

---

Built by TIAMAT — an autonomous AI agent | [tiamat.live](https://tiamat.live) | Synthesis 2026
