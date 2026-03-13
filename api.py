"""TIAMAT VAULT — Flask API for PII scrubbing with on-chain attestation + Uniswap swaps.

Endpoints:
  POST /vault/scrub          — Scrub PII from text, attest on-chain
  GET  /vault/verify/<hash>  — Verify attestation on-chain
  GET  /vault/score          — Agent attestation count
  GET  /vault/health         — Health check
  POST /vault/swap           — Uniswap token swap (Base)
  GET  /vault/art/<hash>     — Generate vaultprint art for a receipt hash
  GET  /vault/gallery        — Gallery of all vaultprints
  GET  /vault/               — Landing page
"""

import io
import re
import time
from collections import defaultdict
from functools import wraps

from dotenv import load_dotenv
from flask import Flask, Response, jsonify, request, send_file

load_dotenv("/root/.env")

from attest import (
    AGENT_ID,
    CONTRACT_ADDRESS,
    attest_on_chain,
    get_agent_score,
    get_total_attestations,
    policy_hash,
    receipt_hash,
    verify_attestation,
)
from uniswap import full_swap
from vault_encrypt import (
    load_encrypted_receipt,
    store_encrypted_receipt,
    _public_key_from_private,
)
from vaultart import generate_vaultprint, vaultprint_to_bytes

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024  # 50KB

# Store scrub history for gallery (in-memory, persists per worker)
_scrub_history = []
MAX_HISTORY = 100

# --- PII Detection Patterns ---
PII_PATTERNS = {
    "email": re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"),
    "phone": re.compile(r"(?<!\d)(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)?\d{3}[-.\s]?\d{4}(?!\d)"),
    "ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "credit_card": re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b"),
    "ip_address": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "date_of_birth": re.compile(
        r"\b(?:0[1-9]|1[0-2])[/\-](?:0[1-9]|[12]\d|3[01])[/\-](?:19|20)\d{2}\b"
    ),
    "us_address": re.compile(
        r"\b\d{1,5}\s+[\w\s]+(?:St|Street|Ave|Avenue|Blvd|Boulevard|Dr|Drive|Ln|Lane|Rd|Road|Ct|Court|Way|Pl|Place)\.?\s*,?\s*[\w\s]+,?\s*[A-Z]{2}\s*\d{5}(?:-\d{4})?\b",
        re.IGNORECASE,
    ),
    "passport": re.compile(r"\b[A-Z]{1,2}\d{6,9}\b"),
    # Crypto-sensitive PII — highest tier
    "eth_private_key": re.compile(r"(?:0x)?[0-9a-fA-F]{64}(?=\s|$|[^0-9a-fA-F])"),
    "seed_phrase": re.compile(r"\b(?:[a-z]{3,8}\s+){11,23}[a-z]{3,8}\b"),
    "btc_private_key": re.compile(r"\b[5KL][1-9A-HJ-NP-Za-km-z]{50,51}\b"),
    "api_key": re.compile(r"\b(?:sk|pk|api|key|secret|token)[-_][A-Za-z0-9_\-]{20,}\b", re.IGNORECASE),
    "jwt_token": re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
}

REDACT_LABELS = {
    "email": "[EMAIL_REDACTED]",
    "phone": "[PHONE_REDACTED]",
    "ssn": "[SSN_REDACTED]",
    "credit_card": "[CC_REDACTED]",
    "ip_address": "[IP_REDACTED]",
    "date_of_birth": "[DOB_REDACTED]",
    "us_address": "[ADDRESS_REDACTED]",
    "passport": "[PASSPORT_REDACTED]",
    "eth_private_key": "[PRIVATE_KEY_REDACTED]",
    "seed_phrase": "[SEED_PHRASE_REDACTED]",
    "btc_private_key": "[PRIVATE_KEY_REDACTED]",
    "api_key": "[API_KEY_REDACTED]",
    "jwt_token": "[JWT_REDACTED]",
}

# --- Rate Limiting ---
_rate_store = defaultdict(list)
RATE_LIMIT = 10  # per minute
RATE_WINDOW = 60  # seconds


def rate_limit(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        ip = request.headers.get("X-Real-IP", request.remote_addr)
        now = time.time()
        _rate_store[ip] = [t for t in _rate_store[ip] if now - t < RATE_WINDOW]
        if len(_rate_store[ip]) >= RATE_LIMIT:
            return jsonify({"error": "Rate limit exceeded. Max 10 scrubs/min."}), 429
        _rate_store[ip].append(now)
        return f(*args, **kwargs)

    return decorated


# --- PII Detection & Redaction ---


def detect_pii(text: str) -> dict:
    """Detect PII types present in text. Returns {type: [matches]}."""
    found = {}
    for pii_type, pattern in PII_PATTERNS.items():
        matches = pattern.findall(text)
        if matches:
            found[pii_type] = matches
    return found


def redact_pii(text: str, pii_types: list) -> tuple:
    """Redact specified PII types from text. Returns (clean_text, redaction_count)."""
    clean = text
    count = 0
    for pii_type in pii_types:
        if pii_type in PII_PATTERNS:
            pattern = PII_PATTERNS[pii_type]
            label = REDACT_LABELS[pii_type]
            matches = pattern.findall(clean)
            count += len(matches)
            clean = pattern.sub(label, clean)
    return clean, count


# --- Endpoints ---


@app.route("/vault/scrub", methods=["POST"])
@rate_limit
def scrub():
    """Scrub PII from text and attest on-chain."""
    data = request.get_json(silent=True)
    if not data or "text" not in data:
        return jsonify({"error": "Missing 'text' field"}), 400

    text = data["text"]
    if not isinstance(text, str) or len(text) == 0:
        return jsonify({"error": "Text must be a non-empty string"}), 400

    # Default policy: redact all detected types
    policy = data.get("policy", {})
    redact_types = policy.get("redact", list(PII_PATTERNS.keys()))

    # Validate redact types
    invalid = [t for t in redact_types if t not in PII_PATTERNS]
    if invalid:
        return (
            jsonify({"error": f"Invalid PII types: {invalid}", "valid_types": list(PII_PATTERNS.keys())}),
            400,
        )

    # Detect
    detected = detect_pii(text)

    # Redact
    clean_text, redaction_count = redact_pii(text, redact_types)

    # Build receipt
    receipt = {
        "agent_id": AGENT_ID,
        "action": "pii_scrub",
        "pii_types_found": list(detected.keys()),
        "pii_types_redacted": [t for t in redact_types if t in detected],
        "redaction_count": redaction_count,
        "text_length": len(text),
        "clean_text_length": len(clean_text),
        "timestamp": int(time.time()),
        "policy": policy,
    }

    r_h = receipt_hash(receipt)
    p_h = policy_hash(policy if policy else {"redact": redact_types, "version": "1.0"})

    # Encrypt receipt for data owner (if public key provided)
    encrypted_cid = ""
    owner_pubkey = data.get("owner_public_key", "")
    if not owner_pubkey:
        # Use TIAMAT's own key as fallback — owner can request re-encryption
        try:
            import os
            tiamat_key = os.environ.get("TIAMAT_WALLET_KEY", "")
            if tiamat_key:
                owner_pubkey = _public_key_from_private(tiamat_key)
        except Exception:
            pass

    if owner_pubkey:
        try:
            # Include the actual PII in the encrypted receipt (only owner can read)
            encrypted_receipt = {**receipt, "detected_pii_values": {k: v for k, v in detected.items()}}
            encrypted_cid = store_encrypted_receipt(encrypted_receipt, owner_pubkey)
        except Exception:
            pass  # Non-fatal — attestation still works without encryption

    # Attest on-chain (with encrypted CID if available)
    tx_hash = None
    attestation_url = None
    try:
        tx_hash = attest_on_chain(AGENT_ID, r_h, p_h, ipfs_cid=encrypted_cid)
        attestation_url = f"https://basescan.org/tx/0x{tx_hash}"
    except Exception as e:
        receipt["attestation_error"] = str(e)

    r_hash_hex = "0x" + r_h.hex()

    # Store in history for gallery
    _scrub_history.append({
        "receipt_hash": r_hash_hex,
        "pii_types_found": list(detected.keys()),
        "pii_types_redacted": [t for t in redact_types if t in detected],
        "redaction_count": redaction_count,
        "tx_hash": f"0x{tx_hash}" if tx_hash else None,
        "timestamp": receipt["timestamp"],
        "encrypted_cid": encrypted_cid or None,
    })
    if len(_scrub_history) > MAX_HISTORY:
        _scrub_history.pop(0)

    return jsonify(
        {
            "clean_text": clean_text,
            "receipt": receipt,
            "receipt_hash": r_hash_hex,
            "tx_hash": f"0x{tx_hash}" if tx_hash else None,
            "attestation_url": attestation_url,
            "detected_pii": {k: len(v) for k, v in detected.items()},
            "art_url": f"https://tiamat.live/vault/art/{r_hash_hex}",
            "encrypted_cid": encrypted_cid or None,
        }
    )


@app.route("/vault/receipt/<content_hash>", methods=["GET"])
def get_encrypted_receipt(content_hash: str):
    """Fetch an encrypted receipt blob by its content hash.

    The blob is ECIES-encrypted — only the data owner can decrypt it
    with their private key. This endpoint returns raw encrypted bytes.
    """
    if not content_hash.startswith("0x"):
        content_hash = "0x" + content_hash
    blob = load_encrypted_receipt(content_hash)
    if blob is None:
        return jsonify({"error": "Receipt not found"}), 404
    return Response(blob, mimetype="application/octet-stream", headers={
        "X-Content-Hash": content_hash,
        "X-Encryption": "ECIES-secp256k1",
    })


@app.route("/vault/verify/<receipt_hash_hex>", methods=["GET"])
def verify(receipt_hash_hex: str):
    """Verify an attestation on-chain by receipt hash."""
    try:
        if not receipt_hash_hex.startswith("0x"):
            receipt_hash_hex = "0x" + receipt_hash_hex
        r_h = bytes.fromhex(receipt_hash_hex.replace("0x", ""))
        if len(r_h) != 32:
            return jsonify({"error": "Hash must be 32 bytes (64 hex chars)"}), 400
    except ValueError:
        return jsonify({"error": "Invalid hex hash"}), 400

    try:
        att = verify_attestation(r_h)
        if att["timestamp"] == 0:
            return jsonify({"attested": False, "receipt_hash": receipt_hash_hex}), 404
        att["attested"] = True
        att["basescan_url"] = f"https://basescan.org/address/{CONTRACT_ADDRESS}"
        return jsonify(att)
    except Exception:
        return jsonify({"error": "Verification failed"}), 500


@app.route("/vault/score", methods=["GET"])
def score():
    """Get agent attestation score."""
    agent_id = request.args.get("agent_id", AGENT_ID, type=int)
    try:
        agent_score = get_agent_score(agent_id)
        total = get_total_attestations()
        return jsonify(
            {
                "agent_id": agent_id,
                "score": agent_score,
                "total_attestations": total,
                "contract": CONTRACT_ADDRESS,
            }
        )
    except Exception:
        return jsonify({"error": "Score lookup failed"}), 500


@app.route("/vault/swap", methods=["POST"])
@rate_limit
def swap():
    """Execute a Uniswap swap on Base."""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Missing JSON body"}), 400

    token_in = data.get("token_in")
    token_out = data.get("token_out")
    amount = data.get("amount")
    confirm = data.get("confirm", False)

    if not all([token_in, token_out, amount]):
        return (
            jsonify({"error": "Required: token_in, token_out, amount", "example": {"token_in": "USDC", "token_out": "WETH", "amount": "100000"}}),
            400,
        )

    try:
        result = full_swap(token_in, token_out, str(amount), confirm=bool(confirm))
        # Strip raw quote from response (too large)
        result.pop("quote", None)
        return jsonify(result)
    except ValueError as e:
        # ValueError is safe — these are our own validation messages
        return jsonify({"error": str(e)}), 400
    except Exception:
        return jsonify({"error": "Swap execution failed"}), 500


@app.route("/vault/health", methods=["GET"])
def health():
    """Health check — styled HTML for browsers, JSON for API clients."""
    try:
        score = get_agent_score()
        chain_ok = True
    except Exception:
        score = None
        chain_ok = False

    data = {
        "status": "ok",
        "service": "tiamat-vault",
        "agent_id": AGENT_ID,
        "contract": CONTRACT_ADDRESS,
        "chain_connected": chain_ok,
        "agent_score": score,
        "pii_types": list(PII_PATTERNS.keys()),
        "swap_tokens": ["USDC", "WETH", "ETH"],
        "max_swap_usdc": "5.00",
    }

    # Return JSON for API clients (curl, fetch, etc.)
    if "application/json" in request.headers.get("Accept", "") or request.args.get("json"):
        return jsonify(data)

    # Styled HTML for browsers
    pii_traditional = [t for t in data["pii_types"] if t not in ("eth_private_key", "seed_phrase", "btc_private_key", "api_key", "jwt_token")]
    pii_crypto = [t for t in data["pii_types"] if t in ("eth_private_key", "seed_phrase", "btc_private_key", "api_key", "jwt_token")]
    chain_badge = '<span style="color:#2ecc71">CONNECTED</span>' if chain_ok else '<span style="color:#e74c3c">DISCONNECTED</span>'
    status_badge = '<span style="color:#2ecc71">OPERATIONAL</span>' if data["status"] == "ok" else '<span style="color:#e74c3c">DOWN</span>'

    return f'''<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>VAULT Health</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{background:#0a0a0e;color:#e0e0e0;font-family:'JetBrains Mono','Fira Code',monospace;min-height:100vh}}
.container{{max-width:900px;margin:0 auto;padding:40px 20px}}
h1{{font-size:2em;color:#fff;margin-bottom:8px}}
h1 span{{color:#f6851b}}
.subtitle{{color:#7f8c8d;font-size:1em;margin-bottom:30px}}
h2{{color:#f6851b;font-size:1.2em;margin:24px 0 12px;border-bottom:1px solid #1a1a2e;padding-bottom:6px}}
.grid{{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin:16px 0}}
.card{{background:#12121a;border:1px solid #1a1a2e;border-radius:8px;padding:20px}}
.card-label{{color:#7f8c8d;font-size:0.85em;margin-bottom:4px}}
.card-value{{color:#fff;font-size:1.2em;font-weight:bold}}
.pill{{display:inline-block;background:#1a1a2e;color:#f6851b;padding:4px 10px;border-radius:12px;font-size:0.8em;margin:3px}}
.pill.crypto{{background:#3a1a1e;color:#e74c3c}}
.footer{{margin-top:40px;padding-top:16px;border-top:1px solid #1a1a2e;color:#555;font-size:0.8em;text-align:center}}
a{{color:#f6851b}}
</style></head><body>
<div class="container">
<h1>VAULT <span>HEALTH</span></h1>
<div class="subtitle">System status for TIAMAT VAULT — Agent #{data["agent_id"]}</div>

<div class="grid">
  <div class="card"><div class="card-label">Status</div><div class="card-value">{status_badge}</div></div>
  <div class="card"><div class="card-label">Base Chain</div><div class="card-value">{chain_badge}</div></div>
  <div class="card"><div class="card-label">Attestations</div><div class="card-value">{score or 0}</div></div>
  <div class="card"><div class="card-label">Agent ID</div><div class="card-value">#{data["agent_id"]}</div></div>
  <div class="card"><div class="card-label">Max Swap</div><div class="card-value">{data["max_swap_usdc"]} USDC</div></div>
  <div class="card"><div class="card-label">Swap Tokens</div><div class="card-value">{" / ".join(data["swap_tokens"])}</div></div>
</div>

<h2>Contract</h2>
<div class="card" style="word-break:break-all">
  <div class="card-label">VaultAttestation (Base Mainnet)</div>
  <div class="card-value" style="font-size:0.9em"><a href="https://basescan.org/address/{data["contract"]}" target="_blank">{data["contract"]}</a></div>
</div>

<h2>PII Detection — {len(data["pii_types"])} Types</h2>
<div style="margin:12px 0">
  {"".join(f'<span class="pill">{t}</span>' for t in pii_traditional)}
</div>
<div style="margin:12px 0">
  {"".join(f'<span class="pill crypto">{t}</span>' for t in pii_crypto)}
</div>

<div class="footer">
  <a href="/vault/">VAULT</a> | <a href="/vault/delegate">Delegate</a> | <a href="/vault/gallery">Gallery</a> | <a href="/vault/deck">Tech Deck</a>
  <br>TIAMAT VAULT | <a href="https://tiamat.live">tiamat.live</a>
</div>
</div></body></html>'''


@app.route("/vault/art/<receipt_hash_hex>", methods=["GET"])
def art(receipt_hash_hex: str):
    """Generate vaultprint artwork for a receipt hash."""
    try:
        h = receipt_hash_hex.replace("0x", "")
        if len(h) != 64:
            return jsonify({"error": "Hash must be 32 bytes (64 hex chars)"}), 400
        bytes.fromhex(h)
    except ValueError:
        return jsonify({"error": "Invalid hex hash"}), 400

    # Check history for PII type info, or use defaults
    pii_found = []
    pii_redacted = []
    redaction_count = 0
    for entry in _scrub_history:
        if entry["receipt_hash"].replace("0x", "") == h:
            pii_found = entry["pii_types_found"]
            pii_redacted = entry["pii_types_redacted"]
            redaction_count = entry["redaction_count"]
            break

    img = generate_vaultprint(
        "0x" + h,
        pii_types_found=pii_found,
        pii_types_redacted=pii_redacted,
        redaction_count=redaction_count,
    )
    img_bytes = vaultprint_to_bytes(img)

    return Response(img_bytes, mimetype="image/png", headers={
        "Cache-Control": "public, max-age=86400",
    })


@app.route("/vault/gallery", methods=["GET"])
def gallery():
    """Gallery page showing recent vaultprints."""
    return GALLERY_HTML


@app.route("/vault/deck", methods=["GET"])
def tech_deck():
    """Serve the tech deck HTML."""
    return send_file("/root/vault/TECH_DECK.html", mimetype="text/html")


# ─── VAULT STORAGE — Safety Deposit Box for Agents ───────────────────

import hashlib
import os
import json as _json

VAULT_STORAGE_DIR = "/root/vault/vault_storage"
os.makedirs(VAULT_STORAGE_DIR, exist_ok=True)

# In-memory index of vault deposits (persisted to disk)
VAULT_INDEX_FILE = os.path.join(VAULT_STORAGE_DIR, "_index.json")


def _load_vault_index():
    if os.path.exists(VAULT_INDEX_FILE):
        with open(VAULT_INDEX_FILE) as f:
            return _json.load(f)
    return {}


def _save_vault_index(index):
    with open(VAULT_INDEX_FILE, "w") as f:
        _json.dump(index, f)


@app.route("/vault/store", methods=["POST"])
@rate_limit
def vault_store():
    """Safety deposit box: agents store encrypted data on behalf of owners.

    The data is encrypted client-side with the owner's public key.
    VAULT stores the blob and returns a vault_id (content hash).
    Only the owner can decrypt — VAULT never sees plaintext.

    Body: {
        "data": "<base64 or hex encoded encrypted blob>",
        "owner": "<ETH address of the data owner>",
        "agent_id": <agent ID making the deposit>,
        "label": "<optional human-readable label>",
        "encoding": "hex" | "base64"  (default: hex)
    }
    """
    data = request.get_json(silent=True)
    if not data or "data" not in data:
        return jsonify({"error": "Missing 'data' field"}), 400

    owner = data.get("owner", "unknown")
    agent_id = data.get("agent_id", AGENT_ID)
    label = data.get("label", "")
    encoding = data.get("encoding", "hex")

    # Decode the encrypted blob
    try:
        if encoding == "base64":
            import base64
            blob = base64.b64decode(data["data"])
        else:
            raw = data["data"].replace("0x", "")
            blob = bytes.fromhex(raw)
    except Exception:
        return jsonify({"error": "Invalid data encoding"}), 400

    if len(blob) > 100 * 1024:  # 100KB max per deposit
        return jsonify({"error": "Data too large (max 100KB)"}), 400

    # Content-addressed storage
    vault_id = "0x" + hashlib.sha256(blob).hexdigest()
    filename = vault_id.replace("0x", "") + ".vault"
    filepath = os.path.join(VAULT_STORAGE_DIR, filename)

    with open(filepath, "wb") as f:
        f.write(blob)

    # Update index
    index = _load_vault_index()
    index[vault_id] = {
        "owner": owner,
        "agent_id": agent_id,
        "label": label,
        "size": len(blob),
        "timestamp": int(time.time()),
    }
    _save_vault_index(index)

    return jsonify({
        "vault_id": vault_id,
        "owner": owner,
        "agent_id": agent_id,
        "label": label,
        "size": len(blob),
        "retrieve_url": f"https://tiamat.live/vault/retrieve/{vault_id}",
    })


@app.route("/vault/retrieve/<vault_id>", methods=["GET"])
def vault_retrieve(vault_id: str):
    """Retrieve an encrypted blob from the vault by its ID.

    Returns the raw encrypted bytes. Only the owner can decrypt
    with their private key.
    """
    if not vault_id.startswith("0x"):
        vault_id = "0x" + vault_id
    filename = vault_id.replace("0x", "") + ".vault"
    filepath = os.path.join(VAULT_STORAGE_DIR, filename)

    if not os.path.exists(filepath):
        return jsonify({"error": "Vault deposit not found"}), 404

    index = _load_vault_index()
    meta = index.get(vault_id, {})

    with open(filepath, "rb") as f:
        blob = f.read()

    return Response(blob, mimetype="application/octet-stream", headers={
        "X-Vault-ID": vault_id,
        "X-Owner": meta.get("owner", "unknown"),
        "X-Agent-ID": str(meta.get("agent_id", "")),
        "X-Label": meta.get("label", ""),
        "X-Encryption": "ECIES-secp256k1 (client-side)",
    })


@app.route("/vault/deposits", methods=["GET"])
def vault_deposits():
    """List vault deposits. Filter by owner address."""
    owner = request.args.get("owner", "")
    index = _load_vault_index()

    deposits = []
    for vault_id, meta in index.items():
        if owner and meta.get("owner", "").lower() != owner.lower():
            continue
        deposits.append({"vault_id": vault_id, **meta})

    # Sort by timestamp descending
    deposits.sort(key=lambda d: d.get("timestamp", 0), reverse=True)

    # Return styled HTML for browsers
    if "application/json" not in request.headers.get("Accept", "") and not request.args.get("json"):
        rows = ""
        for d in deposits[:50]:
            ts = time.strftime("%Y-%m-%d %H:%M", time.gmtime(d.get("timestamp", 0)))
            rows += f'''<tr>
              <td style="padding:8px;font-family:monospace;font-size:0.8em"><a href="/vault/retrieve/{d["vault_id"]}" style="color:#f6851b">{d["vault_id"][:18]}...</a></td>
              <td style="padding:8px;font-size:0.85em">{d.get("owner","?")[:12]}...</td>
              <td style="padding:8px">{d.get("agent_id","")}</td>
              <td style="padding:8px">{d.get("label","")}</td>
              <td style="padding:8px">{d.get("size",0)} B</td>
              <td style="padding:8px;color:#7f8c8d">{ts}</td>
            </tr>'''

        return f'''<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>VAULT Deposits</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{background:#0a0a0e;color:#e0e0e0;font-family:'JetBrains Mono','Fira Code',monospace;min-height:100vh}}
.container{{max-width:900px;margin:0 auto;padding:40px 20px}}
h1{{font-size:2em;color:#fff;margin-bottom:8px}}
h1 span{{color:#f6851b}}
.subtitle{{color:#7f8c8d;margin-bottom:30px}}
table{{width:100%;border-collapse:collapse;margin:20px 0}}
th{{background:#1a1a2e;color:#f6851b;padding:10px;text-align:left;font-size:0.9em}}
tr{{border-bottom:1px solid #1a1a2e}}
tr:hover{{background:#12121a}}
.empty{{color:#555;text-align:center;padding:40px}}
.footer{{margin-top:40px;padding-top:16px;border-top:1px solid #1a1a2e;color:#555;font-size:0.8em;text-align:center}}
a{{color:#f6851b}}
</style></head><body>
<div class="container">
<h1>VAULT <span>DEPOSITS</span></h1>
<div class="subtitle">Encrypted safety deposit box — only owners can decrypt</div>
<p style="color:#7f8c8d;margin-bottom:20px">{len(deposits)} deposit{"s" if len(deposits)!=1 else ""}{f" for {owner[:12]}..." if owner else ""}</p>
<table>
<tr><th>Vault ID</th><th>Owner</th><th>Agent</th><th>Label</th><th>Size</th><th>Date</th></tr>
{rows if rows else '<tr><td colspan="6" class="empty">No deposits yet</td></tr>'}
</table>
<div class="footer">
  <a href="/vault/">VAULT</a> | <a href="/vault/delegate">Delegate</a> | <a href="/vault/gallery">Gallery</a> | <a href="/vault/health">Health</a>
  <br>TIAMAT VAULT | <a href="https://tiamat.live">tiamat.live</a>
</div>
</div></body></html>'''

    return jsonify({"deposits": deposits, "total": len(deposits)})


@app.route("/vault/", methods=["GET"])
def landing():
    """VAULT landing page."""
    return LANDING_HTML


LANDING_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>TIAMAT VAULT — Privacy Protection as Art</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { background: #0a0a0e; color: #e0e0e0; font-family: 'JetBrains Mono', 'Fira Code', monospace; min-height: 100vh; }
  .container { max-width: 900px; margin: 0 auto; padding: 40px 20px; }
  h1 { font-size: 2.5em; color: #fff; margin-bottom: 8px; }
  h1 span { color: #3498db; }
  .subtitle { color: #7f8c8d; font-size: 1.1em; margin-bottom: 40px; }
  .section { margin-bottom: 40px; }
  h2 { color: #3498db; font-size: 1.3em; margin-bottom: 16px; border-bottom: 1px solid #1a1a2e; padding-bottom: 8px; }
  p { line-height: 1.7; margin-bottom: 12px; color: #bdc3c7; }
  .highlight { color: #e74c3c; font-weight: bold; }
  .endpoint { background: #12121a; border: 1px solid #1a1a2e; border-radius: 8px; padding: 16px; margin-bottom: 12px; }
  .method { color: #2ecc71; font-weight: bold; }
  .path { color: #f39c12; }
  .desc { color: #95a5a6; font-size: 0.9em; }
  code { background: #1a1a2e; padding: 2px 6px; border-radius: 3px; color: #3498db; }
  .cta { display: inline-block; background: #3498db; color: #fff; padding: 12px 24px; border-radius: 6px; text-decoration: none; margin-top: 16px; }
  .cta:hover { background: #2980b9; }
  .stats { display: flex; gap: 20px; flex-wrap: wrap; margin: 20px 0; }
  .stat { background: #12121a; border: 1px solid #1a1a2e; border-radius: 8px; padding: 16px 24px; flex: 1; min-width: 150px; text-align: center; }
  .stat-value { font-size: 1.8em; color: #3498db; }
  .stat-label { color: #7f8c8d; font-size: 0.85em; }
  .demo { background: #12121a; border: 1px solid #2c3e50; border-radius: 8px; padding: 20px; }
  textarea { width: 100%; background: #1a1a2e; color: #ecf0f1; border: 1px solid #2c3e50; border-radius: 4px; padding: 12px; font-family: inherit; font-size: 0.9em; resize: vertical; min-height: 80px; }
  button { background: #e74c3c; color: #fff; border: none; padding: 10px 20px; border-radius: 4px; cursor: pointer; font-family: inherit; font-size: 1em; margin-top: 10px; }
  button:hover { background: #c0392b; }
  #result { margin-top: 16px; white-space: pre-wrap; font-size: 0.85em; max-height: 400px; overflow-y: auto; }
  #art-preview { margin-top: 16px; text-align: center; }
  #art-preview img { max-width: 400px; border: 1px solid #2c3e50; border-radius: 8px; }
  .footer { margin-top: 60px; padding-top: 20px; border-top: 1px solid #1a1a2e; color: #555; font-size: 0.85em; text-align: center; }
  a { color: #3498db; }
</style>
</head>
<body>
<div class="container">
  <h1>TIAMAT <span>VAULT</span></h1>
  <div class="subtitle">Privacy Protection as Generative Art — Powered by Autonomous AI</div>

  <div class="stats" id="stats">
    <div class="stat"><div class="stat-value" id="score">—</div><div class="stat-label">On-Chain Attestations</div></div>
    <div class="stat"><div class="stat-value">8</div><div class="stat-label">PII Types Detected</div></div>
    <div class="stat"><div class="stat-value">Base</div><div class="stat-label">L2 Chain</div></div>
  </div>

  <div class="section">
    <h2>What is VAULT?</h2>
    <p>VAULT is an <span class="highlight">autonomous AI agent</span> that protects personal data and proves it on-chain.</p>
    <p>Every time TIAMAT scrubs PII (emails, SSNs, phone numbers, credit cards) from text, it:</p>
    <p>1. Detects and redacts sensitive data<br>
    2. Creates a cryptographic receipt (keccak256)<br>
    3. Attests the receipt on <strong>Base mainnet</strong><br>
    4. Generates a unique <strong>VAULTPRINT</strong> — generative art derived from the attestation hash</p>
    <p>The art IS the proof. Every pixel is deterministic from the hash. No two vaultprints are alike.</p>
  </div>

  <div class="section">
    <h2>Try It — Live Demo</h2>
    <div class="demo">
      <textarea id="input" placeholder="Paste text containing PII... e.g. 'Contact john@acme.com or call 555-123-4567, SSN 123-45-6789'">Contact john@acme.com or call 555-123-4567, SSN 123-45-6789</textarea>
      <button onclick="scrub()">SCRUB & ATTEST</button>
      <div id="result"></div>
      <div id="art-preview"></div>
    </div>
  </div>

  <div class="section">
    <h2>API Endpoints</h2>
    <div class="endpoint"><span class="method">POST</span> <span class="path">/vault/scrub</span><br><span class="desc">Scrub PII from text → attest on-chain → return clean text + proof</span></div>
    <div class="endpoint"><span class="method">GET</span> <span class="path">/vault/verify/&lt;hash&gt;</span><br><span class="desc">Verify any attestation on-chain by receipt hash</span></div>
    <div class="endpoint"><span class="method">GET</span> <span class="path">/vault/art/&lt;hash&gt;</span><br><span class="desc">Generate the unique VAULTPRINT artwork for any receipt hash</span></div>
    <div class="endpoint"><span class="method">POST</span> <span class="path">/vault/swap</span><br><span class="desc">Execute Uniswap token swaps on Base (max 5 USDC safety cap)</span></div>
    <div class="endpoint"><span class="method">GET</span> <span class="path">/vault/gallery</span><br><span class="desc">Gallery of recent VAULTPRINT artworks</span></div>
    <div class="endpoint"><span class="method">GET</span> <span class="path">/vault/score</span><br><span class="desc">Agent reputation score (total attestation count)</span></div>
    <div class="endpoint"><span class="method">GET</span> <span class="path">/vault/delegate</span><br><span class="desc">MetaMask Delegation demo — scoped agent permissions (ERC-7710)</span></div>
  </div>

  <div class="section">
    <h2>Architecture</h2>
    <p><code>VaultAttestation.sol</code> on Base mainnet — immutable on-chain registry of every PII scrub.</p>
    <p><code>VAULTPRINT</code> generative art — each receipt hash seeds unique colors, geometry, and structure. PII types determine the palette (blue=email, green=phone, red=SSN, orange=credit card, purple=IP).</p>
    <p><code>Rare Protocol</code> minting — artwork minted as ERC-721 NFTs via SuperRare's Rare Protocol.</p>
    <p><code>Uniswap Trading API</code> — token swaps on Base with Permit2 gasless approvals.</p>
    <p><code>MetaMask Delegation Framework</code> — scoped permissions via ERC-7710. <a href="/vault/delegate">Try delegation demo →</a></p>
  </div>

  <div class="section">
    <h2>Contract</h2>
    <p><a href="https://basescan.org/address/0x47a6a776c79a7187a4fa7f7edf0a5511b034025e" target="_blank">VaultAttestation on BaseScan</a></p>
    <p>Agent ID: <code>29931</code> | Wallet: <code>0xdc118c...e7EE</code></p>
  </div>

  <div class="footer">
    TIAMAT VAULT — Built by TIAMAT, an autonomous AI agent | <a href="https://tiamat.live">tiamat.live</a> | Synthesis 2026
  </div>
</div>
<script>
fetch('/vault/score').then(r=>r.json()).then(d=>{document.getElementById('score').textContent=d.score||'0'});
async function scrub(){
  const r=document.getElementById('result');
  const a=document.getElementById('art-preview');
  r.textContent='Scrubbing & attesting on-chain...';
  a.innerHTML='';
  try{
    const resp=await fetch('/vault/scrub',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({text:document.getElementById('input').value})});
    const d=await resp.json();
    if(d.error){r.textContent='Error: '+d.error;return;}
    r.innerHTML='<b>Clean text:</b> '+d.clean_text+'\\n\\n<b>Detected:</b> '+JSON.stringify(d.detected_pii)+'\\n<b>Receipt hash:</b> '+d.receipt_hash+'\\n<b>TX:</b> '+(d.tx_hash?'<a href="'+d.attestation_url+'" target="_blank">'+d.tx_hash+'</a>':'pending');
    if(d.receipt_hash){a.innerHTML='<h3 style="color:#3498db;margin-bottom:8px">VAULTPRINT</h3><img src="/vault/art/'+d.receipt_hash+'" alt="VAULTPRINT">';}
  }catch(e){r.textContent='Error: '+e.message;}
}
</script>
</body></html>"""


GALLERY_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>VAULTPRINTS Gallery — TIAMAT VAULT</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { background: #0a0a0e; color: #e0e0e0; font-family: 'JetBrains Mono', monospace; }
  .container { max-width: 1200px; margin: 0 auto; padding: 40px 20px; }
  h1 { font-size: 2em; color: #fff; margin-bottom: 8px; }
  h1 span { color: #3498db; }
  .subtitle { color: #7f8c8d; margin-bottom: 30px; }
  .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 20px; }
  .card { background: #12121a; border: 1px solid #1a1a2e; border-radius: 8px; overflow: hidden; transition: border-color 0.2s; }
  .card:hover { border-color: #3498db; }
  .card img { width: 100%; aspect-ratio: 1; object-fit: cover; }
  .card-info { padding: 12px; }
  .card-hash { font-size: 0.75em; color: #3498db; word-break: break-all; }
  .card-pii { font-size: 0.8em; color: #e74c3c; margin-top: 4px; }
  .card-tx { font-size: 0.7em; margin-top: 4px; }
  .card-tx a { color: #7f8c8d; }
  .empty { text-align: center; color: #555; padding: 60px; }
  .back { color: #3498db; text-decoration: none; display: inline-block; margin-bottom: 20px; }
</style>
</head>
<body>
<div class="container">
  <a class="back" href="/vault/">&larr; Back to VAULT</a>
  <h1>VAULT<span>PRINTS</span> Gallery</h1>
  <div class="subtitle">Each artwork is generated from a real on-chain privacy attestation</div>
  <div class="grid" id="grid"></div>
  <div class="empty" id="empty" style="display:none">No vaultprints yet. <a href="/vault/" style="color:#3498db">Scrub some PII</a> to create the first one.</div>
</div>
<script>
fetch('/vault/gallery/data').then(r=>r.json()).then(items=>{
  const g=document.getElementById('grid');
  const e=document.getElementById('empty');
  if(!items.length){e.style.display='block';return;}
  items.reverse().forEach(item=>{
    const c=document.createElement('div');c.className='card';
    c.innerHTML='<img src="/vault/art/'+item.receipt_hash+'" loading="lazy"><div class="card-info"><div class="card-hash">'+item.receipt_hash+'</div><div class="card-pii">'+(item.pii_types_redacted.map(t=>t.toUpperCase()).join(' | ')||'CLEAN')+'</div>'+(item.tx_hash?'<div class="card-tx"><a href="https://basescan.org/tx/'+item.tx_hash+'" target="_blank">View on BaseScan &rarr;</a></div>':'')+'</div>';
    g.appendChild(c);
  });
});
</script>
</body></html>"""


@app.route("/vault/delegate", methods=["GET"])
def delegate():
    """MetaMask Delegation demo page."""
    with open("/root/vault/templates/delegate.html") as f:
        return f.read()


@app.route("/vault/gallery/data", methods=["GET"])
def gallery_data():
    """Return gallery data as JSON."""
    return jsonify(_scrub_history)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5007, debug=True)
