"""VAULTPRINTS — Generative art from privacy attestation hashes.

Each PII scrub produces a unique on-chain receipt hash (keccak256).
This module transforms that hash into a unique generative artwork —
the visual proof that data was protected.

The art IS the attestation. Every pixel is deterministic from the hash.
"""

import colorsys
import math
import struct
from io import BytesIO

from PIL import Image, ImageDraw, ImageFont

WIDTH = 1200
HEIGHT = 1200
MARGIN = 60

# PII type → visual identity
PII_PALETTES = {
    "email": [(41, 128, 185), (52, 152, 219), (174, 214, 241)],
    "phone": [(39, 174, 96), (46, 204, 113), (171, 235, 198)],
    "ssn": [(192, 57, 43), (231, 76, 60), (245, 183, 177)],
    "credit_card": [(243, 156, 18), (241, 196, 15), (249, 231, 159)],
    "ip_address": [(142, 68, 173), (155, 89, 182), (215, 189, 226)],
    "date_of_birth": [(230, 126, 34), (211, 84, 0), (245, 176, 65)],
    "us_address": [(44, 62, 80), (52, 73, 94), (149, 165, 166)],
    "passport": [(22, 160, 133), (26, 188, 156), (162, 217, 206)],
}

DEFAULT_PALETTE = [(93, 109, 126), (127, 140, 141), (189, 195, 199)]
BG_COLOR = (10, 10, 14)


def _hash_bytes(receipt_hash_hex: str) -> bytes:
    """Convert hex hash to 32 bytes."""
    h = receipt_hash_hex.replace("0x", "")
    return bytes.fromhex(h)


def _byte_at(data: bytes, idx: int) -> int:
    return data[idx % len(data)]


def _float_at(data: bytes, idx: int) -> float:
    """Get a float 0.0-1.0 from byte position."""
    return _byte_at(data, idx) / 255.0


def _color_from_hash(data: bytes, offset: int) -> tuple:
    """Generate an RGB color from hash bytes at offset."""
    h = _float_at(data, offset)
    s = 0.5 + _float_at(data, offset + 1) * 0.5  # 0.5-1.0 saturation
    v = 0.6 + _float_at(data, offset + 2) * 0.4  # 0.6-1.0 value
    r, g, b = colorsys.hsv_to_rgb(h, s, v)
    return (int(r * 255), int(g * 255), int(b * 255))


def generate_vaultprint(
    receipt_hash_hex: str,
    pii_types_found: list[str] = None,
    pii_types_redacted: list[str] = None,
    redaction_count: int = 0,
    agent_id: int = 29931,
) -> Image.Image:
    """Generate a unique artwork from an attestation receipt hash.

    The hash determines every visual element — colors, patterns, geometry.
    PII types influence the color palette. Redaction count affects density.
    """
    data = _hash_bytes(receipt_hash_hex)
    pii_types_found = pii_types_found or []
    pii_types_redacted = pii_types_redacted or []

    img = Image.new("RGB", (WIDTH, HEIGHT), BG_COLOR)
    draw = ImageDraw.Draw(img)

    # Build palette from PII types found
    palette = []
    for pii_type in pii_types_found:
        palette.extend(PII_PALETTES.get(pii_type, DEFAULT_PALETTE))
    if not palette:
        palette = [_color_from_hash(data, i * 3) for i in range(6)]

    # === Layer 1: Radial grid (the "vault" structure) ===
    cx, cy = WIDTH // 2, HEIGHT // 2
    num_rings = 5 + (_byte_at(data, 0) % 8)
    num_sectors = 6 + (_byte_at(data, 1) % 12)

    for ring in range(num_rings):
        r = MARGIN + (ring + 1) * ((min(WIDTH, HEIGHT) // 2 - MARGIN) // num_rings)
        alpha = 30 + _byte_at(data, 2 + ring) % 40
        color = palette[ring % len(palette)]
        faded = tuple(max(0, min(255, c * alpha // 255)) for c in color)

        # Draw ring
        draw.ellipse(
            [cx - r, cy - r, cx + r, cy + r],
            outline=faded,
            width=1,
        )

        # Draw sector lines
        for sector in range(num_sectors):
            angle = (2 * math.pi * sector / num_sectors) + _float_at(data, 10 + ring) * 0.3
            x1 = cx + int(r * 0.3 * math.cos(angle))
            y1 = cy + int(r * 0.3 * math.sin(angle))
            x2 = cx + int(r * math.cos(angle))
            y2 = cy + int(r * math.sin(angle))
            draw.line([(x1, y1), (x2, y2)], fill=faded, width=1)

    # === Layer 2: Data nodes (each redacted item = a node) ===
    node_count = max(redaction_count * 3, 8)
    for i in range(node_count):
        b1, b2 = _byte_at(data, i * 2), _byte_at(data, i * 2 + 1)
        angle = 2 * math.pi * b1 / 256
        dist = MARGIN + (b2 / 256) * (min(WIDTH, HEIGHT) // 2 - MARGIN * 2)
        nx = cx + int(dist * math.cos(angle))
        ny = cy + int(dist * math.sin(angle))
        size = 3 + _byte_at(data, 20 + i) % 12
        color = palette[i % len(palette)]

        # Glow effect
        for g in range(3, 0, -1):
            glow_color = tuple(c // (g + 1) for c in color)
            draw.ellipse(
                [nx - size - g * 2, ny - size - g * 2, nx + size + g * 2, ny + size + g * 2],
                fill=glow_color,
            )
        draw.ellipse([nx - size, ny - size, nx + size, ny + size], fill=color)

    # === Layer 3: Connection lines (the "redaction web") ===
    # Connect nodes that share hash-byte relationships
    connections = _byte_at(data, 5) % 20 + 10
    for i in range(connections):
        b1 = _byte_at(data, i) % node_count
        b2 = _byte_at(data, 31 - (i % 32)) % node_count
        if b1 == b2:
            continue

        # Recompute positions for these nodes
        def node_pos(idx):
            _b1 = _byte_at(data, idx * 2)
            _b2 = _byte_at(data, idx * 2 + 1)
            a = 2 * math.pi * _b1 / 256
            d = MARGIN + (_b2 / 256) * (min(WIDTH, HEIGHT) // 2 - MARGIN * 2)
            return cx + int(d * math.cos(a)), cy + int(d * math.sin(a))

        p1 = node_pos(b1)
        p2 = node_pos(b2)
        color = palette[i % len(palette)]
        faded = tuple(c // 4 for c in color)
        draw.line([p1, p2], fill=faded, width=1)

    # === Layer 4: Hash inscription (bottom arc) ===
    short_hash = receipt_hash_hex[:10] + "..." + receipt_hash_hex[-8:]
    try:
        font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", 14)
        font_large = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf", 18)
    except OSError:
        font = ImageFont.load_default()
        font_large = font

    # Top label
    draw.text(
        (MARGIN, MARGIN // 2 - 10),
        "VAULTPRINT",
        fill=(255, 255, 255, 180),
        font=font_large,
    )

    # PII types label
    pii_label = " | ".join(t.upper() for t in pii_types_redacted) if pii_types_redacted else "CLEAN"
    draw.text(
        (WIDTH - MARGIN - len(pii_label) * 11, MARGIN // 2 - 10),
        pii_label,
        fill=palette[0] if palette else (150, 150, 150),
        font=font,
    )

    # Bottom: hash + agent ID
    draw.text(
        (MARGIN, HEIGHT - MARGIN // 2 - 5),
        short_hash,
        fill=(100, 100, 110),
        font=font,
    )
    draw.text(
        (WIDTH - MARGIN - 140, HEIGHT - MARGIN // 2 - 5),
        f"AGENT #{agent_id}",
        fill=(100, 100, 110),
        font=font,
    )

    # === Layer 5: Central sigil (unique per hash) ===
    # Use first 8 bytes as float pairs for a bezier-like sigil
    sigil_points = []
    for i in range(8):
        angle = 2 * math.pi * i / 8 + _float_at(data, 24 + i) * 0.8
        dist = 30 + _byte_at(data, i) % 60
        sx = cx + int(dist * math.cos(angle))
        sy = cy + int(dist * math.sin(angle))
        sigil_points.append((sx, sy))

    if len(sigil_points) >= 3:
        # Draw sigil as connected polygon with glow
        primary = palette[0] if palette else (255, 255, 255)
        for g in range(4, 0, -1):
            glow = tuple(c // (g + 1) for c in primary)
            expanded = []
            for sx, sy in sigil_points:
                dx, dy = sx - cx, sy - cy
                mag = math.sqrt(dx * dx + dy * dy) or 1
                expanded.append((sx + int(dx / mag * g * 3), sy + int(dy / mag * g * 3)))
            draw.polygon(expanded, outline=glow)

        draw.polygon(sigil_points, outline=primary, fill=None)

        # Inner dot
        draw.ellipse([cx - 4, cy - 4, cx + 4, cy + 4], fill=primary)

    return img


def save_vaultprint(img: Image.Image, path: str):
    """Save the vaultprint to disk."""
    img.save(path, quality=95)


def vaultprint_to_bytes(img: Image.Image, fmt: str = "PNG") -> bytes:
    """Convert vaultprint to bytes for upload."""
    buf = BytesIO()
    img.save(buf, format=fmt)
    return buf.getvalue()


if __name__ == "__main__":
    import sys
    import time

    # Generate from the test attestation hash
    test_hash = "0x3ba9dfab9400fd38c6946b0ad1667d452c8e710f725e2fb400b1f142e8e00a74"
    pii_found = ["email", "phone", "ssn"]
    pii_redacted = ["email", "phone", "ssn"]

    print(f"Generating vaultprint for {test_hash[:16]}...")
    img = generate_vaultprint(
        test_hash,
        pii_types_found=pii_found,
        pii_types_redacted=pii_redacted,
        redaction_count=3,
    )

    out = "/root/vault/test_vaultprint.png"
    save_vaultprint(img, out)
    print(f"Saved: {out} ({img.size[0]}x{img.size[1]})")

    # Generate a second one to show uniqueness
    test_hash2 = "0x373c125f49bf9a215c56184e976224f3695d5d6f5e131049150c19302be7c886"
    img2 = generate_vaultprint(
        test_hash2,
        pii_types_found=["credit_card", "ip_address"],
        pii_types_redacted=["credit_card", "ip_address"],
        redaction_count=5,
    )
    out2 = "/root/vault/test_vaultprint2.png"
    save_vaultprint(img2, out2)
    print(f"Saved: {out2} ({img2.size[0]}x{img2.size[1]})")
