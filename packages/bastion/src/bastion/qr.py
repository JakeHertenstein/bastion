"""QR utilities for Bastion CLI transfers.

Provides consistent multi-QR framing compatible with airgap exports.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

import qrcode
from qrcode.constants import ERROR_CORRECT_H

# Protocol prefix used by airgap exports
MULTI_QR_PREFIX = "BASTION:"
MULTI_QR_PATTERN = re.compile(r"^BASTION:(\d+)/(\d+):(.*)$", re.DOTALL)
DEFAULT_MAX_BYTES = 2000  # conservative per-QR payload


@dataclass
class MultiQRPart:
    """A single QR part following the BASTION:seq/total protocol."""

    sequence: int
    total: int
    data: str

    def to_qr_string(self) -> str:
        return f"{MULTI_QR_PREFIX}{self.sequence}/{self.total}:{self.data}"

    @classmethod
    def from_qr_string(cls, qr_string: str) -> MultiQRPart | None:
        match = MULTI_QR_PATTERN.match(qr_string)
        if not match:
            return None
        return cls(sequence=int(match.group(1)), total=int(match.group(2)), data=match.group(3))


def split_for_qr(data: str, max_bytes: int = DEFAULT_MAX_BYTES) -> list[MultiQRPart]:
    """Split data into QR-safe chunks using the BASTION prefix."""
    data_bytes = data.encode()
    prefix_overhead = 20
    effective_max = max_bytes - prefix_overhead

    if len(data_bytes) <= max_bytes:
        return [MultiQRPart(sequence=1, total=1, data=data)]

    parts: list[MultiQRPart] = []
    pos = 0
    total = 0
    chunks: list[str] = []

    while pos < len(data_bytes):
        end = min(pos + effective_max, len(data_bytes))
        chunk_bytes = data_bytes[pos:end]
        while True:
            try:
                chunk = chunk_bytes.decode()
                break
            except UnicodeDecodeError:
                end -= 1
                if end <= pos:
                    raise ValueError("Unable to split data on UTF-8 boundary")
                chunk_bytes = data_bytes[pos:end]
        chunks.append(chunk)
        pos = end

    total = len(chunks)
    for idx, chunk in enumerate(chunks, start=1):
        parts.append(MultiQRPart(sequence=idx, total=total, data=chunk))
    return parts


def reassemble_qr_parts(parts: Sequence[MultiQRPart]) -> str:
    """Reassemble multi-QR parts into the original string."""
    if not parts:
        raise ValueError("No QR parts provided")

    total = parts[0].total
    if any(p.total != total for p in parts):
        raise ValueError("Inconsistent total counts across QR parts")

    sequences = {p.sequence for p in parts}
    expected = set(range(1, total + 1))
    if sequences != expected:
        missing = expected - sequences
        raise ValueError(f"Missing QR parts: {sorted(missing)}")

    ordered = sorted(parts, key=lambda p: p.sequence)
    return "".join(p.data for p in ordered)


def decode_qr_payloads(qr_strings: Iterable[str]) -> str:
    """Decode one or more QR strings into the original payload.

    Accepts either a single raw payload (no prefix) or multi-part strings
    using the BASTION:seq/total prefix.
    """
    parts: list[MultiQRPart] = []
    single: list[str] = []

    for raw in qr_strings:
        parsed = MultiQRPart.from_qr_string(raw)
        if parsed:
            parts.append(parsed)
        else:
            single.append(raw)

    if parts:
        if len(single) > 0:
            raise ValueError("Mixed raw and multi-part QR payloads provided")
        return reassemble_qr_parts(parts)

    if len(single) != 1:
        raise ValueError("Provide exactly one payload or a full multi-part set")
    return single[0]


def generate_qr_terminal(data: str) -> str:
    """Generate a terminal-friendly QR string (ANSI-free)."""
    qr = qrcode.QRCode(error_correction=ERROR_CORRECT_H)
    qr.add_data(data)
    qr.make(fit=True)
    # qrcode's print_ascii returns None and prints; capture via terminal output
    # Instead, use terminal() to get string representation
    img = qr.get_matrix()
    lines: list[str] = []
    # Use two spaces for white, double block for black to keep square aspect
    for row in img:
        line = "".join("██" if cell else "  " for cell in row)
        lines.append(line)
    return "\n".join(lines)
