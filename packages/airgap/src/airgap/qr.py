"""QR code generation and multi-QR handling for airgap transfers.

This module provides QR code generation for transferring encrypted data
from the airgap machine to the manager. Supports:

- Terminal display using Unicode half-blocks
- PNG file export
- PDF generation with reportlab for printable multi-QR sheets
- Multi-QR splitting with BASTION:seq/total: prefix protocol
- Reassembly of scanned QR parts

Protocol Format:
    Single QR: raw data (no prefix)
    Multi-QR:  BASTION:1/3:<chunk1>
               BASTION:2/3:<chunk2>
               BASTION:3/3:<chunk3>
"""

from __future__ import annotations

import io
import re
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

import qrcode
from qrcode.constants import ERROR_CORRECT_H, ERROR_CORRECT_L, ERROR_CORRECT_M, ERROR_CORRECT_Q

# Error correction levels
ERROR_CORRECTION_MAP = {
    "L": ERROR_CORRECT_L,  # 7% recovery
    "M": ERROR_CORRECT_M,  # 15% recovery
    "Q": ERROR_CORRECT_Q,  # 25% recovery
    "H": ERROR_CORRECT_H,  # 30% recovery
}

# QR capacity limits (alphanumeric mode, which GPG armor uses)
# Format: {version: {error_level: capacity}}
# Using conservative estimates for mixed content
QR_CAPACITY = {
    10: {"L": 652, "M": 513, "Q": 364, "H": 288},
    15: {"L": 1156, "M": 909, "Q": 642, "H": 504},
    20: {"L": 1852, "M": 1455, "Q": 1022, "H": 798},
    25: {"L": 2670, "M": 2095, "Q": 1465, "H": 1139},
    30: {"L": 3516, "M": 2759, "Q": 1933, "H": 1499},
    40: {"L": 4296, "M": 3391, "Q": 2386, "H": 1852},
}

# Default max bytes per QR (conservative for reliable scanning)
DEFAULT_MAX_BYTES = 2000

# Multi-QR protocol prefix
MULTI_QR_PREFIX = "BASTION:"
MULTI_QR_PATTERN = re.compile(r"^BASTION:(\d+)/(\d+):(.*)$", re.DOTALL)


@dataclass
class QRInfo:
    """Information about a generated QR code."""

    version: int
    modules: int
    data_bytes: int
    error_correction: str
    is_multi_part: bool = False
    part_number: int = 1
    total_parts: int = 1


@dataclass
class MultiQRPart:
    """A single part of a multi-QR sequence."""

    sequence: int
    total: int
    data: str

    def to_qr_string(self) -> str:
        """Format as QR-encodable string with protocol prefix."""
        return f"{MULTI_QR_PREFIX}{self.sequence}/{self.total}:{self.data}"

    @classmethod
    def from_qr_string(cls, qr_string: str) -> MultiQRPart | None:
        """Parse a scanned QR string into a MultiQRPart.
        
        Returns None if the string doesn't match the multi-QR protocol.
        """
        match = MULTI_QR_PATTERN.match(qr_string)
        if not match:
            return None

        return cls(
            sequence=int(match.group(1)),
            total=int(match.group(2)),
            data=match.group(3),
        )


def estimate_qr_size(data: str, error_correction: str = "H") -> QRInfo:
    """Estimate QR code size for given data.
    
    Args:
        data: Data to encode
        error_correction: L/M/Q/H (7%/15%/25%/30% recovery)
        
    Returns:
        QRInfo with version and module count
    """
    ec_level = ERROR_CORRECTION_MAP.get(error_correction, ERROR_CORRECT_H)

    qr = qrcode.QRCode(error_correction=ec_level)
    qr.add_data(data)
    qr.make(fit=True)

    return QRInfo(
        version=qr.version,
        modules=qr.modules_count,
        data_bytes=len(data.encode()),
        error_correction=error_correction,
    )


def split_for_qr(
    data: str,
    max_bytes: int = DEFAULT_MAX_BYTES,
) -> list[MultiQRPart]:
    """Split data into multiple QR-encodable parts if needed.
    
    Uses BASTION:seq/total: prefix protocol for reassembly.
    
    Args:
        data: Data to split
        max_bytes: Maximum bytes per QR code (before prefix overhead)
        
    Returns:
        List of MultiQRPart objects (single item if no split needed)
    """
    data_bytes = data.encode()

    # Account for prefix overhead: "BASTION:XX/XX:" = ~15 bytes max
    prefix_overhead = 20
    effective_max = max_bytes - prefix_overhead

    if len(data_bytes) <= max_bytes:
        # Single QR, no prefix needed
        return [MultiQRPart(sequence=1, total=1, data=data)]

    # Split into chunks
    chunks: list[str] = []
    pos = 0

    while pos < len(data_bytes):
        # Find safe split point (don't break UTF-8 sequences)
        end = min(pos + effective_max, len(data_bytes))

        # Decode chunk safely
        chunk_bytes = data_bytes[pos:end]
        try:
            chunk = chunk_bytes.decode()
        except UnicodeDecodeError:
            # Back up to find valid UTF-8 boundary
            while end > pos:
                end -= 1
                try:
                    chunk = data_bytes[pos:end].decode()
                    break
                except UnicodeDecodeError:
                    continue
            else:
                raise ValueError("Cannot split data at valid UTF-8 boundary")

        chunks.append(chunk)
        pos = end

    total = len(chunks)
    return [
        MultiQRPart(sequence=i + 1, total=total, data=chunk)
        for i, chunk in enumerate(chunks)
    ]


def reassemble_qr_parts(parts: Sequence[MultiQRPart]) -> str:
    """Reassemble multi-QR parts into original data.
    
    Args:
        parts: List of MultiQRPart objects (any order)
        
    Returns:
        Reassembled data string
        
    Raises:
        ValueError: If parts are missing or inconsistent
    """
    if not parts:
        raise ValueError("No parts to reassemble")

    # Get expected total from first part
    total = parts[0].total

    # Validate all parts have same total
    if not all(p.total == total for p in parts):
        raise ValueError("Inconsistent total count across parts")

    # Check we have all parts
    sequences = {p.sequence for p in parts}
    expected = set(range(1, total + 1))

    if sequences != expected:
        missing = expected - sequences
        raise ValueError(f"Missing parts: {sorted(missing)}")

    # Sort and concatenate
    sorted_parts = sorted(parts, key=lambda p: p.sequence)
    return "".join(p.data for p in sorted_parts)


def generate_qr_terminal(
    data: str,
    error_correction: str = "H",
    invert: bool = True,
) -> str:
    """Generate QR code for terminal display using Unicode half-blocks.
    
    Uses Unicode block characters for compact display:
    - █ (full block) for black
    - ▀ (upper half) for top black, bottom white
    - ▄ (lower half) for top white, bottom black
    - (space) for white
    
    Args:
        data: Data to encode
        error_correction: L/M/Q/H (7%/15%/25%/30% recovery)
        invert: If True, dark modules on light background (default for terminals)
        
    Returns:
        String with Unicode QR code for terminal display
    """
    ec_level = ERROR_CORRECTION_MAP.get(error_correction, ERROR_CORRECT_H)

    qr = qrcode.QRCode(
        error_correction=ec_level,
        border=2,
        box_size=1,
    )
    qr.add_data(data)
    qr.make(fit=True)

    # Get matrix
    matrix = qr.get_matrix()
    if matrix is None:
        raise RuntimeError("Failed to generate QR matrix")

    # Use half-block characters for 2:1 height compression
    # Each output row represents 2 matrix rows
    lines: list[str] = []

    height = len(matrix)
    width = len(matrix[0]) if matrix else 0

    for y in range(0, height, 2):
        line = ""
        for x in range(width):
            top = matrix[y][x] if y < height else False
            bottom = matrix[y + 1][x] if y + 1 < height else False

            if invert:
                top, bottom = not top, not bottom

            if top and bottom:
                line += "█"  # Full block
            elif top and not bottom:
                line += "▀"  # Upper half
            elif not top and bottom:
                line += "▄"  # Lower half
            else:
                line += " "  # Space

        lines.append(line)

    return "\n".join(lines)


def generate_qr_png(
    data: str,
    output_path: Path | str,
    error_correction: str = "H",
    box_size: int = 10,
    border: int = 4,
) -> Path:
    """Generate QR code as PNG file.
    
    Args:
        data: Data to encode
        output_path: Path for output PNG file
        error_correction: L/M/Q/H
        box_size: Pixels per module
        border: Border width in modules
        
    Returns:
        Path to generated PNG file
    """
    ec_level = ERROR_CORRECTION_MAP.get(error_correction, ERROR_CORRECT_H)
    output_path = Path(output_path)

    qr = qrcode.QRCode(
        error_correction=ec_level,
        box_size=box_size,
        border=border,
    )
    qr.add_data(data)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white")
    img.save(str(output_path))

    return output_path


def generate_qr_image_bytes(
    data: str,
    error_correction: str = "H",
    box_size: int = 10,
    border: int = 4,
    format: str = "PNG",
) -> bytes:
    """Generate QR code as image bytes (for embedding in PDF).
    
    Args:
        data: Data to encode
        error_correction: L/M/Q/H
        box_size: Pixels per module
        border: Border width in modules
        format: Image format (PNG, JPEG, etc.)
        
    Returns:
        Image data as bytes
    """
    ec_level = ERROR_CORRECTION_MAP.get(error_correction, ERROR_CORRECT_H)

    qr = qrcode.QRCode(
        error_correction=ec_level,
        box_size=box_size,
        border=border,
    )
    qr.add_data(data)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white")

    buffer = io.BytesIO()
    img.save(buffer, format=format)
    return buffer.getvalue()


def generate_pdf(
    parts: Sequence[MultiQRPart],
    output_path: Path | str,
    title: str = "Bastion Encrypted Transfer",
    error_correction: str = "H",
) -> Path:
    """Generate PDF with multiple QR codes for printing.
    
    Creates a printable document with one QR code per page,
    labeled with sequence numbers.
    
    Args:
        parts: List of MultiQRPart objects
        output_path: Path for output PDF file
        title: Document title
        error_correction: QR error correction level
        
    Returns:
        Path to generated PDF file
    """
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.units import inch
    from reportlab.lib.utils import ImageReader
    from reportlab.pdfgen import canvas

    output_path = Path(output_path)

    # Page setup
    page_width, page_height = letter
    margin = 0.75 * inch

    c = canvas.Canvas(str(output_path), pagesize=letter)
    c.setTitle(title)

    for part in parts:
        # Generate QR code image
        qr_data = part.to_qr_string() if part.total > 1 else part.data
        qr_bytes = generate_qr_image_bytes(qr_data, error_correction=error_correction)
        qr_image = ImageReader(io.BytesIO(qr_bytes))

        # Calculate QR size (max 5 inches, centered)
        qr_size = min(5 * inch, page_width - 2 * margin)
        qr_x = (page_width - qr_size) / 2
        qr_y = (page_height - qr_size) / 2

        # Draw title
        c.setFont("Helvetica-Bold", 16)
        c.drawCentredString(page_width / 2, page_height - margin, title)

        # Draw sequence indicator
        c.setFont("Helvetica", 14)
        if part.total > 1:
            seq_text = f"Part {part.sequence} of {part.total}"
        else:
            seq_text = "Single QR Code"
        c.drawCentredString(page_width / 2, page_height - margin - 24, seq_text)

        # Draw QR code
        c.drawImage(qr_image, qr_x, qr_y, width=qr_size, height=qr_size)

        # Draw instructions
        c.setFont("Helvetica", 10)
        instructions = [
            "Scan this QR code with the manager machine.",
            "Ensure good lighting and hold camera steady.",
        ]
        if part.total > 1:
            instructions.append(f"Scan all {part.total} codes in any order.")

        y = qr_y - 20
        for line in instructions:
            c.drawCentredString(page_width / 2, y, line)
            y -= 14

        # Footer with timestamp
        c.setFont("Helvetica", 8)
        from datetime import datetime
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        c.drawCentredString(page_width / 2, margin / 2, f"Generated: {timestamp}")

        c.showPage()

    c.save()
    return output_path


class QRPartCollector:
    """Collector for reassembling multi-QR sequences from scans.
    
    Maintains state across multiple scans and validates completeness.
    
    Example:
        collector = QRPartCollector()
        
        # Scan QR codes in any order
        collector.add_scan("BASTION:2/3:middle_chunk")
        collector.add_scan("BASTION:1/3:first_chunk")
        collector.add_scan("BASTION:3/3:last_chunk")
        
        if collector.is_complete():
            data = collector.reassemble()
    """

    def __init__(self) -> None:
        self.parts: dict[int, MultiQRPart] = {}
        self.expected_total: int | None = None

    def add_scan(self, qr_string: str) -> bool:
        """Add a scanned QR code string.
        
        Args:
            qr_string: Raw string from QR scanner
            
        Returns:
            True if this is a valid multi-QR part, False otherwise
        """
        part = MultiQRPart.from_qr_string(qr_string)

        if part is None:
            # Not a multi-QR format, treat as single complete message
            self.parts = {1: MultiQRPart(sequence=1, total=1, data=qr_string)}
            self.expected_total = 1
            return True

        # Validate consistency
        if self.expected_total is None:
            self.expected_total = part.total
        elif self.expected_total != part.total:
            raise ValueError(
                f"Inconsistent total: expected {self.expected_total}, got {part.total}"
            )

        self.parts[part.sequence] = part
        return True

    def is_complete(self) -> bool:
        """Check if all parts have been collected."""
        if self.expected_total is None:
            return False

        return len(self.parts) == self.expected_total

    def missing_parts(self) -> list[int]:
        """Get list of missing part numbers."""
        if self.expected_total is None:
            return []

        expected = set(range(1, self.expected_total + 1))
        received = set(self.parts.keys())
        return sorted(expected - received)

    def progress(self) -> tuple[int, int]:
        """Get progress as (received, total)."""
        total = self.expected_total or 0
        return len(self.parts), total

    def reassemble(self) -> str:
        """Reassemble collected parts into original data.
        
        Raises:
            ValueError: If collection is incomplete
        """
        if not self.is_complete():
            missing = self.missing_parts()
            raise ValueError(f"Cannot reassemble: missing parts {missing}")

        return reassemble_qr_parts(list(self.parts.values()))

    def reset(self) -> None:
        """Clear collected parts and start fresh."""
        self.parts = {}
        self.expected_total = None
