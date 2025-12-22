"""Tests for the airgap QR code module."""

import tempfile
from pathlib import Path

import pytest
from airgap.qr import (
    MultiQRPart,
    QRInfo,
    QRPartCollector,
    estimate_qr_size,
    generate_qr_png,
    generate_qr_terminal,
    reassemble_qr_parts,
    split_for_qr,
)


class TestMultiQRPart:
    """Tests for MultiQRPart dataclass."""

    def test_create_part(self):
        """Test creating a QR part."""
        part = MultiQRPart(sequence=1, total=3, data="test data")
        assert part.sequence == 1
        assert part.total == 3
        assert part.data == "test data"

    def test_to_qr_string(self):
        """Test converting to QR string format."""
        part = MultiQRPart(sequence=2, total=5, data="hello world")
        qr_string = part.to_qr_string()
        assert qr_string == "BASTION:2/5:hello world"

    def test_from_qr_string(self):
        """Test parsing QR string format."""
        qr_string = "BASTION:3/4:some data here"
        part = MultiQRPart.from_qr_string(qr_string)
        assert part.sequence == 3
        assert part.total == 4
        assert part.data == "some data here"

    def test_from_qr_string_with_colons(self):
        """Test parsing QR string with colons in data."""
        # Data containing colons should be preserved
        qr_string = "BASTION:1/1:key:value:extra"
        part = MultiQRPart.from_qr_string(qr_string)
        assert part.sequence == 1
        assert part.total == 1
        assert part.data == "key:value:extra"

    def test_from_qr_string_invalid(self):
        """Test parsing invalid QR string returns None."""
        result = MultiQRPart.from_qr_string("invalid string")
        assert result is None

    def test_from_qr_string_wrong_prefix(self):
        """Test parsing QR string with wrong prefix returns None."""
        result = MultiQRPart.from_qr_string("OTHER:1/1:data")
        assert result is None

    def test_roundtrip(self):
        """Test to_qr_string and from_qr_string roundtrip."""
        original = MultiQRPart(sequence=1, total=2, data="test payload")
        qr_string = original.to_qr_string()
        parsed = MultiQRPart.from_qr_string(qr_string)
        assert parsed.sequence == original.sequence
        assert parsed.total == original.total
        assert parsed.data == original.data


class TestQRPartCollector:
    """Tests for QRPartCollector class."""

    def test_create_collector(self):
        """Test creating a collector."""
        collector = QRPartCollector()
        assert not collector.is_complete()
        assert collector.expected_total is None

    def test_add_first_part(self):
        """Test adding first part sets total."""
        collector = QRPartCollector()
        part = MultiQRPart(sequence=1, total=3, data="part1")
        collector.add_scan(part.to_qr_string())
        assert collector.expected_total == 3
        assert not collector.is_complete()

    def test_add_all_parts(self):
        """Test adding all parts completes collection."""
        collector = QRPartCollector()
        for i in range(1, 4):
            part = MultiQRPart(sequence=i, total=3, data=f"part{i}")
            collector.add_scan(part.to_qr_string())
        assert collector.is_complete()

    def test_add_parts_out_of_order(self):
        """Test adding parts out of order works."""
        collector = QRPartCollector()
        collector.add_scan(MultiQRPart(sequence=3, total=3, data="c").to_qr_string())
        collector.add_scan(MultiQRPart(sequence=1, total=3, data="a").to_qr_string())
        collector.add_scan(MultiQRPart(sequence=2, total=3, data="b").to_qr_string())
        assert collector.is_complete()

    def test_get_assembled_data(self):
        """Test assembling data from parts."""
        collector = QRPartCollector()
        collector.add_scan(MultiQRPart(sequence=1, total=3, data="aaa").to_qr_string())
        collector.add_scan(MultiQRPart(sequence=2, total=3, data="bbb").to_qr_string())
        collector.add_scan(MultiQRPart(sequence=3, total=3, data="ccc").to_qr_string())
        data = collector.reassemble()
        assert data == "aaabbbccc"

    def test_get_assembled_data_incomplete(self):
        """Test that incomplete collection raises error."""
        collector = QRPartCollector()
        collector.add_scan(MultiQRPart(sequence=1, total=3, data="a").to_qr_string())
        with pytest.raises(ValueError, match="missing"):
            collector.reassemble()

    def test_duplicate_part_ignored(self):
        """Test that duplicate parts are handled."""
        collector = QRPartCollector()
        collector.add_scan(MultiQRPart(sequence=1, total=2, data="a").to_qr_string())
        collector.add_scan(MultiQRPart(sequence=1, total=2, data="a").to_qr_string())  # duplicate
        collector.add_scan(MultiQRPart(sequence=2, total=2, data="b").to_qr_string())
        assert collector.is_complete()
        assert collector.reassemble() == "ab"

    def test_missing_parts(self):
        """Test getting list of missing parts."""
        collector = QRPartCollector()
        collector.add_scan(MultiQRPart(sequence=1, total=5, data="a").to_qr_string())
        collector.add_scan(MultiQRPart(sequence=3, total=5, data="c").to_qr_string())
        missing = collector.missing_parts()
        assert 2 in missing
        assert 4 in missing
        assert 5 in missing
        assert 1 not in missing
        assert 3 not in missing


class TestSplitForQR:
    """Tests for split_for_qr function."""

    def test_small_data_single_part(self):
        """Test that small data produces single part."""
        data = "hello world"
        parts = split_for_qr(data, max_bytes=100)
        assert len(parts) == 1
        assert parts[0].sequence == 1
        assert parts[0].total == 1
        assert parts[0].data == data

    def test_large_data_multiple_parts(self):
        """Test that large data is split into parts."""
        data = "x" * 5000
        parts = split_for_qr(data, max_bytes=1000)
        assert len(parts) > 1
        # Check sequence numbers
        for i, part in enumerate(parts, 1):
            assert part.sequence == i
            assert part.total == len(parts)

    def test_split_preserves_data(self):
        """Test that splitting and reassembling preserves data."""
        data = "A" * 3000 + "B" * 3000
        parts = split_for_qr(data, max_bytes=1000)
        reassembled = "".join(p.data for p in parts)
        assert reassembled == data

    def test_default_max_bytes(self):
        """Test default max_bytes value."""
        data = "x" * 2500
        parts = split_for_qr(data)  # Default is 2000
        assert len(parts) == 2


class TestReassembleQRParts:
    """Tests for reassemble_qr_parts function."""

    def test_reassemble_single(self):
        """Test reassembling single part."""
        parts = [MultiQRPart(sequence=1, total=1, data="hello")]
        result = reassemble_qr_parts(parts)
        assert result == "hello"

    def test_reassemble_multiple(self):
        """Test reassembling multiple parts."""
        parts = [
            MultiQRPart(sequence=1, total=3, data="aaa"),
            MultiQRPart(sequence=2, total=3, data="bbb"),
            MultiQRPart(sequence=3, total=3, data="ccc"),
        ]
        result = reassemble_qr_parts(parts)
        assert result == "aaabbbccc"

    def test_reassemble_out_of_order(self):
        """Test reassembling parts that arrive out of order."""
        parts = [
            MultiQRPart(sequence=3, total=3, data="ccc"),
            MultiQRPart(sequence=1, total=3, data="aaa"),
            MultiQRPart(sequence=2, total=3, data="bbb"),
        ]
        result = reassemble_qr_parts(parts)
        assert result == "aaabbbccc"

    def test_reassemble_from_strings(self):
        """Test reassembling from QR string format."""
        strings = [
            "BASTION:1/2:first",
            "BASTION:2/2:second",
        ]
        parts = [MultiQRPart.from_qr_string(s) for s in strings]
        result = reassemble_qr_parts(parts)
        assert result == "firstsecond"


class TestGenerateQRTerminal:
    """Tests for generate_qr_terminal function."""

    def test_generate_simple(self):
        """Test generating terminal QR for simple data."""
        output = generate_qr_terminal("hello")
        assert output is not None
        assert len(output) > 0
        # Should contain Unicode block characters
        assert "█" in output or "▀" in output or "▄" in output

    def test_generate_returns_string(self):
        """Test that output is a string."""
        output = generate_qr_terminal("test")
        assert isinstance(output, str)


class TestGenerateQRPng:
    """Tests for generate_qr_png function."""

    def test_generate_png_file(self):
        """Test generating PNG file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "test.png"
            generate_qr_png("hello", output_path)
            assert output_path.exists()
            assert output_path.stat().st_size > 0

    def test_generate_png_returns_path(self):
        """Test generating PNG returns path."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "test.png"
            result = generate_qr_png("hello", output_path)
            assert isinstance(result, Path)
            # PNG magic bytes check
            with open(result, 'rb') as f:
                magic = f.read(4)
            assert magic == b'\x89PNG'


class TestEstimateQRSize:
    """Tests for estimate_qr_size function."""

    def test_small_data(self):
        """Test size estimation for small data."""
        info = estimate_qr_size("hello")
        assert isinstance(info, QRInfo)
        assert info.version >= 1
        assert info.modules >= 21  # Minimum QR size

    def test_large_data(self):
        """Test size estimation for larger data."""
        info = estimate_qr_size("x" * 1000)
        assert info.version > 1

    def test_info_properties(self):
        """Test QRInfo properties."""
        info = estimate_qr_size("test data")
        assert hasattr(info, 'version')
        assert hasattr(info, 'modules')
        assert hasattr(info, 'error_correction')


class TestIntegration:
    """Integration tests for QR workflow."""

    def test_full_split_reassemble_cycle(self):
        """Test full cycle: split → qr_string → parse → reassemble."""
        original_data = "This is a test of the BASTION QR protocol. " * 100

        # Split into parts
        parts = split_for_qr(original_data, max_bytes=500)

        # Convert to QR strings (what would be in actual QR codes)
        qr_strings = [part.to_qr_string() for part in parts]

        # Parse back
        parsed_parts = [MultiQRPart.from_qr_string(s) for s in qr_strings]

        # Reassemble
        result = reassemble_qr_parts(parsed_parts)

        assert result == original_data

    def test_gpg_message_split_reassemble(self):
        """Test splitting and reassembling GPG-like message."""
        gpg_message = """-----BEGIN PGP MESSAGE-----

hQEMA+example+key+IDxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
=XXXX
-----END PGP MESSAGE-----"""

        parts = split_for_qr(gpg_message, max_bytes=200)
        reassembled = reassemble_qr_parts(parts)
        assert reassembled == gpg_message
        assert "-----BEGIN PGP MESSAGE-----" in reassembled
        assert "-----END PGP MESSAGE-----" in reassembled
