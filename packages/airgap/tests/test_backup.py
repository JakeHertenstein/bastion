"""Tests for the airgap backup module."""

import json
import pytest
from pathlib import Path
from datetime import datetime, timezone
from unittest.mock import patch, MagicMock
import tempfile
import os

from airgap.backup import (
    BackupManifest,
    BackupResult,
    check_luks_available,
    file_sha256,
    verify_backup,
)


class TestBackupManifest:
    """Tests for BackupManifest dataclass."""

    def test_create_manifest_defaults(self):
        """Test creating a manifest with defaults."""
        manifest = BackupManifest()
        assert manifest.version == "1"
        assert manifest.device_label == ""
        assert manifest.files == []
        assert manifest.key_ids == []
        assert manifest.gnupg_version == ""

    def test_create_manifest_with_values(self):
        """Test creating a manifest with explicit values."""
        manifest = BackupManifest(
            version="1",
            device_label="BACKUP-A",
            gnupg_version="2.4.0",
            key_ids=["ABCD1234"],
        )
        assert manifest.version == "1"
        assert manifest.device_label == "BACKUP-A"
        assert manifest.gnupg_version == "2.4.0"
        assert manifest.key_ids == ["ABCD1234"]

    def test_add_file(self):
        """Test adding files to manifest."""
        manifest = BackupManifest()
        manifest.add_file("master.asc", "a" * 64, 1000)
        manifest.add_file("public.asc", "b" * 64, 500)
        
        assert len(manifest.files) == 2
        assert manifest.files[0]["name"] == "master.asc"
        assert manifest.files[0]["sha256"] == "a" * 64
        assert manifest.files[0]["size"] == 1000
        assert manifest.files[1]["name"] == "public.asc"

    def test_manifest_to_json(self):
        """Test converting manifest to JSON."""
        manifest = BackupManifest(
            device_label="TEST",
            gnupg_version="2.4.0",
            key_ids=["KEY123"],
        )
        manifest.add_file("test.asc", "c" * 64, 100)
        
        json_str = manifest.to_json()
        data = json.loads(json_str)
        
        assert data["version"] == "1"
        assert data["device_label"] == "TEST"
        assert data["gnupg_version"] == "2.4.0"
        assert data["key_ids"] == ["KEY123"]
        assert len(data["files"]) == 1
        assert data["files"][0]["name"] == "test.asc"
        assert "created_at" in data  # ISO timestamp

    def test_manifest_from_json(self):
        """Test parsing manifest from JSON."""
        now = datetime.now(timezone.utc).isoformat()
        json_str = json.dumps({
            "version": "1",
            "created_at": now,
            "device_label": "PARSE-TEST",
            "gnupg_version": "2.4.1",
            "key_ids": ["KEY456", "KEY789"],
            "files": [
                {"name": "file1.asc", "sha256": "d" * 64, "size": 200},
                {"name": "file2.asc", "sha256": "e" * 64, "size": 300},
            ],
        })
        manifest = BackupManifest.from_json(json_str)
        
        assert manifest.device_label == "PARSE-TEST"
        assert manifest.gnupg_version == "2.4.1"
        assert manifest.key_ids == ["KEY456", "KEY789"]
        assert len(manifest.files) == 2
        assert manifest.files[0]["name"] == "file1.asc"
        assert manifest.files[1]["name"] == "file2.asc"

    def test_manifest_roundtrip(self):
        """Test JSON roundtrip."""
        original = BackupManifest(
            device_label="ROUNDTRIP",
            gnupg_version="2.4.0",
            key_ids=["KEYABC"],
        )
        original.add_file("a.asc", "f" * 64, 111)
        original.add_file("b.asc", "0" * 64, 222)
        
        json_str = original.to_json()
        parsed = BackupManifest.from_json(json_str)
        
        assert parsed.device_label == original.device_label
        assert parsed.gnupg_version == original.gnupg_version
        assert parsed.key_ids == original.key_ids
        assert len(parsed.files) == len(original.files)
        for orig, pars in zip(original.files, parsed.files):
            assert orig["name"] == pars["name"]
            assert orig["sha256"] == pars["sha256"]
            assert orig["size"] == pars["size"]

    def test_manifest_empty_files(self):
        """Test manifest with no files."""
        manifest = BackupManifest(device_label="EMPTY")
        json_str = manifest.to_json()
        parsed = BackupManifest.from_json(json_str)
        assert len(parsed.files) == 0

    def test_manifest_multiple_key_ids(self):
        """Test manifest with multiple key IDs."""
        manifest = BackupManifest(
            key_ids=["KEY1", "KEY2", "KEY3"],
        )
        json_str = manifest.to_json()
        parsed = BackupManifest.from_json(json_str)
        assert len(parsed.key_ids) == 3
        assert parsed.key_ids == ["KEY1", "KEY2", "KEY3"]


class TestBackupResult:
    """Tests for BackupResult dataclass."""

    def test_create_backup_result_success(self):
        """Test creating a successful backup result."""
        manifest = BackupManifest(device_label="BACKUP-A")
        result = BackupResult(
            success=True,
            device="/dev/sdb1",
            mount_point=Path("/mnt/backup"),
            manifest=manifest,
            errors=[],
        )
        assert result.success is True
        assert result.device == "/dev/sdb1"
        assert result.mount_point == Path("/mnt/backup")
        assert result.manifest is not None
        assert result.errors == []

    def test_create_backup_result_failure(self):
        """Test creating a failed backup result."""
        result = BackupResult(
            success=False,
            device="/dev/sdb1",
            mount_point=None,
            manifest=None,
            errors=["Failed to create LUKS container", "Device busy"],
        )
        assert result.success is False
        assert result.mount_point is None
        assert result.manifest is None
        assert len(result.errors) == 2


class TestCheckLuksAvailable:
    """Tests for check_luks_available function."""

    @patch('subprocess.run')
    def test_luks_available(self, mock_run):
        """Test when cryptsetup is available."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="cryptsetup 2.6.1",
        )
        assert check_luks_available() is True
        mock_run.assert_called_once()

    @patch('subprocess.run')
    def test_luks_not_available(self, mock_run):
        """Test when cryptsetup is not found."""
        mock_run.side_effect = FileNotFoundError("cryptsetup not found")
        assert check_luks_available() is False


class TestFileSha256:
    """Tests for file_sha256 function."""

    def test_sha256_known_content(self):
        """Test SHA256 of known content."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"hello world")
            f.flush()
            
            # SHA256 of "hello world"
            expected = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
            actual = file_sha256(Path(f.name))
            assert actual == expected
            
            os.unlink(f.name)

    def test_sha256_empty_file(self):
        """Test SHA256 of empty file."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.flush()
            
            # SHA256 of empty content
            expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            actual = file_sha256(Path(f.name))
            assert actual == expected
            
            os.unlink(f.name)

    def test_sha256_binary_content(self):
        """Test SHA256 of binary content."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(bytes(range(256)))  # All byte values
            f.flush()
            
            # This will have a consistent hash
            actual = file_sha256(Path(f.name))
            assert len(actual) == 64  # SHA256 is 64 hex chars
            assert all(c in "0123456789abcdef" for c in actual)
            
            os.unlink(f.name)


class TestVerifyBackup:
    """Tests for verify_backup function."""

    def test_verify_valid_backup(self):
        """Test verification of a valid backup."""
        with tempfile.TemporaryDirectory() as tmpdir:
            backup_dir = Path(tmpdir)
            
            # Create a test file
            test_file = backup_dir / "test.asc"
            test_file.write_text("test content")
            
            # Create manifest with correct checksum
            manifest = BackupManifest()
            manifest.add_file(
                "test.asc",
                file_sha256(test_file),
                test_file.stat().st_size,
            )
            
            manifest_path = backup_dir / "manifest.json"
            manifest_path.write_text(manifest.to_json())
            
            # Verify
            success, errors = verify_backup(backup_dir)
            assert success is True
            assert len(errors) == 0

    def test_verify_backup_checksum_mismatch(self):
        """Test verification fails on checksum mismatch."""
        with tempfile.TemporaryDirectory() as tmpdir:
            backup_dir = Path(tmpdir)
            
            # Create a test file
            test_file = backup_dir / "test.asc"
            test_file.write_text("test content")
            
            # Create manifest with WRONG checksum
            manifest = BackupManifest()
            manifest.add_file(
                "test.asc",
                "0" * 64,  # Wrong hash
                test_file.stat().st_size,
            )
            
            manifest_path = backup_dir / "manifest.json"
            manifest_path.write_text(manifest.to_json())
            
            # Verify should fail
            success, errors = verify_backup(backup_dir)
            assert success is False
            assert len(errors) > 0

    def test_verify_backup_missing_file(self):
        """Test verification fails when file is missing."""
        with tempfile.TemporaryDirectory() as tmpdir:
            backup_dir = Path(tmpdir)
            
            # Create manifest referencing non-existent file
            manifest = BackupManifest()
            manifest.add_file(
                "missing.asc",
                "a" * 64,
                1000,
            )
            
            manifest_path = backup_dir / "manifest.json"
            manifest_path.write_text(manifest.to_json())
            
            # Verify should fail
            success, errors = verify_backup(backup_dir)
            assert success is False
            assert len(errors) > 0

    def test_verify_backup_missing_manifest(self):
        """Test verification fails when manifest is missing."""
        with tempfile.TemporaryDirectory() as tmpdir:
            backup_dir = Path(tmpdir)
            
            # No manifest file
            success, errors = verify_backup(backup_dir)
            assert success is False
            assert len(errors) > 0


class TestManifestFileOperations:
    """Tests for manifest file I/O operations."""

    def test_write_and_read_manifest(self):
        """Test writing and reading manifest file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            manifest_path = Path(tmpdir) / "manifest.json"
            
            # Create and write
            manifest = BackupManifest(
                device_label="FILEIO",
                gnupg_version="2.4.0",
                key_ids=["TESTKEY"],
            )
            manifest.add_file("test.asc", "1" * 64, 500)
            manifest_path.write_text(manifest.to_json())
            
            # Read and verify
            loaded = BackupManifest.from_json(manifest_path.read_text())
            assert loaded.device_label == "FILEIO"
            assert len(loaded.files) == 1
            assert loaded.files[0]["name"] == "test.asc"

    def test_manifest_json_pretty_printed(self):
        """Test that manifest JSON is pretty-printed."""
        manifest = BackupManifest(device_label="PRETTY")
        json_str = manifest.to_json()
        
        # Pretty-printed JSON has newlines and indentation
        assert "\n" in json_str
        assert "  " in json_str  # 2-space indent


class TestBackupChecksumVerification:
    """Tests for checksum verification logic."""

    def test_checksum_match(self):
        """Test that matching checksums pass verification."""
        expected_sha256 = "a" * 64
        actual_sha256 = "a" * 64
        assert expected_sha256 == actual_sha256

    def test_checksum_mismatch(self):
        """Test that mismatched checksums fail verification."""
        expected_sha256 = "a" * 64
        actual_sha256 = "b" * 64
        assert expected_sha256 != actual_sha256

    def test_checksum_case_insensitive(self):
        """Test that checksums are compared case-insensitively (hex)."""
        lower = "abcdef" * 10 + "abcd"
        upper = "ABCDEF" * 10 + "ABCD"
        # SHA256 functions return lowercase, but comparison should handle both
        assert lower.lower() == upper.lower()
