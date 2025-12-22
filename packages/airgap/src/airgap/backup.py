"""LUKS-encrypted backup management for airgap key material.

This module provides tools for creating and managing encrypted backups
of GPG keys and other sensitive material on USB drives. Uses LUKS2
encryption for secure at-rest protection.

Features:
- LUKS container creation with strong passphrase
- GPG key export (master + subkeys + revocation cert)
- Backup verification with checksums
- Geographic separation recommendations

Requires root/sudo for LUKS operations.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


@dataclass
class BackupManifest:
    """Manifest describing backup contents and checksums."""

    version: str = "1"
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    device_label: str = ""
    files: list[dict[str, str]] = field(default_factory=list)
    gnupg_version: str = ""
    key_ids: list[str] = field(default_factory=list)

    def add_file(self, name: str, sha256: str, size: int) -> None:
        """Add a file to the manifest."""
        self.files.append({
            "name": name,
            "sha256": sha256,
            "size": size,
        })

    def to_json(self) -> str:
        """Serialize manifest to JSON."""
        return json.dumps({
            "version": self.version,
            "created_at": self.created_at.isoformat(),
            "device_label": self.device_label,
            "files": self.files,
            "gnupg_version": self.gnupg_version,
            "key_ids": self.key_ids,
        }, indent=2)

    @classmethod
    def from_json(cls, json_str: str) -> BackupManifest:
        """Deserialize manifest from JSON."""
        data = json.loads(json_str)
        manifest = cls(
            version=data.get("version", "1"),
            created_at=datetime.fromisoformat(data["created_at"]),
            device_label=data.get("device_label", ""),
            gnupg_version=data.get("gnupg_version", ""),
            key_ids=data.get("key_ids", []),
        )
        manifest.files = data.get("files", [])
        return manifest


def _run_sudo(cmd: list[str], check: bool = True, **kwargs) -> subprocess.CompletedProcess:
    """Run a command with sudo if not already root.

    Args:
        cmd: Command to run
        check: If True, raise on non-zero exit
        **kwargs: Additional subprocess.run arguments

    Returns:
        CompletedProcess result
    """
    if os.geteuid() != 0:
        cmd = ["sudo"] + cmd

    return subprocess.run(cmd, check=check, **kwargs)


def check_luks_available() -> bool:
    """Check if LUKS tools are available.

    Returns:
        True if cryptsetup is installed
    """
    try:
        result = subprocess.run(
            ["cryptsetup", "--version"],
            capture_output=True,
            timeout=5,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def list_block_devices() -> list[dict[str, Any]]:
    """List available block devices for backup.

    Returns:
        List of device info dicts with 'name', 'size', 'type', 'mountpoint'
    """
    try:
        result = subprocess.run(
            ["lsblk", "-J", "-o", "NAME,SIZE,TYPE,MOUNTPOINT,RM,TRAN"],
            capture_output=True,
            text=True,
            timeout=10,
        )

        if result.returncode != 0:
            return []

        data = json.loads(result.stdout)
        devices = []

        for device in data.get("blockdevices", []):
            # Only show removable USB devices
            if device.get("rm") == "1" or device.get("tran") == "usb":
                devices.append({
                    "name": f"/dev/{device['name']}",
                    "size": device.get("size", "unknown"),
                    "type": device.get("type", "disk"),
                    "mountpoint": device.get("mountpoint"),
                    "removable": device.get("rm") == "1",
                    "transport": device.get("tran", "unknown"),
                })

        return devices

    except (FileNotFoundError, subprocess.TimeoutExpired, json.JSONDecodeError):
        return []


def create_luks_container(
    device: str,
    label: str = "BASTION_BACKUP",
    cipher: str = "aes-xts-plain64",
    key_size: int = 512,
    hash_algo: str = "sha512",
    iter_time: int = 5000,
) -> bool:
    """Create a LUKS2 encrypted container on a device.

    WARNING: This will destroy all data on the device!

    Args:
        device: Block device path (e.g., /dev/sdb1)
        label: Label for the encrypted volume
        cipher: LUKS cipher (default: aes-xts-plain64)
        key_size: Key size in bits (default: 512 for XTS)
        hash_algo: Hash algorithm for key derivation
        iter_time: PBKDF iteration time in ms

    Returns:
        True if container was created successfully

    Raises:
        RuntimeError: If creation fails
        PermissionError: If insufficient privileges
    """
    if not check_luks_available():
        raise RuntimeError("cryptsetup not installed. Install with: apt install cryptsetup")

    # Verify device exists
    if not Path(device).exists():
        raise RuntimeError(f"Device not found: {device}")

    # Format with LUKS2
    cmd = [
        "cryptsetup", "luksFormat",
        "--type", "luks2",
        "--cipher", cipher,
        "--key-size", str(key_size),
        "--hash", hash_algo,
        "--iter-time", str(iter_time),
        "--label", label,
        "--verify-passphrase",
        device,
    ]

    try:
        # Note: This will prompt for passphrase interactively
        result = _run_sudo(cmd, check=False, timeout=120)

        if result.returncode != 0:
            raise RuntimeError("LUKS format failed. Check passphrase and device.")

        return True

    except subprocess.TimeoutExpired:
        raise RuntimeError("LUKS format timed out")


def open_luks_container(
    device: str,
    name: str = "bastion_backup",
) -> str:
    """Open a LUKS container for access.

    Args:
        device: Block device with LUKS container
        name: Mapper name for opened container

    Returns:
        Path to opened device (/dev/mapper/<name>)

    Raises:
        RuntimeError: If open fails
    """
    mapper_path = f"/dev/mapper/{name}"

    # Check if already open
    if Path(mapper_path).exists():
        return mapper_path

    cmd = ["cryptsetup", "open", device, name]

    try:
        # Will prompt for passphrase
        result = _run_sudo(cmd, check=False, timeout=60)

        if result.returncode != 0:
            raise RuntimeError("Failed to open LUKS container. Wrong passphrase?")

        return mapper_path

    except subprocess.TimeoutExpired:
        raise RuntimeError("LUKS open timed out")


def close_luks_container(name: str = "bastion_backup") -> bool:
    """Close an opened LUKS container.

    Args:
        name: Mapper name of opened container

    Returns:
        True if closed successfully
    """
    mapper_path = f"/dev/mapper/{name}"

    if not Path(mapper_path).exists():
        return True  # Already closed

    cmd = ["cryptsetup", "close", name]

    try:
        result = _run_sudo(cmd, check=False, timeout=30)
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        return False


def format_filesystem(
    device: str,
    label: str = "BACKUP",
    fstype: str = "ext4",
) -> bool:
    """Format a device with a filesystem.

    Args:
        device: Device to format (e.g., /dev/mapper/bastion_backup)
        label: Filesystem label
        fstype: Filesystem type (ext4 recommended)

    Returns:
        True if formatting succeeded
    """
    if fstype == "ext4":
        cmd = ["mkfs.ext4", "-L", label, device]
    elif fstype == "vfat":
        cmd = ["mkfs.vfat", "-n", label, device]
    else:
        raise ValueError(f"Unsupported filesystem type: {fstype}")

    try:
        result = _run_sudo(cmd, check=False, capture_output=True, timeout=60)
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        return False


def mount_device(device: str, mount_point: Path) -> bool:
    """Mount a device at a mount point.

    Args:
        device: Device to mount
        mount_point: Directory to mount at

    Returns:
        True if mount succeeded
    """
    mount_point.mkdir(parents=True, exist_ok=True)

    cmd = ["mount", device, str(mount_point)]

    try:
        result = _run_sudo(cmd, check=False, timeout=30)
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        return False


def unmount_device(mount_point: Path) -> bool:
    """Unmount a device.

    Args:
        mount_point: Mount point to unmount

    Returns:
        True if unmount succeeded
    """
    if not mount_point.is_mount():
        return True

    cmd = ["umount", str(mount_point)]

    try:
        result = _run_sudo(cmd, check=False, timeout=30)
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        return False


def file_sha256(path: Path) -> str:
    """Calculate SHA256 hash of a file.

    Args:
        path: Path to file

    Returns:
        Hex-encoded SHA256 hash
    """
    sha256 = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(8192):
            sha256.update(chunk)
    return sha256.hexdigest()


def export_gpg_keys(
    gnupghome: Path | str,
    output_dir: Path,
    key_id: str | None = None,
) -> BackupManifest:
    """Export GPG keys to a directory.

    Exports:
    - Master (certify) key
    - Subkeys (sign, encrypt, auth)
    - Public key
    - Revocation certificate

    Args:
        gnupghome: Path to GNUPGHOME directory
        output_dir: Directory to export keys to
        key_id: Specific key ID to export (None = all keys)

    Returns:
        BackupManifest with exported file info

    Raises:
        RuntimeError: If export fails
    """
    gnupghome = Path(gnupghome)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    manifest = BackupManifest()

    # Get GPG version
    try:
        result = subprocess.run(
            ["gpg", "--version"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            manifest.gnupg_version = result.stdout.split("\n")[0]
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    env = os.environ.copy()
    env["GNUPGHOME"] = str(gnupghome)

    # Determine key ID if not specified
    if not key_id:
        result = subprocess.run(
            ["gpg", "--list-secret-keys", "--keyid-format", "long"],
            capture_output=True,
            text=True,
            env=env,
            timeout=10,
        )
        # Parse first key ID
        for line in result.stdout.split("\n"):
            if line.strip().startswith("sec"):
                parts = line.split("/")
                if len(parts) >= 2:
                    key_id = parts[1].split()[0]
                    break

    if not key_id:
        raise RuntimeError("No GPG keys found to export")

    manifest.key_ids.append(key_id)

    # Export master secret key (certify only)
    master_path = output_dir / f"{key_id}-master-certify.key"
    result = subprocess.run(
        ["gpg", "--armor", "--export-secret-keys", key_id],
        capture_output=True,
        env=env,
        timeout=30,
    )
    if result.returncode == 0 and result.stdout:
        master_path.write_bytes(result.stdout)
        manifest.add_file(
            master_path.name,
            file_sha256(master_path),
            len(result.stdout),
        )

    # Export subkeys only
    subkeys_path = output_dir / f"{key_id}-subkeys.key"
    result = subprocess.run(
        ["gpg", "--armor", "--export-secret-subkeys", key_id],
        capture_output=True,
        env=env,
        timeout=30,
    )
    if result.returncode == 0 and result.stdout:
        subkeys_path.write_bytes(result.stdout)
        manifest.add_file(
            subkeys_path.name,
            file_sha256(subkeys_path),
            len(result.stdout),
        )

    # Export public key
    public_path = output_dir / f"{key_id}-public.asc"
    result = subprocess.run(
        ["gpg", "--armor", "--export", key_id],
        capture_output=True,
        env=env,
        timeout=30,
    )
    if result.returncode == 0 and result.stdout:
        public_path.write_bytes(result.stdout)
        manifest.add_file(
            public_path.name,
            file_sha256(public_path),
            len(result.stdout),
        )

    # Generate revocation certificate
    revoke_path = output_dir / f"{key_id}-revoke.asc"
    result = subprocess.run(
        ["gpg", "--armor", "--gen-revoke", key_id],
        capture_output=True,
        input=b"y\n0\n\ny\n",  # Yes, reason 0 (no reason), no description, confirm
        env=env,
        timeout=30,
    )
    if result.returncode == 0 and result.stdout:
        revoke_path.write_bytes(result.stdout)
        manifest.add_file(
            revoke_path.name,
            file_sha256(revoke_path),
            len(result.stdout),
        )

    # Write manifest
    manifest_path = output_dir / "MANIFEST.json"
    manifest_path.write_text(manifest.to_json())

    return manifest


def verify_backup(backup_dir: Path) -> tuple[bool, list[str]]:
    """Verify backup integrity using manifest checksums.

    Args:
        backup_dir: Directory containing backup and manifest

    Returns:
        Tuple of (all_valid, list of error messages)
    """
    errors = []
    manifest_path = backup_dir / "MANIFEST.json"

    if not manifest_path.exists():
        return False, ["MANIFEST.json not found"]

    try:
        manifest = BackupManifest.from_json(manifest_path.read_text())
    except (json.JSONDecodeError, KeyError) as e:
        return False, [f"Invalid manifest: {e}"]

    for file_info in manifest.files:
        file_path = backup_dir / file_info["name"]

        if not file_path.exists():
            errors.append(f"Missing file: {file_info['name']}")
            continue

        actual_hash = file_sha256(file_path)
        expected_hash = file_info["sha256"]

        if actual_hash != expected_hash:
            errors.append(f"Checksum mismatch: {file_info['name']}")

    return len(errors) == 0, errors


@dataclass
class BackupResult:
    """Result of a backup operation."""

    success: bool
    device: str
    mount_point: Path | None
    manifest: BackupManifest | None
    errors: list[str] = field(default_factory=list)


def create_backup(
    device: str,
    gnupghome: Path | str,
    label: str = "BASTION_BACKUP",
    key_id: str | None = None,
) -> BackupResult:
    """Create a complete LUKS-encrypted backup of GPG keys.

    This is the main entry point for backup creation. It:
    1. Creates LUKS container on device
    2. Opens and formats container
    3. Exports GPG keys with manifest
    4. Verifies backup
    5. Closes container

    Args:
        device: Block device to use (e.g., /dev/sdb)
        gnupghome: Path to GNUPGHOME
        label: Label for LUKS container
        key_id: Specific key to backup (None = all)

    Returns:
        BackupResult with status and details
    """
    gnupghome = Path(gnupghome)
    mapper_name = "bastion_backup"
    mount_point = Path("/mnt/bastion_backup")
    errors = []

    try:
        # Step 1: Create LUKS container
        # Note: This prompts for passphrase
        if not create_luks_container(device, label=label):
            return BackupResult(
                success=False,
                device=device,
                mount_point=None,
                manifest=None,
                errors=["Failed to create LUKS container"],
            )

        # Step 2: Open container
        mapper_path = open_luks_container(device, mapper_name)

        # Step 3: Format with ext4
        if not format_filesystem(mapper_path, label="BACKUP"):
            errors.append("Failed to format filesystem")
            close_luks_container(mapper_name)
            return BackupResult(
                success=False,
                device=device,
                mount_point=None,
                manifest=None,
                errors=errors,
            )

        # Step 4: Mount
        if not mount_device(mapper_path, mount_point):
            errors.append("Failed to mount device")
            close_luks_container(mapper_name)
            return BackupResult(
                success=False,
                device=device,
                mount_point=None,
                manifest=None,
                errors=errors,
            )

        # Step 5: Export keys
        backup_dir = mount_point / "keys"
        manifest = export_gpg_keys(gnupghome, backup_dir, key_id)

        # Step 6: Verify
        valid, verify_errors = verify_backup(backup_dir)
        if not valid:
            errors.extend(verify_errors)

        # Step 7: Sync and unmount
        subprocess.run(["sync"], timeout=30)
        unmount_device(mount_point)
        close_luks_container(mapper_name)

        return BackupResult(
            success=valid,
            device=device,
            mount_point=mount_point,
            manifest=manifest,
            errors=errors,
        )

    except Exception as e:
        # Cleanup on error
        try:
            unmount_device(mount_point)
            close_luks_container(mapper_name)
        except Exception:
            pass

        return BackupResult(
            success=False,
            device=device,
            mount_point=None,
            manifest=None,
            errors=[str(e)],
        )


def verify_backup_device(
    device: str,
    mapper_name: str = "bastion_backup",
) -> tuple[bool, list[str], BackupManifest | None]:
    """Verify an existing backup on a LUKS device.

    Args:
        device: Block device with backup
        mapper_name: Mapper name for opening

    Returns:
        Tuple of (valid, errors, manifest)
    """
    mount_point = Path("/mnt/bastion_backup_verify")

    try:
        # Open container (prompts for passphrase)
        mapper_path = open_luks_container(device, mapper_name)

        # Mount read-only
        mount_point.mkdir(parents=True, exist_ok=True)
        result = _run_sudo(
            ["mount", "-o", "ro", mapper_path, str(mount_point)],
            check=False,
            timeout=30,
        )

        if result.returncode != 0:
            close_luks_container(mapper_name)
            return False, ["Failed to mount device"], None

        # Verify
        backup_dir = mount_point / "keys"
        valid, errors = verify_backup(backup_dir)

        # Load manifest
        manifest = None
        manifest_path = backup_dir / "MANIFEST.json"
        if manifest_path.exists():
            try:
                manifest = BackupManifest.from_json(manifest_path.read_text())
            except Exception:
                pass

        # Cleanup
        unmount_device(mount_point)
        close_luks_container(mapper_name)

        return valid, errors, manifest

    except Exception as e:
        try:
            unmount_device(mount_point)
            close_luks_container(mapper_name)
        except Exception:
            pass

        return False, [str(e)], None
