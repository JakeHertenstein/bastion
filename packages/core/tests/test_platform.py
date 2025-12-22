"""Tests for bastion_core.platform module."""

import sys

import pytest
from bastion_core import platform


class TestCurrentPlatform:
    """Tests for platform detection."""

    def test_current_platform_returns_valid_value(self):
        """current_platform() should return one of the known values."""
        result = platform.current_platform()
        assert result in ("macos", "linux", "windows", "unknown")

    def test_is_macos_matches_current_platform(self):
        """is_macos() should match current_platform() == 'macos'."""
        assert platform.is_macos() == (platform.current_platform() == "macos")

    def test_is_linux_matches_current_platform(self):
        """is_linux() should match current_platform() == 'linux'."""
        assert platform.is_linux() == (platform.current_platform() == "linux")

    def test_is_windows_matches_current_platform(self):
        """is_windows() should match current_platform() == 'windows'."""
        assert platform.is_windows() == (platform.current_platform() == "windows")


class TestMacOSVersion:
    """Tests for macOS version detection."""

    def test_macos_version_returns_tuple_on_macos(self):
        """On macOS, should return a version tuple."""
        if not platform.is_macos():
            pytest.skip("Not running on macOS")
        version = platform.macos_version()
        assert version is not None
        assert isinstance(version, tuple)
        assert len(version) == 3
        assert all(isinstance(v, int) for v in version)

    def test_macos_version_returns_none_on_non_macos(self):
        """On non-macOS, should return None."""
        if platform.is_macos():
            pytest.skip("Running on macOS")
        assert platform.macos_version() is None


class TestArchitecture:
    """Tests for CPU architecture detection."""

    def test_architecture_returns_valid_value(self):
        """architecture() should return a known value."""
        result = platform.architecture()
        assert result in ("arm64", "x86_64", "unknown")

    def test_is_arm64_matches_architecture(self):
        """is_arm64() should match architecture() == 'arm64'."""
        assert platform.is_arm64() == (platform.architecture() == "arm64")

    def test_is_x86_64_matches_architecture(self):
        """is_x86_64() should match architecture() == 'x86_64'."""
        assert platform.is_x86_64() == (platform.architecture() == "x86_64")


class TestPythonVersion:
    """Tests for Python version detection."""

    def test_python_version_matches_sys_version(self):
        """python_version() should match sys.version_info."""
        version = platform.python_version()
        assert version == (
            sys.version_info.major,
            sys.version_info.minor,
            sys.version_info.micro,
        )

    def test_python_version_is_at_least_311(self):
        """Python version should be at least 3.11 for this project."""
        major, minor, _ = platform.python_version()
        assert (major, minor) >= (3, 11)


class TestHomebrew:
    """Tests for Homebrew detection."""

    def test_has_homebrew_returns_bool(self):
        """has_homebrew() should return a boolean."""
        result = platform.has_homebrew()
        assert isinstance(result, bool)

    def test_homebrew_prefix_when_available(self):
        """If Homebrew is installed, prefix should be a valid path."""
        if not platform.has_homebrew():
            pytest.skip("Homebrew not installed")
        prefix = platform.homebrew_prefix()
        assert prefix is not None
        assert isinstance(prefix, str)
        assert len(prefix) > 0

    def test_homebrew_prefix_when_not_available(self):
        """If Homebrew is not installed, prefix should be None."""
        if platform.has_homebrew():
            pytest.skip("Homebrew is installed")
        assert platform.homebrew_prefix() is None
