"""Tests for bastion_core.hardware module."""


from bastion_core import hardware


class TestYubiKey:
    """Tests for YubiKey detection."""

    def test_has_yubikey_returns_bool(self):
        """has_yubikey() should return a boolean."""
        result = hardware.has_yubikey()
        assert isinstance(result, bool)

    def test_yubikey_serials_returns_list(self):
        """yubikey_serials() should return a list."""
        result = hardware.yubikey_serials()
        assert isinstance(result, list)

    def test_yubikey_serials_consistent_with_has_yubikey(self):
        """yubikey_serials() should be non-empty iff has_yubikey() is True."""
        has_key = hardware.has_yubikey()
        serials = hardware.yubikey_serials()
        assert has_key == (len(serials) > 0)


class TestInfnoise:
    """Tests for Infinite Noise TRNG detection."""

    def test_has_infnoise_returns_bool(self):
        """has_infnoise() should return a boolean."""
        result = hardware.has_infnoise()
        assert isinstance(result, bool)

    def test_infnoise_device_path_type(self):
        """infnoise_device_path() should return Path or None."""
        from pathlib import Path

        result = hardware.infnoise_device_path()
        assert result is None or isinstance(result, Path)


class TestSmartCard:
    """Tests for smart card reader detection."""

    def test_has_smartcard_reader_returns_bool(self):
        """has_smartcard_reader() should return a boolean."""
        result = hardware.has_smartcard_reader()
        assert isinstance(result, bool)


class TestCheckAllHardware:
    """Tests for combined hardware status check."""

    def test_check_all_hardware_returns_status(self):
        """check_all_hardware() should return HardwareStatus."""
        result = hardware.check_all_hardware()
        assert isinstance(result, hardware.HardwareStatus)

    def test_hardware_status_fields(self):
        """HardwareStatus should have all expected fields."""
        status = hardware.check_all_hardware()
        assert hasattr(status, "yubikey")
        assert hasattr(status, "yubikey_count")
        assert hasattr(status, "infnoise")
        assert hasattr(status, "smartcard_reader")

    def test_hardware_status_types(self):
        """HardwareStatus fields should have correct types."""
        status = hardware.check_all_hardware()
        assert isinstance(status.yubikey, bool)
        assert isinstance(status.yubikey_count, int)
        assert isinstance(status.infnoise, bool)
        assert isinstance(status.smartcard_reader, bool)

    def test_yubikey_count_consistency(self):
        """yubikey_count should match yubikey flag."""
        status = hardware.check_all_hardware()
        assert status.yubikey == (status.yubikey_count > 0)
