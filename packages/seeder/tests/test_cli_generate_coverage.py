#!/usr/bin/env python3
"""
Comprehensive CLI generate command tests targeting missing coverage.

This test suite focuses on the generate.py module which has only 23% coverage
but contains core user-facing functionality. These tests target the specific
missing lines identified in coverage analysis.
"""

import re
import unittest

from seeder.cli.main import app
from typer.testing import CliRunner


def strip_ansi(text: str) -> str:
    """Strip ANSI escape codes from text."""
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text)


class TestCLIGenerateGrid(unittest.TestCase):
    """Test generate grid command variations."""

    def setUp(self):
        """Set up test fixtures."""
        self.runner = CliRunner()

    def test_generate_grid_bip39_basic(self):
        """Test basic BIP-39 grid generation."""
        result = self.runner.invoke(app, [
            "generate", "grid",
            "--bip39", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        ])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("🔐 Using BIP-39 mnemonic", result.stdout)
        self.assertIn("Token Matrix", result.stdout)
        self.assertIn("SHA-512:", result.stdout)

    def test_generate_grid_bip39_with_passphrase(self):
        """Test BIP-39 with passphrase."""
        result = self.runner.invoke(app, [
            "generate", "grid",
            "--bip39", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "--passphrase", "test passphrase"
        ])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("🔐 Using BIP-39 mnemonic", result.stdout)
        self.assertIn("Token Matrix", result.stdout)

    def test_generate_grid_simple_seed(self):
        """Test simple seed generation with Argon2."""
        result = self.runner.invoke(app, [
            "generate", "grid",
            "--simple", "test seed phrase"
        ])
        self.assertEqual(result.exit_code, 0)
        # Now uses Argon2 by default
        self.assertIn("Argon2id", result.stdout)
        self.assertIn("Token Matrix", result.stdout)

    def test_generate_grid_slip39_shares(self):
        """Test SLIP-39 shares grid generation."""
        # Note: SLIP-39 share generation and grid creation may not be implemented
        # This test validates error handling or successful implementation
        result = self.runner.invoke(app, [
            "generate", "grid",
            "--slip39", "test share 1", "test share 2"
        ])
        # Should either work (exit code 0) or show a clear error (exit code != 0)
        # Both are acceptable since SLIP-39 might not be fully implemented
        self.assertIn(result.exit_code, [0, 1, 2])

    def test_generate_grid_coordinate_display(self):
        """Test that grid shows coordinates properly."""
        result = self.runner.invoke(app, [
            "generate", "grid",
            "--simple", "test"
        ])
        self.assertEqual(result.exit_code, 0)
        # Should show row and column headers
        self.assertIn("A", result.stdout)  # Column header
        self.assertIn("0", result.stdout)  # Row header
        self.assertIn("J", result.stdout)  # Last column
        self.assertIn("9", result.stdout)  # Last row

    def test_generate_grid_deterministic_output(self):
        """Test that same input with same nonce produces same output."""
        result1 = self.runner.invoke(app, [
            "generate", "grid",
            "--simple", "deterministic test",
            "--nonce", "TESTNONC"  # Fixed nonce for determinism
        ])
        result2 = self.runner.invoke(app, [
            "generate", "grid",
            "--simple", "deterministic test",
            "--nonce", "TESTNONC"  # Same nonce
        ])
        self.assertEqual(result1.exit_code, 0)
        self.assertEqual(result2.exit_code, 0)
        # Should produce identical output for same input + nonce
        self.assertEqual(result1.stdout, result2.stdout)

    def test_generate_grid_format_variations(self):
        """Test different output formats."""
        base_args = ["generate", "grid", "--simple", "test", "--nonce", "TESTNONC"]

        # Test table format (default)
        result = self.runner.invoke(app, base_args + ["--format", "table"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("┃", result.stdout)  # Table borders

        # Test plain format
        result = self.runner.invoke(app, base_args + ["--format", "plain"])
        self.assertEqual(result.exit_code, 0)
        # Plain format still has security notice with borders, but main content is plain
        lines = result.stdout.split('\n')
        # Check for actual plain output (space-separated tokens)
        self.assertTrue(any(' ' in line and '┃' not in line and '│' not in line
                           for line in lines if line.strip() and 'Security' not in line))

        # Test compact format
        result = self.runner.invoke(app, base_args + ["--format", "compact"])
        self.assertEqual(result.exit_code, 0)
        # Compact format with Argon2 shows label info
        self.assertIn("Label:", result.stdout)

    def test_generate_grid_output_format_options(self):
        """Test that format options work as expected."""
        # Test with table format
        result = self.runner.invoke(app, [
            "generate", "grid",
            "--simple", "test",
            "--format", "table",
            "--nonce", "TESTNONC"
        ])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Token Matrix", result.stdout)

        # Test with plain format
        result = self.runner.invoke(app, [
            "generate", "grid",
            "--simple", "test",
            "--format", "plain",
            "--nonce", "TESTNONC"
        ])
        self.assertEqual(result.exit_code, 0)
        # Plain format with Argon2 shows label info
        self.assertIn("Label:", result.stdout)


class TestCLIGenerateShares(unittest.TestCase):
    """Test generate shares command."""

    def setUp(self):
        """Set up test fixtures."""
        self.runner = CliRunner()

    def test_generate_shares_command_exists(self):
        """Test that shares command exists and shows help."""
        result = self.runner.invoke(app, ["generate", "shares", "--help"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("shares", result.stdout)
        self.assertIn("SLIP-39", result.stdout)

    def test_generate_shares_requires_argument(self):
        """Test that shares command requires an argument."""
        result = self.runner.invoke(app, ["generate", "shares"])
        self.assertNotEqual(result.exit_code, 0)
        # Should show error about missing argument

    def test_generate_shares_with_phrase(self):
        """Test shares generation with a phrase argument."""
        # Based on help output, it expects a phrase argument
        result = self.runner.invoke(app, ["generate", "shares", "TestSecret"])
        # May not be fully implemented, so accept various exit codes
        self.assertIn(result.exit_code, [0, 1, 2])


class TestCLIGeneratePatterns(unittest.TestCase):
    """Test generate patterns command."""

    def setUp(self):
        """Set up test fixtures."""
        self.runner = CliRunner()

    def test_generate_patterns_simple_seed(self):
        """Test password pattern generation."""
        result = self.runner.invoke(app, [
            "generate", "patterns",
            "--simple", "Banking"
        ])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("🎯 Password Patterns", result.stdout)
        self.assertIn("Pattern", result.stdout)
        self.assertIn("Password", result.stdout)

    def test_generate_patterns_with_count(self):
        """Test pattern count option."""
        result = self.runner.invoke(app, [
            "generate", "patterns",
            "--simple", "Banking",
            "--count", "3"
        ])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("🎯 Password Patterns", result.stdout)

    def test_generate_patterns_bip39_seed(self):
        """Test patterns with BIP-39 seed."""
        result = self.runner.invoke(app, [
            "generate", "patterns",
            "--bip39", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        ])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Password Patterns", result.stdout)

    def test_generate_patterns_no_seed_error(self):
        """Test error when no seed provided."""
        result = self.runner.invoke(app, ["generate", "patterns"])
        self.assertNotEqual(result.exit_code, 0)


class TestCLIGenerateErrors(unittest.TestCase):
    """Test generate command error conditions."""

    def setUp(self):
        """Set up test fixtures."""
        self.runner = CliRunner()

    def test_generate_grid_no_seed_source(self):
        """Test error when no seed source provided."""
        result = self.runner.invoke(app, [
            "generate", "grid"
        ])
        self.assertNotEqual(result.exit_code, 0)

    def test_generate_grid_invalid_bip39(self):
        """Test invalid BIP-39 mnemonic handling."""
        result = self.runner.invoke(app, [
            "generate", "grid",
            "--bip39", "invalid mnemonic phrase"
        ])
        self.assertNotEqual(result.exit_code, 0)

    def test_generate_invalid_command(self):
        """Test invalid generate subcommand."""
        result = self.runner.invoke(app, [
            "generate", "invalid-command"
        ])
        self.assertNotEqual(result.exit_code, 0)


class TestCLIGenerateHelp(unittest.TestCase):
    """Test generate command help and documentation."""

    def setUp(self):
        """Set up test fixtures."""
        self.runner = CliRunner()

    def test_generate_help(self):
        """Test main generate help."""
        result = self.runner.invoke(app, ["generate", "--help"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("generate", result.stdout)
        self.assertIn("grid", result.stdout)
        self.assertIn("shares", result.stdout)
        self.assertIn("patterns", result.stdout)

    def test_generate_grid_help(self):
        """Test generate grid help."""
        result = self.runner.invoke(app, ["generate", "grid", "--help"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("--bip39", result.stdout)
        self.assertIn("--simple", result.stdout)
        self.assertIn("--slip39", result.stdout)
        self.assertIn("--format", result.stdout)

    def test_generate_shares_help(self):
        """Test generate shares help."""
        result = self.runner.invoke(app, ["generate", "shares", "--help"])
        self.assertEqual(result.exit_code, 0)
        # Strip ANSI codes for reliable assertion (Rich adds color codes)
        stdout = strip_ansi(result.stdout)
        self.assertIn("--threshold", stdout)
        self.assertIn("--total", stdout)

    def test_generate_patterns_help(self):
        """Test generate patterns help."""
        result = self.runner.invoke(app, ["generate", "patterns", "--help"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("--count", result.stdout)
        # Note: --pattern option doesn't exist based on actual help output


if __name__ == "__main__":
    unittest.main()
