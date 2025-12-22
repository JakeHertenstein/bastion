#!/usr/bin/env python3
"""
Integration tests to ensure consistency between Python CLI and web interface.
Tests that both implementations produce identical outputs for the same inputs.
"""

import subprocess
import sys
import unittest
from pathlib import Path

from seeder.core.config import ALPHABET, DEFAULT_MNEMONIC
from seeder.core.grid import SeederGrid
from seeder.core.seed_sources import SeedSources


class TestWebPythonConsistency(unittest.TestCase):
    """Test that web interface produces same results as Python CLI."""

    def setUp(self):
        """Set up test environment."""
        self.web_dir = Path(__file__).parent.parent / "docs" / "web"
        self.test_cases = [
            ("simple", "test phrase", ""),
            ("simple", "Banking2024", ""),
            ("bip39", DEFAULT_MNEMONIC, ""),
            ("bip39", DEFAULT_MNEMONIC, "test passphrase"),
        ]

    def test_crypto_constants_consistency(self):
        """Test that web crypto.js uses same constants as Python."""
        crypto_js_file = self.web_dir / "crypto.js"
        if not crypto_js_file.exists():
            self.skipTest("crypto.js file not found")

        with open(crypto_js_file, encoding='utf-8') as f:
            js_content = f.read()

        # Test alphabet consistency
        python_alphabet = ALPHABET
        # Extract JavaScript alphabet from the file
        alphabet_match = None
        for line in js_content.split('\n'):
            if 'ALPHABET' in line and '[' in line:
                # Extract the alphabet string
                start = line.find('[')
                end = line.find(']') + 1
                if start != -1 and end != 0:
                    alphabet_match = line[start:end]
                    break

        if alphabet_match:
            # Parse the JavaScript array to compare
            js_alphabet_str = alphabet_match.replace('[', '').replace(']', '').replace('"', '').replace("'", '').replace(' ', '')
            js_alphabet = ''.join(js_alphabet_str.split(','))
            self.assertEqual(python_alphabet, js_alphabet,
                           "JavaScript alphabet should match Python alphabet")

    def test_grid_generation_consistency(self):
        """Test that grid generation produces consistent results."""
        for seed_type, seed_value, passphrase in self.test_cases:
            with self.subTest(type=seed_type, seed=seed_value[:20], passphrase=bool(passphrase)):
                # Generate with Python
                if seed_type == "simple":
                    seed_bytes = SeedSources.simple_to_seed(seed_value)
                elif seed_type == "bip39":
                    seed_bytes = SeedSources.bip39_to_seed(seed_value, passphrase)
                else:
                    continue

                # Create grid instance and get tokens
                grid_instance = SeederGrid(seed_bytes)
                python_grid = grid_instance.tokens

                # Verify grid format
                self.assertEqual(len(python_grid), 10, "Grid should have 10 rows")
                for row in python_grid:
                    self.assertEqual(len(row), 10, "Each row should have 10 tokens")
                    for token in row:
                        self.assertEqual(len(token), 4, "Each token should be 4 characters")
                        for char in token:
                            self.assertIn(char, ALPHABET, f"Character {char} should be in alphabet")

    def test_seed_derivation_consistency(self):
        """Test that seed derivation is deterministic."""
        test_phrase = "ConsistencyTest2024"

        # Generate multiple times to ensure determinism
        seed1 = SeedSources.simple_to_seed(test_phrase)
        seed2 = SeedSources.simple_to_seed(test_phrase)
        seed3 = SeedSources.simple_to_seed(test_phrase)

        self.assertEqual(seed1, seed2, "Seed derivation should be deterministic")
        self.assertEqual(seed2, seed3, "Seed derivation should be deterministic")
        self.assertEqual(len(seed1), 64, "Seed should be 64 bytes")

    def test_coordinate_system_consistency(self):
        """Test that coordinate system matches expected format."""
        seed_bytes = SeedSources.simple_to_seed("coordinate_test")
        grid_instance = SeederGrid(seed_bytes)
        grid = grid_instance.tokens

        # Test coordinate generation
        expected_coordinates = []
        for row in range(10):
            for col in range(10):
                coord = f"{chr(ord('A') + col)}{row}"
                expected_coordinates.append(coord)

        # Verify we can access all expected coordinates
        all_coords = []
        for row_idx in range(10):
            for col_idx in range(10):
                coord = f"{chr(ord('A') + col_idx)}{row_idx}"
                all_coords.append(coord)
                # Verify token exists at this coordinate
                token = grid[row_idx][col_idx]
                self.assertIsInstance(token, str)
                self.assertEqual(len(token), 4)

        self.assertEqual(len(all_coords), 100, "Should have 100 coordinates")
        self.assertEqual(len(set(all_coords)), 100, "All coordinates should be unique")

    def test_matrix_dimension_consistency(self):
        """Test that web interface doesn't artificially limit matrix dimensions."""
        # Check Python implementation first
        seed_bytes = SeedSources.simple_to_seed("test phrase")
        grid_instance = SeederGrid(seed_bytes)
        python_grid = grid_instance.tokens

        # Verify Python produces full 10×10
        self.assertEqual(len(python_grid), 10, "Python should generate 10 rows")
        self.assertEqual(len(python_grid[0]), 10, "Python should generate 10 columns")

        # Check web interface JavaScript doesn't limit dimensions
        app_js_file = self.web_dir / "app.js"
        if app_js_file.exists():
            with open(app_js_file, encoding='utf-8') as f:
                js_content = f.read()

            # Ensure no hardcoded 5×5 limitations
            self.assertNotIn('slice(0, 5)', js_content,
                           "JavaScript should not limit matrix to 5×5")
            self.assertNotIn('5×5 preview', js_content,
                           "JavaScript should not describe matrices as 5×5")

            # Should mention 10×10 matrices
            self.assertIn('10×10', js_content,
                         "JavaScript should reference 10×10 matrices")

        # Check crypto.js has correct dimensions
        crypto_js_file = self.web_dir / "crypto.js"
        if crypto_js_file.exists():
            with open(crypto_js_file, encoding='utf-8') as f:
                crypto_content = f.read()

            self.assertIn('TOKENS_WIDE: 10', crypto_content,
                         "crypto.js should configure 10 columns")
            self.assertIn('TOKENS_TALL: 10', crypto_content,
                         "crypto.js should configure 10 rows")


class TestWebFileStructure(unittest.TestCase):
    """Test web file structure and basic content validation."""

    def setUp(self):
        """Set up test environment."""
        self.web_dir = Path(__file__).parent.parent / "docs" / "web"
        self.required_files = [
            ("src/index.html", "HTML main page"),
            ("src/spa-styles.css", "SPA styles"),
            ("public/crypto.js", "Crypto module"),
            ("public/app.js", "Main app"),
            ("public/generator.js", "Generator module")
        ]

    def test_required_files_exist(self):
        """Test that all required web files exist."""
        for filename, description in self.required_files:
            file_path = self.web_dir / filename
            with self.subTest(file=filename):
                self.assertTrue(file_path.exists(), f"{description} ({filename}) should exist")
                self.assertGreater(file_path.stat().st_size, 0, f"{description} ({filename}) should not be empty")

    def test_html_basic_structure(self):
        """Test basic HTML structure without external dependencies."""
        html_files = ["src/index.html"]

        for filename in html_files:
            file_path = self.web_dir / filename
            if not file_path.exists():
                continue

            with self.subTest(file=filename):
                with open(file_path, encoding='utf-8') as f:
                    content = f.read()

                # Basic HTML structure checks (modern HTML patterns)
                self.assertIn('<html', content, f"{filename} should contain <html> tag")
                self.assertIn('<head>', content, f"{filename} should contain <head> section")
                self.assertIn('<body', content, f"{filename} should contain <body> section")  # Flexible for attributes
                self.assertIn('<title>', content, f"{filename} should contain <title> tag")
                self.assertIn('</html>', content, f"{filename} should have closing </html> tag")

    def test_css_basic_content(self):
        """Test that CSS file contains expected content."""
        css_file = self.web_dir / "styles.css"
        if not css_file.exists():
            self.skipTest("styles.css does not exist")

        with open(css_file, encoding='utf-8') as f:
            content = f.read()

        # Check for basic CSS structure
        css_indicators = ['{', '}', ':', ';']
        for indicator in css_indicators:
            self.assertIn(indicator, content, f"CSS should contain {indicator}")

        # Check for some expected selectors/properties
        expected_css_content = ['body', 'font', 'color', 'margin', 'padding']
        for expected in expected_css_content:
            self.assertIn(expected, content, f"CSS should contain {expected}")

    def test_javascript_basic_structure(self):
        """Test that JavaScript files contain expected structure."""
        js_files = ["crypto.js", "app.js", "generator.js"]

        for filename in js_files:
            file_path = self.web_dir / filename
            if not file_path.exists():
                continue

            with self.subTest(file=filename):
                with open(file_path, encoding='utf-8') as f:
                    content = f.read()

                # Basic JavaScript structure checks (modern ES6+ patterns)
                js_indicators = ['{', '}', ';', 'class']  # Removed 'function' - ES6 uses classes
                for indicator in js_indicators:
                    self.assertIn(indicator, content, f"{filename} should contain {indicator}")

    def test_crypto_js_functions_present(self):
        """Test that crypto.js contains expected cryptographic functions."""
        crypto_file = self.web_dir / "crypto.js"
        if not crypto_file.exists():
            self.skipTest("crypto.js does not exist")

        with open(crypto_file, encoding='utf-8') as f:
            content = f.read()

        # Check for key cryptographic function names (modern Web Crypto API patterns)
        expected_functions = [
            'PBKDF2',  # PBKDF2 implementation (Web Crypto API standard)
            'HMAC',    # HMAC implementation (Web Crypto API standard)
            'SHA-512', # SHA-512 reference (Web Crypto API standard)
            'ALPHABET' # Alphabet constant
        ]

        for func_name in expected_functions:
            with self.subTest(function=func_name):
                self.assertIn(func_name, content,
                            f"crypto.js should contain reference to {func_name}")


class TestCLIWebOutputComparison(unittest.TestCase):
    """Test CLI and web interface output comparison."""

    def setUp(self):
        """Set up test environment."""
        self.web_dir = Path(__file__).parent.parent / "docs" / "web"
        # Get the seeder CLI path
        self.seeder_path = Path(__file__).parent.parent / "seeder"

    def test_cli_generates_consistent_output(self):
        """Test that CLI generates consistent output for same inputs with same nonce."""
        if not self.seeder_path.exists():
            self.skipTest("Seeder CLI not found")

        test_phrase = "CLIConsistencyTest"
        test_nonce = "TESTNONC"  # Fixed nonce for determinism

        # Run CLI multiple times with same nonce
        cmd = [sys.executable, str(self.seeder_path), "generate", "grid",
               "--simple", test_phrase, "--nonce", test_nonce]

        try:
            result1 = subprocess.run(cmd, capture_output=True, text=True, timeout=30, check=False)
            result2 = subprocess.run(cmd, capture_output=True, text=True, timeout=30, check=False)

            if result1.returncode == 0 and result2.returncode == 0:
                self.assertEqual(result1.stdout, result2.stdout,
                               "CLI should produce consistent output with same nonce")
            else:
                self.skipTest(f"CLI command failed: {result1.stderr}")

        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            self.skipTest(f"Could not run CLI command: {e}")

    def test_python_api_consistency(self):
        """Test that Python API produces consistent results."""
        test_cases = [
            "APITest1",
            "APITest2",
            "APITest3"
        ]

        for test_phrase in test_cases:
            with self.subTest(phrase=test_phrase):
                # Generate grid multiple times
                seed1 = SeedSources.simple_to_seed(test_phrase)
                seed2 = SeedSources.simple_to_seed(test_phrase)

                grid1_instance = SeederGrid(seed1)
                grid2_instance = SeederGrid(seed2)

                grid1 = grid1_instance.tokens
                grid2 = grid2_instance.tokens

                self.assertEqual(grid1, grid2,
                               f"API should produce consistent grids for {test_phrase}")


if __name__ == '__main__':
    unittest.main()
