#!/usr/bin/env python3
"""
Test runner script that provides a comprehensive overview of all test results.
Shows which tests pass, fail, and what the issues are.
"""

import os
import subprocess
import sys
from pathlib import Path


def run_test_category(category_name, test_pattern, description):
    """Run a category of tests and return results."""
    print(f"\n{'='*60}")
    print(f"🧪 {category_name.upper()}")
    print(f"📋 {description}")
    print('='*60)

    # Use the project's venv python and set environment
    project_dir = Path(__file__).parent.parent
    venv_python = project_dir / "venv" / "bin" / "python"

    # Set up environment
    env = os.environ.copy()
    env['PYTHONPATH'] = str(project_dir / 'src')

    # Split multiple test files if provided
    test_files = test_pattern.split()
    cmd = [str(venv_python), "-m", "pytest"] + test_files + ["-v", "--tb=short"]

    # Debug output
    print(f"🔧 Running: {' '.join(cmd)}")
    print(f"🔧 PYTHONPATH: {env.get('PYTHONPATH', 'Not set')}")
    print(f"🔧 Working dir: {project_dir}")
    print()

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120,
                               cwd=project_dir, env=env)

        if result.returncode == 0:
            print(f"✅ {category_name}: ALL TESTS PASSED")
        else:
            print(f"⚠️  {category_name}: SOME TESTS FAILED")

        # Show summary from output
        lines = result.stdout.split('\n')
        for line in lines:
            if 'failed' in line and 'passed' in line:
                print(f"📊 {line.strip()}")
                break

        # Show first few failures
        if result.returncode != 0:
            print("\n🔍 First few failures:")
            failure_lines = [line for line in lines if 'FAILED' in line][:5]
            for line in failure_lines:
                print(f"   ❌ {line.strip()}")

            # Also show stderr if there are import errors
            if result.stderr:
                print("\n💥 Error output:")
                print(result.stderr[:500])  # First 500 chars of stderr

        return result.returncode == 0

    except subprocess.TimeoutExpired:
        print(f"⏰ {category_name}: TESTS TIMED OUT")
        return False
    except Exception as e:
        print(f"💥 {category_name}: ERROR RUNNING TESTS: {e}")
        return False


def main():
    """Run comprehensive test suite with detailed reporting."""
    print("🚀 SEED CARD COMPREHENSIVE TEST SUITE")
    print("="*60)

    # Change to project directory
    project_dir = Path(__file__).parent.parent
    os.chdir(project_dir)

    # Set Python path
    env = os.environ.copy()
    env['PYTHONPATH'] = str(project_dir / 'src')

    test_categories = [
        ("Core Python Tests", "tests/test_comprehensive.py", "Core cryptographic and seed generation functionality"),
        ("CLI Tests", "tests/test_cli_comprehensive.py tests/test_cli_generate_coverage.py tests/test_cli_working.py", "Command line interface and user interaction"),
        ("Integration Tests", "tests/test_integration_consistency.py", "Python-Web consistency and cross-platform validation"),
        ("Web Validation", "tests/test_web_validation.py", "HTML/CSS/JS structure and security validation"),
        ("All Other Tests", "tests/test_modular.py tests/test_core_coverage.py tests/test_core_missing_coverage.py tests/test_html_validation.py", "Additional component and coverage tests")
    ]

    results = {}

    for category, pattern, description in test_categories:
        results[category] = run_test_category(category, pattern, description)

    # Final summary
    print(f"\n{'='*60}")
    print("📈 FINAL TEST SUMMARY")
    print('='*60)

    total_categories = len(results)
    passing_categories = sum(1 for passed in results.values() if passed)

    for category, passed in results.items():
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"{status} {category}")

    print(f"\n🎯 OVERALL STATUS: {passing_categories}/{total_categories} categories passing")

    if passing_categories == total_categories:
        print("🎉 ALL TEST CATEGORIES PASSING! Ready for deployment.")
        return 0
    else:
        print("⚠️  Some test categories need attention. See details above.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
