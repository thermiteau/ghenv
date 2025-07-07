#!/usr/bin/env python3
"""
Test runner for ghenv_lib.py

This script runs the unit tests for the GitHub Environment Variable Management Library.
It can be used to run tests with different options and generate coverage reports.

Usage:
    python run_tests.py                    # Run all tests
    python run_tests.py -v                 # Run tests with verbose output
    python run_tests.py --cov              # Run tests with coverage report
    python run_tests.py -k "test_name"     # Run specific tests
"""

import argparse
import subprocess
import sys


def main():
    """Run the test suite with specified options."""
    parser = argparse.ArgumentParser(description="Run unit tests for ghenv_lib.py")
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Run tests with verbose output"
    )
    parser.add_argument("--cov", action="store_true", help="Generate coverage report")
    parser.add_argument(
        "-k", "--keyword", type=str, help="Only run tests matching the given substring"
    )
    parser.add_argument(
        "--html", action="store_true", help="Generate HTML coverage report"
    )

    args = parser.parse_args()

    # Build pytest command
    cmd = [
        "python",
        "-m",
        "pytest",
        "tests/test_ghenv_lib.py",
        "--import-mode=importlib",
    ]

    if args.verbose:
        cmd.append("-v")

    if args.cov:
        cmd.extend(
            [
                "--cov=ghenv.ghenv_lib",
                "--cov-report=term-missing",
                "--cov-fail-under=80",
            ]
        )

    if args.html:
        cmd.extend(
            ["--cov=ghenv.ghenv_lib", "--cov-report=html", "--cov-fail-under=80"]
        )

    if args.keyword:
        cmd.extend(["-k", args.keyword])

    # Run the tests
    try:
        result = subprocess.run(cmd, check=True)
        print("\n✅ All tests passed!")
        return 0
    except subprocess.CalledProcessError as e:
        print(f"\n❌ Tests failed with exit code {e.returncode}")
        return e.returncode
    except FileNotFoundError:
        print("❌ pytest not found. Please install test dependencies:")
        print("   pip install -r requirements-test.txt")
        return 1


if __name__ == "__main__":
    sys.exit(main())
