"""
Test Runner - Bypass web3 plugin issue
Esegue i test senza caricare i plugin problematici
"""

import sys
import os

# Add backend to path
sys.path.insert(0, os.path.dirname(__file__))

# Disable web3 plugin BEFORE importing pytest
os.environ['PYTEST_DISABLE_PLUGIN_AUTOLOAD'] = '1'

import pytest

if __name__ == '__main__':
    # Run pytest with custom args
    args = [
        'tests/',
        '-v',
        '--tb=short',
        '--disable-warnings',
        '-p', 'no:pytest_ethereum',
        '-p', 'no:web3',
    ]

    # Add coverage if requested
    if '--cov' in sys.argv:
        args.extend([
            '--cov=.',
            '--cov-report=term',
            '--cov-report=html',
        ])

    # Add specific test file if provided
    if len(sys.argv) > 1 and sys.argv[1].endswith('.py'):
        args = [sys.argv[1]] + args[1:]

    print("Running tests...")
    print(f"Args: {args}")
    print("-" * 60)

    exit_code = pytest.main(args)

    print("-" * 60)
    if exit_code == 0:
        print("[OK] All tests passed!")
    else:
        print(f"[FAIL] Tests failed with exit code: {exit_code}")

    sys.exit(exit_code)
