#!/usr/bin/env python3
"""Deploy test suite runner with strict skip enforcement (MTEVIL_REQUIRE_ALL_TESTS=1)."""
import os
from pathlib import Path
import sys
import unittest


def main() -> int:
    deploy_dir = Path(__file__).resolve().parent
    loader = unittest.defaultTestLoader
    suite = loader.discover(start_dir=str(deploy_dir), pattern="test_*.py", top_level_dir=str(deploy_dir))
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    failed = len(result.failures)
    errors = len(result.errors)
    skipped = len(result.skipped)
    passed = result.testsRun - failed - errors - skipped
    print(
        f"DEPLOY_TEST_SUMMARY: total={result.testsRun} passed={passed} failed={failed} errors={errors} skipped={skipped}",
        flush=True,
    )

    if os.environ.get("MTEVIL_REQUIRE_ALL_TESTS") == "1" and skipped > 0:
        print(
            f"ERROR: MTEVIL_REQUIRE_ALL_TESTS=1 but {skipped} deploy test(s) were skipped",
            file=sys.stderr,
        )
        return 1
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
