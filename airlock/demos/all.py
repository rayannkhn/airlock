"""Run every attack demo and print a PASS/FAIL summary. Takes a few seconds; no camera needed.

    python -m airlock.demos.all            # full narration
    python -m airlock.demos.all --summary  # one line per demo

Exit code 0 only if every demo passes.
"""

from __future__ import annotations

import argparse
import time
from typing import Callable

from airlock.demos import eavesdrop, mitm_airlock, mitm_insecure, replay, tamper, truncate

DEMOS: list[tuple[str, str, Callable[..., bool]]] = [
    ("Eavesdropper", "captured frames are unreadable ciphertext", eavesdrop.run),
    ("MITM vs insecure variant", "attack SUCCEEDS (expected: no authentication)", mitm_insecure.run),
    ("MITM vs AirLock", "rejected: signatures, trust store, verification code", mitm_airlock.run),
    ("Replay", "old recordings and packets rejected", replay.run),
    ("Tampering", "every modified packet rejected", tamper.run),
    ("Truncation", "no partial file ever written", truncate.run),
]


def run_all(quiet: bool = False) -> bool:
    results: list[tuple[str, str, bool, float]] = []
    for name, outcome, func in DEMOS:
        start = time.perf_counter()
        ok = func(quiet=quiet)
        results.append((name, outcome, ok, time.perf_counter() - start))

    print("\n" + "=" * 72)
    print("AirLock attack demos: summary")
    print("=" * 72)
    for name, outcome, ok, seconds in results:
        print(f"[{'PASS' if ok else 'FAIL'}] {name:<26} {outcome}  ({seconds:.1f}s)")
    passed = sum(ok for _, _, ok, _ in results)
    print("-" * 72)
    print(f"{passed}/{len(results)} demos passed. AirLock was tested against these attacks;")
    print("that is evidence, not a proof of security.")
    return passed == len(results)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--summary", action="store_true", help="only print the summary table")
    args = parser.parse_args()
    return 0 if run_all(quiet=args.summary) else 1


if __name__ == "__main__":
    raise SystemExit(main())
