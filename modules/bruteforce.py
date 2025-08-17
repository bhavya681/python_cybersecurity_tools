"""
modules/bruteforce.py
Brute force simulator against a provided verifier callback.
"""
from __future__ import annotations
from typing import Iterable, Callable, Optional

class BruteForceSimulator:
    def simulate(self, candidates: Iterable[str], verify_func: Callable[[str], bool], max_attempts: int = 10000) -> Optional[str]:
        """Return the first password that passes verify_func, else None."""
        for i, pwd in enumerate(candidates):
            if i >= max_attempts:
                break
            if verify_func(pwd):
                return pwd
        return None
