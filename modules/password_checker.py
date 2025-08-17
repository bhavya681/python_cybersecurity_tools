"""
modules/password_checker.py
Password complexity checks + HaveIBeenPwned k-anonymity API.
"""
from __future__ import annotations
import re
import hashlib
import requests

class PasswordStrengthChecker:
    def check_strength(self, password: str) -> dict:
        length = len(password)
        has_upper = bool(re.search(r"[A-Z]", password))
        has_lower = bool(re.search(r"[a-z]", password))
        has_digit = bool(re.search(r"\d", password))
        has_special = bool(re.search(r"[^A-Za-z0-9]", password))
        score = sum([length >= 12, has_upper, has_lower, has_digit, has_special])
        return {
            "length": length,
            "has_upper": has_upper,
            "has_lower": has_lower,
            "has_digit": has_digit,
            "has_special": has_special,
            "score": score,
            "rating": ["Very Weak","Weak","Okay","Good","Strong","Very Strong"][min(score,5)]
        }

    def hibp_pwned_count(self, password: str) -> int:
        """Use HIBP range API without sending full password. Returns number of times seen."""
        sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix, suffix = sha1[:5], sha1[5:]
        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        headers = {"Add-Padding": "true", "User-Agent": "PyCyberSuite/1.0"}
        r = requests.get(url, headers=headers, timeout=10)
        r.raise_for_status()
        for line in r.text.splitlines():
            hash_suffix, count = line.split(":")
            if hash_suffix.strip().upper() == suffix:
                return int(count.strip())
        return 0
