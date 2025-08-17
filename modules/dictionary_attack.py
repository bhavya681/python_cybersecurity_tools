"""
modules/dictionary_attack.py
Dictionary attack against a stored hash (bcrypt preferred, sha256 fallback).
"""
from __future__ import annotations
from typing import Iterable, Optional
import bcrypt
import hashlib

class DictionaryAttackTool:
    def crack_bcrypt(self, hashed: str, candidates: Iterable[str], max_attempts: int = 500000) -> Optional[str]:
        hashed_bytes = hashed.encode('utf-8')
        for i, pwd in enumerate(candidates):
            if i >= max_attempts:
                break
            if bcrypt.checkpw(pwd.strip().encode('utf-8'), hashed_bytes):
                return pwd.strip()
        return None

    def crack_sha256(self, hashed_hex: str, candidates: Iterable[str], max_attempts: int = 1000000) -> Optional[str]:
        target = hashed_hex.lower()
        for i, pwd in enumerate(candidates):
            if i >= max_attempts:
                break
            if hashlib.sha256(pwd.strip().encode('utf-8')).hexdigest().lower() == target:
                return pwd.strip()
        return None
