"""
modules/subdomains.py
Simple subdomain enumeration by resolving DNS using a wordlist.
"""
from __future__ import annotations
import socket
from typing import Iterable, List

class SubdomainEnumerator:
    def __init__(self, resolver=socket.gethostbyname):
        self.resolver = resolver

    def enumerate(self, domain: str, wordlist: Iterable[str]) -> List[str]:
        found = []
        for word in wordlist:
            sub = f"{word.strip()}.{domain}".strip()
            if not sub or sub.startswith("."):
                continue
            try:
                self.resolver(sub)
                found.append(sub)
            except Exception:
                pass
        return found
