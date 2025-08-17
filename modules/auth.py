"""
modules/auth.py
User authentication using bcrypt for hashing and JSON file storage.
"""
from __future__ import annotations
import json
import os
from dataclasses import dataclass
from typing import Optional
import bcrypt

USERS_FILE = os.path.join(os.path.dirname(__file__), "..", "data", "users.json")

@dataclass
class User:
    username: str

class UserAuth:
    def __init__(self, users_file: str = USERS_FILE):
        self.users_file = os.path.abspath(users_file)
        os.makedirs(os.path.dirname(self.users_file), exist_ok=True)
        if not os.path.exists(self.users_file):
            with open(self.users_file, "w", encoding="utf-8") as f:
                json.dump({}, f)

    def _load(self) -> dict:
        with open(self.users_file, "r", encoding="utf-8") as f:
            return json.load(f)

    def _save(self, data: dict) -> None:
        with open(self.users_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def register(self, username: str, password: str) -> bool:
        data = self._load()
        if username in data:
            return False
        hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        data[username] = hashed.decode('utf-8')
        self._save(data)
        return True

    def verify(self, username: str, password: str) -> Optional[User]:
        data = self._load()
        if username not in data:
            return None
        stored = data[username].encode('utf-8')
        if bcrypt.checkpw(password.encode('utf-8'), stored):
            return User(username=username)
        return None
