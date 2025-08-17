"""
modules/report.py
Report generator to save results in JSON or TXT.
"""
from __future__ import annotations
import json
from datetime import datetime
from typing import Any, Dict, Optional
import os

REPORTS_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "reports")

class ReportGenerator:
    def __init__(self, out_dir: str = REPORTS_DIR):
        self.out_dir = os.path.abspath(out_dir)
        os.makedirs(self.out_dir, exist_ok=True)

    def _ts(self) -> str:
        return datetime.utcnow().strftime("%Y%m%d_%H%M%S")

    def save_json(self, name: str, payload: Dict[str, Any]) -> str:
        path = os.path.join(self.out_dir, f"{name}_{self._ts()}.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
        return path

    def save_text(self, name: str, text: str) -> str:
        path = os.path.join(self.out_dir, f"{name}_{self._ts()}.txt")
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
        return path
