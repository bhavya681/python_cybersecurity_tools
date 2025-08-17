"""
modules/automation.py
Simple scheduling using schedule in a background thread.
"""
from __future__ import annotations
import threading
import schedule
import time
from typing import Callable

class AutomationModule:
    def __init__(self):
        self._stop = threading.Event()
        self._thread = None

    def schedule_daily(self, hour: int, minute: int, job_func: Callable[[], None]) -> None:
        schedule.clear('daily')
        schedule.every().day.at(f"{hour:02d}:{minute:02d}").do(job_func).tag('daily')

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        def runner():
            while not self._stop.is_set():
                schedule.run_pending()
                time.sleep(1)
        self._thread = threading.Thread(target=runner, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
