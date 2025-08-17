"""
modules/scanner.py
Network scanning via python-nmap if available, with socket fallback.
"""
from __future__ import annotations
import socket
import subprocess
from typing import List, Dict, Tuple

def _is_port_open(host: str, port: int, timeout: float = 0.5) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        try:
            s.connect((host, port))
            return True
        except Exception:
            return False

class NetworkScanner:
    def __init__(self):
        # Try to import nmap lazily
        try:
            import nmap  # type: ignore
            self._nmap = nmap.PortScanner()
        except Exception:
            self._nmap = None

    def live_hosts(self, base_ip: str, start: int = 1, end: int = 10) -> List[str]:
        """Very simple ping sweep using socket.gethostbyname lookup + TCP probe on port 80."""
        hosts = []
        for i in range(start, end + 1):
            host = f"{base_ip}.{i}"
            if _is_port_open(host, 80) or _is_port_open(host, 443) or _is_port_open(host, 22):
                hosts.append(host)
        return hosts

    def scan_ports(self, host: str, ports: List[int]) -> Dict[int, bool]:
        results: Dict[int, bool] = {}
        if self._nmap:
            try:
                port_str = ",".join(map(str, ports))
                self._nmap.scan(hosts=host, arguments=f"-p {port_str}")
                for p in ports:
                    try:
                        state = self._nmap[host]['tcp'][p]['state']
                        results[p] = (state == 'open')
                    except Exception:
                        results[p] = _is_port_open(host, p)
                return results
            except Exception:
                pass
        # Fallback
        for p in ports:
            results[p] = _is_port_open(host, p)
        return results
