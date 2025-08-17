"""
gui/gui.py
Tkinter GUI integrating modules. Long-running actions run in threads.
"""
from __future__ import annotations
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext

from modules.auth import UserAuth
from modules.scanner import NetworkScanner
from modules.subdomains import SubdomainEnumerator
from modules.password_checker import PasswordStrengthChecker
from modules.bruteforce import BruteForceSimulator
from modules.dictionary_attack import DictionaryAttackTool
from modules.crypto_tools import CryptoTool
from modules.automation import AutomationModule
from modules.report import ReportGenerator

class PyCyberSuiteGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("PyCyberSuite – All-in-One Cybersecurity Toolkit")
        self.geometry("1000x700")
        self.auth = UserAuth()
        self.scanner = NetworkScanner()
        self.subenum = SubdomainEnumerator()
        self.pwcheck = PasswordStrengthChecker()
        self.brute = BruteForceSimulator()
        self.dictatk = DictionaryAttackTool()
        self.crypto = CryptoTool()
        self.auto = AutomationModule()
        self.report = ReportGenerator()

        self._build()

    def _build(self):
        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True)

        self._auth_tab(nb)
        self._scanner_tab(nb)
        self._subdomain_tab(nb)
        self._password_tab(nb)
        self._brute_tab(nb)
        self._dict_tab(nb)
        self._crypto_tab(nb)
        self._automation_tab(nb)
        self._report_tab(nb)

    # --- Tabs ---
    def _auth_tab(self, nb):
        f = ttk.Frame(nb); nb.add(f, text="Auth")
        tk.Label(f, text="Username").grid(row=0, column=0, sticky="e")
        tk.Label(f, text="Password").grid(row=1, column=0, sticky="e")
        self.auth_user = tk.Entry(f); self.auth_user.grid(row=0, column=1)
        self.auth_pass = tk.Entry(f, show="*"); self.auth_pass.grid(row=1, column=1)
        ttk.Button(f, text="Register", command=self.register_feature).grid(row=2, column=0, pady=4)
        ttk.Button(f, text="Login", command=self._login).grid(row=2, column=1, pady=4)
        self.auth_status = tk.Label(f, text="", fg="blue"); self.auth_status.grid(row=3, column=0, columnspan=2)

    def _scanner_tab(self, nb):
        f = ttk.Frame(nb); nb.add(f, text="Network Scanner")
        tk.Label(f, text="Base IP (e.g., 192.168.1)").grid(row=0, column=0, sticky="e")
        tk.Label(f, text="Range start").grid(row=1, column=0, sticky="e")
        tk.Label(f, text="Range end").grid(row=2, column=0, sticky="e")
        self.base_ip = tk.Entry(f); self.base_ip.insert(0, "192.168.1"); self.base_ip.grid(row=0, column=1)
        self.range_start = tk.Entry(f); self.range_start.insert(0, "1"); self.range_start.grid(row=1, column=1)
        self.range_end = tk.Entry(f); self.range_end.insert(0, "10"); self.range_end.grid(row=2, column=1)
        ttk.Button(f, text="Find Live Hosts", command=lambda: self._thread(self._find_hosts)).grid(row=3, column=0, pady=4)
        ttk.Button(f, text="Scan Ports (top)", command=lambda: self._thread(self._scan_ports)).grid(row=3, column=1, pady=4)
        self.scan_output = scrolledtext.ScrolledText(f, height=20); self.scan_output.grid(row=4, column=0, columnspan=3, sticky="nsew")
        f.rowconfigure(4, weight=1); f.columnconfigure(2, weight=1)

    def _subdomain_tab(self, nb):
        f = ttk.Frame(nb); nb.add(f, text="Subdomains")
        tk.Label(f, text="Domain").grid(row=0, column=0)
        self.sub_domain = tk.Entry(f); self.sub_domain.insert(0, "example.com"); self.sub_domain.grid(row=0, column=1)
        ttk.Button(f, text="Choose Wordlist", command=self._choose_wordlist).grid(row=0, column=2)
        ttk.Button(f, text="Enumerate", command=lambda: self._thread(self._enumerate_subdomains)).grid(row=1, column=1, pady=4)
        self.wordlist_path = tk.Label(f, text="No wordlist selected")
        self.wordlist_path.grid(row=1, column=0)
        self.sub_output = scrolledtext.ScrolledText(f, height=20); self.sub_output.grid(row=2, column=0, columnspan=3, sticky="nsew")
        f.rowconfigure(2, weight=1)

    def _password_tab(self, nb):
        f = ttk.Frame(nb); nb.add(f, text="Password Check")
        tk.Label(f, text="Password").grid(row=0, column=0)
        self.pw_entry = tk.Entry(f, show="*"); self.pw_entry.grid(row=0, column=1)
        ttk.Button(f, text="Strength", command=self._check_strength).grid(row=0, column=2)
        ttk.Button(f, text="HIBP Breach Count", command=lambda: self._thread(self._check_hibp)).grid(row=1, column=2)
        self.pw_output = tk.Label(f, text="", wraplength=700, justify="left"); self.pw_output.grid(row=1, column=0, columnspan=2)

    def _brute_tab(self, nb):
        f = ttk.Frame(nb); nb.add(f, text="Brute Force Simulator")
        tk.Label(f, text="Target Password").grid(row=0, column=0)
        self.target_pw = tk.Entry(f, show="*"); self.target_pw.grid(row=0, column=1)
        tk.Label(f, text="Wordlist File").grid(row=1, column=0)
        self.brute_wordlist = tk.Entry(f); self.brute_wordlist.grid(row=1, column=1)
        ttk.Button(f, text="Browse", command=lambda: self._browse_to(self.brute_wordlist)).grid(row=1, column=2)
        ttk.Button(f, text="Run", command=lambda: self._thread(self._run_bruteforce)).grid(row=2, column=1, pady=4)
        self.brute_output = tk.Label(f, text="")

    def _dict_tab(self, nb):
        f = ttk.Frame(nb); nb.add(f, text="Dictionary Attack")
        tk.Label(f, text="Hashed (bcrypt or sha256 hex)").grid(row=0, column=0)
        self.hash_entry = tk.Entry(f, width=60); self.hash_entry.grid(row=0, column=1, columnspan=2, sticky="we")
        tk.Label(f, text="Wordlist File").grid(row=1, column=0)
        self.dict_wordlist = tk.Entry(f); self.dict_wordlist.grid(row=1, column=1)
        ttk.Button(f, text="Browse", command=lambda: self._browse_to(self.dict_wordlist)).grid(row=1, column=2)
        ttk.Button(f, text="Crack", command=lambda: self._thread(self._run_dict_attack)).grid(row=2, column=1, pady=4)
        self.dict_output = tk.Label(f, text=""); self.dict_output.grid(row=3, column=0, columnspan=3)

    def _crypto_tab(self, nb):
        f = ttk.Frame(nb); nb.add(f, text="Crypto")
        # Fernet
        ttk.Label(f, text="Fernet").grid(row=0, column=0, sticky="w")
        ttk.Button(f, text="Generate Key", command=self._fernet_key).grid(row=1, column=0)
        self.fernet_key = tk.Entry(f, width=80); self.fernet_key.grid(row=1, column=1, columnspan=3)
        tk.Label(f, text="Text").grid(row=2, column=0); self.fernet_text = tk.Entry(f, width=60); self.fernet_text.grid(row=2, column=1, columnspan=2)
        ttk.Button(f, text="Encrypt", command=self._fernet_encrypt).grid(row=2, column=3)
        ttk.Button(f, text="Decrypt", command=self._fernet_decrypt).grid(row=3, column=3)
        self.fernet_out = tk.Text(f, height=5); self.fernet_out.grid(row=3, column=0, columnspan=3, sticky="we")

        # RSA
        row = 4
        ttk.Label(f, text="RSA").grid(row=row, column=0, sticky="w")
        ttk.Button(f, text="Generate Keys", command=self._rsa_keys).grid(row=row+1, column=0)
        self.rsa_priv = tk.Text(f, height=6, width=60); self.rsa_priv.grid(row=row+1, column=1, columnspan=3)
        self.rsa_pub = tk.Text(f, height=6, width=60); self.rsa_pub.grid(row=row+2, column=1, columnspan=3)
        tk.Label(f, text="Plaintext").grid(row=row+3, column=0); self.rsa_text = tk.Entry(f, width=60); self.rsa_text.grid(row=row+3, column=1, columnspan=2)
        ttk.Button(f, text="RSA Encrypt", command=self._rsa_encrypt).grid(row=row+3, column=3)
        ttk.Button(f, text="RSA Decrypt", command=self._rsa_decrypt).grid(row=row+4, column=3)
        self.rsa_out = tk.Text(f, height=5); self.rsa_out.grid(row=row+4, column=0, columnspan=3, sticky="we")

    def _automation_tab(self, nb):
        f = ttk.Frame(nb); nb.add(f, text="Automation")
        tk.Label(f, text="Daily job time (HH:MM)").grid(row=0, column=0)
        self.auto_time = tk.Entry(f); self.auto_time.insert(0, "09:00"); self.auto_time.grid(row=0, column=1)
        ttk.Button(f, text="Schedule Dummy Job", command=self._schedule_job).grid(row=1, column=1)
        ttk.Button(f, text="Start Scheduler", command=self.auto.start).grid(row=2, column=1)
        ttk.Button(f, text="Stop Scheduler", command=self.auto.stop).grid(row=3, column=1)
        self.auto_status = tk.Label(f, text="No job scheduled"); self.auto_status.grid(row=4, column=0, columnspan=3)

    def _report_tab(self, nb):
        f = ttk.Frame(nb); nb.add(f, text="Reports")
        tk.Label(f, text="Save last scan/password results as:").grid(row=0, column=0)
        self.report_name = tk.Entry(f); self.report_name.insert(0, "report"); self.report_name.grid(row=0, column=1)
        ttk.Button(f, text="Save Text", command=self._save_text).grid(row=1, column=0)
        ttk.Button(f, text="Save JSON", command=self._save_json).grid(row=1, column=1)
        self.report_msg = tk.Label(f, text=""); self.report_msg.grid(row=2, column=0, columnspan=3)
        self._last_payload = {}

    # --- Helper methods ---
    def _thread(self, fn):
        threading.Thread(target=fn, daemon=True).start()

    def register_feature(self):
        ok = self.auth.register(self.auth_user.get(), self.auth_pass.get())
        self.auth_status.config(text="Registered!" if ok else "User exists.")

    def _login(self):
        user = self.auth.verify(self.auth_user.get(), self.auth_pass.get())
        self.auth_status.config(text=f"Welcome {user.username}!" if user else "Invalid credentials.")

    def _find_hosts(self):
        base = self.base_ip.get().strip()
        start, end = int(self.range_start.get()), int(self.range_end.get())
        hosts = self.scanner.live_hosts(base, start, end)
        self.scan_output.insert("end", f"Live hosts: {hosts}\n")
        self._last_payload = {"live_hosts": hosts}

    def _scan_ports(self):
        top_ports = [21,22,23,25,53,80,110,139,143,443,445,3389]
        base = self.base_ip.get().strip()
        start, end = int(self.range_start.get()), int(self.range_end.get())
        for i in range(start, end+1):
            host = f"{base}.{i}"
            results = self.scanner.scan_ports(host, top_ports)
            open_ports = [p for p, is_open in results.items() if is_open]
            if open_ports:
                self.scan_output.insert("end", f"{host}: open {open_ports}\n")
        self._last_payload = {"scan_results": "See text output"}

    def _choose_wordlist(self):
        path = filedialog.askopenfilename(title="Select wordlist")
        if path:
            self.wordlist_path.config(text=path)

    def _enumerate_subdomains(self):
        domain = self.sub_domain.get().strip()
        path = self.wordlist_path.cget("text")
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                words = [line.strip() for line in f if line.strip()]
        except Exception:
            messagebox.showerror("Error", "Please choose a valid wordlist file.")
            return
        found = self.subenum.enumerate(domain, words)
        self.sub_output.insert("end", "\n".join(found) + "\n")
        self._last_payload = {"domain": domain, "subdomains": found}

    def _check_strength(self):
        res = self.pwcheck.check_strength(self.pw_entry.get())
        self.pw_output.config(text=str(res))
        self._last_payload = {"password_strength": res}

    def _check_hibp(self):
        try:
            count = self.pwcheck.hibp_pwned_count(self.pw_entry.get())
            messagebox.showinfo("HIBP", f"Password seen {count} times in breaches.")
            self._last_payload = {"hibp_count": count}
        except Exception as e:
            messagebox.showerror("HIBP Error", str(e))

    def _run_bruteforce(self):
        path = self.brute_wordlist.get().strip()
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                words = [w.strip() for w in f if w.strip()]
        except Exception:
            messagebox.showerror("Error", "Invalid wordlist path.")
            return
        target = self.target_pw.get()
        def verify(pw): return pw == target
        found = self.brute.simulate(words, verify, max_attempts=100000)
        messagebox.showinfo("Bruteforce", f"Found: {found}" if found else "Not found")
        self._last_payload = {"bruteforce_found": found}

    def _run_dict_attack(self):
        path = self.dict_wordlist.get().strip()
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                words = [w.strip() for w in f if w.strip()]
        except Exception:
            messagebox.showerror("Error", "Invalid wordlist path.")
            return
        hashed = self.hash_entry.get().strip()
        found = None
        if hashed.startswith("$2"):
            found = self.dictatk.crack_bcrypt(hashed, words)
        else:
            found = self.dictatk.crack_sha256(hashed, words)
        messagebox.showinfo("Dictionary Attack", f"Found: {found}" if found else "Not found")
        self._last_payload = {"dictionary_found": found}

    def _fernet_key(self):
        key = self.crypto.fernet_generate_key()
        self.fernet_key.delete(0, "end")
        self.fernet_key.insert(0, key.decode())

    def _fernet_encrypt(self):
        try:
            key = self.fernet_key.get().encode()
            token = self.crypto.fernet_encrypt(key, self.fernet_text.get().encode())
            self.fernet_out.delete("1.0", "end"); self.fernet_out.insert("end", token.decode())
        except Exception as e:
            messagebox.showerror("Fernet", str(e))

    def _fernet_decrypt(self):
        try:
            key = self.fernet_key.get().encode()
            token = self.fernet_out.get("1.0", "end").strip().encode()
            pt = self.crypto.fernet_decrypt(key, token)
            self.fernet_out.delete("1.0", "end"); self.fernet_out.insert("end", pt.decode())
        except Exception as e:
            messagebox.showerror("Fernet", str(e))

    def _rsa_keys(self):
        priv, pub = self.crypto.rsa_generate_keys()
        self.rsa_priv.delete("1.0", "end"); self.rsa_priv.insert("end", priv.decode())
        self.rsa_pub.delete("1.0", "end"); self.rsa_pub.insert("end", pub.decode())

    def _rsa_encrypt(self):
        try:
            pub = self.rsa_pub.get("1.0", "end").encode()
            ct = self.crypto.rsa_encrypt(pub, self.rsa_text.get().encode())
            self.rsa_out.delete("1.0", "end"); self.rsa_out.insert("end", ct.hex())
        except Exception as e:
            messagebox.showerror("RSA", str(e))

    def _rsa_decrypt(self):
        try:
            priv = self.rsa_priv.get("1.0", "end").encode()
            ct = bytes.fromhex(self.rsa_out.get("1.0", "end").strip())
            pt = self.crypto.rsa_decrypt(priv, ct)
            self.rsa_out.delete("1.0", "end"); self.rsa_out.insert("end", pt.decode())
        except Exception as e:
            messagebox.showerror("RSA", str(e))

    def _schedule_job(self):
        t = self.auto_time.get().strip()
        try:
            hh, mm = map(int, t.split(":"))
            def job():
                self.auto_status.config(text="Scheduled job ran.")
            self.auto.schedule_daily(hh, mm, job)
            self.auto_status.config(text=f"Scheduled daily at {t}.")
        except Exception:
            self.auto_status.config(text="Invalid time format.")

    def _save_text(self):
        name = self.report_name.get().strip() or "report"
        path = self.report.save_text(name, str(self._last_payload))
        self.report_msg.config(text=f"Saved: {path}")

    def _save_json(self):
        name = self.report_name.get().strip() or "report"
        path = self.report.save_json(name, self._last_payload)
        self.report_msg.config(text=f"Saved: {path}")

def run():
    app = PyCyberSuiteGUI()
    app.mainloop()
