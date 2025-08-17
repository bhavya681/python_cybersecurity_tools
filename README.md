# PyCyberSuite – All-in-One Cybersecurity Toolkit (Python + Tkinter)

A modular toolkit that bundles authentication, network scanning, subdomain enumeration, password checks (with HaveIBeenPwned), brute-force simulation, dictionary attacks, crypto (Fernet + RSA), automation, and report generation — all behind a simple Tkinter GUI.

## Features
- **User Authentication**: bcrypt-hashed credentials stored in `data/users.json`.
- **Network Scanner**: live host probe + port scan via `python-nmap` if present, with socket fallback.
- **Subdomain Enumerator**: wordlist-based DNS resolution.
- **Password Strength Checker**: local complexity scoring + HaveIBeenPwned k-anonymity API.
- **Brute Force Simulator**: simulate attempts against a verifier callback.
- **Dictionary Attack Tool**: crack bcrypt or sha256 hashes using a wordlist.
- **Crypto Tool**: Fernet (symmetric) + RSA (asymmetric).
- **Automation**: schedule daily tasks using `schedule` (runs in a background thread).
- **Report Generator**: save results to `.json` or `.txt` in `data/reports/`.
- **GUI**: Tkinter Notebook with tabs for each module.

## Tech
- Python 3.9+ recommended
- GUI: Tkinter
- Libraries: `bcrypt`, `cryptography`, `requests`, `schedule`, `python-nmap` (optional), `pytest` or `unittest`

### Install
```bash
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

> **Note**: For advanced port scanning, install `nmap` on your system and `python-nmap` in your virtualenv. Otherwise the app falls back to a basic socket scanner.

### Run
```bash
python main.py
```

### Tests
```bash
python -m unittest discover -s tests -v
```

### HaveIBeenPwned (HIBP)
This project uses the [range API](https://haveibeenpwned.com/API/v3#SearchingPwnedPasswordsByRange) (k-anonymity). No password is transmitted, only the first five SHA-1 characters. Requires internet access to query the API.

### Project Structure
```
PyCyberSuite/
├─ main.py
├─ gui/
│  └─ gui.py
├─ modules/
│  ├─ auth.py
│  ├─ scanner.py
│  ├─ subdomains.py
│  ├─ password_checker.py
│  ├─ bruteforce.py
│  ├─ dictionary_attack.py
│  ├─ crypto_tools.py
│  ├─ automation.py
│  └─ report.py
├─ tests/
│  ├─ test_auth.py
│  ├─ test_crypto.py
│  └─ test_password_checker.py
├─ data/
│  ├─ users.json (auto-created)
│  └─ wordlist.txt
└─ README.md
```

### Debugging with `pdb`
You can drop into the debugger anywhere, for example in `modules/scanner.py`:
```python
import pdb; pdb.set_trace()
```
Run the app/tests in a terminal to interact with pdb.

## Security & Ethics
This toolkit is for **education and authorized testing only**. Always obtain explicit permission before scanning or attacking any system.
# python_cybersecurity_tools
