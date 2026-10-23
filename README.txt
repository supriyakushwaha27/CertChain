# CertiChain

A blockchain-based academic certificate verification system built using Python.

## Features
- Certificate issuance and verification
- Digital signatures and SHA-256 hashing
- Proof-of-Work consensus
- Certificate revocation
- Tamper detection and blockchain validation

## Requirements
- Python 3.10+
- `cryptography`

## Setup and Run

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
py -m pip install cryptography
py demo.py
```

Run tests:

```powershell
py -m unittest test_certchain -v
```

Optional benchmark:

```powershell
py benchmark.py
```

If virtual environment activation is blocked, use `.venv\Scripts\python.exe` instead of `py` to install dependencies and run scripts.

**Note:** CertiChain is a custom Python blockchain prototype, not a Solidity/Remix implementation. The included output files are reference examples; rerun the scripts to generate fresh results.
