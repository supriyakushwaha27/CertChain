CERTCHAIN - QUICK START

Requirements: Python 3.10+ and the cryptography package.

Windows PowerShell steps:
1. Open this folder in VS Code.
2. Open Terminal > New Terminal.
3. Run: py -m venv .venv
4. Run: .venv\Scripts\Activate.ps1
   If activation is blocked, use: .venv\Scripts\python.exe -m pip install cryptography
   and run scripts with .venv\Scripts\python.exe instead.
5. Install dependency: py -m pip install cryptography
6. Run demo: py demo.py
7. Run tests: py -m unittest test_certchain -v
8. Run benchmark (optional): py benchmark.py

The project is a custom Python blockchain prototype. It is not the Solidity/Remix implementation.
Use demo_output.txt and benchmark_output.txt only as reference examples; rerun scripts to generate fresh results.
