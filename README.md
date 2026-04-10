# SubEnum Pro
<img width="538" height="203" alt="image" src="https://github.com/user-attachments/assets/6a94200a-57ab-4a10-a171-ae48ead4bf91" />

**Advanced Subdomain Enumeration Engine**
*Deep Recon | Multi-Source | Live Validation*

SubEnum Pro is an advanced, high-performance subdomain enumeration tool designed for bug bounty hunters and penetration testers. It aggregates passive sources, integrates with popular external tools, performs automated DNS resolution, and runs active probing against identified targets.

## Features

- **Multi-Source Passive Recon**: Queries multiple passive sources like crt.sh, HackerTarget, AlienVault, and URLScan without requiring API keys.
- **External Tool Integration**: Automatically detects and uses installed recon tools like `subfinder`, `amass`, `assetfinder`, and `findomain` to maximize coverage.
- **Smart Brute-Forcing**: Built-in wordlists for smart brute-forcing or custom wordlist support.
- **Async DNS Resolution**: High-speed, concurrent DNS validation using multiple public resolvers.
- **Deep Permutation Engine**: Generates and resolves target permutations for deeper discovery.
- **Active HTTP Probing**: Swiftly validates live HTTP/HTTPS services and discovers basic tech fingerprints.
- **Subdomain Takeover Detection**: Built-in fingerprints to detect potentially vulnerable dangling CNAME records.
- **Zone Transfer Support**: Attempts automatic AXFR against discovered nameservers.

## Requirements

SubEnum Pro requires Python 3.7+ and the following packages:
- `aiohttp`
- `aiodns`
- `colorama`
- `dnspython`
- `tqdm`
- `requests`

Installation:

```bash
pip install -r requirements.txt
```

### Optional External Tools
For significantly better results, make sure the following tools are installed and available in your system's `PATH`:
- `subfinder`
- `amass`
- `assetfinder`
- `findomain`
- `httpx`
- `massdns`
- `puredns`

## Usage

Basic run on a single domain:
```bash
python3 subenum_pro.py -d target.com
```

With an output directory and custom thread (concurrency) count:
```bash
python3 subenum_pro.py -d target.com -o results/ -t 100
```

Enable brute-force mode with a custom wordlist and deep permutation:
```bash
python3 subenum_pro.py -d target.com --brute --wordlist dns.txt --deep
```

Run with port scanning and screenshots enabled:
```bash
python3 subenum_pro.py -d target.com --ports --screenshots
```

## Disclaimer

This tool is created for **authorized testing and educational purposes only**. Ensure you have explicit permission from the target owners before running active enumeration. The author is not responsible for any misuse or damage caused by this program.

---

**Author**: Ravindu Lakmina
