# IPLOC v1.0 — OSINT IP Geolocation Recon

```
    o8o             oooo                      
    `"'             `888                      
    oooo  oo.ooooo.   888   .ooooo.   .ooooo.  
    `888   888' `88b  888  d88' `88b d88' `"Y8 
    888   888   888  888  888   888 888       
    888   888   888  888  888   888 888   .o8 
    o888o  888bod8P' o888o `Y8bod8P' `Y8bod8P' 
        888                                 
        o888o                                
```

> CLI-based OSINT tool for IP geolocation and reconnaissance. Cross-checks multiple sources and pulls Shodan intel in one shot.

---

## Features

- **Single IP Lookup** — Query geolocation data for any public IP address
- **Domain Resolution** — Resolve a domain to its IP and run a full lookup
- **Batch Mode** — Process multiple IPs from a text file automatically
- **Dual-source Cross-check** — Validates results using both `ip-api.com` and `ipinfo.io`
- **Shodan Intel** — Fetches open ports, known vulnerabilities, and tags via Shodan InternetDB
- **Google Maps Link** — Auto-generates a Maps URL from the returned coordinates

---

## Installation

**Clone the repository:**
```bash
git clone https://github.com/parhandesuu/iploc.git
cd iploc
```

**Install dependencies:**
```bash
pip install requests
```

> `socket`, `json`, `os`, `sys`, `time`, and `urllib` are part of the Python standard library — no extra install needed.

---

## Usage

```bash
python iploc.py
```

You'll be presented with an interactive menu:

```
  [1] Single IP Lookup
  [2] Domain to IP + Lookup
  [3] Batch Mode (file)
  [4] Clear Screen
  [5] Exit
```

### Option 1 — Single IP Lookup

Enter any valid public IPv4 address. The tool will:
1. Query `ip-api.com` as the primary source
2. Cross-check with `ipinfo.io`
3. Pull open ports and CVEs from Shodan InternetDB

**Example:**
```
  Target IP: 8.8.8.8
```

### Option 2 — Domain to IP + Lookup

Enter a domain name (e.g. `example.com`). The tool resolves it to an IP via DNS and runs a full geolocation lookup.

**Example:**
```
  Domain: example.com
```

### Option 3 — Batch Mode

Provide a `.txt` file with one IP per line. The tool processes each IP sequentially with a 1-second delay between requests to avoid rate limiting.

**Example file (`targets.txt`):**
```
1.1.1.1
8.8.8.8
9.9.9.9
```

---

## Output Example

```
  Source: ip-api
  ────────────────────────────────────────────────────────────
  IP Address     : 8.8.8.8
  Country        : United States
  Region         : California
  City           : Mountain View
  Latitude       : 37.386
  Longitude      : -122.0838
  ISP            : Google LLC
  Organization   : Google LLC
  AS Number      : AS15169 Google LLC
  Timezone       : America/Los_Angeles

  Maps: https://www.google.com/maps?q=37.386,-122.0838

  ── Shodan Intel ──
  Ports          : 53, 443
  Tags           : anycast
```

---

## Requirements

- Python 3.6+
- `requests` library

---

## Disclaimer

This tool is intended for **educational purposes and authorized security research only**. Do not use it against systems or IP addresses without explicit permission. The author is not responsible for any misuse or damage caused by this tool.

---

## Author

**@parhandesuu** — [GitHub](https://github.com/parhandesuu)