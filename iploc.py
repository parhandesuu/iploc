import os
import sys
import json
import time
import socket
import requests
import urllib.request as urllib2
from urllib.error import URLError, HTTPError

IPAPI_URL = "http://ip-api.com/json/{}"
TIMEOUT = 10
BANNER = """
    o8o             oooo                      
    `"'             `888                      
    oooo  oo.ooooo.   888   .ooooo.   .ooooo.  
    `888   888' `88b  888  d88' `88b d88' `"Y8 
    888   888   888  888  888   888 888       
    888   888   888  888  888   888 888   .o8 
    o888o  888bod8P' o888o `Y8bod8P' `Y8bod8P' 
        888                                 
        o888o                                

                    IPLOC v1.0
            OSINT IP Geolocation Reconn
             By: @parhandesuu on github
"""

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def validate_ip(ip):
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

def resolve_domain(domain):
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None

def ipapi_geo(ip):
    """Primary: ip-api.com"""
    try:
        req = urllib2.Request(IPAPI_URL.format(ip),
        headers={'User-Agent': 'Mozilla/5.0'})
        response = urllib2.urlopen(req, timeout=TIMEOUT)
        data = json.loads(response.read())
        if data.get("status") == "success":
            return {
                "source": "ip-api",
                "ip": data.get("query", ip),
                "country": data.get("country", "N/A"),
                "countryCode": data.get("countryCode", "N/A"),
                "region": data.get("regionName", "N/A"),
                "city": data.get("city", "N/A"),
                "zip": data.get("zip", "N/A"),
                "lat": data.get("lat", "N/A"),
                "lon": data.get("lon", "N/A"),
                "isp": data.get("isp", "N/A"),
                "org": data.get("org", "N/A"),
                "as": data.get("as", "N/A"),
                "timezone": data.get("timezone", "N/A"),
            }
        else:
            return {"source": "ip-api.com", "error": data.get("status", "unknown")}
    except HTTPError as e:
        return {"source": "ip-api.com", "error": f"HTTP {e.code}"}
    except URLError as e:
        return {"source": "ip-api.com", "error": f"Connection failed: {e.reason}"}
    except Exception as e:
        return {"source": "ip-api.com", "error": str(e)}

def ipinfo_lookup(ip):
    """Secondary: ipinfo.io"""
    try:
        resp = requests.get(f"https://ipinfo.io/{ip}/json",
                            headers={'User-Agent': 'Mozilla/5.0'},
                            timeout=TIMEOUT)
        if resp.status_code == 200:
            data = resp.json()
            loc = data.get("loc", "0,0").split(",")
            return {
                "source": "ipinfo.io",
                "ip": data.get("ip", ip),
                "city": data.get("city", "N/A"),
                "region": data.get("region", "N/A"),
                "country": data.get("country", "N/A"),
                "loc": data.get("loc", "N/A"),
                "lat": loc[0] if len(loc) > 0 else "N/A",
                "lon": loc[1] if len(loc) > 1 else "N/A",
                "org": data.get("org", "N/A"),
                "postal": data.get("postal", "N/A"),
                "timezone": data.get("timezone", "N/A"),
            }
        else:
            return {"source": "ipinfo.io", "error": f"HTTP {resp.status_code}"}
    except requests.exceptions.Timeout:
        return {"source": "ipinfo.io", "error": "Timeout"}
    except requests.exceptions.ConnectionError:
        return {"source": "ipinfo.io", "error": "Connection failed"}
    except Exception as e:
        return {"source": "ipinfo.io", "error": str(e)}

def shodan_lookup(ip):
    try:
        resp = requests.get(f"https://internetdb.shodan.io/{ip}", timeout=TIMEOUT)
        if resp.status_code == 200:
            return resp.json()
    except:
        pass
    return None

def print_separator(char="─", length=60):
    print(char * length)

def display_results(results):
    if not results or "error" in results:
        return
    source = results.get("source", "Unknown")
    print(f"\n  Source: {source}")
    print_separator()

    fields = [
        ("IP Address", "ip"),
        ("Country", "country"),
        ("Region", "region"),
        ("City", "city"),
        ("ZIP/Postal", "zip", "postal"),
        ("Latitude", "lat"),
        ("Longitude", "lon"),
        ("ISP", "isp", "org"),
        ("Organization", "org"),
        ("AS Number", "as"),
        ("Timezone", "timezone"),
    ]

    for field in fields:
        key = field[1]
        alt_key = field[2] if len(field) > 2 else None
        value = results.get(key) or (results.get(alt_key) if alt_key else None)
        if value and value != "N/A":
            print(f"  {field[0]:15}: {value}")

    lat = results.get("lat", "N/A")
    lon = results.get("lon", "N/A")
    if lat != "N/A" and lon != "N/A":
        print(f"\n  Maps: https://www.google.com/maps?q={lat},{lon}")

def display_shodan(data):
    if not data:
        return
    ports = data.get('ports', [])
    vulns = data.get('vulns', [])
    tags = data.get('tags', [])
    if ports or vulns or tags:
        print(f"\n  ── Shodan Intel ──")
        if ports:
            print(f"  Ports          : {', '.join(map(str, ports))}")
        if vulns:
            print(f"  Vulnerabilities: {', '.join(vulns)}")
        if tags:
            print(f"  Tags           : {', '.join(tags)}")

def batch_mode():
    filename = input("  Enter filename (one IP per line): ").strip()
    try:
        with open(filename, 'r') as f:
            ips = [line.strip() for line in f if line.strip()]
        print(f"\n  Loaded {len(ips)} IPs from {filename}")
        for i, ip in enumerate(ips, 1):
            print_separator("━")
            print(f"  [{i}/{len(ips)}] Processing: {ip}")
            if validate_ip(ip):
                res = ipapi_geo(ip)
                if res and "error" not in res:
                    display_results(res)
                else:
                    err = res.get('error', 'Unknown') if res else 'No response'
                    print(f"  [!] Error: {err}")
            else:
                print(f"  [!] Invalid IP: {ip}")
            time.sleep(1)
    except FileNotFoundError:
        print(f"  [!] File not found: {filename}")
    except Exception as e:
        print(f"  [!] Error: {e}")

def main():
    clear_screen()
    print(BANNER)

    while True:
        print("\n  [1] Single IP Lookup")
        print("  [2] Domain to IP + Lookup")
        print("  [3] Batch Mode (file)")
        print("  [4] Clear Screen")
        print("  [5] Exit")
        choice = input("\n  Choose [1-5]: ").strip()

        if choice == "1":
            ip = input("  Target IP: ").strip()
            if not validate_ip(ip):
                print("  [!] Invalid IP format!")
                continue

            print(f"\n  [!] Reconning: {ip}")
            print_separator("━")

            # Primary
            result1 = ipapi_geo(ip)
            if result1 and "error" not in result1:
                display_results(result1)
            else:
                err = result1.get('error', 'Unknown') if result1 else 'No response'
                print(f"  [!] ip-api error: {err}")

            # Secondary
            print("\n  [!] Cross-checking with ipinfo.io...")
            result2 = ipinfo_lookup(ip)
            if result2 and "error" not in result2:
                display_results(result2)
            elif result2:
                print(f"  [!] ipinfo error: {result2['error']}")
            else:
                print("  [!] ipinfo: No response")

            # Shodan
            print("\n  [!] Checking Shodan...")
            shodan_data = shodan_lookup(ip)
            display_shodan(shodan_data)

        elif choice == "2":
            domain = input("  Domain: ").strip()
            ip = resolve_domain(domain)
            if not ip:
                print("  [!] Could not resolve domain!")
                continue
            print(f"  [!] {domain} → {ip}")
            print_separator("━")

            result = ipapi_geo(ip)
            if result and "error" not in result:
                display_results(result)
            else:
                err = result.get('error', 'Unknown') if result else 'No response'
                print(f"  [!] Error: {err}")

        elif choice == "3":
            batch_mode()

        elif choice == "4":
            clear_screen()
            print(BANNER)

        elif choice == "5":
            print("\n see u! \n")
            sys.exit(0)

        else:
            print("  [!] Invalid choice!")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n  [!] Interrupted by user.\n")
