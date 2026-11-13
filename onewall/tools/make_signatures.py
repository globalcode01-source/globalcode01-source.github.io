#!/usr/bin/env python3
"""OneWall imza listesi üretici: abuse.ch (anahtar gerekir), OpenPhish, Phishing Army, Hagezi TIF'ten
son kayıtları çekip tek signatures.txt yazar. Yalnızca standart kütüphane. Kullanım:
    ABUSECH_KEY=... python3 -I onewall/tools/make_signatures.py onewall/signatures.txt
Bir kaynak çalışmazsa atlanır; en az bir kaynak başarılıysa dosya yazılır."""
import json, os, re, sys, urllib.request, urllib.parse, datetime

OUT = sys.argv[1] if len(sys.argv) > 1 else "signatures.txt"
KEY = os.environ.get("ABUSECH_KEY", "").strip()
UA = "OneWall-signatures/1.0"
HEX = re.compile(r"^[0-9a-f]{64}$")
DOMAIN = re.compile(r"^(?=.{4,253}$)([a-z0-9-]+\.)+[a-z]{2,}$")
MAX_DOMAINS = 150_000
EICAR = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"

hashes, domains, sources = set(), set(), []

def fetch(url, data=None, headers=None, timeout=60):
    req = urllib.request.Request(url, data=data, headers={"User-Agent": UA, **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "replace")

def host_of(url):
    try:
        h = urllib.parse.urlsplit(url if "://" in url else "http://" + url).hostname or ""
    except ValueError:
        return ""
    return h.lower().strip(".")

def add_domain(d):
    d = d.lower().strip().strip(".")
    if DOMAIN.match(d) and not re.match(r"^\d+(\.\d+){3}$", d):
        domains.add(d)

def abusech(name, url, body):
    if not KEY:
        print(f"{name}: ABUSECH_KEY yok, atlandı"); return
    try:
        txt = fetch(url, data=urllib.parse.urlencode(body).encode(), headers={"Auth-Key": KEY})
        j = json.loads(txt); n = 0
        for item in j.get("data") or j.get("urls") or []:
            h = (item.get("sha256_hash") or "").lower()
            if HEX.match(h): hashes.add(h); n += 1
            u = item.get("url") or item.get("host")
            if u: add_domain(host_of(u)); n += 1
        sources.append(f"{name} {n}"); print(name, n)
    except Exception as e:
        print(f"{name}: hata {e}")

def text_source(name, url, is_url=False, comment="#"):
    try:
        n = 0
        for line in fetch(url).splitlines():
            line = line.strip()
            if not line or line.startswith(comment): continue
            if line.startswith("0.0.0.0 ") or line.startswith("127.0.0.1 "): line = line.split()[1]
            add_domain(host_of(line) if is_url else line); n += 1
            if len(domains) >= MAX_DOMAINS: break
        sources.append(f"{name} {n}"); print(name, n)
    except Exception as e:
        print(f"{name}: hata {e}")

# Android zararlı APK özetleri (MalwareBazaar, son 1000 apk) ve zararlı alan adları (URLhaus son 1000 URL)
abusech("MalwareBazaar", "https://mb-api.abuse.ch/api/v1/", {"query": "get_file_type", "file_type": "apk", "limit": "1000"})
abusech("URLhaus", "https://urlhaus-api.abuse.ch/v1/urls/recent/?limit=1000", {})
# Oltalama alan adları (anahtarsız)
text_source("OpenPhish", "https://openphish.com/feed.txt", is_url=True)
text_source("PhishingArmy", "https://phishing.army/download/phishing_army_blocklist.txt")
text_source("HageziTIF", "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif.mini-onlydomains.txt")

if not sources:
    sys.exit("hiçbir kaynak çalışmadı, dosya yazılmadı")
hashes.add(EICAR)
with open(OUT, "w", encoding="utf-8") as f:
    f.write("# OneWall imza listesi: SHA-256 (APK/dosya) ya da domain:<alan adı>. Otomatik üretilir, elle düzenleme.\n")
    f.write(f"# updated: {datetime.date.today().isoformat()}\n# sources: {', '.join(sources)}\n")
    for h in sorted(hashes): f.write(h + "\n")
    for d in sorted(domains): f.write("domain:" + d + "\n")
print("yazıldı:", OUT, len(hashes), "özet,", len(domains), "alan adı")
