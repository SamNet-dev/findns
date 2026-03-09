🌐 Languages: [English](#-findns) | [فارسی](#-findns-1)

# 🔍 findns

**A fast, multi-protocol DNS resolver scanner for finding resolvers compatible with DNS tunneling.**

Supports both **UDP** and **DoH (DNS-over-HTTPS)** resolvers with end-to-end tunnel verification through [DNSTT](https://www.bamsoftware.com/software/dnstt/) and [Slipstream](https://github.com/Mygod/slipstream-rust).

> 🌐 Built for **restricted networks** where finding a working resolver is the difference between connectivity and isolation.

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🔄 **UDP + DoH Scanning** | Test both plain DNS (port 53) and DNS-over-HTTPS (port 443) |
| 🔗 **Full Scan Pipeline** | Ping → Resolve → NXDOMAIN → EDNS → Tunnel → E2E in one command |
| 🛡️ **Hijack Detection** | Detect DNS resolvers that inject fake answers (NXDOMAIN check) |
| 📏 **EDNS Payload Testing** | Find resolvers that support large DNS payloads (faster tunnels) |
| 🚇 **E2E Tunnel Verification** | Actually launches DNSTT/Slipstream clients to verify real connectivity |
| 📥 **Resolver List Fetcher** | Auto-download thousands of resolvers from public sources |
| 🌍 **Regional Resolver Lists** | Built-in support for regional intranet resolver lists (7,800+ IPs) |
| ⚡ **High Concurrency** | 50 parallel workers by default — scans thousands of resolvers in minutes |
| 📋 **JSON Pipeline** | Output from one scan feeds into the next for multi-stage filtering |
| 🌐 **CIDR Input** | Accept IP ranges like `185.51.200.0/24` — auto-expanded to individual hosts |

---

## 🏗️ How It Works

```
          Restricted Network                   |     Open Internet
                                               |
  📱 Client ──[UDP:53]──→ Resolver ──[UDP:53]──→ 🖥️ DNSTT Server
  📱 Client ──[HTTPS:443]──→ DoH Resolver ────→ 🖥️ DNSTT Server
                                               |
           ↑ scanner tests this part ↑
```

### 🤔 Why DoH Matters

| Transport | Port | Visibility | Restricted Networks |
|-----------|------|------------|---------------------|
| 🔴 UDP DNS | 53 | Fully visible to DPI | Monitored, often blocked |
| 🔴 DoT | 853 | TLS on known port | Often blocked |
| 🟢 **DoH** | **443** | **Looks like HTTPS** | **Hard to detect** |
| 🔴 DoQ | 443/UDP | QUIC-based | Often disabled |

The DNSTT server **always** listens on port 53 — that never changes. But the **client** can talk to the middleman resolver using different transports. DoH wraps DNS queries inside regular HTTPS, making it nearly invisible to firewalls.

---

## 📦 Install

### From Source

```bash
git clone https://github.com/SamNet-dev/findns.git
cd findns
go build -o findns ./cmd
```

### Go Install

```bash
go install github.com/SamNet-dev/findns/cmd@latest
```

### Download Binary

Pre-built binaries for Linux, macOS, and Windows are available on the [Releases](https://github.com/SamNet-dev/findns/releases) page.

```bash
# Example: Linux x64
curl -LO https://github.com/SamNet-dev/findns/releases/latest/download/findns-linux-amd64
chmod +x findns-linux-amd64
./findns-linux-amd64 --help
```

### Requirements

- **Go 1.24+** for building from source
- **dnstt-client** — only for e2e tunnel tests (`--pubkey`). Install: `go install www.bamsoftware.com/git/dnstt.git/dnstt-client@latest`
- **slipstream-client** — only for e2e Slipstream tests (`--cert`)
- **curl** — for e2e connectivity verification

> **Finding binaries:** findns automatically searches for `dnstt-client` and `slipstream-client` in three places: 1) `PATH` 2) current directory 3) next to the findns executable. The simplest approach: place the binary next to findns.
>
> Without `--pubkey`, the scanner still finds resolvers compatible with DNS tunneling — it tests ping, resolve, NXDOMAIN, EDNS, and tunnel delegation without needing dnstt-client.

---

## 🪟 Windows Guide

Windows is fully supported. Two ways to get started:

### Option 1: Download Binary (Easiest)

1. Go to the [Releases](https://github.com/SamNet-dev/findns/releases) page
2. Download `findns-windows-amd64.exe`
3. Rename it to `findns.exe` (optional, for convenience)
4. Open **cmd** or **PowerShell** in the same folder
5. Run:

```powershell
.\findns.exe --help
```

> No Go installation needed — just download and run.

### Option 2: Build from Source

Requires **Go 1.24+** installed from [go.dev/dl](https://go.dev/dl/).

```powershell
git clone https://github.com/SamNet-dev/findns.git
cd findns
go build -o findns.exe ./cmd
```

### Run

Use `.\findns.exe` instead of `findns` in all commands:

```powershell
# Fetch resolvers
.\findns.exe fetch -o resolvers.txt

# Full scan
.\findns.exe scan -i resolvers.txt -o results.json --domain t.example.com

# With e2e test
.\findns.exe scan -i resolvers.txt -o results.json ^
  --domain t.example.com --pubkey <hex-pubkey>
```

> **Tip:** In PowerShell, use backtick `` ` `` for line continuation instead of `^`.

### Prerequisites

- **curl** — included by default in Windows 10/11
- **dnstt-client.exe** — place next to `findns.exe` or in a folder in your `PATH` (only for e2e DNSTT tests)
- **slipstream-client.exe** — same as above (only for e2e Slipstream tests)

### Common Issues

| Issue | Fix |
|-------|-----|
| `ping` shows 0% loss but scan fails | Run as **Administrator** — Windows ICMP requires elevated privileges |
| `dnstt-client` not found | Place `dnstt-client.exe` next to `findns.exe` or add its folder to PATH |
| PowerShell blocks execution | Use `cmd.exe` or run `Set-ExecutionPolicy RemoteSigned -Scope CurrentUser` |
| Long commands break | Use backtick `` ` `` (PowerShell) or `^` (cmd) for line continuation |

---

## 🚀 Quick Start

### 1️⃣ Get Resolver Lists

```bash
# 📥 Download global UDP resolvers
findns fetch -o resolvers.txt

# 🌍 Include 7,800+ known regional resolvers (embedded, offline)
findns fetch -o resolvers.txt --local

# 🔒 Download DoH resolver URLs
findns fetch -o doh-resolvers.txt --doh
```

### 2️⃣ Run Full Scan

```bash
# 🔍 Scan UDP resolvers (all checks)
findns scan -i resolvers.txt -o results.json --domain t.example.com

# 🔍 Scan with e2e DNSTT verification
findns scan -i resolvers.txt -o results.json \
  --domain t.example.com --pubkey <hex-pubkey>

# 🔒 Scan DoH resolvers
findns scan -i doh-resolvers.txt -o results.json \
  --domain t.example.com --doh

# 🔒 DoH scan with e2e verification
findns scan -i doh-resolvers.txt -o results.json \
  --domain t.example.com --pubkey <hex-pubkey> --doh
```

### 3️⃣ Check Results

Results are saved as JSON. The `passed` array contains resolvers that survived all steps, sorted by performance:

```json
{
  "passed": [
    {"ip": "1.1.1.1", "metrics": {"ping_ms": 4.2, "resolve_ms": 15.3, "edns_max": 1232}},
    {"ip": "8.8.8.8", "metrics": {"ping_ms": 12.7, "resolve_ms": 22.1, "edns_max": 1232}}
  ]
}
```

---

## 📖 Commands

### 🎯 `scan` — All-in-One Pipeline (Recommended)

Automatically chains the right scan steps based on your flags. This is the **recommended** way to use the scanner.

```bash
findns scan -i resolvers.txt -o results.json --domain t.example.com
```

**UDP mode pipeline:** `ping → resolve → nxdomain → edns → tunnel → e2e`
**DoH mode pipeline:** `doh/resolve → doh/tunnel → doh/e2e`

| Flag | Description | Default |
|------|-------------|---------|
| `--domain` | Tunnel domain (enables tunnel/edns/e2e steps) | — |
| `--pubkey` | DNSTT server public key (enables e2e test) | — |
| `--cert` | Slipstream cert path (enables Slipstream e2e) | — |
| `--test-url` | URL to fetch through tunnel for e2e test | `https://httpbin.org/ip` |
| `--proxy-auth` | SOCKS proxy auth as `user:pass` (for e2e tests) | — |
| `--doh` | Scan DoH resolvers instead of UDP | `false` |
| `--skip-ping` | Skip ICMP ping step | `false` |
| `--skip-nxdomain` | Skip NXDOMAIN hijack check | `false` |
| `--top` | Number of top results to display | `10` |

---

### 📥 `fetch` — Download Resolver Lists

Automatically downloads and deduplicates resolver lists from public sources.

```bash
# Global UDP resolvers (from trickest/resolvers)
findns fetch -o resolvers.txt

# Include 7,800+ known regional resolvers (embedded, no download needed)
findns fetch -o resolvers.txt --local

# DoH resolver URLs (19+ well-known + public lists)
findns fetch -o doh-resolvers.txt --doh
```

**Built-in DoH endpoints** include:
- 🔵 Google (`dns.google`)
- 🟠 Cloudflare (`cloudflare-dns.com`)
- 🟣 Quad9 (`dns.quad9.net`)
- 🟢 AdGuard, Mullvad, NextDNS, LibreDNS, BlahDNS, and more

---

### 🌍 `local` — Export Bundled Regional Data

Export regional resolver data bundled inside the binary. No internet connection needed.

**Two modes:**

```bash
# Mode 1: Known resolvers (default, recommended)
# Exports 7,800+ pre-verified regional DNS resolvers — high scan success rate
findns local -o resolvers.txt

# Mode 2: Discover NEW resolvers (--discover)
# Exports candidate IPs from 1,919 CIDR ranges (~10.8M IPs)
# Most will NOT be DNS servers — use this to find resolvers not in the known list
findns local -o candidates.txt --discover

# Discovery with batch scanning (non-overlapping, no duplicates)
findns local -o batch1.txt --discover --batch 1000000
findns local -o batch2.txt --discover --batch 1000000 --offset 1000000

# Show embedded CIDR ranges
findns local --list-ranges
```

| Flag | Description | Default |
|------|-------------|---------|
| `--discover` | Switch to discovery mode (CIDR expansion) | `false` |
| `--sample N` | [discover] Random IPs per subnet | `10` |
| `--full` | [discover] Export all ~10.8M IPs | `false` |
| `--batch N` | [discover] Export exactly N IPs (use with `--offset`) | `0` |
| `--offset N` | [discover] Skip N IPs before starting batch | `0` |
| `--list-ranges` | Print embedded CIDR ranges and exit | `false` |

---

### 🏓 `ping` — ICMP Reachability

```bash
findns ping -i resolvers.txt -o result.json
findns ping -i resolvers.txt -o result.json -c 5 -t 2
```

📊 **Metric:** `ping_ms` (average RTT)

---

### 🔎 `resolve` — DNS Resolution Test

```bash
findns resolve -i resolvers.txt -o result.json --domain google.com
```

📊 **Metric:** `resolve_ms` (average resolve time)

---

### 🔎 `resolve tunnel` — NS Delegation Check

Tests whether a resolver can see your tunnel's NS records and resolve the glue A record.

```bash
findns resolve tunnel -i resolvers.txt -o result.json --domain t.example.com
```

📊 **Metric:** `resolve_ms` (average NS + glue query time)

---

### 🛡️ `nxdomain` — DNS Hijack Detection

Tests whether resolvers return proper NXDOMAIN for non-existent domains. Hijacking resolvers return fake NOERROR answers — these are **not safe** for tunneling.

```bash
findns nxdomain -i resolvers.txt -o result.json
```

📊 **Metrics:** `nxdomain_ok` (count of correct responses), `hijack` (1.0 = hijacking detected)

---

### 📏 `edns` — EDNS Payload Size Test

Tests which EDNS buffer sizes a resolver supports. Larger payloads = faster DNS tunnel. Tests 512, 900, and 1232 bytes.

```bash
findns edns -i resolvers.txt -o result.json --domain t.example.com
```

📊 **Metric:** `edns_max` (largest working payload: 512, 900, or 1232)

---

### 🚇 `e2e dnstt` — End-to-End DNSTT Test (UDP)

Actually launches `dnstt-client`, creates a SOCKS tunnel, and verifies connectivity with `curl`.

```bash
findns e2e dnstt -i resolvers.txt -o result.json \
  --domain t.example.com --pubkey <hex-pubkey>
```

📊 **Metric:** `e2e_ms` (time from start to successful connection)

---

### 🚇 `e2e slipstream` — End-to-End Slipstream Test

```bash
findns e2e slipstream -i resolvers.txt -o result.json \
  --domain s.example.com --cert /path/to/cert.pem
```

📊 **Metric:** `e2e_ms`

---

### 🔒 `doh resolve` — DoH Resolver Test

Test DNS resolution through DoH endpoints (HTTPS POST with `application/dns-message`).

```bash
findns doh resolve -i doh-resolvers.txt -o result.json --domain google.com
```

---

### 🔒 `doh resolve tunnel` — DoH NS Delegation

```bash
findns doh resolve tunnel -i doh-resolvers.txt -o result.json --domain t.example.com
```

---

### 🔒 `doh e2e` — End-to-End DNSTT via DoH

Launches `dnstt-client -doh <url>` and verifies tunnel connectivity.

```bash
findns doh e2e -i doh-resolvers.txt -o result.json \
  --domain t.example.com --pubkey <hex-pubkey>
```

---

### ⛓️ `chain` — Custom Step Pipeline

Run any combination of steps in sequence. Only resolvers that pass each step advance.

```bash
findns chain -i resolvers.txt -o result.json \
  --step "ping" \
  --step "resolve:domain=google.com" \
  --step "nxdomain" \
  --step "edns:domain=t.example.com" \
  --step "resolve/tunnel:domain=t.example.com" \
  --step "e2e/dnstt:domain=t.example.com,pubkey=<key>"
```

DoH chain example:

```bash
findns chain -i doh-resolvers.txt -o result.json \
  --step "doh/resolve:domain=google.com" \
  --step "doh/resolve/tunnel:domain=t.example.com" \
  --step "doh/e2e:domain=t.example.com,pubkey=<key>"
```

**All available steps:**

| Step | Required Params | Metrics | Description |
|------|----------------|---------|-------------|
| `ping` | — | `ping_ms` | ICMP reachability |
| `resolve` | `domain` | `resolve_ms` | DNS A record resolution |
| `resolve/tunnel` | `domain` | `resolve_ms` | NS delegation + glue record |
| `nxdomain` | — | `hijack`, `nxdomain_ok` | NXDOMAIN integrity check |
| `edns` | `domain` | `edns_max` | EDNS payload size support |
| `e2e/dnstt` | `domain`, `pubkey` | `e2e_ms` | Real DNSTT tunnel test |
| `e2e/slipstream` | `domain`, `cert` | `e2e_ms` | Real Slipstream tunnel test |
| `doh/resolve` | `domain` | `resolve_ms` | DoH DNS resolution |
| `doh/resolve/tunnel` | `domain` | `resolve_ms` | DoH NS delegation |
| `doh/e2e` | `domain`, `pubkey` | `e2e_ms` | Real DNSTT tunnel via DoH |

Step format: `type:key=val,key=val`. Optional params: `count`, `timeout`.

| Flag | Description | Default |
|------|-------------|---------|
| `--port-base` | Base port for e2e SOCKS proxies | `30000` |

---

## ⚙️ Global Flags

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--input` | `-i` | Input file (text or JSON) | required |
| `--output` | `-o` | Output JSON file | required |
| `--timeout` | `-t` | Timeout per attempt (seconds) | 3 |
| `--count` | `-c` | Attempts per IP/URL | 3 |
| `--workers` | | Concurrent workers | 50 |
| `--e2e-timeout` | | Timeout for e2e tests (seconds) | 10 |
| `--include-failed` | | Also scan failed entries from JSON input | false |

---

## 📄 Input / Output Format

### Input

Plain text file with one entry per line. Supports IPs, CIDR ranges, and DoH URLs:

```text
# UDP resolvers (one IP per line)
8.8.8.8
1.1.1.1
9.9.9.9

# CIDR ranges (expanded automatically)
185.51.200.0/24
10.202.10.0/28

# DoH resolvers (full URLs)
https://dns.google/dns-query
https://cloudflare-dns.com/dns-query
https://dns.quad9.net/dns-query
```

**CIDR support:** Ranges like `1.2.3.0/24` are automatically expanded to individual host IPs (network and broadcast addresses are excluded). This is useful for scanning regional IP blocks (e.g. `iran-ipv4.cidrs` files). A warning is shown when expansion exceeds 100,000 IPs.

Can also accept JSON output from a previous scan (only `passed` entries are used by default).

### Output

JSON with structured results:

```json
{
  "steps": [
    {
      "name": "ping",
      "tested": 10000,
      "passed": 9200,
      "failed": 800,
      "duration_secs": 15.1
    }
  ],
  "passed": [
    {
      "ip": "1.1.1.1",
      "metrics": {
        "ping_ms": 4.2,
        "resolve_ms": 15.3,
        "edns_max": 1232,
        "e2e_ms": 3200.5
      }
    }
  ],
  "failed": [
    {"ip": "9.9.9.9"}
  ]
}
```

---

## 🔧 Example Workflows

### Find working UDP resolvers for DNSTT

```bash
# 1. Get resolvers
findns fetch -o resolvers.txt --local

# 2. Full scan with e2e
findns scan -i resolvers.txt -o results.json \
  --domain t.mysite.com --pubkey abc123...

# 3. Use the best resolver in your DNSTT client
dnstt-client -udp <best-ip>:53 -pubkey-file server.pub t.mysite.com 127.0.0.1:1080
```

### Find working DoH resolvers for DNSTT

```bash
# 1. Get DoH endpoints
findns fetch -o doh.txt --doh

# 2. Scan with DoH e2e
findns scan -i doh.txt -o results.json \
  --domain t.mysite.com --pubkey abc123... --doh

# 3. Use the best DoH resolver
dnstt-client -doh <best-url> -pubkey-file server.pub t.mysite.com 127.0.0.1:1080
```

### Multi-stage filtering with chain

```bash
# Quick filter → deep test
findns chain -i resolvers.txt -o results.json \
  --step "ping:count=1" \
  --step "resolve:domain=google.com,count=1" \
  --step "nxdomain:count=2" \
  --step "edns:domain=t.mysite.com" \
  --step "e2e/dnstt:domain=t.mysite.com,pubkey=abc123,timeout=10"
```

---

## 🙏 Credits

This project was originally inspired by [net2share/dnst-scanner](https://github.com/net2share/dnst-scanner). We rebuilt and expanded it with DoH support, NXDOMAIN/EDNS checks, a full scan pipeline, TUI, cross-platform fixes, and CI releases.

---

## 🔗 Related Projects

| Project | Description |
|---------|-------------|
| [dnstm](https://github.com/net2share/dnstm) | DNS Tunnel Manager (server) |
| [dnstm-setup](https://github.com/SamNet-dev/dnstm-setup) | Interactive setup wizard for dnstm |
| [ir-resolvers](https://github.com/net2share/ir-resolvers) | Regional intranet resolver list (7,800+ IPs) |
| [dnstt](https://www.bamsoftware.com/software/dnstt/) | DNS tunnel with DoH/DoT support |
| [slipstream-rust](https://github.com/Mygod/slipstream-rust) | QUIC-based DNS tunnel |

---

## 📖 Farsi Guide

For a complete guide in Farsi covering every command, flag, and scenario, see [GUIDE.md](GUIDE.md).

---

## 💖 Donate

If this project helps you, consider supporting development: [samnet.dev/donate](https://www.samnet.dev/donate/)

---

## 📜 License

MIT

---
---

<div dir="rtl">

# 🔍 findns

**اسکنر سریع و چندپروتکلی برای پیدا کردن DNS resolverهای سازگار با تانل DNS**

از هر دو پروتکل **UDP** و **DoH (DNS-over-HTTPS)** پشتیبانی می‌کند و تانل‌ها را به صورت واقعی (end-to-end) با [DNSTT](https://www.bamsoftware.com/software/dnstt/) و [Slipstream](https://github.com/Mygod/slipstream-rust) تست می‌کند.

> 🌐 ساخته شده برای **شبکه‌های محدود** — جایی که پیدا کردن یک resolver کارآمد یعنی تفاوت بین اتصال و انزوا.

---

## ✨ امکانات

| امکان | توضیح |
|-------|-------|
| 🔄 **اسکن UDP + DoH** | تست هم DNS ساده (پورت 53) و هم DNS-over-HTTPS (پورت 443) |
| 🔗 **پایپلاین کامل** | Ping → Resolve → NXDOMAIN → EDNS → Tunnel → E2E با یک دستور |
| 🛡️ **تشخیص هایجک** | شناسایی resolverهایی که جواب جعلی برمی‌گردانند |
| 📏 **تست EDNS** | پیدا کردن resolverهایی که payload بزرگ پشتیبانی می‌کنند (تانل سریع‌تر) |
| 🚇 **تست واقعی تانل** | واقعاً کلاینت DNSTT/Slipstream را اجرا می‌کند و اتصال را تأیید می‌کند |
| 📥 **دانلود لیست resolver** | دانلود خودکار از منابع عمومی |
| 🌍 **resolverهای محلی** | لیست داخلی 7,800+ آی‌پی resolver منطقه‌ای |
| ⚡ **همزمانی بالا** | 50 worker موازی — هزاران resolver در چند دقیقه اسکن می‌شود |
| 📋 **خروجی JSON** | خروجی هر اسکن ورودی اسکن بعدی می‌شود |
| 🌐 **ورودی CIDR** | رنج آی‌پی مثل `185.51.200.0/24` را می‌خواند و به صورت خودکار باز می‌کند |

---

## 🏗️ نحوه کار

</div>

```
          شبکه محدود                            |      اینترنت آزاد
                                               |
  📱 کلاینت ──[UDP:53]──→ Resolver ──[UDP:53]──→ 🖥️ سرور DNSTT
  📱 کلاینت ──[HTTPS:443]──→ DoH Resolver ────→ 🖥️ سرور DNSTT
                                               |
              ↑ اسکنر این قسمت را تست می‌کند ↑
```

<div dir="rtl">

### 🤔 چرا DoH مهم است؟

| پروتکل | پورت | قابل شناسایی | وضعیت در شبکه‌های محدود |
|---------|------|-------------|----------------|
| 🔴 UDP DNS | 53 | کاملاً قابل مشاهده | تحت نظارت، اغلب مسدود |
| 🔴 DoT | 853 | TLS روی پورت شناخته شده | از سال ۲۰۲۰ مسدود |
| 🟢 **DoH** | **443** | **شبیه HTTPS معمولی** | **سخت برای شناسایی** |
| 🔴 DoQ | 443/UDP | مبتنی بر QUIC | QUIC در تمام ISPها غیرفعال |

سرور DNSTT **همیشه** روی پورت 53 گوش می‌دهد. اما **کلاینت** می‌تواند با resolver واسط از طریق پروتکل‌های مختلف ارتباط برقرار کند. DoH کوئری‌های DNS را داخل HTTPS معمولی قرار می‌دهد و برای فایروال‌ها تقریباً نامرئی است.

---

## 📦 نصب

### از سورس

</div>

```bash
git clone https://github.com/SamNet-dev/findns.git
cd findns
go build -o findns ./cmd
```

<div dir="rtl">

### Go Install

</div>

```bash
go install github.com/SamNet-dev/findns/cmd@latest
```

<div dir="rtl">

### دانلود باینری

باینری‌های آماده برای Linux، macOS و Windows در صفحه [Releases](https://github.com/SamNet-dev/findns/releases) موجود است.

</div>

```bash
# مثال: Linux x64
curl -LO https://github.com/SamNet-dev/findns/releases/latest/download/findns-linux-amd64
chmod +x findns-linux-amd64
./findns-linux-amd64 --help
```

<div dir="rtl">

### پیش‌نیازها

- **Go 1.24+** برای بیلد از سورس
- **dnstt-client** — فقط برای تست e2e تانل (`--pubkey`). نصب: `go install www.bamsoftware.com/git/dnstt.git/dnstt-client@latest`
- **slipstream-client** — فقط برای تست e2e Slipstream (`--cert`)
- **curl** — برای تأیید اتصال e2e

> **پیدا کردن باینری:** findns به صورت خودکار `dnstt-client` و `slipstream-client` را در سه مسیر جستجو می‌کند: ۱) `PATH` سیستم ۲) پوشه فعلی ۳) کنار فایل findns. ساده‌ترین روش: فایل را کنار findns بگذارید.
>
> بدون `--pubkey` هم اسکنر resolverهای سازگار با تانل DNS را پیدا می‌کند (ping, resolve, nxdomain, edns, tunnel delegation بدون نیاز به dnstt-client).

---

## 🪟 راهنمای ویندوز

ویندوز به طور کامل پشتیبانی می‌شود. دو روش برای شروع:

### روش ۱: دانلود باینری (ساده‌ترین)

1. به صفحه [Releases](https://github.com/SamNet-dev/findns/releases) بروید
2. فایل `findns-windows-amd64.exe` را دانلود کنید
3. نام آن را به `findns.exe` تغییر دهید (اختیاری)
4. **cmd** یا **PowerShell** را در همان پوشه باز کنید
5. اجرا کنید:

</div>

```powershell
.\findns.exe --help
```

<div dir="rtl">

> نیازی به نصب Go نیست — فقط دانلود و اجرا کنید.

### روش ۲: بیلد از سورس

نیاز به **Go 1.24+** از [go.dev/dl](https://go.dev/dl/) دارد.

</div>

```powershell
git clone https://github.com/SamNet-dev/findns.git
cd findns
go build -o findns.exe ./cmd
```

<div dir="rtl">

### اجرا

در تمام دستورات به جای `findns` از `.\findns.exe` استفاده کنید:

</div>

```powershell
# دریافت لیست resolverها
.\findns.exe fetch -o resolvers.txt

# اسکن کامل
.\findns.exe scan -i resolvers.txt -o results.json --domain t.example.com

# با تست e2e
.\findns.exe scan -i resolvers.txt -o results.json ^
  --domain t.example.com --pubkey <hex-pubkey>
```

<div dir="rtl">

> **نکته:** در PowerShell از بک‌تیک `` ` `` برای ادامه خط استفاده کنید (به جای `^`).

### پیش‌نیازها

- **curl** — در ویندوز 10/11 به صورت پیش‌فرض نصب است
- **dnstt-client.exe** — کنار `findns.exe` قرار دهید یا در PATH اضافه کنید (فقط برای تست e2e DNSTT)
- **slipstream-client.exe** — مثل بالا (فقط برای تست e2e Slipstream)

### مشکلات رایج

| مشکل | راه حل |
|------|--------|
| `ping` نشان می‌دهد 0% loss ولی اسکن فیل می‌شود | به عنوان **Administrator** اجرا کنید — ICMP در ویندوز نیاز به دسترسی بالا دارد |
| `dnstt-client` پیدا نمی‌شود | فایل `dnstt-client.exe` را کنار `findns.exe` قرار دهید یا پوشه‌اش را به PATH اضافه کنید |
| PowerShell اجرا را بلاک می‌کند | از `cmd.exe` استفاده کنید یا `Set-ExecutionPolicy RemoteSigned -Scope CurrentUser` را اجرا کنید |
| دستورات طولانی خطا می‌دهند | از بک‌تیک `` ` `` (PowerShell) یا `^` (cmd) برای ادامه خط استفاده کنید |

---

## 🚀 شروع سریع

### 1️⃣ دریافت لیست Resolverها

</div>

```bash
# 📥 دانلود resolverهای UDP جهانی
findns fetch -o resolvers.txt

# 🌍 شامل 7,800+ resolver شناخته‌شده ایرانی (بدون اینترنت)
findns fetch -o resolvers.txt --local

# 🔒 دانلود آدرس‌های DoH
findns fetch -o doh-resolvers.txt --doh
```

<div dir="rtl">

### 2️⃣ اجرای اسکن کامل

</div>

```bash
# 🔍 اسکن resolverهای UDP (تمام بررسی‌ها)
findns scan -i resolvers.txt -o results.json --domain t.example.com

# 🔍 اسکن با تست واقعی تانل DNSTT
findns scan -i resolvers.txt -o results.json \
  --domain t.example.com --pubkey <hex-pubkey>

# 🔒 اسکن resolverهای DoH
findns scan -i doh-resolvers.txt -o results.json \
  --domain t.example.com --doh

# 🔒 اسکن DoH با تست واقعی e2e
findns scan -i doh-resolvers.txt -o results.json \
  --domain t.example.com --pubkey <hex-pubkey> --doh
```

<div dir="rtl">

### 3️⃣ بررسی نتایج

نتایج به صورت JSON ذخیره می‌شوند. آرایه `passed` شامل resolverهایی است که تمام مراحل را با موفقیت گذرانده‌اند:

</div>

```json
{
  "passed": [
    {"ip": "1.1.1.1", "metrics": {"ping_ms": 4.2, "resolve_ms": 15.3, "edns_max": 1232}}
  ]
}
```

<div dir="rtl">

---

## 📖 دستورات

### 🎯 `scan` — پایپلاین یکپارچه (پیشنهادی)

به صورت خودکار مراحل مناسب را بر اساس فلگ‌ها ترتیب می‌دهد.

**حالت UDP:** `ping → resolve → nxdomain → edns → tunnel → e2e`
**حالت DoH:** `doh/resolve → doh/tunnel → doh/e2e`

| فلگ | توضیح | پیش‌فرض |
|-----|-------|---------|
| `--domain` | دامنه تانل (فعال‌سازی تست تانل/edns/e2e) | — |
| `--pubkey` | کلید عمومی سرور DNSTT (فعال‌سازی تست e2e) | — |
| `--cert` | مسیر گواهی Slipstream (فعال‌سازی تست Slipstream) | — |
| `--test-url` | آدرس برای تست اتصال e2e | `https://httpbin.org/ip` |
| `--proxy-auth` | احراز هویت پروکسی SOCKS به صورت `user:pass` (برای تست e2e) | — |
| `--doh` | اسکن DoH به جای UDP | `false` |
| `--skip-ping` | رد کردن مرحله ping | `false` |
| `--skip-nxdomain` | رد کردن بررسی هایجک | `false` |
| `--top` | تعداد نتایج برتر برای نمایش | `10` |

---

### 📥 `fetch` — دانلود لیست Resolverها

</div>

```bash
findns fetch -o resolvers.txt           # resolverهای UDP جهانی
findns fetch -o resolvers.txt --local    # + 7,800+ resolver شناخته‌شده ایرانی
findns fetch -o doh-resolvers.txt --doh # آدرس‌های DoH
```

<div dir="rtl">

**سرویس‌های DoH داخلی** شامل:
- 🔵 Google (`dns.google`)
- 🟠 Cloudflare (`cloudflare-dns.com`)
- 🟣 Quad9 (`dns.quad9.net`)
- 🟢 AdGuard, Mullvad, NextDNS, LibreDNS, BlahDNS و بیشتر

---

### 🌍 `local` — resolverهای ایرانی داخلی

داده‌های ایرانی داخل خود برنامه را خروجی می‌دهد — نیازی به اینترنت ندارد.

**دو حالت:**

</div>

```bash
# حالت 1: resolverهای شناخته‌شده (پیش‌فرض — پیشنهادی)
# 7,800+ resolver تأیید‌شده — نرخ موفقیت بالا
findns local -o resolvers.txt

# حالت 2: کشف resolver جدید (--discover)
# از رنج‌های CIDR ایرانی (~10.8M آی‌پی) — اکثراً DNS سرور نیستند
findns local -o candidates.txt --discover

# تنظیم تعداد نمونه در هر subnet
findns local -o candidates.txt --discover --sample 5    # 5 آی‌پی/subnet
findns local -o candidates.txt --discover --sample 50   # 50 آی‌پی/subnet

# اسکن دسته‌ای (بدون تکرار، بدون آی‌پی تکراری)
findns local -o batch1.txt --discover --batch 1000000
findns local -o batch2.txt --discover --batch 1000000 --offset 1000000

# تمام آی‌پی‌ها (هشدار: اسکن روزها طول می‌کشد!)
findns local -o all-iran.txt --discover --full

# نمایش رنج‌های CIDR
findns local --list-ranges
```

<div dir="rtl">

| فلگ | توضیح | پیش‌فرض |
|-----|-------|---------|
| `--discover` | حالت کشف resolver جدید (از CIDR) | `false` |
| `--sample N` | [discover] آی‌پی تصادفی از هر subnet | `10` |
| `--full` | [discover] تمام ~10.8M آی‌پی | `false` |
| `--batch N` | [discover] دقیقاً N آی‌پی (با `--offset`) | `0` |
| `--offset N` | [discover] رد کردن N آی‌پی اول | `0` |
| `--list-ranges` | چاپ رنج‌های CIDR و خروج | `false` |

---

### 🏓 `ping` — بررسی دسترسی‌پذیری ICMP

</div>

```bash
findns ping -i resolvers.txt -o result.json
findns ping -i resolvers.txt -o result.json -c 5 -t 2
```

<div dir="rtl">

📊 **متریک:** `ping_ms` (میانگین RTT)

---

### 🔎 `resolve` — تست Resolve رکورد DNS

</div>

```bash
findns resolve -i resolvers.txt -o result.json --domain google.com
```

<div dir="rtl">

📊 **متریک:** `resolve_ms` (میانگین زمان resolve)

---

### 🔎 `resolve tunnel` — بررسی NS Delegation

تست اینکه آیا resolver رکوردهای NS تانل شما را می‌بیند و رکورد glue A را resolve می‌کند.

</div>

```bash
findns resolve tunnel -i resolvers.txt -o result.json --domain t.example.com
```

<div dir="rtl">

📊 **متریک:** `resolve_ms` (میانگین زمان کوئری NS + glue)

---

### 🛡️ `nxdomain` — تشخیص هایجک DNS

تست اینکه آیا resolver برای دامنه‌های ناموجود جواب صحیح NXDOMAIN برمی‌گرداند. resolverهای هایجک‌کننده جواب جعلی NOERROR برمی‌گردانند — اینها برای تانل **امن نیستند**.

</div>

```bash
findns nxdomain -i resolvers.txt -o result.json
```

<div dir="rtl">

📊 **متریک‌ها:** `nxdomain_ok` (تعداد جواب‌های صحیح)، `hijack` (1.0 = هایجک شناسایی شد)

---

### 📏 `edns` — تست سایز Payload EDNS

تست اینکه resolver چه اندازه بافر EDNS را پشتیبانی می‌کند. payload بزرگتر = تانل DNS سریعتر. سایزهای 512، 900 و 1232 بایت تست می‌شوند.

</div>

```bash
findns edns -i resolvers.txt -o result.json --domain t.example.com
```

<div dir="rtl">

📊 **متریک:** `edns_max` (بزرگترین payload کارآمد: 512، 900 یا 1232)

---

### 🚇 `e2e dnstt` — تست واقعی تانل DNSTT (UDP)

واقعاً `dnstt-client` را اجرا می‌کند، تانل SOCKS ایجاد می‌کند و اتصال را با `curl` تأیید می‌کند.

</div>

```bash
findns e2e dnstt -i resolvers.txt -o result.json \
  --domain t.example.com --pubkey <hex-pubkey>
```

<div dir="rtl">

📊 **متریک:** `e2e_ms` (زمان از شروع تا اتصال موفق)

---

### 🚇 `e2e slipstream` — تست واقعی تانل Slipstream

</div>

```bash
findns e2e slipstream -i resolvers.txt -o result.json \
  --domain s.example.com --cert /path/to/cert.pem
```

<div dir="rtl">

📊 **متریک:** `e2e_ms`

---

### 🔒 `doh resolve` — تست Resolve از طریق DoH

تست resolve رکورد DNS از طریق DoH (HTTPS POST با `application/dns-message`).

</div>

```bash
findns doh resolve -i doh-resolvers.txt -o result.json --domain google.com
```

<div dir="rtl">

---

### 🔒 `doh resolve tunnel` — بررسی NS Delegation از طریق DoH

</div>

```bash
findns doh resolve tunnel -i doh-resolvers.txt -o result.json --domain t.example.com
```

<div dir="rtl">

---

### 🔒 `doh e2e` — تست واقعی تانل DNSTT از طریق DoH

`dnstt-client -doh <url>` را اجرا و اتصال تانل را تأیید می‌کند.

</div>

```bash
findns doh e2e -i doh-resolvers.txt -o result.json \
  --domain t.example.com --pubkey <hex-pubkey>
```

<div dir="rtl">

---

### ⛓️ `chain` — پایپلاین سفارشی

هر ترکیبی از مراحل را اجرا کنید. فقط resolverهایی که هر مرحله را پاس کنند به مرحله بعد می‌روند.

</div>

```bash
findns chain -i resolvers.txt -o result.json \
  --step "ping" \
  --step "resolve:domain=google.com" \
  --step "nxdomain" \
  --step "edns:domain=t.example.com" \
  --step "resolve/tunnel:domain=t.example.com" \
  --step "e2e/dnstt:domain=t.example.com,pubkey=<key>"
```

<div dir="rtl">

مثال chain با DoH:

</div>

```bash
findns chain -i doh-resolvers.txt -o result.json \
  --step "doh/resolve:domain=google.com" \
  --step "doh/resolve/tunnel:domain=t.example.com" \
  --step "doh/e2e:domain=t.example.com,pubkey=<key>"
```

<div dir="rtl">

**تمام مراحل موجود:**

| مرحله | پارامترهای الزامی | متریک‌ها | توضیح |
|-------|-------------------|----------|-------|
| `ping` | — | `ping_ms` | بررسی دسترسی‌پذیری ICMP |
| `resolve` | `domain` | `resolve_ms` | resolve رکورد A |
| `resolve/tunnel` | `domain` | `resolve_ms` | NS delegation + رکورد glue |
| `nxdomain` | — | `hijack`, `nxdomain_ok` | بررسی صحت NXDOMAIN |
| `edns` | `domain` | `edns_max` | تست سایز payload EDNS |
| `e2e/dnstt` | `domain`, `pubkey` | `e2e_ms` | تست واقعی تانل DNSTT |
| `e2e/slipstream` | `domain`, `cert` | `e2e_ms` | تست واقعی تانل Slipstream |
| `doh/resolve` | `domain` | `resolve_ms` | resolve از طریق DoH |
| `doh/resolve/tunnel` | `domain` | `resolve_ms` | NS delegation از طریق DoH |
| `doh/e2e` | `domain`, `pubkey` | `e2e_ms` | تست واقعی تانل از طریق DoH |

فرمت مراحل: `type:key=val,key=val`. پارامترهای اختیاری: `count`, `timeout`.

| فلگ | توضیح | پیش‌فرض |
|-----|-------|---------|
| `--port-base` | پورت شروع برای پروکسی SOCKS تست e2e | `30000` |

---

## ⚙️ فلگ‌های عمومی

| فلگ | مخفف | توضیح | پیش‌فرض |
|-----|------|-------|---------|
| `--input` | `-i` | فایل ورودی (متن یا JSON) | الزامی |
| `--output` | `-o` | فایل خروجی JSON | الزامی |
| `--timeout` | `-t` | تایم‌اوت هر تلاش (ثانیه) | 3 |
| `--count` | `-c` | تعداد تلاش برای هر IP/URL | 3 |
| `--workers` | | تعداد workerهای موازی | 50 |
| `--e2e-timeout` | | تایم‌اوت تست‌های e2e (ثانیه) | 10 |
| `--include-failed` | | اسکن IPهای فیل‌شده از ورودی JSON | false |

---

## 📄 فرمت ورودی / خروجی

### ورودی

فایل متنی ساده با هر خط یک ورودی. از آی‌پی، رنج CIDR و آدرس DoH پشتیبانی می‌کند:

</div>

```text
# resolverهای UDP (هر خط یک آی‌پی)
8.8.8.8
1.1.1.1
9.9.9.9

# رنج‌های CIDR (خودکار باز می‌شوند)
185.51.200.0/24
10.202.10.0/28

# resolverهای DoH (آدرس کامل)
https://dns.google/dns-query
https://cloudflare-dns.com/dns-query
https://dns.quad9.net/dns-query
```

<div dir="rtl">

**پشتیبانی CIDR:** رنج‌هایی مثل `1.2.3.0/24` به صورت خودکار به آی‌پی‌های تکی باز می‌شوند (آدرس‌های network و broadcast حذف می‌شوند). برای اسکن بلوک‌های آی‌پی منطقه‌ای مفید است. در صورت بازشدن بیش از 100,000 آی‌پی هشدار نمایش داده می‌شود.

همچنین می‌تواند خروجی JSON اسکن قبلی را به عنوان ورودی بپذیرد (فقط ورودی‌های `passed` به صورت پیش‌فرض استفاده می‌شوند).

### خروجی

JSON با نتایج ساختاریافته:

</div>

```json
{
  "steps": [
    {
      "name": "ping",
      "tested": 10000,
      "passed": 9200,
      "failed": 800,
      "duration_secs": 15.1
    }
  ],
  "passed": [
    {
      "ip": "1.1.1.1",
      "metrics": {
        "ping_ms": 4.2,
        "resolve_ms": 15.3,
        "edns_max": 1232,
        "e2e_ms": 3200.5
      }
    }
  ],
  "failed": [
    {"ip": "9.9.9.9"}
  ]
}
```

<div dir="rtl">

---

## 🔧 مثال‌های کاربردی

### پیدا کردن resolver UDP کارآمد برای DNSTT

</div>

```bash
# ۱. دریافت لیست
findns fetch -o resolvers.txt --local

# ۲. اسکن کامل با تست e2e
findns scan -i resolvers.txt -o results.json \
  --domain t.mysite.com --pubkey abc123...

# ۳. استفاده از بهترین resolver
dnstt-client -udp <best-ip>:53 -pubkey-file server.pub t.mysite.com 127.0.0.1:1080
```

<div dir="rtl">

### پیدا کردن resolver DoH کارآمد برای DNSTT

</div>

```bash
# ۱. دریافت لیست DoH
findns fetch -o doh.txt --doh

# ۲. اسکن DoH با تست e2e
findns scan -i doh.txt -o results.json \
  --domain t.mysite.com --pubkey abc123... --doh

# ۳. استفاده از بهترین resolver
dnstt-client -doh <best-url> -pubkey-file server.pub t.mysite.com 127.0.0.1:1080
```

<div dir="rtl">

### فیلتر چندمرحله‌ای با chain

</div>

```bash
# فیلتر سریع → تست عمیق
findns chain -i resolvers.txt -o results.json \
  --step "ping:count=1" \
  --step "resolve:domain=google.com,count=1" \
  --step "nxdomain:count=2" \
  --step "edns:domain=t.mysite.com" \
  --step "e2e/dnstt:domain=t.mysite.com,pubkey=abc123,timeout=10"
```

<div dir="rtl">

---

## 🙏 تقدیر

این پروژه با الهام از [net2share/dnst-scanner](https://github.com/net2share/dnst-scanner) ساخته شده و با پشتیبانی DoH، بررسی NXDOMAIN/EDNS، پایپلاین اسکن، رابط کاربری ترمینال، رفع مشکلات چندسکویی و CI بازسازی و گسترش یافته است.

---

## 🔗 پروژه‌های مرتبط

| پروژه | توضیح |
|-------|-------|
| [dnstm](https://github.com/net2share/dnstm) | مدیریت تانل DNS (سرور) |
| [dnstm-setup](https://github.com/SamNet-dev/dnstm-setup) | ویزارد نصب تعاملی dnstm |
| [ir-resolvers](https://github.com/net2share/ir-resolvers) | لیست resolverهای محلی (7,800+ IP) |
| [dnstt](https://www.bamsoftware.com/software/dnstt/) | تانل DNS با پشتیبانی DoH/DoT |
| [slipstream-rust](https://github.com/Mygod/slipstream-rust) | تانل DNS مبتنی بر QUIC |

---

## 📖 راهنمای کامل فارسی

برای راهنمای جامع فارسی شامل تمام دستورات، فلگ‌ها و سناریوها، فایل [GUIDE.md](GUIDE.md) را ببینید.

---

## 💖 حمایت مالی

اگر این پروژه به شما کمک کرد، از توسعه آن حمایت کنید: [samnet.dev/donate](https://www.samnet.dev/donate/)

---

## 📜 لایسنس

MIT

</div>
