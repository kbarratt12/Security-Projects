# Automated Network Forensics Pipeline

![Zeek](https://img.shields.io/badge/Zeek-Network%20Analysis-blue?style=flat-square)
![Suricata](https://img.shields.io/badge/Suricata-IDS-orange?style=flat-square)
![Bash](https://img.shields.io/badge/Bash-Automation-green?style=flat-square&logo=gnubash)
![Ubuntu](https://img.shields.io/badge/Ubuntu-22.04-E95420?style=flat-square&logo=ubuntu)
![DigitalOcean](https://img.shields.io/badge/DigitalOcean-Cloud-0080FF?style=flat-square&logo=digitalocean)

Forensics pipeline combining Zeek, Suricata, and custom Bash scripts to automate PCAP analysis and IOC extraction. Validated against real-world malware captures from malware-traffic-analysis.net, reducing manual investigations to under 15 minutes.

---

## Pipeline Architecture

Four-stage workflow from raw packet capture to actionable IOC report:

```
Raw PCAP
    │
    ▼
Parallel Analysis
├── Zeek (protocol logs: HTTP, DNS, SSL, Kerberos, SMB, DHCP)
└── Suricata (signature-based IDS alerts)
    │
    ▼
Automated Scripts
├── quick-report.sh   → rapid triage
├── detailed-report.sh → deep forensic analysis
├── ip-look.sh        → targeted IP investigation
└── ioc-cor.sh        → cross-engine IOC correlation
    │
    ▼
Structured Report (IPs, domains, file hashes, correlated alerts)
```

---

## Scripts

### `quick-report.sh` — Rapid Triage
High-level overview in seconds: top destination IPs, protocol breakdown, top Suricata alerts, suspicious high-entropy domains, and file transfers with MIME types.

### `detailed-report.sh` — Deep Forensic Analysis
Multi-section forensic report covering non-standard port connections, long-lived connections (potential C2/exfiltration), SSH/HTTP/Kerberos/SMB authentication failures, executable and script transfers, and TLS certificate anomalies.

### `ip-look.sh` — Targeted IP Investigation
Interactive prompt-based lookup for a specific IP. Pulls MAC address, DHCP lease, Kerberos authentication history, top connections, HTTP requests, file transfers, and DNS queries into a single profile.

### `ioc-cor.sh` — IOC Correlation
Bridges Zeek and Suricata: cross-references Suricata alert IPs against Zeek connection logs, extracts high-entropy domains, unusual user agents, large uploads, and suspicious file hashes. Outputs a confirmed IOC list ready for firewall blocking or threat intel submission.

<details>
<summary><strong>View Scripts</strong></summary>

#### `quick-report.sh`
```bash
#!/bin/bash

LOG_DIR="./"
REPORT_FILE="quick-analysis-report.txt"

cat > "$REPORT_FILE" << EOF
=== Quick PCAP Analysis Report ===
Date: $(date)

## Top 10 Destination IPs
$(cat ${LOG_DIR}conn.log | zeek-cut id.resp_h | sort | uniq -c | sort -rn | head -10)

## Top 5 Protocol Count
$(cat ${LOG_DIR}conn.log | zeek-cut proto | sort | uniq -c | sort -rn | head -5)

## Suricata Alerts (Top 10 Most Frequent)
$(cat suricata-output/fast.log 2>/dev/null | cut -d ' ' -f 4- | sort | uniq -c | sort -rn | head -10)

## Suspicious Domains
$(cat ${LOG_DIR}dns.log | zeek-cut query | grep -E '[a-z0-9]{15,}' | sort | uniq)

## Files Transferred
$(cat ${LOG_DIR}files.log 2>/dev/null | zeek-cut mime_type filename | head -10)
EOF

cat "$REPORT_FILE"
```

#### `detailed-report.sh`
```bash
#!/bin/bash

LOG_DIR="./"
REPORT_FILE="detailed-investigation-report.txt"

cat > "$REPORT_FILE" << EOF
=== DETAILED INVESTIGATION REPORT ===
Date: $(date)

## 1. Unusual Connection Patterns

### Non-Standard Port Connections
$(cat ${LOG_DIR}conn.log | zeek-cut id.orig_h id.resp_h id.resp_p proto | awk '
  $4 !~ /^(80|443|21|22|23|25|110|143|3389)$/ { print }' | head -20)

### Long-Lived Connections (Possible C2 or Exfiltration)
$(cat ${LOG_DIR}conn.log | zeek-cut id.orig_h id.resp_h duration proto service | awk '$3 > 600 { print }' | sort -k3 -rn | head -10)

## 2. Authentication Failures

### SSH Failed Attempts
$(cat ${LOG_DIR}ssh.log 2>/dev/null | grep -iE 'fail|failure' | zeek-cut id.orig_h user 2>/dev/null | sort | uniq -c | sort -rn | head -10)

### HTTP Auth Failures (401/403)
$(cat ${LOG_DIR}http.log 2>/dev/null | zeek-cut id.orig_h user host uri status 2>/dev/null | awk '$5 ~ /401|403/ {print}' | sort | uniq -c | sort -rn | head -10)

### Kerberos Failed Authentications
$(cat ${LOG_DIR}kerberos.log 2>/dev/null | zeek-cut id.orig_h client service success 2>/dev/null | awk '$4 ~ /F|f|0|false/ {print}' | sort | uniq -c | sort -rn | head -10)

## 3. File Activity

### Executables, Scripts, Archives
$(cat ${LOG_DIR}files.log 2>/dev/null | zeek-cut tx_hosts rx_hosts filename mime_type | grep -E '\.(exe|dll|js|vbs|bat|zip|rar|7z)$|application/(x-msdownload|x-executable|zip)' | head -20)

## 4. TLS/SSL Analysis

### Unique TLS Common Names
$(cat ${LOG_DIR}ssl.log 2>/dev/null | zeek-cut id.resp_h server_name | sort | uniq | head -20)
EOF

cat "$REPORT_FILE"
```

#### `ip-look.sh`
```bash
#!/bin/bash

LOG_DIR="./"
REPORT_FILE="ip-investigation-report.txt"

read -p "Enter the suspected IP address: " SUSPECT_IP

if [ -z "$SUSPECT_IP" ]; then
    echo "No IP entered. Exiting."
    exit 1
fi

cat > "$REPORT_FILE" << EOF
=== TARGETED IP INVESTIGATION: $SUSPECT_IP ===
Date: $(date)

## 1. Identity
### MAC Address
$(cat ${LOG_DIR}dhcp.log 2>/dev/null | zeek-cut client_addr mac | grep "$SUSPECT_IP" | sort -u)

### Kerberos Authentication History
$(cat ${LOG_DIR}kerberos.log 2>/dev/null | zeek-cut ts id.orig_h client service success | grep "$SUSPECT_IP" | grep -v '\$' | head -5)

## 2. Connection Summary
### Top 10 Connections
$(cat ${LOG_DIR}conn.log 2>/dev/null | zeek-cut id.orig_h id.resp_h id.resp_p proto | grep "$SUSPECT_IP" | zeek-cut id.resp_h | sort | uniq -c | sort -rn | head -10)

### HTTP Activity
$(cat ${LOG_DIR}http.log 2>/dev/null | zeek-cut ts id.orig_h host uri user_agent method status_code | grep "$SUSPECT_IP" | head -10)

## 3. Files & DNS
### File Transfers
$(cat ${LOG_DIR}files.log 2>/dev/null | zeek-cut id.orig_h id.resp_h mime_type filename sha256 | grep "$SUSPECT_IP" | head -10)

### DNS Lookups
$(cat ${LOG_DIR}dns.log 2>/dev/null | zeek-cut ts id.orig_h query answers | grep "$SUSPECT_IP" | head -5)
EOF

cat "$REPORT_FILE"
```

#### `ioc-cor.sh`
```bash
#!/bin/bash

LOG_DIR="./"
SURICATA_DIR="./suricata-output"
REPORT_FILE="ioc-correlation-report.txt"

if ! command -v jq &> /dev/null; then
    echo "jq is required but not installed."
    exit 1
fi

cat > "$REPORT_FILE" << EOF
=== IOC CORRELATION REPORT ===
Date: $(date)

## 1. Top Connections
### Top 20 IPs by Connection Count
$(cat ${LOG_DIR}conn.log | zeek-cut id.resp_h | sort | uniq -c | sort -rn | head -20)

### Top 10 Long-Duration Connections
$(cat ${LOG_DIR}conn.log | zeek-cut duration id.orig_h id.resp_h id.resp_p service | sort -rn | head -10)

## 2. Suspicious Indicators
### High-Entropy Domains
$(cat ${LOG_DIR}dns.log | zeek-cut query | grep -E '[a-z]{20,}' | sort -u)

### Unusual User Agents
$(cat ${LOG_DIR}http.log | zeek-cut user_agent | grep -iE 'python|curl|wget|powershell|java' | sort -u)

## 3. Exfiltration Indicators
### Large Uploads
$(cat ${LOG_DIR}http.log | zeek-cut method request_body_len id.orig_h host uri | awk '$2 > 0 {print}' | sort -k2 -rn | head -10)

### Suspicious File Hashes
$(cat ${LOG_DIR}files.log | zeek-cut mime_type filename sha1 | grep -iE 'exe|dll|bat|ps1')
EOF

echo "==================================" >> "$REPORT_FILE"
echo "## 4. Suricata-Zeek Correlation" >> "$REPORT_FILE"
echo "==================================" >> "$REPORT_FILE"

cat ${SURICATA_DIR}/eve.json 2>/dev/null | jq -r 'select(.event_type=="alert") | .dest_ip' | sort -u > malicious-ips.tmp

if [ -s malicious-ips.tmp ]; then
    while read ip; do
        echo "--- Connections to $ip ---" >> "$REPORT_FILE"
        cat ${LOG_DIR}conn.log | zeek-cut ts id.orig_h id.resp_h id.resp_p service duration | grep "$ip" >> "$REPORT_FILE"
    done < malicious-ips.tmp
else
    echo "No malicious IPs found in Suricata alerts." >> "$REPORT_FILE"
fi

rm malicious-ips.tmp 2>/dev/null
cat "$REPORT_FILE"
```

</details>

---

## Case Studies

Validated against two real malware PCAPs from malware-traffic-analysis.net with meaningfully different threat profiles.

### Case Study 1 — Fake Software Distribution (2025-01-22)

**Victim:** `10.1.17.215` / `shutchenson@BLUEMOONTUESDAY.COM`

A user downloaded what appeared to be Microsoft Teams from a typo-squatted domain (`authenticatoor.org`). The infection cused PowerShell for staged payload delivery across six files, with a 43-minute C2 session over unencrypted HTTP to `5.252.153.241` — intentionally unencrypted to blend with normal traffic.

**Attack chain:**
1. Initial dropper via HTTP GET (417 bytes)
2. PowerShell recon script (1,512 bytes)
3. Staged executable delivery — fake TeamViewer bundle (4.3 MB), supplementary DLL (668 KB), lightweight stub (12 KB)
4. Persistence script `pas.ps1` (1,553 bytes)

**Key IOCs extracted:**

<details>
<summary>Expand</summary>

| Type | Value |
|------|-------|
| C2 IPs (confirmed) | 5.252.153.241, 45.125.66.32, 45.125.66.252 |
| Secondary infrastructure | 20.10.31.115, 185.188.32.26 |
| Malicious domains | authenticatoor.org, appointedtimeagriculture.com |
| Payloads | 6 files (4 executables, 2 PS1 scripts) |
| Spoofed user agents | 3 |

</details>

**Notable:** Kerberos logs confirmed `shutchenson`'s credentials remained valid post-compromise — the attacker had a live domain foothold, not just local code execution.

---

### Case Study 2 — Exploit Kit / Persistent Compromise (2025-06-13)

**Victim:** `10.6.13.133` / `rgaines@MASSFRICTION.COM`

A categorically more sophisticated operation. Rather than social engineering, this was drive-by delivery via the **LandUpdate808 exploit kit** (Priority 1 Suricata alert on `hillcoweb.com`). The attacker established persistent C2 using Cloudflare Tunnel and legitimate DNS providers as obfuscation layers, with a 34-minute SMB/Kerberos session to the domain controller indicating active lateral movement preparation.

**Exfiltration pattern:** Repeated POST requests with consistent ~30KB payloads to `windows-msgas.com` and a Cloudflare Tunnel endpoint where data exfiltration happened in chunks over obfuscated channels.

**Key IOCs extracted:**

<details>
<summary>Expand</summary>

| Type | Value |
|------|-------|
| Exploit kit IP | 67.217.228.199 (hillcoweb.com) |
| Cloudflare-abused C2 IPs | 104.21.80.1, 104.21.16.1, 104.21.112.1, 104.16.230.132, 104.16.231.132 |
| Malicious domains | hillcoweb.com, event-time-microsoft.org, eventdata-microsoft.live, windows-msgas.com |
| Cloudflare Tunnel C2 | varying-rentals-calgary-predict.trycloudflare.com |
| Footprint DNS abuse | ce7953307ad2079d6aaa354bfc57865b.clo.footprintdns.com |
| Malware user agent | PowerShell/5.1.26100.4202 (spoofed as Mozilla) |

</details>

**Notable:** Single-IP blocking is ineffective against this infrastructure since the attacker used 5+ Cloudflare IPs. The IOC list enables DNS sinkhole policies and ASN-level rules rather than per-IP blocks.

---

### Threat Comparison

| | Case Study 1 | Case Study 2 |
|--|--------------|--------------|
| Initial vector | Social engineering (typo-squat) | Exploit kit (drive-by) |
| Sophistication | Moderate | High |
| Scope | Single workstation | Workstation + domain lateral movement |
| Persistence | Dependent on executables surviving detection | Guaranteed — credentials compromised, C2 established |
| Likely intent | Opportunistic malware distribution | Targeted domain compromise |

---

## Analysis Efficiency

| | Manual Estimate | Pipeline |
|--|----------------|---------|
| Case Study 1 | 5.5–7 hours | ~12 minutes |
| Case Study 2 | 7.5–9.5 hours | ~15 minutes |

Manual estimates based on industry-standard analyst workflows (raw PCAP triage, C2 correlation, payload extraction, IOC compilation). Pipeline time is sequential script execution.

---

## Challenges & Fixes

| Issue | Resolution |
|-------|-----------|
| Noisy Suricata logs | Filtered with `jq` to isolate alert events |
| Distributed Zeek logs | Consolidated with `zeek-cut` pipelines |
| High CPU spikes during analysis | Tuned Suricata thread count, limited concurrent captures |
| DNS resolution failure on fresh droplet | Configured `systemd-resolved` with public DNS (8.8.8.8, 1.1.1.1) |
| Empty script output | Corrected input variable path references |

---

## Roadmap

- Elasticsearch + Kibana integration for dashboard visualization
- Rewrite scripts as modular Python framework for maintainability
- MISP integration for automated threat intelligence sharing
- YARA scanning and file carving for malware payload extraction
