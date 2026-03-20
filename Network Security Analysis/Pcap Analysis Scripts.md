# Automated Network Forensics Pipeline Scripts
**Author:** Malachi Barratt  
**Date:** October 2025  

---

## 1. `detailed-report.sh` — Comprehensive Forensic Report

```bash
#!/bin/bash

# --- Configuration ---
LOG_DIR="./"
REPORT_FILE="detailed-investigation-report.txt"

# --- Main Report Generation ---
cat > "$REPORT_FILE" << EOF
=== DETAILED INVESTIGATION REPORT ===

Date: $(date)
Log Directory: $LOG_DIR

===================================
## 1. Unusual Connection Patterns
===================================

### Connections on Non-Standard Ports (e.g., non-80, 443, 21, 22, 23, 25, 110, 143, 3389)
$(cat ${LOG_DIR}conn.log | zeek-cut id.orig_h id.resp_h id.resp_p proto | awk '
  $4 !~ /^(80|443|21|22|23|25|110|143|3389)$/ { print }' | head -20)

### Long-Lived Connections (Possible Data Exfiltration or Persistent C2)
$(cat ${LOG_DIR}conn.log | zeek-cut id.orig_h id.resp_h duration proto service | awk '$3 > 600 { print }' | sort -k3 -rn | head -10)

=================================
## 2. Authentication Failures
=================================

### SSH - Failed Attempts (Top 10)
$(cat ${LOG_DIR}ssh.log 2>/dev/null | \
  grep -iE 'fail|failure|failed|authentication failed' | \
  zeek-cut id.orig_h user 2>/dev/null | \
  awk '{ if($1!="") print $1, $2 }' | \
  sort | uniq -c | sort -rn | head -n 10)

### HTTP Auth Failures (401/403) - Top 10
$(cat ${LOG_DIR}http.log 2>/dev/null | \
  zeek-cut id.orig_h user host uri status 2>/dev/null | \
  awk '$5 ~ /401|403/ {print $1, $2, $3, $4, $5}' | \
  sort | uniq -c | sort -rn | head -n 10)

### Kerberos - Failed Authentications (Top 10)
$(cat ${LOG_DIR}kerberos.log 2>/dev/null | \
  zeek-cut id.orig_h client service success 2>/dev/null | \
  awk '$4 ~ /F|f|0|false/ {print $1, $2, $3, $4}' | \
  sort | uniq -c | sort -rn | head -n 10)

### SMB / NTLM-like Failures (Top 10)
$(cat ${LOG_DIR}smb.log 2>/dev/null | \
  grep -iE 'fail|failed|access denied|STATUS_LOGON_FAILURE' | \
  zeek-cut id.orig_h user 2>/dev/null | \
  sort | uniq -c | sort -rn | head -n 10)

===================================
## 3. Detailed File Activity
===================================

### Potentially Malicious File Types (Executables, Scripts, Archives)
$(cat ${LOG_DIR}files.log 2>/dev/null | zeek-cut tx_hosts rx_hosts filename mime_type | grep -E '\.(exe|dll|js|vbs|bat|zip|rar|7z)$|application/(x-msdownload|x-executable|zip|x-rar-compressed)' | head -20)

===================================
## 4. TLS/SSL Traffic Analysis
===================================

### Unique TLS Subject Common Names (Unusual Certificates)
$(cat ${LOG_DIR}ssl.log 2>/dev/null | zeek-cut id.resp_h server_name | sort | uniq | head -20)

### Outbound TLS Connections to High-Risk Countries (Placeholder)
# Requires GeoIP enrichment.
EOF

# Display the report
cat "$REPORT_FILE"
```

## ip-look.sh — Targeted IP Investigation
```bash
#!/bin/bash

# --- Configuration ---
LOG_DIR="./"
REPORT_FILE="ip-investigation-report.txt"

# --- Prompt for IP Input ---
echo "======================================================="
read -p "Enter the primary suspected IP address (e.g., 10.1.17.215): " SUSPECT_IP
echo "======================================================="

if [ -z "$SUSPECT_IP" ]; then
    echo "No IP address entered. Exiting."
    exit 1
fi

# --- Core Lookup Function ---
perform_lookup() {
    local ip="$1"

    cat > "$REPORT_FILE" << EOF
=== TARGETED IP INVESTIGATION REPORT: $ip ===

Date: $(date)

==================================================
## 1. IDENTITY & USER
==================================================

### MAC Address of Client ($ip)
$(cat ${LOG_DIR}dhcp.log 2>/dev/null | zeek-cut client_addr mac | grep "$ip" | sort -u)

### Hostname & User Account from Kerberos
$(cat ${LOG_DIR}kerberos.log 2>/dev/null | zeek-cut ts id.orig_h client service success | grep "$ip" | grep -v '\$' | head -5)

==================================================
## 2. CONNECTION SUMMARY
==================================================

### Top 10 Connections from $ip
$(cat ${LOG_DIR}conn.log 2>/dev/null | zeek-cut id.orig_h id.resp_h id.resp_p proto | grep "$ip" | zeek-cut id.resp_h | sort | uniq -c | sort -rn | head -10)

### HTTP Activity
$(cat ${LOG_DIR}http.log 2>/dev/null | zeek-cut ts id.orig_h host uri user_agent method status_code | grep "$ip" | head -10)

==================================================
## 3. GLOBAL THREAT INDICATORS
==================================================

### Suspected C2 IPs
$(cat ${LOG_DIR}conn.log 2>/dev/null | zeek-cut duration id.orig_h id.resp_h id.resp_p service | awk '$1 > 600 && $3 != "10.1.17.2" { print $1 " - " $3 " (" $5 ")" }' | sort -rn)

### Likely Fake Google Authenticator Domain
$(cat ${LOG_DIR}ssl.log 2>/dev/null | zeek-cut server_name | grep 'google-authenticator' | sort -u)

==================================================
## 4. FILES & DNS
==================================================

### File Transfers
$(cat ${LOG_DIR}files.log 2>/dev/null | zeek-cut id.orig_h id.resp_h mime_type filename sha256 | grep "$ip" | head -n 10)

### Probable HTTP downloads
$(cat ${LOG_DIR}http.log 2>/dev/null | zeek-cut ts id.orig_h id.resp_h host uri method status_code response_body_len resp_mime_types user_agent | grep "$ip" | grep -Ei 'get-file|/download|\.ps1|\.exe|\.msi|\.zip|\.rar|\.tar|\.gz|\.dll|octet-stream|application/octet-stream|content-disposition' | head -n 20)

### DNS Lookups
$(cat ${LOG_DIR}dns.log 2>/dev/null | zeek-cut ts id.orig_h query answers | grep "$ip" | head -5)

EOF

# Display the final report
echo "Investigation complete. Reading report..."
echo "------------------------------------------------------"
cat "$REPORT_FILE"
echo "------------------------------------------------------"
}

# --- Execute Lookup ---
perform_lookup "$SUSPECT_IP"
```

## ioc-cor.sh — IOC Extraction & Correlation
```bash
#!/bin/bash

# --- Configuration ---
LOG_DIR="./"
SURICATA_DIR="./suricata-output"
REPORT_FILE="ioc-correlation-report.txt"

# --- Pre-requisite Check ---
if ! command -v jq &> /dev/null
then
    echo "JQ is required for this script but is not installed. Please install JQ."
    exit 1
fi

# --- Main Report Generation ---
cat > "$REPORT_FILE" << EOF
=== IOC & CORRELATION REPORT ===

Date: $(date)

===================================
## 1. Top 20 Suspicious Connections
===================================

### Top 20 IPs with Most Connections
$(cat ${LOG_DIR}conn.log | zeek-cut id.resp_h | sort | uniq -c | sort -rn | head -20)

### Top 10 Long-Duration Connections
$(cat ${LOG_DIR}conn.log | zeek-cut duration id.orig_h id.resp_h id.resp_p service | sort -rn | head -10)

===================================
## 2. Suspicious Domains & Hosts
===================================

### High-Entropy Domains
$(cat ${LOG_DIR}dns.log | zeek-cut query | grep -E '[a-z]{20,}' | sort -u)

### Unusual User Agents
$(cat ${LOG_DIR}http.log | zeek-cut user_agent | grep -iE 'python|curl|wget|powershell|java' | sort -u)

===================================
## 3. Data Exfiltration / Lateral Movement
===================================

### Large Uploads
$(cat ${LOG_DIR}http.log | zeek-cut method request_body_len response_body_len id.orig_h host uri | awk '$2 > 0 { print }' | sort -k2 -rn | head -10)

### Suspicious File Hashes
$(cat ${LOG_DIR}files.log | zeek-cut mime_type filename sha1 | grep -iE 'exe|dll|bat|ps1|script')

EOF

# --- Suricata Correlation ---
echo "===================================" >> "$REPORT_FILE"
echo "## 4. Suricata Correlation Check" >> "$REPORT_FILE"
echo "===================================" >> "$REPORT_FILE"

cat ${SURICATA_DIR}/eve.json 2>/dev/null | jq -r 'select(.event_type=="alert") | .dest_ip' | sort -u > malicious-ips.tmp

if [ -s malicious-ips.tmp ]; then
    echo "-> Cross-referencing malicious IPs with Zeek conn.log:" >> "$REPORT_FILE"
    while read ip; do
        echo "--- Connections to $ip ---" >> "$REPORT_FILE"
        cat ${LOG_DIR}conn.log | zeek-cut ts id.orig_h id.resp_h id.resp_p service duration | grep "$ip" >> "$REPORT_FILE"
    done < malicious-ips.tmp
else
    echo "No unique malicious IPs found in Suricata alerts." >> "$REPORT_FILE"
fi

rm malicious-ips.tmp 2>/dev/null

# Display the report
cat "$REPORT_FILE"
```

## quick-report.sh — Rapid Triage Report
```bash
#!/bin/bash

# --- Configuration ---
LOG_DIR="./"
REPORT_FILE="quick-analysis-report.txt"

# --- Main Report Generation ---
cat > "$REPORT_FILE" << EOF
=== Quick PCAP Analysis Report ===

Date: $(date)
Log Directory: $LOG_DIR

---------------------------------
## Top 10 Destination IPs
---------------------------------
$(cat ${LOG_DIR}conn.log | zeek-cut id.resp_h | sort | uniq -c | sort -rn | head -10)

---------------------------------
## Top 5 Protocol Count
---------------------------------
$(cat ${LOG_DIR}conn.log | zeek-cut proto | sort | uniq -c | sort -rn | head -5)

---------------------------------
## Suricata Alerts (Top 10 Most Frequent)
---------------------------------
$(cat suricata-output/fast.log 2>/dev/null | cut -d ' ' -f 4- | sort | uniq -c | sort -rn | head -10)

---------------------------------
## Suspicious Domains
---------------------------------
$(cat ${LOG_DIR}dns.log | zeek-cut query | grep -E '[a-z0-9]{15,}' | sort | uniq)

---------------------------------
## Files Transferred
---------------------------------
$(cat ${LOG_DIR}files.log 2>/dev/null | zeek-cut mime_type filename | head -10)
EOF

# Display the report
cat "$REPORT_FILE"
```
