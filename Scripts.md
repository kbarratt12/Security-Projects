![Bash](https://img.shields.io/badge/Bash-Automation-green?style=flat-square&logo=gnubash)


# Quick
<details>
<summary><strong>View Quick Script</strong></summary>
  
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
</details>

# Detailed
<details>
<summary><strong>View Detailed Script</strong></summary>
  
``` Bash
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
</details>
  
# IP Look
<details>
<summary><strong>View IP Lookup Script</strong></summary>
  
```Bash
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
</details>

# IOC Cor
<details>
<summary><strong>View Script</strong></summary>
  
``` Bash
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

## Usage
1. Place your Zeek logs and Suricata output in the same directory as the scripts.
2. Make the scripts executable: `chmod +x *.sh`
3. Run the analysis: `./quick-analysis.sh`
