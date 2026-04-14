# T1003.001 — LSASS Memory

## What this technique is

Credential dumping from LSASS memory. Attackers target the Local Security Authority Subsystem Service process to extract plaintext passwords, hashes, and Kerberos tickets from memory. Procdump is a legitimate Sysinternals tool commonly abused for this.

---

## Test run

```
Invoke-AtomicTest T1003.001 -TestNumbers 1
```

Procdump executed against lsass.exe, writing a full memory dump to `C:\Windows\Temp\lsass_dump.dmp`.

---

## What fired

**Rule 92052 — level 4**
"Windows command prompt started by abnormal process"

cmd.exe was flagged because its parent was PowerShell. The rule had no awareness of what cmd.exe was actually doing.

---

## Key log fields

```
timestamp:        2026-04-12T23:14:56.231Z
agent:            windowsvm1 (192.168.1.187)
eventID:          1 (Sysmon Process Create)
image:            C:\Windows\System32\cmd.exe
commandLine:      "cmd.exe" /c "C:\AtomicRedTeam\...\procdump.exe" -accepteula -ma lsass.exe C:\Windows\Temp\lsass_dump.dmp
parentImage:      C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
user:             DESKTOP1\Administrator
integrityLevel:   High
hashes:           SHA256=B99D61D874728EDC0918CA0EB10EAB93D381E7367E377406E65963366C874450
rule.id:          92052
rule.level:       4
mitre:            T1059.003 (tagged by Sysmon ruleName — not T1003.001)
```

---

## Analysis

The default rule caught the parent process anomaly but nothing identified this as a credential dumping attempt. Level 4 means it would never surface above the noise in a real environment. The MITRE tag applied was T1059.003 (Windows Command Shell) — Wazuh had no rule to remap this to T1003.001 where it actually belongs.

The dump file itself (`lsass_dump.dmp`) was written to disk with no detection on the file creation event.

---

## Rule added

**Rule 100110 — level 13**

Matches `procdump.exe` in the image field combined with `lsass.exe` in the command line. Severity set to 13 to reflect the credential access tactic. MITRE tag corrected to T1003.001.
