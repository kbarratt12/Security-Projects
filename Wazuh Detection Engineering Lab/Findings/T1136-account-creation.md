# T1136.001 — Create Local Account

## What this technique is

Creating a local user account to establish persistent access. Attackers add accounts — often immediately adding them to the local Administrators group — to maintain a foothold that survives credential resets or other remediation.

---

## Test run

```
Invoke-AtomicTest T1136.001 -TestNumbers 8
```

net.exe used to create a local account `T1136.001_Admin` with password `T1136_pass`, then immediately added to the local Administrators group.

---

## What fired

**Rule 92052 — level 4**
"Windows command prompt started by abnormal process"

cmd.exe flagged for PowerShell parent. The account creation itself was not the trigger.

---

## Key log fields

```
timestamp:        2026-04-12T22:39:35.694Z
eventID:          1 (Sysmon Process Create)
image:            C:\Windows\System32\cmd.exe
commandLine:      "cmd.exe" /c net user /add "T1136.001_Admin" "T1136_pass" & net localgroup administrators "T1136.001_Admin" /add
parentImage:      C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
user:             DESKTOP1\Administrator
integrityLevel:   High
currentDirectory: C:\Users\ADMINI~1\AppData\Local\Temp\
rule.id:          92052
rule.level:       4
mitre:            T1059.003 (Sysmon tag — not T1136.001)
```

---

## Analysis

An account being created and immediately added to Administrators is about as clear a persistence signal as you can get. The only thing Wazuh saw was an unusual parent process relationship. If that parent chain changes — say the attacker runs net.exe directly — the alert disappears entirely. The command line was fully visible in the log. The detection just wasn't there to act on it.

---

## Rule added

**Rule 100114 — level 14**

Matches `net\s+user\s+/add` in the command line field. Severity set to 14 given the combination of account creation and likely privilege escalation. MITRE tag corrected to T1136.001.
