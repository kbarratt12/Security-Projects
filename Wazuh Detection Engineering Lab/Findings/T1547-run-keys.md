# T1547.001 — Registry Run Keys

## What this technique is

Writing to registry run keys to execute a payload automatically on user logon or system startup. One of the most common persistence mechanisms. The `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` key executes entries as the current user on logon.

---

## Test run

```
Invoke-AtomicTest T1547.001 -TestNumbers 1
```

reg.exe used to add a value to `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` pointing to `C:\Path\AtomicRedTeam.exe`.

---

## What fired

**Rule 92302 — level 6**
Generic registry modification rule.

Sysmon captured both the process create event (EID 1) and the registry value set event (EID 13).

---

## Key log fields

```
timestamp:        2026-04-12T22:49:41.411Z
eventID:          1 (Sysmon Process Create)
image:            C:\Windows\System32\reg.exe
commandLine:      REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /V "Atomic Red Team" /t REG_SZ /F /D "C:\Path\AtomicRedTeam.exe"
parentImage:      C:\Windows\System32\cmd.exe
user:             DESKTOP1\Administrator
integrityLevel:   High
currentDirectory: C:\Users\ADMINI~1\AppData\Local\Temp\
hashes:           SHA256=C0E25B1F9B22DE445298C1E96DDFCEAD265CA030FA6626F61A4A4786CC4A3B7D
rule.id:          92302
rule.level:       6
mitre:            T1547.001

timestamp:        2026-04-12T22:49:41.441Z
eventID:          13 (Sysmon Registry Value Set)
image:            C:\Windows\system32\reg.exe
targetObject:     HKU\S-1-5-21-...-500\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Atomic Red Team
details:          C:\Path\AtomicRedTeam.exe
user:             DESKTOP1\Administrator
rule.id:          92302
rule.level:       6
mitre:            T1547.001
```

---

## Analysis

This was one of the better default detections in the lab — the MITRE tag was correct and both the process create and registry write events were captured. The problem is severity. Level 6 for a persistence mechanism writing to a user run key is too low. Execution from `\Temp\` combined with a run key modification is a pattern that warrants immediate attention, not a mid-tier alert that blends into the baseline.

---

## Rule status

No new rule added. Severity tuning to level 10-12 is the fix needed here. The detection logic is correct — the triage level is not.
