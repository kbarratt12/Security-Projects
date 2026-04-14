# T1083 — File and Directory Discovery

## What this technique is

Enumerating files and directories to understand what is on the system, locate sensitive data, and identify targets for exfiltration or lateral movement. Mass recursive enumeration combined with output redirection to a temp file is a common recon-to-staging pattern.

---

## Test run

```
Invoke-AtomicTest T1083 -TestNumbers 1
```

cmd.exe executed a chained command performing recursive directory listing across the entire C drive, Program Files, and a full tree output — all redirected to a file in %temp%.

---

## What fired

**Rule 100003 — level 5**
"Whoami executed - possible reconnaissance"

**Rule 92052 — level 4**
"Windows command prompt started by abnormal process"

No rule fired for the directory enumeration itself.

---

## Key log fields

```
timestamp:        2026-04-12T23:26:53.631Z
eventID:          1 (Sysmon Process Create)
image:            C:\Windows\System32\cmd.exe
commandLine:      cmd.exe /c dir /s c:\ >> %temp%\T1083Test1.txt & dir /s "c:\Program Files" >> %temp%\T1083Test1.txt & tree /F >> %temp%\T1083Test1.txt
parentImage:      C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
user:             DESKTOP1\Administrator
integrityLevel:   High
currentDirectory: C:\Users\Administrator\AppData\Local\Temp\
hashes:           SHA256=B99D61D874728EDC0918CA0EB10EAB93D381E7367E377406E65963366C874450
rule.id:          92052
rule.level:       4
mitre:            T1059.003

timestamp:        2026-04-12T23:26:53.506Z
eventID:          1 (Sysmon Process Create)
image:            C:\Windows\System32\whoami.exe
parentImage:      C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
rule.id:          100003
rule.level:       5
mitre:            T1033
```

---

## Analysis

The full command line was in the log. A recursive dir across the entire C drive with output staged to a temp file is not normal user behavior. The combination of PowerShell parent, mass enumeration, and output redirection to %temp% is a clear staging pattern. Nothing in the default ruleset recognised it as such.

---

## Rule added

**Rule 100112 — level 10**

Matches `dir\s+/s` or `tree\s+/f` in the command line field. Level 10 reflects that this is reconnaissance and staging behavior rather than immediate high-severity execution. Combined with the parent process context it becomes a meaningful detection.
