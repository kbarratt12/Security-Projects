# T1070.001 — Clear Windows Event Logs

## What this technique is

Clearing Windows event logs to remove evidence of attacker activity. wevtutil is the native Windows utility for managing event logs and is commonly used to clear the System, Security, and Application channels after a compromise.

---

## Test run

```
Invoke-AtomicTest T1070.001 -TestNumbers 1
```

wevtutil used to clear the System event log via cmd.exe spawned from PowerShell.

---

## What fired

**Rule 100003 — level 5**
"Whoami executed - possible reconnaissance"

**Rule 92052 — level 4**
"Windows command prompt started by abnormal process"

**Rule 63104 — level varies**
Windows Event ID 104 — System log cleared (captured via Windows Security log)

The wevtutil execution itself had no dedicated Sysmon detection rule.

---

## Key log fields

```
timestamp:        2026-04-12T23:24:58Z
eventID:          1 (Sysmon Process Create)
image:            C:\Windows\System32\whoami.exe
commandLine:      whoami
parentImage:      powershell.exe
rule.id:          100003
mitre:            T1033

eventID:          1 (Sysmon Process Create)
image:            C:\Windows\System32\cmd.exe
commandLine:      cmd.exe /c wevtutil cl System
parentImage:      powershell.exe
rule.id:          92052
rule.level:       4
mitre:            T1059.003

eventID:          1 (Sysmon Process Create)
image:            C:\Windows\System32\wevtutil.exe
commandLine:      wevtutil cl System
parentImage:      cmd.exe
mitre:            T1070.001

log_event:
  eventID:        104
  description:    Windows System Event Log Cleared
  channel:        System
  actor:          DESKTOP1\Administrator
```

---

## Analysis

The process chain was visible in the logs but the actual log clearing had no dedicated high-severity rule. wevtutil executing `cl System` is unambiguous — there is no legitimate automated reason for an Administrator to clear the System log mid-session. That this only triggered a level 4 generic parent rule is a significant gap. An attacker clearing logs is actively destroying forensic evidence and it should fire at the top of the severity scale.

Windows EID 104 was captured but also had no rule escalating it appropriately.

---

## Rule added

**Rule 100113 — level 15**

Matches wevtutil.exe in the image field combined with `cl` followed by system, security, or application in the command line. Set to level 15 — log clearing during an active session is one of the clearest defense evasion signals available.
