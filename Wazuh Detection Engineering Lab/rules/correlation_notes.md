# Correlation Rule Design Notes

## What this is

This documents the design for a multi-technique attack chain correlation rule and the constraints that prevented full implementation in this lab. The rule logic is sound — the limitation is in how Wazuh's correlation engine handles Sysmon-sourced fields without custom decoder enrichment.

---

## The observation that drove this

Every technique tested in this lab originated from the same parent PowerShell process (PID 7136). Within a 60-second window, the following tactics were all present in the same session:

- Discovery (T1033 — whoami, T1082 — systeminfo)
- Execution (T1059.003 — cmd.exe spawned from PowerShell)
- Persistence (T1053.005 — schtasks, T1547.001 — registry run key)
- Credential Access (T1003.001 — procdump targeting lsass)
- Defense Evasion (T1070.001 — wevtutil log clearing, T1218.011 — rundll32 LOLBIN)

Individually each of those alerts is worth investigating. Together they are an incident. A correlation rule that recognises this pattern and fires a single high-severity alert would be significantly more actionable than the sum of its parts.

---

## The rule (designed, not fully validated)

```xml
<rule id="100200" level="15" frequency="3" timeframe="60">
  <if_matched_sid>100110</if_matched_sid>
  <if_matched_sid>100111</if_matched_sid>
  <if_matched_sid>100112</if_matched_sid>
  <if_matched_sid>100114</if_matched_sid>

  <description>Multi-technique attack chain detected across session</description>

  <mitre>
    <id>T1059</id>
  </mitre>
</rule>
```

This rule fires at level 15 when 3 or more of the technique-specific rules (100110-100114) trigger within a 60-second window.

---

## Why it was not fully implemented

The original design included grouping by `win.eventdata.parentProcessId` to tie alerts back to the same attacker session:

```xml
<same_field>win.eventdata.parentProcessId</same_field>
```

This caused the Wazuh dashboard API to return a 500 error during rule validation. The root cause is that Wazuh's correlation engine does not natively support grouping on Sysmon EventChannel fields like `win.eventdata.parentProcessId` without a custom decoder that extracts and normalises that field into a format the correlation engine can use.

The simplified version above (without `same_field`) is deployable but loses the session-binding logic — it fires on any 3 technique alerts within 60 seconds from any source, not specifically the same process chain.

---

## What proper implementation would require

1. A custom Wazuh decoder that extracts `parentProcessId` from Sysmon Event ID 1 logs and maps it to a normalised field
2. Correlation rules that reference that normalised field via `same_field`
3. Validation via `wazuh-logtest` on the command line rather than the dashboard editor

This is the logical next step for this lab and the difference between alert-level detection and session-level detection.

---

## Reference

- Technique rules this correlates across: 100110, 100111, 100112, 100113, 100114
- Parent rule file: `rules/local_rules.xml`
- Related finding: all techniques in this lab share `parentProcessId: 7136`
