# Case 05 — Defense Evasion / Log Clearing

## Objective
Investigate suspicious Defense Evasion activity using Splunk within a Windows Lab VM environment.

## Environment
- Windows 10 Lab VM (VirtualBox)
- Splunk Enterprise for log analysis
- EVTX-ATTACK-SAMPLES dataset used to simulate real-world attack log data

## Hypothesis
**IF:** Account Name shows user01 and ComputerName shows PC01.example.corp.
**THEN:** This event indicates the Security Event Log was cleared, suggesting an attacker attempted to cover their tracks by removing audit evidence.
**SO:** Search Splunk using `index=main EventCode=1102 | table _time Host Message`.

## Timeline
1. Uploaded the EVTX file to Splunk
2. Queried `index=main source="*1102*" | stats count by EventCode`
3. Queried `index=main EventCode=1102 | table _time Host Message`
4. Found suspicious behavior (EventCode 1102 — Security log cleared)
5. Built the hypothesis based on the identified evidence (Account Name, ComputerName, EventCode)

## MITRE ATT&CK Mapping

| Technique | ID | Tactic |
|---|---|---|
| Clear Windows Event Logs | T1070.001 | Defense Evasion |

## Findings
- Account Name: user01
- ComputerName: PC01.example.corp
- EventCode: 1102
- Time: 3/20/2019 01:35:07 AM
- Domain Name: EXAMPLE
- Logon ID: 0x17DAD
- user01 successfully cleared the Security Event Log

## Evidence

**Search Query**
```spl
index=main EventCode=1102
| table _time Host Message
```

**Evidence 1** — Account Name: user01
**Evidence 2** — Domain Name: EXAMPLE
**Evidence 3** — ComputerName: PC01.example.corp
**Evidence 4** — EventCode: 1102
**Evidence 5** — Logon ID: 0x17DAD

*(Screenshots supporting this evidence are available in the screenshots/ folder.)*

## IOC (Indicators of Compromise)
- Account Name: user01
- ComputerName: PC01.example.corp
- Domain Name: EXAMPLE
- Logon ID: 0x17DAD
- EventCode: 1102

## Detection Logic

```yaml
title: Case 5 - Defense Evasion / Log Clearing
id: c62aa880-9957-4dd6-b4d4-c6d32438ff2c
status: experimental
description: Detects clearing of the Windows Security Event Log, a common technique used to remove evidence of prior activity.
author: MIRGANI AMMAR
date: 2026/08/16
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 1102
    SubjectDomainName: "EXAMPLE"
  condition: selection
falsepositives:
  - Legitimate log clearing activities performed by administrators during maintenance
level: medium
tags:
  - attack.defense_evasion
  - attack.t1070.001
```

## Recommendations
- Monitor EventCode 1102 across all endpoints as a high-value indicator of anti-forensic activity.
- Reduce false positives by deploying the Sigma rule above and tuning against known maintenance windows.
- Check who holds SeSecurityPrivilege and restrict it to administrators only.

## Conclusion
An account (user01) was found to have cleared the Security Event Log on PC01.example.corp (EventCode 1102), indicating a deliberate attempt to erase evidence of prior activity and hinder forensic investigation. This activity was classified as Medium severity, since a single 1102 event alone does not confirm malicious intent but is a strong indicator requiring correlation with surrounding activity. No further malicious action was observed beyond the log clearing itself at this stage; continuous monitoring using the deployed Sigma rule is recommended.
