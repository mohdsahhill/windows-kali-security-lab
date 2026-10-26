# Windows + Kali Linux Security Lab

Self-directed home lab for practicing Windows system hardening, attack simulation, and SOC-style detection using Splunk.

## Overview
This project simulates a brute-force credential attack and a subsequent privileged logon against a Windows host, then detects, triages, and documents it using Splunk and SPL — mirroring the workflow of a SOC/blue-team analyst. Findings are mapped to the MITRE ATT&CK framework.

## Architecture
- **Attacker:** Kali Linux (VM, host-only network)
- **Target / monitored host:** Windows laptop with SMB enabled on a dedicated test account
- **SIEM:** Splunk Enterprise (on the Windows host), ingesting the Windows Security event log

![Lab topology](screenshots/01-lab-topology.png)

## What I Did
1. Hardened and configured a Windows host for audit logging of logon events (Event IDs 4624, 4625, 4672)
2. Ingested the Windows Security log into Splunk, indexed separately for analysis
3. Simulated a brute-force attack from Kali Linux against a local test account
4. Built SPL searches to flag the brute-force threshold and privileged logons, and visualized the failure-to-success pattern on a timeline
5. Mapped the detected behavior to MITRE ATT&CK techniques
6. Documented the investigation in a findings report (see [`docs/detection-report.md`](docs/detection-report.md))

## Detection Logic (SPL)
Full queries in [`splunk/spl-queries.md`](splunk/spl-queries.md). Example — brute-force threshold detection:
```spl
index=win_security_lab sourcetype="WinEventLog:Security" EventCode=4625
| bucket _time span=5m
| stats count as failed_attempts values(Account_Name) as targeted_accounts by _time, Source_Network_Address
| where failed_attempts >= 5
```

## MITRE ATT&CK Mapping
| Observed Behavior | Event ID(s) | Technique | Tactic |
| --- | --- | --- | --- |
| Repeated failed logons, one account, many passwords | 4625 | [T1110.001 – Password Guessing](https://attack.mitre.org/techniques/T1110/001/) | Credential Access |
| Successful logon after guessing | 4624 | T1110.001 | Credential Access |
| Logon by a privileged/admin account | 4672 | [T1078.003 – Valid Accounts: Local Accounts](https://attack.mitre.org/techniques/T1078/003/) | Privilege Escalation |

## Screenshots
See [`/screenshots`](screenshots) — covering setup, attack, detection and analysis.

## Skills Demonstrated
Windows Security auditing · Splunk administration & SPL · log correlation & triage · MITRE ATT&CK mapping · incident documentation · Linux (Kali) tooling
