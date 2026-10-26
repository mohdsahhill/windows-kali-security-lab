# Detection Report: Brute-Force & Privilege Escalation — Windows Security Lab

**Analyst:** Muhammed Sahil
**Date:** October 26, 2026
**Environment:** Self-hosted lab (Windows laptop + Kali Linux VM, isolated host-only network)

## 1. Executive Summary
On October 26, 2026, a simulated brute-force attack was launched from a Kali Linux VM (`192.168.82.50`) against a Windows host (`192.168.82.1`), targeting the local account `labtarget`, using NetExec against SMB. Splunk, ingesting the Windows Security event log, recorded 19 failed authentication attempts (Event ID 4625) in total, with 16 of those falling into two separate 5-minute windows that each exceeded the lab's brute-force threshold. Each burst ended in a successful logon (Event ID 4624) followed immediately by a privileged-logon event (Event ID 4672), confirming the compromised account held administrative rights.

## 2. Scope
- Target: `192.168.82.1`, account `labtarget`
- Source: Kali Linux VM, `192.168.82.50`
- Tooling: NetExec (`nxc smb`) for the attack, Splunk + SPL for detection
- Network: isolated VM host-only network — no production or third-party systems involved

## 3. Timeline
| Time (local) | Event | Event ID | Detail |
| --- | --- | --- | --- |
| 01:20:00–01:24:59 | Failed logon burst (8 attempts) | 4625 | labtarget, from `192.168.82.50` |
| 01:23:22.604 | Successful logon + privilege assignment | 4624, 4672 | labtarget, admin privileges confirmed |
| 01:30:00–01:34:59 | Failed logon burst (8 attempts) | 4625 | labtarget, from `192.168.82.50` |
| 01:32:55.739 | Successful logon + privilege assignment | 4624, 4672 | labtarget, admin privileges confirmed |

## 4. Detection
Detected with the queries in `splunk/spl-queries.md`. The brute-force threshold query flagged two separate 5-minute windows — 01:20:00 and 01:30:00 — each with 8 failed attempts from the same source, both above the 5-attempt threshold used for this lab.

## 5. MITRE ATT&CK Mapping
| Observed Behavior | Event ID(s) | Technique | Tactic |
| --- | --- | --- | --- |
| Repeated failed logons | 4625 | T1110.001 | Credential Access |
| Successful logon after guessing | 4624 | T1110.001 | Credential Access |
| Privileged account logon | 4672 | T1078.003 | Privilege Escalation |

## 6. Indicators
- Source IP: `192.168.82.50`
- Target account: `labtarget`
- Technique: password guessing via SMB (NetExec)

## 7. Recommendations
- Enforce an account lockout policy (e.g., lock after 5 failed attempts / 15 minutes)
- Require MFA or restrict remote access to a VPN/jump host
- Alert in real time on the brute-force threshold query
- Review local administrator group membership regularly

## 8. Screenshots
See `/screenshots`, referenced inline above where relevant.
