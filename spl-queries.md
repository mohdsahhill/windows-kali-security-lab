# SPL Queries — Windows + Kali Security Lab

Four of the original five queries from the lab guide. Query 3 (a transaction-based correlation between failures and the final success) was left out on purpose — Query 2 is the actual detection logic, and Query 5's timeline already shows the same failed-then-succeeded pattern visually, so nothing is lost.

## Query 1 — All failed logons: who and where
```spl
index=win_security_lab sourcetype="WinEventLog:Security" EventCode=4625
| table _time, Account_Name, Source_Network_Address, Logon_Type
| sort -_time
```

## Query 2 — Brute-force threshold (5+ failures in 5 minutes from one source)
```spl
index=win_security_lab sourcetype="WinEventLog:Security" EventCode=4625
| bucket _time span=5m
| stats count as failed_attempts values(Account_Name) as targeted_accounts by _time, Source_Network_Address
| where failed_attempts >= 5
```

## Query 4 — Privileged logon (the escalation signal)
```spl
index=win_security_lab sourcetype="WinEventLog:Security" EventCode=4672 Account_Name=labtarget
| table _time, Account_Name, Privilege_List
```

## Query 5 — Visual timeline
```spl
index=win_security_lab sourcetype="WinEventLog:Security" (EventCode=4624 OR EventCode=4625) Account_Name=labtarget
| timechart span=1m count by EventCode
```
