# WMI - Lateral Movement Hunt (Example Report)

## Description

Windows Management Instrumentation (WMI) is a Windows administration feature that provides a uniform environment for local and remote access to Windows system components. It relies on the WMI service for local and remote access and the server message block (SMB) and Remote Procedure Call Service (RPCS) for remote access. RPCS operates over port 135. An adversary can use WMI to interact with local and remote systems and use it as a means to perform many tactic functions, such as gathering information for Discovery and remote Execution of files as part of Lateral Movement.

| Field                     | Description  |
|---------------------------|--------------|
| Created                   | 08/06/2023   |
| Executed                  | 08/06/2023   |
| Time Frame                | 08/23/2017 - 08/25/2017 |
| Environment               | BOTs v2                 |
| Threat Hunter             | Hunter             |

| MITRE ATT&CK Technique | IDs |
|------------------------|-----|
| Windows Management Instrumentation | [T1047](https://attack.mitre.org/techniques/T1047) | 

## Hypothesis

Adversaries will look to move laterally to other systems using Windows Management Instrumentation (WMI).

## Data That is Needed

- Authentication Logs
- Netflow
- Process Monitoring
- Process Command-Line Parameters

## Queries

### Splunk

What Data Do We Have?

```spl
| metadata type=sourcetypes index=botsv2 
| eval firstTime=strftime(firstTime,"%Y-%m-%d %H:%M:%S") 
| eval lastTime=strftime(lastTime,"%Y-%m-%d %H:%M:%S") 
| eval recentTime=strftime(recentTime,"%Y-%m-%d %H:%M:%S") 
| sort - totalCount
```

WMI Process Execution - Destination Host

```spl
index=botsv2 sourcetype="xmlwineventlog:microsoft-windows-sysmon/operational" EventCode=1 ParentImage="C:\\Windows\\System32\\svchost.exe" CurrentDirectory="C:\\Windows\\system32\\" CommandLine="C:\\Windows\\system32\\wbem\\wmiprvse.exe -secured -Embedding" ParentCommandLine="C:\\Windows\\system32\\svchost.exe -k DcomLaunch" User="NT AUTHORITY\\NETWORK SERVICE" Image="C:\\Windows\\System32\\wbem\\WmiPrvSE.exe"
| table _time, host, User, ParentImage, ParentCommandLine, Image, CommandLine
```

WMI Network Connection - Destination Host

```spl
index=botsv2 sourcetype="xmlwineventlog:microsoft-windows-sysmon/operational" EventCode=3 Image="C:\\Windows\\System32\\svchost.exe" User="NT AUTHORITY\\NETWORK SERVICE"
```

Systems with Network 4624 Event followed by Sysmon Process Creations - Destination Host

```spl
index="botsv2" (sourcetype=wineventlog (EventCode=4624 Logon_Type=3)) OR (sourcetype="xmlwineventlog:microsoft-windows-sysmon/operational" EventCode=1)
| eval login=mvindex(Logon_ID, 1)
| eval user_id=mvindex(Security_ID, 1)
| eval session=lower(coalesce(login,LogonId))
| transaction session startswith=(EventCode=4624) mvlist=ParentImage
| search eventcount>1
| eval Parent_Process=mvindex(ParentImage, 1)
| table _time, dest, session, host, user_id, Parent_Process, Image, CommandLine
```

All Events for Host by Logon ID

```spl
index=botsv2 ((Logon_ID=<login_id> OR LogonId=<login_id>) host=<host>)
| eval ParentCommandLine=substr(ParentCommandLine,1,74)
| eval CommandLine=substr(CommandLine,1,74)
| table _time, EventCode, TaskCategory, Account_Name, Security_ID, ParentImage, ParentCommandLine, Process_Command_Line, CommandLine
| reverse
```

WMI Parent Command-Line

```spl
index=botsv2 sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational ParentCommandLine="C:\\Windows\\system32\\wbem\\wmiprvse.exe -secured -Embedding" 
| table _time user host ProcessId, ParentProcessId, CommandLine, ParentCommandLine
```

## Results

| Search | Hits |
|--------|------|
| WMI Process Execution - Destination Host | 11 |
| WMI Network Connection - Destination Host | 0 |
| Remote Execution via WMI - Destination Host | 2|
| All Events for Host by Logon ID | 27 |
|  WMI Parent Command-Line | 3 |

## Conclusion

During the week of July 6thth, 2023, the Threat Hunt team conducted a threat hunt to identify instances of lateral movement via WMI in the organization's network.

The engagement focused on Splunk logs across the organization's network. The CTH team performed queries Splunk searching for evidence of lateral movement via WMI execution over a 7 day time-frame.

The hunt returned results indicating lateral movement involving 3 workstations. Internal hosts venus and wrk-klagerf were both infected via lateral movement from wrk-btun. PowerShell was used to facilitate the lateral movement. Processes are all running encoded PowerShell. Wrk-btun also sees encoded PowerShell with a different launcher, but the same commands. Based on this, it would be safe to conclude that this was the initial action taken to gain a foothold on the wrk-btun workstation. Proactive validation and repeating of this hunt will be required to detect successful attacks. There is potential for detection logic to be implemented in Splunk to alert on lateral movement.

## Outputs and Follow-up Tasks

- Task: Identify future instances of WMI Lateral Movement activity.
- Task: Create detection logic in Splunk for encoded PowerShell.
- Task: Create detection logic in Splunk for specific orders of action that might indicate lateral movement.
- Task: Hunt for PowerShell Empire activity.
- Visibility Gap: No Sysmone Event ID 3 Logs.

## Notes

What to look for:

- What data sets provide us a way to view lateral movement in general and communication between Windows hosts specifically?
- Can we see network communication between Windows hosts?
- Are there actions taken on hosts that might indicate similar activities occurring on others?
- What systems are communicating with one another?
- What users are associated with those systems?

## References

- <https://attack.mitre.org/techniques/T1047>
- <https://attack.mitre.org/techniques/T1059/001/>
- <https://attack.mitre.org/techniques/T1132/>
- <https://www.jpcert.or.jp/english/pub/sr/Detecting%20Lateral%20Movement%20through%20Tracking%20Event%20Logs_version2.pdf>
- <https://jpcertcc.github.io/ToolAnalysisResultSheet/>
- <https://www.slideshare.net/votadlos/hunting-lateral-movement-in-windows-infrastructure>
