
# Playbook: Detect ClickFix / Fake CAPTCHA Clipboard Execution

## Why this matters
Microsoft reports ClickFix is growing in popularity and is used to trick users into running malicious commands, leading to payload delivery and theft/exfiltration. :contentReference[oaicite:12]{index=12}

## Primary Signals
- powershell.exe with: -enc, -w hidden, IEX, DownloadString
- Browser or explorer.exe as parent initiating PowerShell
- Short-lived PowerShell followed by outbound network to new domain
- Clipboard/paste artifacts (if EDR captures)

## Required Logs
- EDR process telemetry (command line)
- PowerShell 4104 (Script Block) + AMSI
- DNS + proxy logs

## Sentinel KQL – suspicious PowerShell
```kql
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any ("-enc","-encodedcommand","-w hidden","DownloadString","IEX","Invoke-WebRequest","curl")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine
| order by Timestamp desc
