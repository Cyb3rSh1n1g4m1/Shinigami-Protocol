```
---
title:  Storm-1811
created: Monday 2nd March 2026 13:02
Last modified: Monday 2nd March 2026 12:53
Aliases: 
Tags:

---
# Storm-1811
```

## Why Relevant

Storm-1811 is directly associated with:

- ClickFix fake CAPTCHA campaigns
    
- NetSupport RAT
    
- ScreenConnect abuse
    
- Remote management tooling
    

This cluster specifically:

- Uses SEO poisoning to lure IT/admin users
    
- Deploys RATs via user-executed commands
    
- Transitions to credential harvesting and persistence
    

## Techniques

- T1189 – Drive-by
    
- T1059 – PowerShell
    
- T1219 – Remote Access Software
    
- T1003 – Credential Dumping
    
- T1078 – Valid Accounts
    

## Why This Is Strong for Your Repo

Storm-1811 gives you:

- A clean example of social engineering → RAT → hands-on-keyboard
    
- Good opportunity to write hunting hypotheses around:
    
    - Suspicious ScreenConnect installs
        
    - NetSupport processes
        
    - PowerShell launched via explorer

# Storm-1811 – ClickFix + Remote Access Tooling

**Role:** Post-execution intrusion cluster  
**Relevance:** Heavy use of ClickFix leading to NetSupport RAT / ScreenConnect  
**Value in repo:** Modern “user-assisted execution” actor

### Core Behaviors

- Fake verification prompts
    
- Win+R clipboard instructions
    
- Remote access tool deployment
    
- Credential harvesting post-RAT
    

### Key ATT&CK Techniques

- T1189 – Drive-by
    
- T1059 – PowerShell
    
- T1219 – Remote Access Software
    
- T1078 – Valid Accounts
    
- T1003 – Credential Dumping
    

### Portfolio Angle

You can build:

- RAT detection playbooks
    
- Suspicious RMM installation hunting
    
- Persistence mechanism analysis


---

# 5) `threat-actors/Storm-1811/dossier.md`
```md
# Threat Actor Dossier: Storm-1811 (Financially Motivated / Social Engineering + RMM)

## Executive Risk Summary
Storm-1811 is a financially motivated actor linked to ransomware outcomes and known for social engineering initial access methods, including impersonation and abuse of remote support tooling (e.g., Microsoft Quick Assist) to establish interactive access on victim endpoints. (Sources: Microsoft, MITRE, Red Canary) :contentReference[oaicite:6]{index=6}

## Primary Initial Access Pattern (RMM / Remote Support Abuse)
- Social engineering (often via messaging/calls) impersonating IT/help desk
- Convince user to accept remote session via Quick Assist / similar
- Establish hands-on-keyboard access → deploy follow-on tooling → ransomware path :contentReference[oaicite:7]{index=7}

## Relationship to “ClickFix-like” Attacks
Storm-1811’s tradecraft sits in the same family of “user-assisted execution” patterns as ClickFix: the user is coerced into enabling access/executing steps that bypass technical controls. Microsoft documents ClickFix growth as a technique class; Storm-1811 demonstrates adjacent, currently exploited user-coercion for access. :contentReference[oaicite:8]{index=8}

## Zero Trust Violations
- Over-trust in help desk / remote support workflows
- Lack of separation-of-duties for remote support approvals
- Weak session auditing + lack of “remote tool allowed list”
- Telemetry gaps around first-use of remote support tools

## ATT&CK Mapping (Core)
- T1219 Remote Access Software
- T1566 Phishing (often paired with social engineering)
- T1204 User Execution
- T1059 Command and Scripting
- T1078 Valid Accounts (post-foothold)

## Detection & Telemetry Requirements
- Endpoint: process creation, remote tool execution logs, service installs, scheduled tasks
- Identity: MFA reset events, device registration, risky sign-ins
- Network: outbound connections to remote support infrastructure, unusual RDP/SMB expansion

## OpenCTI Queries
- threat-actor:"Storm-1811" AND technique:T1219
- threat-actor:"Storm-1811" AND (tool:* OR malware:* OR technique:*)

## Axonius Validation Queries
- where installed_software.name contains_any ("Quick Assist")
- where process.name contains_any ("QuickAssist.exe") OR service.name contains "QuickAssist"

## Threat Hunting Hypothesis
**Hypothesis:** Remote support tooling is being initiated outside approved support channels as pre-ransomware foothold.

**KQL – Quick Assist / remote tool execution**
```kql
DeviceProcessEvents
| where FileName has_any ("QuickAssist.exe","TeamViewer.exe","AnyDesk.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine
| order by Timestamp desc
