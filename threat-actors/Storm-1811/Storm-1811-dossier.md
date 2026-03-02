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
