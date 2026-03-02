```
---
title:  TA5771
created: Monday 2nd March 2026 13:06
Last modified: Monday 2nd March 2026 13:06
Aliases: 
Tags:

---
# TA5771
```


## Why Relevant

TA571 is one of the most active malware distribution clusters and has been heavily tied to:

- **ClickFix fake CAPTCHA pages**
    
- Clipboard injection (copy/paste PowerShell)
    
- SEO poisoning
    
- Malvertising redirect chains
    
- Delivery of loaders (e.g., SocGholish, IcedID, NetSupport RAT)
    

They are not the final intrusion actor — they are the **initial access broker / distribution layer**.

## ClickFix Use

- Victim lands on compromised site
    
- Fake CAPTCHA prompt appears
    
- Instructs user to press:
    
    - `Win + R`
        
    - Paste PowerShell
        
    - Execute
        
- Payload retrieves stage 2 from attacker-controlled infrastructure
    

This bypasses:

- Email filtering
    
- Traditional attachment scanning
    
- Macro blocking
    

## ATT&CK Mapping

- T1189 – Drive-by Compromise
    
- T1059.001 – PowerShell
    
- T1204 – User Execution
    
- T1105 – Ingress Tool Transfer
    
- T1071 – Web-based C2
    

## Why This Is a Great Portfolio Actor

You can build:

- Infrastructure analysis (rotating domains + CDN abuse)
    
- Clipboard attack breakdown
    
- Delivery-to-ransomware pipeline mapping
    
- Detection guidance around suspicious PowerShell from `explorer.exe`

# TA571 – Initial Access Distribution Cluster

**Role:** Malware delivery broker  
**Relevance:** Active in ClickFix + SEO poisoning + fake CAPTCHA  
**Value in repo:** Infrastructure clustering + loader tradecraft

### Core Behaviors

- Fake CAPTCHA prompts
    
- Clipboard PowerShell injection
    
- SocGholish / IcedID / NetSupport delivery
    
- Redirect chains via compromised websites
    

### Key ATT&CK Techniques

- T1189 – Drive-by Compromise
    
- T1204 – User Execution
    
- T1059.001 – PowerShell
    
- T1105 – Ingress Tool Transfer
    
- T1071 – Web C2
    

### Portfolio Angle

You can analyze:

- Redirect infrastructure
    
- Payload staging domains
    
- PowerShell execution patterns
    
- SEO poisoning ecosystems
