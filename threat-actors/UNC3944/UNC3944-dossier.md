## Why UNC3944 Is a Strong Replacement

- Extremely active in 2023–2025
    
- Targets Okta / Entra ID / SSO environments
    
- Social engineers help desks
    
- Bypasses MFA
    
- Abuses legitimate identity infrastructure
    
- Frequently linked to ransomware deployment
    

They are not relying on malware first — they rely on **human manipulation + valid accounts**.

That contrast is powerful in your repo.

---

## Core Tradecraft

### Initial Access

- Help desk social engineering
    
- SIM swapping
    
- MFA fatigue attacks
    
- OAuth abuse
    
- Token theft
    

### Post-Access

- Privilege escalation
    
- SSO federation abuse
    
- Admin portal access
    
- SaaS data exfiltration
    
- Ransomware affiliate handoff
    

---

## Key ATT&CK Techniques

- T1078 – Valid Accounts
    
- T1566 – Phishing (voice/social engineering)
    
- T1621 – MFA Fatigue
    
- T1556 – Modify Authentication Process
    
- T1098 – Account Manipulation
    
- T1041 – Exfiltration Over Web Services
    

---

## Why UNC3944 Makes Phase 01 Stronger

You now demonstrate:

|Actor|Attack Model|
|---|---|
|TA571|Malware distribution|
|Storm-1811|RAT deployment via ClickFix|
|UNC3944|Identity-first compromise|

That shows you understand:

- Malware-driven compromise
    
- User-assisted execution
    
- Credential-native intrusion
    
- Modern cloud attack paths


---

# 6) `threat-actors/UNC3944/dossier.md`
```md
# Threat Actor Dossier: UNC3944 (Scattered Spider) — Identity-First Intrusion Operator

## Executive Risk Summary
UNC3944 / Scattered Spider is a highly active criminal intrusion set known for social engineering—especially help desk impersonation—paired with MFA bypass (push bombing/MFA fatigue) and SIM swap tactics to gain and maintain access, often leading to extortion and ransomware outcomes. (Sources: CISA, MITRE) :contentReference[oaicite:9]{index=9}

## Core Initial Access Pattern
- Recon employee/victim identity data
- Contact help desk / IT support impersonating employee/contractor
- Reset password, register new MFA device, or downgrade authentication
- Expand access through SSO/IAM and high-value SaaS :contentReference[oaicite:10]{index=10}

## Zero Trust Violations
- Implicit trust in help desk identity proofing
- Over-permissive self-service recovery flows
- Weak MFA method governance (SMS/voice for privileged users)
- Insufficient auditing around auth method changes and device registrations

## ATT&CK Mapping (Core)
- T1078 Valid Accounts
- T1621 MFA Request Generation (MFA fatigue/push bombing)
- T1589 Gather Victim Identity Information
- T1098 Account Manipulation
- T1556 Modify Authentication Process

## Detection & Telemetry Requirements
- Identity: MFA method add/remove, password reset, device registration, Conditional Access changes
- SaaS: mailbox rules, OAuth consent, token issuance anomalies
- Endpoint: remote tool installs post-identity takeover

## OpenCTI Queries
- threat-actor:UNC3944 AND (technique:T1078 OR technique:T1621)
- threat-actor:"Scattered Spider" AND (helpdesk OR MFA OR SIM)

## Axonius Validation Queries
- where identity.mfa_enabled=false AND identity.is_privileged=true
- where identity.auth_methods contains "sms" AND identity.is_privileged=true

## Threat Hunting Hypothesis
**Hypothesis:** Help desk-mediated credential/MFA changes are being abused to register attacker-controlled authentication methods.

**KQL – Azure AD Audit: auth method / reset activity (pattern)**
```kql
AuditLogs
| where OperationName has_any ("Update user", "Reset password", "Add authentication method", "Update authentication method")
| project TimeGenerated, OperationName, InitiatedBy, TargetResources, Result
| order by TimeGenerated desc
