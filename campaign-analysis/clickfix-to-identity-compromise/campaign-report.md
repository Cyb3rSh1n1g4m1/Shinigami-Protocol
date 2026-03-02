

---

# 7) `campaign-analysis/clickfix-to-identity-compromise/campaign-report.md`
```md
# Campaign Reconstruction: ClickFix / User-Assisted Execution → Identity Compromise → Impact

## Executive Risk Summary
ClickFix has grown as a social engineering technique that coerces users into running malicious commands, enabling malware delivery and downstream theft/exfiltration. This campaign reconstruction models a realistic kill chain where ClickFix-like execution enables foothold (RAT/RMM), followed by identity takeover behaviors associated with modern intrusion operators. (Sources: Microsoft, Proofpoint, Splunk detections) :contentReference[oaicite:11]{index=11}

## Timeline (Example)
T0: User browses to compromised site / malvertising redirect  
T1: Fake verification / CAPTCHA lure (ClickFix) copies command to clipboard  
T2: User executes Win+R paste → PowerShell staged downloader  
T3: Payload installs RAT or remote support tooling; establishes persistence  
T4: Credential theft / session theft → IAM abuse (MFA resets/device adds)  
T5: Discovery + lateral movement; data staging & exfil  
T6: Extortion/ransomware impact

## Diamond Model (High-level)
- Adversary: TA571-like distribution + intrusion operator behaviors
- Infrastructure: compromised sites, redirectors, staging domains
- Capability: PowerShell stager, RAT/RMM, identity abuse
- Victim: enterprise users; help desk & SSO are key choke points

## ATT&CK Mapping (Campaign)
- Initial Access: T1189, T1204
- Execution: T1059.001
- Persistence/Access: T1219
- Credential/Identity: T1078, T1621, T1098
- Exfiltration: (to be filled based on sample malware path)

## Intelligence Gaps (What you’d need to confirm)
- What payload family was delivered (stealer vs RAT vs loader)?
- Was identity compromise achieved via endpoint credential theft or help desk workflow abuse?
- What SaaS/data was accessed post-compromise?

## Detection Opportunities (High signal)
- Browser → PowerShell parent/child patterns
- Encoded/hidden PowerShell flags
- First-seen remote support tool execution
- Azure AD audit events: auth method changes + password resets
- Impossible travel / new device sign-ins

## Threat Hunting Hypotheses (linked playbooks)
- H1: ClickFix-driven PowerShell downloaders (see playbooks/clickfix-detection.md)
- H2: Unauthorized remote support tool sessions (see playbooks/rmm-quickassist-abuse.md)
- H3: Help desk/MFA reset abuse (see playbooks/helpdesk-mfa-reset-abuse.md)

## Appendix
- Example OpenCTI pivots
- Example Axonius validation queries
- IOC table placeholder (domain/IP/hash) + confidence scoring rubric
