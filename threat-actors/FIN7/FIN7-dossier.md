# FIN7 Threat Actor Dossier
**MITRE Group ID:** G0046
**Also Known As:** Carbanak Group, Carbon Spider, ITG14, ELBRUS
**Classification:** TLP:WHITE
**Last Updated:** 2026-05-24
**Status:** Active

---

## Why FIN7 Belongs in This Repo

FIN7 is the threat actor most likely to hit the clients this research stack is built to protect. Financially motivated. APT-level discipline. Active since at least 2015 with an estimated $1-3 billion in confirmed theft. They don't need zero-days. They send a phishing email that looks like a software update notification, or they exploit the unpatched backup appliance your team forgot about. Then they wait, map the environment, and move against the SWIFT terminal or the card processing infrastructure. By the time the fraud alert fires, the dwell time has already done the damage.

This dossier documents their tradecraft, toolset, and detection opportunities as identified through structured research using the AI CTI stack.

---

## Group Profile

FIN7 is a structured criminal enterprise, not a loosely organized crew. They operate with defined roles: phishing operators, intrusion specialists, money mule coordinators, and infrastructure managers. The group has evolved post-2020 to include ransomware-as-a-service partnerships, running as both a direct threat actor and a ransomware affiliate alongside Black Basta, Cl0p, REvil, and Maze.

Infrastructure rotates every 90-180 days. This makes IOC-based blocking largely useless. The behavioral signature, not the domain or IP, is the reliable detection surface.

---

## Targeted Sectors

- Financial institutions (banks, credit unions) -- SWIFT fraud, wire transfer manipulation, treasury system access
- Retail and hospitality -- POS memory scraping, payment card harvesting
- Payment processors -- PCI data targeting, card-present fraud infrastructure
- Organizations undergoing mergers and acquisitions -- newly integrated entities with unvalidated security posture are a known targeting pattern

**Geographic reach:** Global. C2 infrastructure has no fixed region. Targeting follows financial system connectivity, not geography.

**Behavioral targeting indicator:** Accounts authenticating from multiple geographic locations within a single hour -- a signal of credential compromise and active session abuse.

---

## Core Tradecraft

### Initial Access

FIN7 prefers two primary vectors.

**Spearphishing (T1566.001):** Word and Excel documents with macros delivering Carbanak RAT or Cobalt Strike. Lures are tailored to the target -- software update notifications, HR communications, and financial documents are common themes.

**Exploit Public-Facing Application (T1190):** CVE-2023-27532 in Veeam Backup and Replication. The exploitation path targets the `/api/v1/credsvc` endpoint. If Veeam is in the environment and unpatched, this is the highest-priority item before anything else.

Trojanized MSIX and MSI installers (T1204.002) are also used -- fake software updates that execute malicious payloads on user interaction.

---

### Execution

- **POWERTRASH (T1059.001):** Fileless PowerShell backdoor. Obfuscated, in-memory, no file dropped to disk. Used for persistence and C2 communication.
- **WMI (T1047):** wmic.exe and wsmprovhost.exe for remote execution and lateral movement. Used to cross network segments where segmentation is absent or incomplete.
- **VBScript and JavaScript loaders (T1059.005 / T1059.007):** GRIFFON JavaScript downloader used in earlier campaigns. VBScript-based loaders for secondary payload delivery.

---

### Persistence

- **Registry Run Keys (T1547.001):**
  - Carbanak: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\shell64`
  - Cobalt Strike: `HKLM\...\Run\runonce`
- **Scheduled Tasks (T1053.005):** Unauthorized scheduled tasks for beacon persistence and payload re-execution.
- **Web Shells (T1505.003):** Deployed on internet-accessible servers as a fallback persistence mechanism.

---

### Credential Access

- **LSASS dumping (T1003):** Mimikatz and ProcDump targeting LSASS memory. Service account credentials are the primary target.
- **Keylogging (T1056.001):** Carbanak RAT includes a keylogger module. POS keyloggers deployed in retail environments.
- **Password spraying (T1110.003):** Pre-intrusion spraying against Azure AD and O365. Low-and-slow approach to avoid lockout.
- **OAuth token theft (T1528):** Browser session token harvesting for cloud environment access without password.

---

### Lateral Movement

- **WMI (T1047):** Cross-segment lateral movement via wmic.exe and wsmprovhost.exe. Effective where VLAN segmentation is incomplete.
- **ShellTea RDP (T1021.001):** Custom RDP exploitation toolkit used for privilege escalation and movement between network segments.
- **Pass-the-Hash (T1550.002):** NTLM hash extraction via Mimikatz, reused for lateral movement without cracking.
- **SMB/Admin Shares (T1021.002):** PsExec-style movement via administrative shares.

---

### Command and Control

- **Cobalt Strike HTTPS (T1071.001):** Primary post-exploitation C2. Periodic outbound beaconing every 5-10 minutes. Detection logic should key on the interval, not the destination.
- **LotL C2 (T1219):** NetSupport Manager and AnyDesk abused as unauthorized remote access C2. These tools appear in non-standard file paths when used maliciously.
- **Carbanak RAT:** Full-featured banking backdoor injected into trusted processes. SWIFT-capable. Communicates over its own encrypted channel.
- **Infrastructure rotation:** Domains and IPs change every 90-180 days. Behavioral detection on beaconing cadence is required. Static IOC blocking is insufficient.

---

### Impact

- **BadRabbit ransomware (T1486):** Confirmed FIN7-associated ransomware variant deployed in impact phase.
- **Black Basta (RaaS affiliate):** Post-2020 partnership. FIN7 provides initial access; Black Basta handles encryption and extortion.
- **VSS deletion (T1490):** vssadmin delete shadows and wmic shadowcopy delete executed before ransomware deployment. Detection of this behavior is a pre-encryption signal.
- **Fund exfiltration via Carbanak:** SWIFT wire transfer manipulation is the primary monetization path against banking targets.

---

## Toolset

### Custom Malware

| Tool | Type | Notes |
|---|---|---|
| Carbanak RAT | Full-featured banking backdoor | Process injection into explorer.exe, svchost.exe, lsass.exe; SWIFT-capable |
| POWERTRASH | Fileless PowerShell backdoor | In-memory execution; persistence and C2 |
| ShellTea | RDP exploitation toolkit | Lateral movement and privilege escalation |
| BadRabbit | Ransomware | Impact phase; FIN7-confirmed variant |
| GRIFFON | JavaScript downloader | Early-stage payload delivery |

### Frameworks and LotL

| Tool | Type | Notes |
|---|---|---|
| Cobalt Strike | Post-exploitation framework | HTTPS beaconing; registry persistence |
| Mimikatz / ProcDump | Credential dumpers | LSASS memory targeting |
| NetSupport Manager | Legitimate RAT (LotL) | Abused as unauthorized C2; non-standard paths |
| AnyDesk | Legitimate remote access (LotL) | Abused as unauthorized C2; non-standard paths |
| wmic.exe / wsmprovhost.exe | Windows LotL | WMI-based execution and lateral movement |

### Ransomware Affiliates

Black Basta, Cl0p, REvil, Maze -- FIN7 acts as initial access broker and intrusion operator for these groups post-2020.

---

## C2 Infrastructure Patterns

**Beaconing:** Cobalt Strike HTTPS beacon profile. Periodic outbound connections every 5-10 minutes regardless of destination domain. This interval is consistent even when FIN7 rotates to new infrastructure.

**Infrastructure rotation:** Every 90-180 days. Known domains and IPs degrade rapidly. Build detection around behavioral patterns, not static indicators.

**Known IOCs (treat as pattern indicators -- may be rotated):**
- Domain: `legitglobaldns[.]com`
- Domain: `adobeadobe[.]com`
- IP: `105.213.118.10`
- IP: `178.213.211.58`

**Process injection C2 concealment:** Carbanak injected into explorer.exe, svchost.exe, and lsass.exe. Network connections from these processes are suspicious.

**Registry persistence keys (high confidence):**
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\shell64` (Carbanak)
- `HKLM\...\Run\runonce` (Cobalt Strike)

---

## Detection Opportunities

All detections below are behavior-based, not IOC-dependent. These work regardless of infrastructure rotation.

**1. CVE-2023-27532 Veeam exploitation**
HTTP POST to `/api/v1/credsvc` in Veeam Backup and Replication from non-administrative source IPs. If Veeam is present and unpatched, this is priority one.

**2. WMI cross-segment lateral movement**
Process creation for wmic.exe or wsmprovhost.exe with remote execution parameters and new source-destination pairs crossing network boundaries. Sysmon Event ID 1 for process creation.

**3. Carbanak process injection**
Any non-security process accessing lsass.exe memory. explorer.exe, svchost.exe, or lsass.exe spawning unexpected child processes or initiating outbound network connections.

**4. Registry persistence monitoring**
Monitor for creation or modification of Carbanak and Cobalt Strike Run keys. Windows Event ID 4657 or Sysmon Event ID 13 (registry value set).

**5. Beaconing behavior (behavior-based)**
Endpoints making periodic outbound HTTPS connections every 5-10 minutes regardless of destination. This pattern holds even after infrastructure rotation. Build a frequency-based hunt, not a destination-based block.

**6. LSASS credential dumping**
Mimikatz or ProcDump accessing LSASS. Supplementary: Event ID 4624 Type 2 (interactive logon) for service accounts indicates credential reuse.

**7. LotL C2 tool installation**
NetSupport Manager or AnyDesk installed outside IT change management. Parent process and file path are the signal -- these tools in %TEMP%, %APPDATA%, or non-standard paths are high-confidence indicators.

**8. MSIX/MSI execution from untrusted sources**
MSIX or MSI installer execution where the signing certificate does not match an approved vendor list.

**9. Pre-ransomware VSS deletion**
vssadmin delete shadows, wmic shadowcopy delete, or disabling of Windows Backup service. These are pre-encryption preparation behaviors. Detection here buys time.

**10. Anomalous SWIFT or treasury system access**
Accounts authenticating from multiple geographic locations within a single hour. Unauthorized jumps to SWIFT or treasury hosts via PAM systems.

---

## Threat Hunt Hypotheses

**Hypothesis 1 -- Veeam exploitation (T1190)**
If CVE-2023-27532 is unpatched in the environment, FIN7 may have attempted credential harvesting via the /api/v1/credsvc endpoint. Hunt for HTTP POST requests to this path from non-administrative source IPs in Veeam access logs.

**Hypothesis 2 -- Carbanak HTTPS beaconing (T1071.001)**
If FIN7 has established a Cobalt Strike or Carbanak C2 channel, endpoints will exhibit periodic outbound HTTPS connections every 5-10 minutes to a consistent destination. Hunt for endpoints with high-frequency, low-variance outbound connection intervals regardless of destination domain reputation.

**Hypothesis 3 -- WMI lateral movement across network segments (T1047)**
If FIN7 has obtained initial access and is moving laterally, WMI execution (wmic.exe, wsmprovhost.exe) will appear on hosts that have not previously used WMI for remote execution, crossing into adjacent network segments. Hunt for process creation events where source and destination are in different VLANs.

**Hypothesis 4 -- LotL C2 via NetSupport or AnyDesk (T1219)**
If FIN7 has installed unauthorized remote access tools, they will appear in non-standard file paths or spawned by unusual parent processes. Hunt for NetSupport Manager or AnyDesk binaries in %TEMP%, %APPDATA%, or paths outside standard installation directories.

**Hypothesis 5 -- Pre-ransomware VSS deletion (T1490)**
If FIN7 is preparing for a ransomware deployment, VSS deletion commands will precede the encryption event. Hunt for vssadmin delete shadows or wmic shadowcopy delete process execution. This is a high-confidence pre-encryption signal.

---

## MITRE ATT&CK Coverage Summary

| Tactic | Key Techniques |
|---|---|
| Initial Access | T1566.001 (spearphishing), T1190 (Veeam CVE-2023-27532), T1204.002 (MSIX installers) |
| Execution | T1059.001 (POWERTRASH), T1047 (WMI), T1059.005/007 (VBScript/JS loaders) |
| Persistence | T1547.001 (registry Run keys), T1053.005 (scheduled tasks), T1505.003 (web shells) |
| Credential Access | T1003 (LSASS dumping), T1056.001 (keylogging), T1110.003 (password spray) |
| Defense Evasion | T1055 (process injection), T1027 (obfuscation), T1562.001 (disable defenses) |
| Lateral Movement | T1021.001 (ShellTea RDP), T1047 (WMI), T1550.002 (pass-the-hash) |
| Command and Control | T1071.001 (Cobalt Strike HTTPS), T1219 (NetSupport/AnyDesk LotL) |
| Collection | T1005 (local data), T1056.001 (keylogging), T1114.001 (email collection) |
| Exfiltration | T1041 (over C2 channel) |
| Impact | T1486 (BadRabbit/Black Basta), T1490 (VSS deletion) |

**Total techniques mapped:** 58 across 11 tactics.
**Highest priority for detection:** T1190 (CVE-2023-27532), T1047 (WMI lateral movement), T1055 (process injection), T1219 (LotL C2), T1566.001 (spearphishing).

---

## Intelligence Sources

- MITRE ATT&CK Group G0046 -- FIN7: https://attack.mitre.org/groups/G0046/
- CISA Advisory AA22-277A -- FIN7 Campaigns
- Mandiant (Google Cloud) -- FIN7 Evolution and Tooling
- CrowdStrike -- CARBON SPIDER Intelligence Profile
- NVD -- CVE-2023-27532 (Veeam Backup and Replication credential exposure)
- Secureworks -- GOLD NIAGARA (FIN7) threat profile

---

*Part of the Shinigami Protocol threat actor research series. Produced using the AI-assisted CTI research stack: NotebookLM + Claude.*
