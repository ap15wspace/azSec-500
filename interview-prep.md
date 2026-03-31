# Interview Preparation — Senior Security Engineer: Directory Services & Authentication
> Based on the requirements in `Cisco-ad-sec.md`
>
> Questions are ordered from **junior engineer refresh** → **mid-level** → **senior/lead** → **multi-project management**.
> Each question is followed by a model answer and key talking points.

---

## Table of Contents
1. [Active Directory Fundamentals (Junior Refresh)](#1-active-directory-fundamentals-junior-refresh)
2. [Hybrid Cloud & Entra ID / Azure AD](#2-hybrid-cloud--entra-id--azure-ad)
3. [Security Guardrails & Zero Trust](#3-security-guardrails--zero-trust)
4. [Authentication & Authorization Protocols](#4-authentication--authorization-protocols)
5. [Scripting & Automation](#5-scripting--automation)
6. [SIEM, Monitoring & Incident Response](#6-siem-monitoring--incident-response)
7. [Privileged Access Management (PAM)](#7-privileged-access-management-pam)
8. [Senior / Multi-Project Management Scenarios](#8-senior--multi-project-management-scenarios)
9. [Architecture Diagrams](#9-architecture-diagrams)
10. [Detailed Troubleshooting Reference](#10-detailed-troubleshooting-reference)
11. [Dual-Audience Troubleshooting Narratives — Architect & Engineer Views](#11-dual-audience-troubleshooting-narratives--architect--engineer-views)

---

## 1. Active Directory Fundamentals (Junior Refresh)

### Q1 — What is Active Directory and what are its core components?
**Model Answer:**  
Active Directory (AD) is Microsoft's directory service that stores information about network objects (users, computers, groups, printers) and provides authentication and authorization services.

Key components:
- **Domain** – logical grouping of objects sharing the same AD database.
- **Domain Controller (DC)** – server that hosts the AD database (`NTDS.dit`) and handles auth.
- **Forest / Tree** – a forest is the top-level security boundary; a tree is a hierarchy of domains sharing a contiguous namespace.
- **Organizational Units (OUs)** – containers for grouping objects to apply GPOs or delegate administration.
- **Global Catalog (GC)** – partial, read-only replica of all objects in the forest; used for cross-domain lookups.
- **FSMO Roles** – five Flexible Single Master Operations roles (Schema Master, Domain Naming Master, RID Master, PDC Emulator, Infrastructure Master).

*Key talking point: Be prepared to explain how replication works between DCs (KCC, site links, replication topology).*

---

### Q2 — What is the difference between a Domain, Tree, and Forest in Active Directory?
**Model Answer:**
- **Domain** – the basic administrative unit; objects share a single security boundary and the same AD database partition.
- **Tree** – one or more domains that share a contiguous DNS namespace (e.g., `corp.com` → `us.corp.com`). Parent-child trust is automatic and transitive.
- **Forest** – a collection of one or more trees that share a common schema, configuration partition, and Global Catalog. The forest is the ultimate security boundary.

*Key talking point: Multi-forest environments (the job description) require explicit trust relationships between forests and careful design of UPN suffixes and name resolution.*

---

### Q3 — Explain AD replication and why it matters in a multi-site environment.
**Model Answer:**  
AD uses **multi-master replication** — changes can be made on any DC and are replicated to all others.

- **Intra-site replication** – happens over fast, reliable LAN links using RPC; change notification triggers replication within ~15 seconds.
- **Inter-site replication** – controlled by **Site Links** (schedule, cost, replication interval). Uses either RPC over IP or SMTP.
- **KCC (Knowledge Consistency Checker)** – automatically builds the replication topology.
- **USN (Update Sequence Number)** – each DC tracks changes locally; replication uses USNs to identify what needs to be synchronized.
- **Lingering Objects** – stale objects that can appear if a DC is offline longer than the tombstone lifetime (default 180 days).

*Multi-site relevance: misconfigured site links cause authentication failures, slow logons, and replication lag — critical in large enterprise environments.*

---

### Q4 — What is a Group Policy Object (GPO) and how is it applied?
**Model Answer:**  
A GPO is a collection of settings that control the working environment for user accounts and computer accounts. GPOs are linked to Sites, Domains, or OUs.

Application order (**LSDOU**):
1. Local policy
2. Site-linked GPOs
3. Domain-linked GPOs
4. OU-linked GPOs (deepest OU wins)

Key concepts:
- **Enforcement / Block Inheritance** – `Enforced` GPOs cannot be blocked; `Block Inheritance` prevents GPOs from higher-level containers from applying.
- **Security Filtering** – limit which users/computers a GPO applies to using security groups.
- **WMI Filtering** – target GPOs to specific OS versions or hardware.
- **gpresult /R** and **RSOP** – tools for troubleshooting GPO application.

---

### Q5 — What is LDAP and how does Active Directory use it?
**Model Answer:**  
**LDAP (Lightweight Directory Access Protocol)** is the protocol used to query and modify directory services. AD uses LDAP (port 389) and LDAPS (port 636, TLS-encrypted) to allow clients and applications to search for and authenticate against directory objects.

Key operations: `BIND` (authenticate), `SEARCH` (query), `ADD/MODIFY/DELETE` (manage objects).

*Security note: Legacy LDAP (plain port 389) should be disabled in favor of LDAPS or LDAP channel binding/signing — directly referenced in the job's requirement to disable legacy protocols.*

---

### Q6 — What is DNS and why is it critical for Active Directory?
**Model Answer:**  
AD is entirely dependent on DNS for service location. DCs register **SRV records** (`_ldap._tcp`, `_kerberos._tcp`, etc.) that clients use to find the appropriate DC.

Common DNS issues that break AD:
- Missing or stale SRV records.
- DNS scavenging misconfiguration.
- Split-brain DNS (internal vs. external namespace resolution).
- Clients pointing to wrong DNS servers.

Commands: `nltest /dsgetdc:<domain>`, `nslookup -type=SRV _ldap._tcp.<domain>`, `dcdiag /test:DNS`.

---

## 2. Hybrid Cloud & Entra ID / Azure AD

### Q7 — What is Entra ID (Azure AD) and how does it differ from on-premises Active Directory?
**Model Answer:**

| Feature | On-Prem AD | Entra ID (Azure AD) |
|---|---|---|
| Protocol | Kerberos, NTLM, LDAP | SAML, OIDC, OAuth 2.0 |
| Object model | Forest/Domain/OU | Tenant/flat namespace |
| Group Policy | Yes | No (Intune/MDM instead) |
| Authentication | DC-based | Cloud-based STS |
| Trust model | Kerberos trusts | B2B/B2C federation |
| DNS dependency | Critical | Not required |

*Entra ID is not a domain controller in the cloud — it is an Identity-as-a-Service (IDaaS) platform optimized for modern app authentication.*

---

### Q8 — What is Azure AD Connect / Entra Connect, and what are its sync modes?
**Model Answer:**  
**Entra Connect** (formerly Azure AD Connect) synchronizes on-premises AD objects to Entra ID.

Sync modes:
- **Password Hash Sync (PHS)** – hashes of on-prem password hashes are synced to the cloud; simplest and most resilient option.
- **Pass-Through Authentication (PTA)** – authentication requests are passed back to on-prem DCs; no hash stored in cloud.
- **Federation (AD FS)** – authentication is fully handled on-prem by AD FS; Entra ID trusts the federation service.

Staging mode: allows a second Entra Connect server as a hot standby.

*Security consideration: PHS exposes password hashes to the cloud; PTA requires on-prem agents to be highly available; federation adds complexity but gives maximum control.*

---

### Q9 — What is a multi-tenant Entra ID environment and what are the operational challenges?
**Model Answer:**  
A **multi-tenant** environment means an organization manages multiple Entra ID tenants (e.g., separate tenants per subsidiary, geography, or security boundary).

Challenges:
- **Identity synchronization** – each tenant requires its own Entra Connect instance or cloud-only accounts with cross-tenant sync.
- **Cross-tenant access** – requires B2B collaboration policies or cross-tenant synchronization (new Entra ID feature).
- **Conditional Access** – policies must be consistently applied across all tenants.
- **Licensing** – each tenant needs its own licenses.
- **Monitoring** – sign-in logs and audit logs are per-tenant; aggregating into a centralized SIEM is essential.

---

### Q10 — What is Conditional Access in Entra ID?
**Model Answer:**  
**Conditional Access (CA)** is the policy engine of Entra ID that enforces access decisions based on signals:

- **Signals**: user/group, location (named location/IP range), device compliance, application, risk level (Identity Protection).
- **Controls**: grant access (require MFA, compliant device, hybrid Azure AD join), block access, or require session controls.

Key policies every environment should have:
1. Require MFA for all users.
2. Block legacy authentication protocols.
3. Require compliant/hybrid-joined device for sensitive apps.
4. Block access from high-risk sign-ins.
5. Restrict admin access to privileged workstations (PAW/SAW).

*Named Locations and IP allowlisting are common misconfigurations that bypass security controls — audit them regularly.*

---

## 3. Security Guardrails & Zero Trust

### Q11 — What is LAPS and why is it important?
**Model Answer:**  
**LAPS (Local Administrator Password Solution)** — now **Windows LAPS** (built into Windows natively since 2023) — automatically manages the local administrator account password on every domain-joined machine.

Without LAPS: all machines share the same local admin password → one compromised machine = lateral movement across the entire environment (Pass-the-Hash).

With LAPS:
- Each machine gets a unique, randomly generated password.
- Passwords are stored in AD (`ms-Mcs-AdmPwd` attribute) or Entra ID.
- Expiry is enforced automatically.
- Access to read the password is controlled by AD ACLs.

*Deployment tip: delegate read access only to helpdesk/tier-1 admins for their scope; never grant broad read access.*

---

### Q12 — What legacy protocols should be disabled and why?
**Model Answer:**

| Protocol | Risk | Mitigation |
|---|---|---|
| NTLMv1 | Trivially cracked offline | Disable via GPO (`LmCompatibilityLevel = 5`) |
| LM hashes | Very weak, legacy | Disable via GPO (`NoLMHash`) |
| SMBv1 | EternalBlue (WannaCry/NotPetya) | Disable via PowerShell / GPO |
| WDigest | Stores cleartext passwords in LSASS | Disable via registry GPO |
| RC4 for Kerberos | Weak cipher | Disable, enforce AES-128/256 |
| LDAP without signing/binding | LDAP relay attacks | Enforce LDAP signing and channel binding |
| Basic Auth (Exchange, O365) | Credentials in base64 | Block via Conditional Access |

*Use `Set-ADDefaultDomainPasswordPolicy` and Conditional Access "Block legacy authentication" as two complementary controls.*

---

### Q13 — Explain Zero Trust and how it applies to directory services.
**Model Answer:**  
**Zero Trust** is a security model based on "never trust, always verify." Key principles:

1. **Verify explicitly** – authenticate and authorize every request based on all available data points (identity, location, device health, service/workload, data classification, anomalies).
2. **Use least privilege access** – limit user access with JIT (Just-in-Time) and JEA (Just Enough Administration); use risk-based adaptive policies.
3. **Assume breach** – minimize blast radius, segment access, verify end-to-end encryption, use analytics to detect anomalies.

Applied to directory services:
- **No implicit trust for on-prem** – even internal domain traffic should be authenticated and encrypted.
- **Privileged Identity Management (PIM)** – admins activate roles JIT rather than having standing privilege.
- **Conditional Access + Identity Protection** – continuous evaluation of sign-in risk.
- **Tiered administration model (PAW)** – admin accounts never used on regular workstations.

---

### Q14 — What is the Active Directory Tiered Administration Model?
**Model Answer:**

| Tier | Scope | Examples |
|---|---|---|
| Tier 0 | AD infrastructure itself | Domain Admins, Schema Admins, DC admins, AD Connect |
| Tier 1 | Servers & applications | Server admins, DBA, application admins |
| Tier 2 | Workstations & end users | Helpdesk, standard user admins |

Rules:
- Tier 0 admins **only** log into Tier 0 assets (PAWs / Privileged Workstations).
- No account should span tiers — a Domain Admin account is **never** used to manage workstations.
- Authentication silos and authentication policies enforce this in AD.

*Attack path context: Most ransomware and APT attacks escalate from Tier 2 → Tier 1 → Tier 0 by reusing credentials. The tiered model breaks this path.*

---

### Q15 — What is "defense in depth" in the context of identity security?
**Model Answer:**  
Defense in depth layers multiple security controls so that the failure of one layer does not result in a full compromise.

Identity-focused layers:
1. **MFA / passwordless** – compromising a password alone is not enough.
2. **Conditional Access** – even with valid credentials, access is blocked from non-compliant devices or risky locations.
3. **LAPS** – lateral movement via local admin credential reuse is blocked.
4. **PIM / JIT** – standing privileged access is minimized.
5. **SIEM alerting** – suspicious activity is detected even if controls are bypassed.
6. **Tiered admin model** – blast radius of any single compromise is bounded.
7. **Regular access reviews** – stale/over-provisioned accounts are removed.

---

## 4. Authentication & Authorization Protocols

### Q16 — How does Kerberos authentication work?
**Model Answer:**  
Kerberos is the default authentication protocol in Active Directory. It uses a trusted third party (the KDC — Key Distribution Center, hosted on DCs).

**Steps:**
1. **AS-REQ / AS-REP (Pre-authentication)** – client sends a timestamp encrypted with its password hash to the KDC. KDC returns a **TGT (Ticket Granting Ticket)** encrypted with the `krbtgt` account key.
2. **TGS-REQ / TGS-REP** – client presents the TGT to request a **service ticket (TGS)** for a specific resource. KDC returns the service ticket encrypted with the target service's key.
3. **AP-REQ** – client presents the service ticket directly to the target service. No password is ever sent across the network.

*Security relevance: `krbtgt` account compromise = Golden Ticket attack. Service account with SPN = Kerberoasting. Pre-auth disabled = AS-REP Roasting.*

---

### Q17 — When is NTLM used and what are its security risks?
**Model Answer:**  
NTLM (NT LAN Manager) is used as a fallback when Kerberos cannot be used:
- Authentication to IP addresses (not hostnames).
- When no SPN is registered.
- Non-domain joined systems.
- Some legacy applications.

Security risks:
- **Pass-the-Hash (PtH)** – NTLM uses only the password hash; if captured, the hash can be used directly to authenticate.
- **NTLM Relay** – attacker relays NTLM challenge/response to another service.
- **NTLMv1 is trivially crackable** – always enforce NTLMv2 minimum.

Mitigation: Enable SMB signing, LDAP signing/channel binding; use Extended Protection for Authentication (EPA); restrict NTLM with `Network Security: Restrict NTLM` GPO settings.

---

### Q18 — What is the difference between SAML, OIDC, and OAuth 2.0?
**Model Answer:**

| | SAML 2.0 | OAuth 2.0 | OIDC |
|---|---|---|---|
| Purpose | Authentication + Authorization | Authorization (delegated access) | Authentication layer on top of OAuth 2.0 |
| Token format | XML assertions | Opaque/JWT access tokens | ID Token (JWT) |
| Primary use | Enterprise SSO, federated identity | API access delegation | Modern SSO for web/mobile apps |
| Initiated by | SP or IdP | Client application | Client application |
| Common IdPs | AD FS, Ping, Okta | Entra ID, Okta, Google | Entra ID, Okta, Google |

*AD FS is a SAML 2.0 + WS-Federation IdP; Entra ID supports SAML, OIDC, and OAuth natively.*

---

### Q19 — What is FIDO2 / WebAuthn and what problem does it solve?
**Model Answer:**  
**FIDO2** is an open authentication standard (from the FIDO Alliance) consisting of:
- **WebAuthn** – W3C web API that enables browsers/apps to use authenticators.
- **CTAP2** – protocol for external authenticators (YubiKey, Windows Hello, passkeys) to communicate with a platform.

FIDO2 solves the **phishing problem**: credentials are bound to a specific origin (domain). A phishing site at `evil.com` cannot capture or replay a FIDO2 credential registered for `corp.com`.

Authentication flow:
1. Server sends a challenge.
2. Authenticator signs the challenge with a private key (stored securely in TPM or security key).
3. Server verifies the signature with the public key on file.

*No password is ever sent or stored on the server — completely passwordless.*

*Entra ID supports FIDO2 security keys as a passwordless authentication method.*

---

## 5. Scripting & Automation

### Q20 — Write a PowerShell script to find all disabled user accounts in Active Directory.
**Model Answer:**
```powershell
# Get all disabled user accounts in Active Directory
Get-ADUser -Filter { Enabled -eq $false } -Properties DisplayName, SamAccountName, DistinguishedName, LastLogonDate |
    Select-Object DisplayName, SamAccountName, DistinguishedName, LastLogonDate |
    Sort-Object DisplayName
```

*Senior extension: pipe to `Export-Csv` for reporting, or add `-SearchBase` to scope to a specific OU.*

---

### Q21 — Write a PowerShell script to enforce LAPS deployment status across all computers in an OU.
**Model Answer:**
```powershell
$OU = "OU=Workstations,DC=corp,DC=com"

$computers = Get-ADComputer -SearchBase $OU -Filter * -Properties "ms-Mcs-AdmPwdExpirationTime", "ms-Mcs-AdmPwd"

$results = foreach ($computer in $computers) {
    [PSCustomObject]@{
        Name           = $computer.Name
        LAPSEnabled    = $null -ne $computer."ms-Mcs-AdmPwd"
        PasswordExpiry = $computer."ms-Mcs-AdmPwdExpirationTime"
    }
}

$results | Where-Object { -not $_.LAPSEnabled } |
    Format-Table -AutoSize
```

---

### Q22 — How would you use Python to query Entra ID / Azure AD for all guest users with the Microsoft Graph API?
**Model Answer:**
```python
import requests

# Obtain an access token using client credentials (app registration)
def get_token(tenant_id, client_id, client_secret):
    url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    data = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": "https://graph.microsoft.com/.default",
    }
    response = requests.post(url, data=data)
    response.raise_for_status()
    return response.json()["access_token"]

def get_guest_users(token):
    url = "https://graph.microsoft.com/v1.0/users"
    headers = {"Authorization": f"Bearer {token}"}
    params = {"$filter": "userType eq 'Guest'", "$select": "displayName,mail,createdDateTime,accountEnabled"}
    users = []
    while url:
        resp = requests.get(url, headers=headers, params=params)
        resp.raise_for_status()
        data = resp.json()
        users.extend(data.get("value", []))
        url = data.get("@odata.nextLink")  # handle pagination
        params = None  # nextLink already includes params
    return users
```

*Key point: always handle `@odata.nextLink` pagination; real tenants can have thousands of users.*

---

### Q23 — How do you automate detection of stale accounts (no logon in 90 days)?
**Model Answer:**
```powershell
$cutoff = (Get-Date).AddDays(-90)

$staleUsers = Get-ADUser -Filter { Enabled -eq $true -and LastLogonDate -lt $cutoff } `
    -Properties LastLogonDate, Manager, Department |
    Select-Object SamAccountName, DisplayName, LastLogonDate, Manager, Department

# Export for review / remediation workflow
$staleUsers | Export-Csv -Path "C:\Reports\StaleAccounts_$(Get-Date -Format yyyyMMdd).csv" -NoTypeInformation

Write-Host "$($staleUsers.Count) stale accounts found."
```

*Note: `LastLogonDate` is replicated; `LastLogon` is not — use `LastLogonDate` in multi-DC environments.*

---

## 6. SIEM, Monitoring & Incident Response

### Q24 — What Active Directory events should you monitor in a SIEM (e.g., Splunk)?
**Model Answer:**

| Event ID | Description | Why Monitor |
|---|---|---|
| 4625 | Failed logon | Brute force, password spray |
| 4648 | Logon with explicit credentials | Lateral movement, pass-the-hash |
| 4672 | Special privileges assigned | Privileged account usage |
| 4720 | User account created | Unauthorized account creation |
| 4728/4756 | Member added to security/universal group | Privilege escalation |
| 4768/4769 | Kerberos TGT/TGS requested | Kerberoasting, Golden Ticket |
| 4771 | Kerberos pre-auth failed | Password spray against Kerberos |
| 4776 | NTLM credential validation | NTLM usage monitoring |
| 7045 | New service installed | Malware persistence |
| 4698 | Scheduled task created | Malware persistence |

*Splunk SPL example: alert on 4625 for >10 failures in 5 minutes for the same account from different source IPs = password spray.*

---

### Q25 — Walk me through your incident response process for a suspected AD compromise.
**Model Answer:**  
**Phase 1 — Detection & Triage**
- Alert fires: unusual DC login, Golden/Silver Ticket indicators, anomalous Kerberos requests.
- Isolate indicators: which accounts, which DCs, time window.

**Phase 2 — Containment**
- Reset `krbtgt` password **twice** (invalidates all existing TGTs) with a 10-hour gap (Kerberos ticket lifetime).
- Disable/reset compromised accounts.
- Block lateral movement: isolate affected hosts, revoke sessions in Entra ID.

**Phase 3 — Eradication**
- Identify persistence: scheduled tasks, new admin accounts, modified GPOs, AD replication changes.
- Review DCSync permissions (members of Domain Admins, Replicating Directory Changes).

**Phase 4 — Recovery**
- Restore from known-good backup if AD database is corrupted.
- Verify all DCs are healthy: `dcdiag`, `repadmin /replsummary`.

**Phase 5 — Post-Incident**
- Document timeline, IOCs, root cause.
- Implement missing controls (LAPS, tiered model, logging gaps).
- Present findings to leadership.

---

### Q26 — What is DCSync and why is it dangerous?
**Model Answer:**  
**DCSync** is an attack technique where an adversary with replication rights (`Replicating Directory Changes All`) calls the `MS-DRSR` protocol to request password hashes for any account — including `krbtgt` and Domain Admin accounts — without ever touching a DC directly.

How attackers get there:
- Compromise a Domain Admin account.
- Add `Replicating Directory Changes All` permission to a lower-privileged account.

Detection:
- Monitor for `4662` events (An operation was performed on an object) with the GUID for `Replicating Directory Changes All` from non-DC sources.
- Splunk / Microsoft Sentinel have built-in rules for this.

Mitigation:
- Audit `Replicating Directory Changes` permissions on the domain root object regularly.
- Use Defender for Identity (formerly Azure ATP) — detects DCSync in real time.

---

## 7. Privileged Access Management (PAM)

### Q27 — What is Privileged Identity Management (PIM) in Entra ID?
**Model Answer:**  
**PIM** allows organizations to manage, control, and monitor access to privileged roles in Entra ID and Azure resources.

Key features:
- **Just-in-Time (JIT) access** – admins request activation of a role for a limited time window (e.g., 8 hours) with justification.
- **Approval workflow** – high-risk roles (Global Admin) require manager approval.
- **MFA on activation** – always required.
- **Access reviews** – periodic reviews to confirm role assignments are still needed.
- **Audit logs** – full history of who activated which role, when, and why.

*Without PIM: standing Global Admin accounts are a high-value target. With PIM: an attacker who compromises an account gets no standing privilege.*

---

### Q28 — What is CyberArk and how does it fit into a PAM strategy?
**Model Answer:**  
**CyberArk** is a Privileged Access Management (PAM) platform that vaults, rotates, and monitors privileged credentials (passwords, SSH keys, API tokens).

Core components:
- **Digital Vault** – encrypted repository for credentials.
- **Central Policy Manager (CPM)** – automatically rotates passwords on schedule or after use.
- **Privileged Session Manager (PSM)** – proxy all privileged sessions; records sessions for audit.
- **Privileged Threat Analytics (PTA)** – detects anomalous privileged activity.

Integration with AD:
- Service account passwords in AD can be managed and rotated by CyberArk.
- PSM can use RDP/SSH through the vault to servers without exposing the actual password to the admin.

*The job mentions "CyberArk Guardian" certification — be prepared to discuss session recording, credential checkout workflows, and CyberArk's role in zero-standing-privilege strategies.*

---

## 8. Senior / Multi-Project Management Scenarios

### Q29 — How would you design the rollout of LAPS across 10,000 endpoints in a change-managed environment?
**Model Answer:**  
This is a phased, risk-managed rollout:

**Phase 1 — Planning (Weeks 1–2)**
- Identify scope: all Windows endpoints, server exclusions (already have CyberArk/PIM).
- Assess: which OUs, how many machines, who currently has local admin access.
- Schema extension for legacy LAPS (or Windows LAPS — no schema extension needed).
- Define ACLs: who can read LAPS passwords (tiered by OU/scope).

**Phase 2 — Pilot (Weeks 3–4)**
- Deploy to a representative pilot OU (500 machines, mixed OS/app mix).
- Validate: password rotation works, helpdesk can retrieve passwords, no application breaks.
- Update change request and get CAB approval.

**Phase 3 — Phased Rollout (Weeks 5–10)**
- Roll out OU by OU, 1,000–2,000 machines per week.
- Monitor: SIEM alerts for LAPS-related events, helpdesk ticket volume.
- Pause if failure rate exceeds threshold.

**Phase 4 — Completion & Audit (Week 11)**
- Report on coverage: `Get-ADComputer -Filter * -Properties "ms-Mcs-AdmPwd"` — any gaps?
- Update asset inventory and runbooks.

*Key point: communicate to all IT teams beforehand that shared local admin passwords will stop working — helpdesk needs a process to retrieve LAPS passwords.*

---

### Q30 — How do you manage and prioritize security projects across multiple concurrent workstreams?
**Model Answer:**  
**Framework: Risk-based prioritization**

1. **Inventory and risk score** each project:
   - CVSS/risk severity × likelihood × business impact.
   - Compliance deadlines (SOX, PCI, SOC2) get hard deadlines.

2. **Project portfolio visibility** — use a living roadmap (Jira, Azure DevOps, or similar):
   - Each project has an owner, milestone dates, dependencies, and status.
   - Weekly status updates to leadership (RAG status: Red/Amber/Green).

3. **Resource management**:
   - Identify shared resources (e.g., the one AD SME on the team).
   - Buffer capacity (20%) for operational/incident work.
   - Escalate blockers immediately — don't sit on them.

4. **Stakeholder communication**:
   - Tailor the message: technical teams get technical details; executive sponsors get risk reduction metrics.
   - Change Advisory Board (CAB) submissions submitted on schedule; no surprises.

5. **Post-project retrospectives**:
   - What went well, what didn't, what to improve for the next project.
   - Feed lessons learned back into runbooks and standard operating procedures.

---

### Q31 — Describe a time you had to lead a major AD migration or consolidation (multi-forest to single forest, or on-prem to hybrid).
**Model Answer (STAR format):**

**Situation:** Inherited a 3-forest AD environment after a merger — 15,000 users, 3 separate IT teams, no central SIEM.

**Task:** Consolidate to a 2-forest model (corp + DMZ) and onboard all identities to a single Entra ID tenant within 12 months.

**Action:**
- Discovery phase: used `BloodHound` and `ADRecon` to map trust relationships, attack paths, stale accounts.
- Architecture: designed a resource forest with accounts forest model to minimize blast radius.
- Migration tooling: used ADMT (Active Directory Migration Tool) for user/group migration with SID history.
- Entra Connect: deployed for each source domain with filtering to avoid syncing sensitive service accounts.
- Phased cutover: migrated by department, communicated timelines, provided helpdesk runbooks.
- Decommissioned legacy forests after 90-day coexistence period.

**Result:** Reduced attack surface by eliminating 2 legacy forests, reduced operational overhead by 40%, passed SOC2 audit with no AD-related findings.

*Tip: Even if you don't have this exact experience, walk through what you WOULD do step-by-step — it demonstrates architectural thinking.*

---

### Q32 — How do you enforce Zero Trust principles for a team of 50 administrators managing 5 separate environments?
**Model Answer:**

1. **Separate admin accounts** – no shared admin accounts; every admin has a dedicated `adm-username` account used only for admin tasks.
2. **PAWs (Privileged Access Workstations)** – admins only perform admin tasks from hardened, dedicated workstations, never their daily-use laptops.
3. **PIM for all privileged roles** – no standing admin roles; all activations are JIT, logged, and time-limited.
4. **Conditional Access** – admin roles require MFA + compliant PAW + named location (VPN/corporate network). Block if any signal is missing.
5. **Session recording** – CyberArk PSM or Azure Bastion for all privileged sessions; recordings archived for 1 year.
6. **Regular access reviews** – quarterly PIM access reviews; automated deprovisioning for leavers within 24 hours.
7. **SIEM alerting** – alert on any admin-role activation outside business hours or from unexpected locations.
8. **Separation of duties** – no single admin can approve their own access or modify audit logs.

---

### Q33 — What metrics would you report to leadership to demonstrate the security posture of directory services?
**Model Answer:**

| Metric | Target | Why It Matters |
|---|---|---|
| % of privileged accounts with PIM (no standing privilege) | >95% | Measures JIT adoption |
| % of endpoints with LAPS deployed | 100% | Lateral movement resilience |
| Legacy authentication sign-ins (Entra ID) | 0 | Protocol hardening |
| Mean time to disable departed employee accounts | <4 hours | Orphaned account risk |
| Kerberoastable accounts (weak cipher SPNs) | 0 | Kerberoasting exposure |
| Stale computer accounts (>90 days, not disabled) | <1% | Attack surface control |
| AD replication failures | 0 | Infrastructure health |
| Privileged session recording coverage | 100% | Audit readiness |
| MFA adoption (all users) | 100% | Phishing resilience |
| Time to detect / Time to respond (MTTD/MTTR) | Track monthly trend | SOC effectiveness |

*Present as a dashboard trend (monthly), not just a point-in-time snapshot — leadership wants to see direction of travel.*

---

## Quick-Reference Cheat Sheet

### Key Tools
| Tool | Purpose |
|---|---|
| `dcdiag` | DC health and diagnostics |
| `repadmin /replsummary` | Replication status |
| `nltest /dsgetdc` | DC discovery |
| `gpresult /R` | GPO RSoP |
| `klist` | View/purge Kerberos tickets |
| `Get-ADUser / Get-ADComputer` | AD object queries |
| `Connect-MgGraph` | Microsoft Graph PowerShell |
| `az ad user list` | Azure CLI for Entra ID |
| `BloodHound` | AD attack path analysis |
| `Microsoft Entra ID Protection` | Risk-based sign-in policies |
| `Defender for Identity` | On-prem AD threat detection |

### Key Acronyms
| Acronym | Meaning |
|---|---|
| FSMO | Flexible Single Master Operations |
| KDC | Key Distribution Center (Kerberos) |
| TGT | Ticket Granting Ticket |
| PAW | Privileged Access Workstation |
| PIM | Privileged Identity Management |
| JIT | Just-in-Time (access) |
| JEA | Just Enough Administration |
| PAM | Privileged Access Management |
| IGA | Identity Governance & Administration |
| LAPS | Local Administrator Password Solution |
| PHS | Password Hash Sync |
| PTA | Pass-Through Authentication |
| CA | Conditional Access |
| DCSync | AD replication abuse attack technique |

---

*Good luck with your interview! Focus on demonstrating both deep technical depth AND the ability to communicate risk and strategy to non-technical stakeholders — that is what separates senior engineers from staff/principal-level candidates.*

---

## 9. Architecture Diagrams

### 9.1 Multi-Site Active Directory

The diagram below shows a typical enterprise multi-site, multi-domain Active Directory deployment spanning two geographic regions, connected by WAN site links, with each site containing dedicated Domain Controllers.

```
╔══════════════════════════════════════════════════════════════════════════════════════╗
║                          FOREST: corp.com  (Schema / Config Partition)              ║
║                                                                                      ║
║  ┌─────────────────────────────────┐         ┌──────────────────────────────────┐   ║
║  │       DOMAIN: corp.com          │         │      DOMAIN: emea.corp.com        │   ║
║  │  (Forest Root / US HQ Domain)  │◄───────►│      (Child Domain / Europe)     │   ║
║  └─────────────────────────────────┘  Parent │  └─────────────────────────────┘  │   ║
║            │                          -Child │                                    │   ║
║            │                          Trust  │                                    │   ║
║  ╔═════════╧══════════════╗                  ╔═════════════════════════╗          ║
║  ║    SITE: US-HQ          ║                  ║   SITE: EMEA-London      ║          ║
║  ║  (Subnet 10.1.0.0/16)  ║                  ║  (Subnet 10.20.0.0/16)  ║          ║
║  ║                         ║                  ║                          ║          ║
║  ║  ┌─────────────────┐   ║                  ║  ┌──────────────────┐   ║          ║
║  ║  │  DC1-US-HQ      │   ║                  ║  │  DC1-EMEA-LON    │   ║          ║
║  ║  │  PDC Emulator   │   ║                  ║  │  GC / RODC       │   ║          ║
║  ║  │  RID Master     │   ║                  ║  └──────────────────┘   ║          ║
║  ║  │  GC Server      │   ║   Site Link:     ║                          ║          ║
║  ║  └────────┬────────┘   ║   WAN (MPLS)     ║  ┌──────────────────┐   ║          ║
║  ║           │            ║◄────────────────►║  │  DC2-EMEA-LON    │   ║          ║
║  ║  ┌────────┴────────┐   ║  Cost: 100       ║  │  GC Server       │   ║          ║
║  ║  │  DC2-US-HQ      │   ║  Interval: 15min ║  └──────────────────┘   ║          ║
║  ║  │  GC Server      │   ║                  ╚═════════════════════════╝          ║
║  ║  └─────────────────┘   ║                                                        ║
║  ╚════════════════════════╝                  ╔═════════════════════════╗          ║
║                                              ║   SITE: APAC-Singapore   ║          ║
║  ╔═════════════════════════╗                 ║  (Subnet 10.30.0.0/16)  ║          ║
║  ║    SITE: US-DR           ║                 ║                          ║          ║
║  ║  (Subnet 10.2.0.0/16)  ║                 ║  ┌──────────────────┐   ║          ║
║  ║                          ║   Site Link:   ║  │  DC1-APAC-SIN    │   ║          ║
║  ║  ┌──────────────────┐   ║   WAN           ║  │  GC / RODC       │   ║          ║
║  ║  │  DC1-US-DR       │   ║◄──────────────►║  └──────────────────┘   ║          ║
║  ║  │  GC Server       │   ║  Cost: 200      ╚═════════════════════════╝          ║
║  ║  │  (DR / Standby)  │   ║                                                        ║
║  ║  └──────────────────┘   ║                                                        ║
║  ╚════════════════════════╝                                                         ║
║                                                                                      ║
║  FSMO Role Placement (corp.com):                                                     ║
║  ┌───────────────────────────────────────────────────────────────────────────────┐  ║
║  │  Schema Master         → DC1-US-HQ (forest-wide, one per forest)             │  ║
║  │  Domain Naming Master  → DC1-US-HQ (forest-wide, one per forest)             │  ║
║  │  PDC Emulator          → DC1-US-HQ (per domain — time sync, auth fallback)   │  ║
║  │  RID Master            → DC1-US-HQ (per domain — allocates RID pools)        │  ║
║  │  Infrastructure Master → DC2-US-HQ (per domain — NOT on GC if multi-domain)  │  ║
║  └───────────────────────────────────────────────────────────────────────────────┘  ║
╚══════════════════════════════════════════════════════════════════════════════════════╝

Legend:
  ◄───────► = Two-way transitive trust (automatic parent-child)
  ╔═══╗     = AD Site boundary
  GC       = Global Catalog server
  RODC     = Read-Only Domain Controller (branch offices / low-security locations)
```

**Key Design Decisions:**
- Every site with >200 users should have a local DC to avoid WAN authentication latency.
- Branch offices with limited physical security → deploy RODCs (Read-Only DCs); credentials not stored locally.
- Site Links should reflect actual WAN topology: `Cost` (lower = preferred path) and `Replication Interval` (default 180 min inter-site).
- Infrastructure Master must **not** reside on a Global Catalog server in multi-domain forests.
- Place PDC Emulator in the site with the best WAN connectivity — it receives authentication failures first and is the primary time sync source.

---

### 9.2 Azure AD Connect (Entra Connect) — Hybrid Identity Architecture

The diagram below shows a hybrid identity environment with Entra Connect synchronizing on-premises AD to Entra ID (Azure AD), including Password Hash Sync, Pass-Through Authentication agents, and federation options.

```
╔══════════════════════════════════════════════════════════════════════════════════════════╗
║                          ON-PREMISES ENVIRONMENT                                         ║
║                                                                                          ║
║  ┌──────────────────────┐     LDAP/     ┌──────────────────────────────────────────┐   ║
║  │  Active Directory    │◄────Kerberos──│         Entra Connect Server             │   ║
║  │  corp.com            │               │  (Windows Server — dedicated, non-DC)    │   ║
║  │                      │               │                                            │   ║
║  │  ┌────────────────┐  │               │  ┌───────────────────────────────────┐   │   ║
║  │  │ DC1 / DC2      │  │               │  │  Sync Engine                      │   │   ║
║  │  │ (LDAP source)  │  │               │  │  ┌──────────┐  ┌──────────────┐  │   │   ║
║  │  └────────────────┘  │               │  │  │ Connector│  │ Metaverse    │  │   │   ║
║  │                      │               │  │  │ (AD DS)  │─►│ (staging DB) │  │   │   ║
║  │  Objects synced:     │               │  │  └──────────┘  └──────┬───────┘  │   │   ║
║  │  - Users             │               │  │                        │           │   │   ║
║  │  - Groups            │               │  │  ┌─────────────────────▼───────┐  │   │   ║
║  │  - Contacts          │               │  │  │ Connector (Azure AD)         │  │   │   ║
║  │  - Devices           │               │  │  └─────────────────────────────┘  │   │   ║
║  └──────────────────────┘               │  └───────────────────────────────────┘   │   ║
║                                          │                                            │   ║
║  ┌──────────────────────┐               │  Sync Mode (choose one):                  │   ║
║  │  Staging Entra       │               │  ┌─────────────────────────────────────┐  │   ║
║  │  Connect Server      │               │  │ ● PHS  — password hashes synced     │  │   ║
║  │  (Hot Standby)       │               │  │ ○ PTA  — auth passes to on-prem     │  │   ║
║  │  Staging Mode = ON   │               │  │ ○ Federation (AD FS)                │  │   ║
║  └──────────────────────┘               │  └─────────────────────────────────────┘  │   ║
║                                          └─────────────────────┬────────────────────┘   ║
║  ┌──────────────────────┐                                       │                        ║
║  │  AD FS Farm          │                 HTTPS/443             │  HTTPS                 ║
║  │  (only if Federation)│◄──────────────────────────────────────┤                        ║
║  │  sts.corp.com        │                                        │                        ║
║  └──────────────────────┘                                        │                        ║
║                                                                   │                        ║
║  ┌────────────────────────────────────┐                          │                        ║
║  │  PTA Agents (Pass-Through Auth)    │◄─────────────────────────┘                        ║
║  │  corp-pta-agent01 / 02             │  (only if PTA mode)                               ║
║  │  Installed on member servers       │                                                    ║
║  └────────────────────────────────────┘                                                   ║
╚══════════════════════════════════════════════════════════════════════════════════════════╝
                          │
                          │  Encrypted HTTPS sync tunnel
                          │  (port 443 outbound only — no inbound firewall rules needed)
                          ▼
╔══════════════════════════════════════════════════════════════════════════════════════════╗
║                          MICROSOFT CLOUD (Entra ID Tenant)                               ║
║                                                                                          ║
║  ┌──────────────────────────────────────────────────────────────────────────────────┐   ║
║  │                         Entra ID (Azure AD) Tenant                               │   ║
║  │                                                                                    │   ║
║  │  Synchronized objects:       Sign-in policies:                                    │   ║
║  │  ┌────────────────────┐      ┌───────────────────────────────────┐               │   ║
║  │  │ Users (cloud copy) │      │ Conditional Access Policies        │               │   ║
║  │  │ Groups             │      │  - Require MFA for all users       │               │   ║
║  │  │ Contacts           │      │  - Block legacy auth               │               │   ║
║  │  │ Devices (hybrid    │      │  - Compliant device required       │               │   ║
║  │  │   joined)          │      └───────────────────────────────────┘               │   ║
║  │  └────────────────────┘                                                            │   ║
║  │                                                                                    │   ║
║  │  Auth flow per sync mode:                                                          │   ║
║  │  ┌─────────────────────────────────────────────────────────────────────────────┐  │   ║
║  │  │  PHS:   User → Entra ID → validates against synced hash  → ✓ / ✗           │  │   ║
║  │  │  PTA:   User → Entra ID → PTA agent → on-prem DC validates → ✓ / ✗         │  │   ║
║  │  │  ADFS:  User → Entra ID → redirects to AD FS → SAML token issued → ✓ / ✗  │  │   ║
║  │  └─────────────────────────────────────────────────────────────────────────────┘  │   ║
║  │                                                                                    │   ║
║  │  Connected apps:   Microsoft 365 │ Azure Resources │ SaaS apps (SAML/OIDC)       │   ║
║  └──────────────────────────────────────────────────────────────────────────────────┘   ║
╚══════════════════════════════════════════════════════════════════════════════════════════╝

Sync Schedule: Default delta sync every 30 minutes (configurable)
               Full sync: on-demand or after schema changes
```

**Key Ports & Network Requirements:**

| Direction | Source | Destination | Port | Purpose |
|---|---|---|---|---|
| Outbound | Entra Connect | `*.msappproxy.net` | TCP 443 | Sync to Entra ID |
| Outbound | Entra Connect | AD DS DCs | TCP/UDP 389, 636, 3268 | LDAP / LDAPS / GC |
| Outbound | Entra Connect | AD DS DCs | TCP/UDP 88 | Kerberos |
| Outbound | PTA Agent | `*.msappproxy.net` | TCP 443 | Auth relay |
| Inbound  | None required | — | — | No inbound firewall rules needed |

**Entra Connect Filtering Options:**
- **Domain/OU-based** – sync only specific OUs (exclude service accounts OU, admin accounts OU).
- **Attribute-based** – sync only users where `extensionAttribute1 = "Sync"`.
- **Group-based** – pilot mode: sync only members of a specific group (max 50k members).

---

### 9.3 Kerberos Authentication Flow Diagram

```
  CLIENT                   KDC (DC)               TARGET SERVICE
  (workstation)            AS + TGS               (file server, app)
      │                        │                         │
      │──── 1. AS-REQ ────────►│                         │
      │  (username +           │                         │
      │   encrypted timestamp) │                         │
      │                        │                         │
      │◄─── 2. AS-REP ─────────│                         │
      │  (TGT encrypted with   │                         │
      │   krbtgt key +         │                         │
      │   session key)         │                         │
      │                        │                         │
      │──── 3. TGS-REQ ───────►│                         │
      │  (TGT + service SPN)   │                         │
      │                        │                         │
      │◄─── 4. TGS-REP ────────│                         │
      │  (Service Ticket       │                         │
      │   encrypted with       │                         │
      │   target service key)  │                         │
      │                        │                         │
      │──── 5. AP-REQ ─────────────────────────────────►│
      │  (Service Ticket)      │                         │
      │                        │                         │
      │◄─── 6. AP-REP ─────────────────────────────────►│
      │  (mutual auth confirm) │              (validates ticket,
      │                        │               grants access)
      │                        │                         │

Attack surface mapping:
  Step 1-2 → AS-REP Roasting  (pre-auth disabled accounts)
  Step 3-4 → Kerberoasting    (service account with SPN, request TGS offline crack)
  TGT forgery → Golden Ticket  (requires krbtgt hash)
  TGS forgery → Silver Ticket  (requires service account hash)
```

---

## 10. Detailed Troubleshooting Reference

### 10.1 AD Replication Troubleshooting (Step-by-Step)

**Symptom:** Users in Site B cannot authenticate, or objects created in Site A are not visible in Site B.

#### Step 1 — Check replication summary across all DCs
```
repadmin /replsummary
```
Look for: `Fails`, `Delta` (time since last successful sync). Any non-zero `Fails` or `Delta > 1 hour` is a problem.

#### Step 2 — Show replication status per DC
```
repadmin /showrepl
repadmin /showrepl DC2-US-HQ /errorsonly
```
Output shows: each replication partner, last attempt, last success, consecutive failures, error code.

#### Step 3 — Force replication and check
```
# Force sync from a specific partner
repadmin /sync dc=corp,dc=com DC2-US-HQ <source-DC-GUID>

# Force sync all partitions from all partners
repadmin /syncall /AdeP
```
Flags: `/A` = all partitions, `/d` = identify by DN, `/e` = enterprise (cross-site), `/P` = push mode.

#### Step 4 — Identify the error code

| Error Code | Meaning | Fix |
|---|---|---|
| 1256 | Remote procedure call failed | Check network/firewall (RPC ports TCP 135, 49152–65535) |
| 1722 | RPC server unavailable | DNS resolution failure or DC offline |
| 1753 | No more endpoints | RPC endpoint mapper issue; restart `NTDS` service |
| 8453 | Replication access denied | Check replication permissions on domain NC head |
| 8606 | Insufficient attributes | Lingering object; run `repadmin /removelingeringobjects` |
| -2146893022 | Target principal name incorrect | SPN mismatch; run `netdom resetpwd` on affected DC |
| 1396 | Logon failure target account name incorrect | `krbtgt` account or SPN issue |

#### Step 5 — Check DC health
```
dcdiag /test:replications /v
dcdiag /test:connectivity /v
dcdiag /test:DNS /v
dcdiag /test:KccEvent /v
dcdiag /test:NCSecDesc /v   # replication permissions check
```

#### Step 6 — Check Event Viewer on both DCs
- `Directory Service` log → Event IDs **1864** (replication not occurred in N days), **1311** (KCC topology error), **1388** (lingering object inbound) / **1862** (replication partner unresponsive) (lingering objects).
- `System` log → Event ID **5774** (DC cannot register DNS SRV records).

#### Step 7 — Fix lingering objects (if detected)
```
# Find lingering objects
repadmin /removelingeringobjects <DestDC> <SourceDC-GUID> <NC> /advisory_mode

# Remove them (after review)
repadmin /removelingeringobjects <DestDC> <SourceDC-GUID> dc=corp,dc=com
```

---

### 10.2 Kerberos Authentication Troubleshooting (Step-by-Step)

**Symptoms:** "The security database on the server does not have a computer account for this workstation," KDC errors, Event ID 4771.

#### Step 1 — Check clock skew (most common cause)
Kerberos tolerates only ±5 minutes of clock difference.
```powershell
# Check DC time
w32tm /query /status

# Force re-sync
w32tm /resync /force

# Check all DCs in the domain
Get-ADDomainController -Filter * | ForEach-Object {
    $name = $_.Name
    $time = Invoke-Command -ComputerName $name { (Get-Date).ToString("HH:mm:ss") }
    [PSCustomObject]@{ DC = $name; Time = $time }
}
```

#### Step 2 — Inspect current Kerberos tickets
```
# List all cached tickets
klist

# Purge ticket cache (force re-authentication)
klist purge

# Check tickets for a specific service
klist tickets
```

#### Step 3 — Diagnose with Event IDs

| Event ID | Location | Meaning | Action |
|---|---|---|---|
| 4771 | DC Security log | Kerberos pre-auth failed | Wrong password, account locked, or disabled |
| 4768 | DC Security log | TGT requested (success/fail) | Baseline normal; alert on failures |
| 4769 | DC Security log | Service ticket requested | Monitor for RC4 encryption requests (Kerberoasting) |
| 4772 | DC Security log | Kerberos auth ticket request failed | Account expired / smart card issue |
| 14 | System log | KDC cannot find name | SPN not registered |

#### Step 4 — Check SPNs
```
# Find all SPNs for a service account
setspn -L serviceaccount

# Find duplicate SPNs (common cause of Kerberos failures)
setspn -X -F

# Register a missing SPN
setspn -A HTTP/webserver.corp.com corp\websvcaccount
```

#### Step 5 — Test Kerberos end-to-end
```powershell
# Test authentication to a service
Test-ComputerSecureChannel -Verbose

# Re-secure the channel if broken
Test-ComputerSecureChannel -Repair -Credential (Get-Credential)
```

---

### 10.3 Group Policy (GPO) Troubleshooting (Step-by-Step)

**Symptom:** GPO settings not applying, or wrong settings applying to a machine/user.

#### Step 1 — Generate RSoP (Resultant Set of Policy)
```
# Quick summary on the local machine
gpresult /R

# Detailed HTML report
gpresult /H C:\Reports\gpresult.html /F

# For a remote computer / specific user
gpresult /S <computername> /U corp\username /H C:\Reports\gpresult.html /F
```

#### Step 2 — Force a GPO refresh
```
# Local machine
gpupdate /force

# Remote computers (PowerShell — requires WinRM)
Invoke-GPUpdate -Computer "WS001" -Force -RandomDelayInMinutes 0
```

#### Step 3 — Check SYSVOL replication
GPO files live in `\\<domain>\SYSVOL` — if SYSVOL is not replicating, GPOs can't apply.
```
# Check SYSVOL replication health (DFS-R)
dfsrdiag ReplicationState

# Check DFS-R event log
Get-WinEvent -LogName "DFS Replication" -MaxEvents 50 | Where-Object { $_.LevelDisplayName -ne "Information" }

# Check SYSVOL share exists on all DCs
Get-ADDomainController -Filter * | ForEach-Object {
    Test-Path "\\$($_.Name)\SYSVOL"
}
```

#### Step 4 — Verify LSDOU order and inheritance
```
# Show applied GPOs and their order
gpresult /R | Select-String -Pattern "Applied GPO|Denied GPO|Reason"
```
Check for:
- **Block Inheritance** on an OU (visible in GPMC with a blue exclamation icon).
- **Enforced** GPOs overriding Block Inheritance (padlock icon in GPMC).
- **WMI Filter** returning `FALSE` (GPO shows as "filtered").
- **Security Filtering** — the computer/user account (or `Authenticated Users`) must have **Read + Apply Group Policy** permissions.

#### Step 5 — Common GPO issues and fixes

| Issue | Symptom | Fix |
|---|---|---|
| GPO not applying to computer | Setting absent from `gpresult /R` | Verify `Authenticated Users` or computer account has `Apply GP` permission on the GPO |
| User settings not applying | Only computer settings apply | Loopback Processing may be enabled (Replace mode) — check if intentional |
| GPO applies but setting reverts | Competing GPO with higher precedence | Check GPO link order; use Enforced if needed |
| SYSVOL out of sync | Different GPO version on different DCs | Fix DFS-R replication; run `repadmin /syncall` |
| WMI filter blocking GPO | GPO shows as "Denied (WMI Filter)" | Review filter logic; test with `wbemtest` or `Get-WmiObject` |

---

### 10.4 Entra Connect (Azure AD Connect) Troubleshooting (Step-by-Step)

**Symptoms:** Users not appearing in Entra ID, password changes not syncing, sync errors in portal.

#### Step 1 — Check sync status in the Entra portal
`Entra ID Portal → Entra Connect → Sync Status`
Look for: last sync time, staging mode status, sync errors count.

#### Step 2 — Check sync errors in PowerShell
```powershell
# Connect to Entra ID (requires MSOnline or Microsoft.Graph module)
Connect-MsolService

# List all sync errors
Get-MsolSyncDirectoryError | Format-List

# Or use the newer Graph module
Connect-MgGraph -Scopes "AuditLog.Read.All"
Get-MgDirectoryDeletedItem -DirectoryObjectId <objectId>  # check for soft-deleted objects
```

#### Step 3 — View Entra Connect sync logs
```powershell
# Open the built-in Synchronization Service Manager UI
"%ProgramFiles%\Microsoft Azure AD Sync\UIShell\miisclient.exe"
```
- **Operations tab** → see each sync cycle, errors per run step.
- **Connectors tab** → check connector state (Running / Idle / Error).
- **Metaverse Search** → look up specific objects and trace where they came from / where they go.

#### Step 4 — Force a sync cycle
```powershell
# Delta sync (only changed objects since last sync)
Start-ADSyncSyncCycle -PolicyType Delta

# Full sync (re-evaluate all objects)
Start-ADSyncSyncCycle -PolicyType Initial
```

#### Step 5 — Common sync errors and fixes

| Error Code | Error Description | Root Cause | Fix |
|---|---|---|---|
| `AttributeValueMustBeUnique` | Duplicate proxy address / UPN | Two objects share same email/UPN | Deduplicate in on-prem AD |
| `InvalidSoftMatch` | Soft match conflict | Multiple objects match the same cloud user | Use hard match (`ms-DS-ConsistencyGuid`) |
| `DataValidationFailed` | Invalid attribute value | Illegal characters in display name or UPN | Clean up the attribute in AD |
| `ObjectTypeMismatch` | User synced as contact or vice versa | Source object type mismatch | Check connector space object type mapping |
| `ExportedChange` stuck | Object not leaving export state | Permissions on Entra connector account | Verify connector account has required roles |
| `PasswordPolicyViolation` | PHS password hash not syncing | Cloud password policy stricter than on-prem | Check cloud minimum password age policy |

#### Step 6 — Verify PTA agent health (if using Pass-Through Auth)
```powershell
# Check PTA agent registration on the agents server
Get-Item "HKLM:\SOFTWARE\Microsoft\AzureADConnect\AuthenticationAgents"

# View PTA agent status in portal:
# Entra ID → Entra Connect → Pass-through authentication → Active agents
```
Ensure minimum 3 PTA agents deployed across different servers for HA.

---

### 10.5 Conditional Access Troubleshooting (Step-by-Step)

**Symptom:** User being unexpectedly blocked, MFA prompt not appearing, or policy not applying as expected.

#### Step 1 — Use the "What If" tool
`Entra ID Portal → Security → Conditional Access → What If`
- Input: user, application, IP address, device platform, sign-in risk level.
- Output: which CA policies would apply and what controls they would enforce.

#### Step 2 — Review Sign-In Logs
`Entra ID Portal → Monitoring → Sign-in logs`
- Filter by user, application, date range.
- Click a sign-in entry → **Conditional Access tab** → shows each policy and its result:
  - ✅ **Success** – policy applied, controls satisfied.
  - ❌ **Failure** – policy applied, control not satisfied (blocked).
  - ⚠️ **Not applied** – conditions not matched (policy did not target this sign-in).

#### Step 3 — PowerShell — export CA sign-in failures
```powershell
Connect-MgGraph -Scopes "AuditLog.Read.All"

$signIns = Get-MgAuditLogSignIn -Filter "conditionalAccessStatus eq 'failure'" -Top 100
$signIns | Select-Object UserDisplayName, AppDisplayName, IpAddress, CreatedDateTime, ConditionalAccessStatus |
    Export-Csv "C:\Reports\CA_Failures_$(Get-Date -Format yyyyMMdd).csv" -NoTypeInformation
```

#### Step 4 — Common CA misconfigurations and fixes

| Issue | Symptom | Fix |
|---|---|---|
| Break-glass account blocked | Emergency admin locked out | Exclude break-glass accounts from all CA policies; secure with FIDO2 key + monitoring |
| Named location too broad | On-prem subnet included, bypasses MFA | Audit named locations; never use /8 or /16 blocks as trusted |
| Device compliance policy lag | User blocked on new device | Ensure Intune compliance check-in; allow 24h grace for newly enrolled devices |
| Legacy auth not fully blocked | Old SMTP/IMAP clients still signing in | Check sign-in logs for `clientAppUsed = "Other clients"` and block via CA |
| CA policy in Report-Only mode | Policy appears but has no enforcement | Validate in report-only → switch to Enabled after testing |
| Guest users blocked from all apps | B2B collaboration broken | Create separate CA policies scoped to `Guest users` with appropriate controls |

---

### 10.6 LAPS Troubleshooting (Step-by-Step)

**Symptom:** LAPS password not rotating, helpdesk cannot retrieve password, blank password attribute.

#### Step 1 — Verify LAPS is installed on the endpoint
```powershell
# Legacy LAPS — check the CSE (Client Side Extension) DLL is present
Get-Service AdmPwd*
Test-Path "C:\Program Files\LAPS\CSE\AdmPwd.dll"

# Windows LAPS (built-in to Windows 11 22H2+ / Server 2022 CU+)
# Confirm the built-in cmdlets are available
Get-Command -Module LAPS -ErrorAction SilentlyContinue

# Check LAPS policy is applying
gpresult /R | Select-String "LAPS"
```

#### Step 2 — Check the password attribute in AD
```powershell
# Legacy LAPS
Get-ADComputer WS001 -Properties "ms-Mcs-AdmPwd", "ms-Mcs-AdmPwdExpirationTime" |
    Select-Object Name, "ms-Mcs-AdmPwd", "ms-Mcs-AdmPwdExpirationTime"

# Windows LAPS
Get-LapsADPassword -Identity WS001 -AsPlainText
```
If `ms-Mcs-AdmPwd` is blank:
- LAPS CSE (Client Side Extension) is not installed on the endpoint.
- The GPO for LAPS is not reaching the computer (see GPO troubleshooting).
- The computer account doesn't have `SELF: Write ms-Mcs-AdmPwd` permission on its own object.

#### Step 3 — Check AD permissions (most common issue)
```powershell
# Verify LAPS schema extension exists
Get-ADObject "CN=ms-Mcs-AdmPwd,CN=Schema,CN=Configuration,DC=corp,DC=com" -ErrorAction SilentlyContinue

# Verify SELF write permission (run as Domain Admin)
Set-AdmPwdComputerSelfPermission -OrgUnit "OU=Workstations,DC=corp,DC=com"

# Verify who can READ LAPS passwords in an OU
Find-AdmPwdExtendedRights -Identity "OU=Workstations,DC=corp,DC=com" | Format-Table
```

#### Step 4 — Force an immediate password reset
```powershell
# Set expiration time to now, forcing rotation on next group policy refresh
Set-AdmPwdAccountExpiration -Identity WS001 -ExpirationTime (Get-Date)

# Then trigger GP update on the endpoint
Invoke-GPUpdate -Computer WS001 -Force
```

---

### 10.7 DNS Troubleshooting for Active Directory (Step-by-Step)

**Symptom:** DCs cannot be located, `dcdiag` fails, users cannot log in from specific sites.

#### Step 1 — Verify SRV record registration
```
# Confirm DCs are registering SRV records
nslookup -type=SRV _ldap._tcp.corp.com
nslookup -type=SRV _kerberos._tcp.corp.com
nslookup -type=SRV _ldap._tcp.dc._msdcs.corp.com
nslookup -type=SRV _kerberos._tcp.<site-name>._sites.corp.com
```
If SRV records are missing → the DC `Netlogon` service needs to re-register them:
```
# Force SRV record re-registration
nltest /dsregdns
net stop netlogon && net start netlogon
```

#### Step 2 — Run dcdiag DNS test
```
dcdiag /test:DNS /DnsBasic /v
dcdiag /test:DNS /DnsForwarders /v
dcdiag /test:DNS /DnsDynamicUpdate /v
```

#### Step 3 — Check DNS scavenging settings
Stale DNS records cause authentication failures if old DCs are decommissioned but records persist.
```powershell
# Check scavenging on DNS zones
Get-DnsServerZone -Name "corp.com" | Select-Object ZoneName, IsScavengingEnabled, ScavengingInterval
Get-DnsServerScavenging

# Enable scavenging (if not already enabled)
Set-DnsServerScavenging -ScavengingInterval "7.00:00:00" -PassThru
Set-DnsServerZoneAging -Name "corp.com" -Aging $true -ScavengeServers <dns-server-ip>
```

#### Step 4 — Test DC locator
```
# Find the DC a client is using
nltest /dsgetdc:corp.com /force

# Find the DC for a specific site
nltest /dsgetdc:corp.com /site:US-HQ /force

# Check all DCs in the domain
nltest /dclist:corp.com
```

#### Step 5 — Check for split-brain DNS issues
Split-brain = internal clients resolve `corp.com` to internal IPs; external clients resolve to public IPs.
```powershell
# Check what DNS server the machine is using
Get-DnsClientServerAddress -InterfaceAlias "Ethernet"

# Resolve from specific DNS server to compare
Resolve-DnsName -Name "corp.com" -Server "10.1.1.10"  # internal DNS
Resolve-DnsName -Name "corp.com" -Server "8.8.8.8"     # external DNS (should be different)
```

---

*Good luck with your interview! Focus on demonstrating both deep technical depth AND the ability to communicate risk and strategy to non-technical stakeholders — that is what separates senior engineers from staff/principal-level candidates.*

---

## 11. Dual-Audience Troubleshooting Narratives — Architect & Engineer Views

> **How to use this section:**  
> Each topic is split into two perspectives:  
> - 🏛️ **Architect View** — conceptual framing, decision rationale, risk language, and what you communicate upward or to peer architects.  
> - 🔧 **Engineer View** — exact commands with expected output, decision logic at each step, and teaching notes for junior engineers.

---

### 11.1 AD Multi-Site: Replication Failure

#### 🏛️ Architect View — What to Communicate

**The problem in business terms:**  
Multi-site AD replication failure means users in affected sites may authenticate against stale data — wrong passwords, expired accounts still working, or objects (like new employees) invisible to remote DCs. If a DC in a branch site falls out of replication for more than the tombstone lifetime (default 180 days), it creates a permanent "tombstone boundary" requiring DC demotion. This is an availability and integrity risk.

**Design principles you'd articulate:**

| Design Decision | Rationale |
|---|---|
| Deploy a writable DC at every site with >200 users | Eliminates WAN auth latency; provides local login if WAN fails |
| Deploy RODCs at small/untrusted sites | Limits blast radius if physical DC is stolen — no writable credentials cached locally |
| Site link topology must mirror physical WAN | Incorrect site links cause KCC to generate wrong replication topology |
| Monitor with `repadmin /replsummary` on schedule | Delta > 24h = operational risk; Delta > 60 days = approaching tombstone/USN rollback risk |
| Prefer IP-based inter-site replication | Faster than SMTP; SMTP requires a CA-signed certificate and is only for disconnected sites |

**What you tell the architect or steering committee:**  
> "The replication failure between US-HQ and EMEA-London means EMEA staff are authenticating against a domain controller that hasn't received updates for X hours. The immediate risk is stale password or group membership data causing incorrect access decisions. I've contained the issue by forcing a manual sync, and I'm remediating the site link configuration. I'll recommend a DC monitoring alert threshold of 2-hour replication lag going forward."

---

#### 🔧 Engineer View — Step-by-Step Teaching Guide

**Scenario:** A junior engineer reports "users in London can't log in after a password reset was done in HQ."

**Teach them the mental model first:**

```
1. Authentication is local to the site's DC
2. Password changes replicate urgently through the PDC Emulator (hosted at HQ)
3. PDC Emulator pushes the change to ALL DCs immediately
4. If the EMEA DC hasn't replicated → it rejects the new password
5. The old-password grace period (2 attempts) may mask this temporarily
```

**Step 1: Identify the PDC Emulator and the EMEA DC**
```powershell
Get-ADDomain | Select-Object PDCEmulator
nltest /dsgetdc:corp.com /site:EMEA-London /force
```

**Step 2: Check replication status on the EMEA DC**
```
repadmin /showrepl DC1-EMEA-LON
repadmin /showrepl DC1-EMEA-LON /errorsonly
```
Expected good output:
```
Last attempt @ 2026-03-31 00:10:22 was successful.
0 consecutive failure(s).
```
Bad output: consecutive failures > 0; "Last success" many hours ago.

**Step 3: Force immediate sync from HQ to EMEA**
```
repadmin /syncall DC1-EMEA-LON /AdeP
```
Flag breakdown (teach each one):
```
/A  All naming contexts (domain, schema, config, DNS)
/d  Display progress using Distinguished Names
/e  Enterprise-wide, crossing site links
/P  Push mode: HQ sends to EMEA rather than EMEA pulling
```

**Step 4: Confirm success and verify user can log in**
```
repadmin /replsummary
```
All DCs should show 0 failures and a recent "Last Success" timestamp.

**Step 5: Prevent recurrence — replication monitoring one-liner**
```powershell
# Schedule daily; alert if any non-zero failure count is found
repadmin /replsummary | Select-String "Fail" | Where-Object { $_ -notmatch "\s0\s" }
```

> 👩‍🏫 **Teaching note:** "The PDC Emulator is the single point for urgent password change replication. If you ever see auth failures after a password reset, the first thing to check is whether the user's home-site DC has replicated from the PDC Emulator. Always confirm with `repadmin /showrepl` before resetting the password again."

---

### 11.2 AD Multi-Site: DC Discovery & Site Coverage Gaps

#### 🏛️ Architect View — What to Communicate

**The risk:**  
If a site has no DC and no explicit site-link to a DC site, Windows uses "automatic site coverage" — an unpredictable DC from any site handles authentication over the WAN. This creates latency spikes and single-WAN-link dependency for all logins.

**Site-to-DC placement decision matrix:**

| Site Profile | DC Model | Rationale |
|---|---|---|
| HQ / primary datacenter | 2+ writable DCs + GC | Redundancy; GC required for forest-wide attribute lookups |
| Regional office (200+ users) | 1 writable DC + GC | Local auth; survives WAN failure |
| Branch office (50–200 users) | RODC with credential caching | Reduced attack surface; credential cache allows offline auth |
| Micro-office (<50 users) | No DC; VPN to nearest site | Cost vs. risk; acceptable if VPN is reliable |
| Azure IaaS VMs | AD DS replica in Azure or Entra Domain Services | Never authenticate Azure VMs against on-prem DCs — latency is unacceptable |

**What you tell the architect:**  
> "The Austin branch currently relies on automatic site coverage and authenticates against the Dallas DC over a 50ms WAN link. During peak hours that link carries 400+ auth requests per minute. An RODC in Austin eliminates that WAN dependency and is the lowest-risk option since RODCs store only cached credentials for Austin users."

---

#### 🔧 Engineer View — Step-by-Step Teaching Guide

**Teach KCC and site link concepts:**

```
AD Sites & Services defines sites (IP subnet boundaries) and site links (inter-site replication paths)
KCC (Knowledge Consistency Checker) runs every 15 minutes on each DC
KCC reads site links → generates Connection Objects (actual replication schedule)
Without a local DC: Windows uses "automatic site coverage" → non-deterministic DC selection
Fix: deploy a DC in the site, or configure a "preferred bridgehead" explicitly
```

**Step 1: Identify which DC a client is authenticating against**
```cmd
REM On the client
set LOGONSERVER
nltest /dsgetdc:corp.com /force
```

**Step 2: Map IP subnets to sites**
```powershell
Get-ADReplicationSubnet -Filter * | Select-Object Name, Site | Format-Table
nltest /dsaddresstosite:10.40.5.22    # find which site an IP belongs to
```

**Step 3: View all sites and their DCs**
```powershell
Get-ADDomainController -Filter * |
    Select-Object Name, Site, IsGlobalCatalog, IsReadOnly, IPv4Address |
    Sort-Object Site | Format-Table
```

**Step 4: Review and tune site link costs**
```powershell
# View site links
Get-ADReplicationSiteLink -Filter * |
    Select-Object Name, Cost, ReplicationFrequencyInMinutes, SitesIncluded

# Lower cost = preferred path (like routing metric)
Set-ADReplicationSiteLink -Identity "HQ-EMEA-Link" -Cost 100 -ReplicationFrequencyInMinutes 15
Set-ADReplicationSiteLink -Identity "HQ-EMEA-Backup" -Cost 500
```

> 👩‍🏫 **Teaching note:** "Site link cost is exactly like a routing metric. If two paths exist between HQ and EMEA, the one with the lower cost wins for replication. Always set cost to reflect real WAN quality — a dedicated MPLS link should cost less than a backup internet VPN."

---

### 11.3 Entra ID / IAM: Conditional Access Sign-In Failures

#### 🏛️ Architect View — What to Communicate

**CA policy risk matrix:**

```
Too permissive  → attacker bypasses MFA → credential stuffing succeeds → breach
Too restrictive → mass user lockout → helpdesk surge → business downtime
Optimal path    → report-only (2–4 weeks) → pilot group → staged rollout → all users
                  break-glass always excluded | sign-in logs always monitored
```

**Design principles:**

| Principle | Implementation |
|---|---|
| Start every new policy in Report-Only | Zero impact; baseline data collection for 2–4 weeks |
| Exclude break-glass accounts from all CA | 2 accounts per tenant; FIDO2 hardware key; alerts on any use |
| Use What If before enabling | Test synthetic sign-ins before real users are affected |
| Scope to assignment groups, not All Users | Phase: pilot → department → all users |
| Separate policies for guests vs. members | Guests have no Entra-registered devices; different baseline required |

**What you tell the architect before enabling a new policy:**  
> "I want two weeks of report-only data to quantify the impact of the 'compliant device required' control specifically. That control has the highest lockout risk for BYOD users and contractors. I'll present the impact numbers to the IAM steering group before we switch to Enabled."

---

#### 🔧 Engineer View — Step-by-Step Teaching Guide

**Teach the CA evaluation model:**

```
User signs in
  → Entra ID evaluates ALL enabled CA policies in the tenant
  → For each policy: do ALL conditions match? (user, group, app, location, device, risk level)
  → If conditions match → apply controls (require MFA, require compliant device, block, etc.)
  → If any required control is not satisfied → sign-in BLOCKED
  → Sign-in log records every policy evaluated, its result, and which control failed
```

**Step 1: Pull the sign-in log for the affected user**
```powershell
Connect-MgGraph -Scopes "AuditLog.Read.All"
$signIns = Get-MgAuditLogSignIn `
    -Filter "userPrincipalName eq 'jsmith@corp.com'" `
    -Top 10 -Sort "createdDateTime desc"
$signIns | Select-Object CreatedDateTime, AppDisplayName, ConditionalAccessStatus, IpAddress |
    Format-Table -AutoSize
```

**Step 2: Inspect which CA policy caused the failure**
```powershell
$failed = $signIns | Where-Object { $_.ConditionalAccessStatus -eq "failure" } | Select-Object -First 1
$failed.AppliedConditionalAccessPolicies |
    Select-Object DisplayName, Result, GrantControlsNotSatisfied | Format-List
```

`Result` values explained:
```
success              → policy matched, all controls satisfied
failure              → policy matched, a required control was not met (this is the blocker)
notApplied           → conditions did not match this sign-in (user/app/location/etc.)
reportOnlySuccess    → report-only mode; would succeed if enabled
reportOnlyFailure    → report-only mode; would block if enabled
```

**Step 3: Use the What If tool for rapid diagnosis**
```
Portal path: Entra ID → Security → Conditional Access → What If
Enter: user, application, IP address, device platform, sign-in risk
Result: every policy that matches and its outcome
```
> 👩‍🏫 **Teaching note:** "What If is the fastest way to understand *which policy* is blocking a specific user. Run it with the exact parameters from the sign-in log — same IP, same app, same device — and it will show you exactly what the user experienced."

**Step 4: Verify and fix common root causes**
```powershell
# Is device compliant? (Intune)
Get-MgDeviceManagementManagedDevice `
    -Filter "userPrincipalName eq 'jsmith@corp.com'" |
    Select-Object DeviceName, ComplianceState, LastSyncDateTime

# Is user in the correct CA target group?
Get-MgGroupMember -GroupId "<ca-target-group-id>" |
    Where-Object { $_.AdditionalProperties.userPrincipalName -eq "jsmith@corp.com" }

# Temporary mitigation: add user to exclusion group (document with change ticket!)
New-MgGroupMember -GroupId "<ca-exclusion-group-id>" -DirectoryObjectId "<user-object-id>"
```

---

### 11.4 Entra ID / IAM: PIM Activation Failures

#### 🏛️ Architect View — What to Communicate

**Why PIM failures are a dual risk:**

```
PIM activation blocked during change window
    → Engineer cannot complete critical task
    → Engineer uses standing service account instead
    → Standing account = no JIT, no audit trail, no auto-expiry
    → This is worse than the original risk PIM was designed to prevent
```

**Design principles:**

| Decision | Recommendation |
|---|---|
| Pre-activation requirement | Activate PIM 15 min before a change window opens — not during |
| Always configure alternate approvers | Single approver = single point of failure for emergency changes |
| Activation duration | Match to longest expected change window; never set "indefinitely" |
| Notification on unused eligible assignments | Quarterly report; remove assignments not activated in 90 days |

**What you tell the architect:**  
> "I recommend adding a pre-activation requirement to our change management standard: engineers must activate their PIM role at least 15 minutes before a maintenance window begins. This eliminates the race condition between PIM approval latency and the start of the change window."

---

#### 🔧 Engineer View — Step-by-Step Teaching Guide

**Teach the PIM activation flow:**

```
User: MyAccess portal → "Activate" eligible role
  → PIM: verifies eligibility
  → Issues MFA challenge (if configured)
  → Requests justification text (if required)
  → Sends approval request to approver (if required)
  → Approver approves in portal or email
  → Role becomes Active for configured duration
  → After duration: automatic removal
  → ALL steps written to PIM Audit Log
```

**Step 1: Check eligible assignments**
```powershell
Connect-MgGraph -Scopes "RoleManagement.Read.Directory"
Get-MgRoleManagementDirectoryRoleEligibilitySchedule `
    -Filter "principalId eq '<user-object-id>'" |
    Select-Object RoleDefinitionId, StartDateTime, EndDateTime
```

**Step 2: Check currently active assignments**
```powershell
Get-MgRoleManagementDirectoryRoleAssignmentScheduleInstance `
    -Filter "principalId eq '<user-object-id>'" |
    Select-Object RoleDefinitionId, StartDateTime, EndDateTime, AssignmentType
```

**Step 3: Read the PIM audit log for the failure**
```powershell
Get-MgAuditLogDirectoryAudit `
    -Filter "category eq 'RoleManagement'" `
    -Top 20 |
    Where-Object { $_.Result -eq "failure" } |
    Select-Object ActivityDateTime, ActivityDisplayName, InitiatedBy, ResultReason |
    Format-List
```

**Step 4: Common PIM failures and fixes**

| Failure Message | Cause | Fix |
|---|---|---|
| MFA required but not completed | MFA method not registered or failed | Register/verify MFA method in MyAccount portal |
| Activation request expired | Approver did not act within 24h | Re-submit; add backup approver to PIM policy |
| Role assignment not found | Eligible assignment expired or was removed | Re-add eligible assignment in PIM → Roles → Add Assignments |
| Justification is required | Policy requires ticket number/reason | Re-submit with justification field populated |
| Max duration exceeded | Requested longer than policy allows | Re-submit with correct duration; escalate policy change if needed |

---

### 11.5 Access Controls: RBAC and Least Privilege Teaching Guide

#### 🏛️ Architect View — What to Communicate

**The AD administrative tier model:**

```
Tier 0 — Forest / Domain control plane
  Accounts: Domain Admins, Schema Admins, Enterprise Admins
  Access: ONLY from PAW; JIT via PIM; hardware MFA
  Rule: Tier 0 accounts NEVER touch Tier 1 or Tier 2 systems

Tier 1 — Server / application plane
  Accounts: Server Admins, Exchange Admins, SQL DBAs, service accounts
  Access: From admin workstations (not general-use laptops)
  Rule: Tier 1 accounts never log into workstations

Tier 2 — Workstation / end-user plane
  Accounts: Helpdesk, desktop support
  Local admin: LAPS only (no shared passwords)
  Rule: Tier 2 accounts never manage servers
```

**What you tell leadership about LAPS:**  
> "Our current shared local admin password gives every engineer with helpdesk access the ability to authenticate as local admin on any of our 8,000 endpoints. A single compromised helpdesk credential enables lateral movement across the entire fleet via Pass-the-Hash. LAPS gives every machine a unique, automatically rotating password with an AD audit trail. The deployment is low-cost; the risk reduction is substantial."

---

#### 🔧 Engineer View — Teaching RBAC Delegation and LAPS

**Teach AD delegation (least privilege in practice):**

```powershell
# WRONG: Adding helpdesk to Domain Admins
# → Full domain control for a simple password reset task

# RIGHT: Delegate only "Reset Password" on the Workstations OU
$ou = "OU=Workstations,DC=corp,DC=com"

# Grant helpdesk: Reset Password and Change Password on user objects
dsacls $ou /G "CORP\Helpdesk:CA;Reset Password;user"
dsacls $ou /G "CORP\Helpdesk:CA;Change Password;user"

# Grant helpdesk: Write lockoutTime (unlock account)
dsacls $ou /G "CORP\Helpdesk:WP;lockoutTime;user"

# Verify delegation
dsacls $ou | Select-String "Helpdesk"
```

> 👩‍🏫 **Teaching note:** "Domain Admins membership is the nuclear option. Every task in AD can be delegated more narrowly: password resets on one OU, group membership changes in another. Always ask 'what is the minimum permission needed?' before assigning any admin right."

**Teach LAPS deployment phases:**

```powershell
# Phase 1: Extend AD schema (run once, as Schema Admin)
Update-LapsADSchema    # Windows LAPS (built-in)

# Phase 2: Grant computer accounts SELF-WRITE on their LAPS attribute
Set-LapsADComputerSelfPermission -Identity "OU=Workstations,DC=corp,DC=com"

# Phase 3: Deploy GPO
# Computer Config → Admin Templates → LAPS
#   Password Settings: Length=20, Complexity=4 (upper/lower/digit/special), Age=30 days
#   Admin account: specify managed account name (or default Administrator)

# Phase 4: Verify on pilot machine
gpupdate /force       # run on the test endpoint
Get-LapsADPassword -Identity "PILOT-PC01" -AsPlainText

# Phase 5: Audit who can read LAPS passwords
Find-LapsADExtendedRights -Identity "OU=Workstations,DC=corp,DC=com" | Format-Table
# Should show: Helpdesk + Security team ONLY
# Remove any group that shouldn't have read access
```

**Teach Azure RBAC vs. Entra ID roles (common confusion point):**

```
Two independent RBAC systems — knowing the boundary prevents misconfigurations:

System 1: Entra ID Roles
  Examples: Global Admin, User Admin, Security Reader, Privileged Role Admin
  Scope:    Entire Entra tenant (directory-wide)
  Where:    Entra portal → Roles and Administrators
  PIM:      Yes

System 2: Azure Resource RBAC
  Examples: Owner, Contributor, Reader, Key Vault Secrets Officer
  Scope:    Hierarchical — Management Group > Subscription > Resource Group > Resource
  Where:    Azure portal → IAM blade on any resource
  PIM:      Yes (Azure resource roles via PIM)

Critical rule: Entra ID role ≠ Azure resource access
               Azure resource RBAC ≠ Entra directory access
               They are entirely separate systems with no automatic crossover
```

```powershell
# Audit high-privilege Azure RBAC assignments at subscription scope
Get-AzRoleAssignment -Scope "/subscriptions/<sub-id>" |
    Where-Object {
        $_.RoleDefinitionName -in @("Owner","Contributor") -and
        $_.Scope -eq "/subscriptions/<sub-id>"   # subscription-level = highest risk
    } |
    Select-Object DisplayName, SignInName, RoleDefinitionName, Scope
```

> 👩‍🏫 **Teaching note:** "Owner at subscription scope is the equivalent of Domain Admin for Azure resources. That permission should be held by no more than 2 break-glass service principals and activated only via PIM. Regular engineers should have Contributor or a custom role scoped to their specific resource group."

---

### 11.6 Communication Summary: Adapting Your Explanation by Audience

| Audience | What They Need to Hear | Example Framing |
|---|---|---|
| **CISO / VP** | Business risk, compliance, cost | "LAPS eliminates the pass-the-hash attack path across 8k endpoints. Aligns to CIS Level 2 and our cyber insurance requirements." |
| **Security Architect** | Design tradeoffs, threat model mapping | "RODC at branch offices limits Kerberoasting surface: no service account hashes cached locally. The tradeoff is read-only replication requiring a writable DC for writes." |
| **Senior Engineer (peer)** | Root cause, precise fix, recurrence prevention | "`repadmin /replsummary` showed error 1722 (RPC unavailable) on DC1-EMEA. DNS SRV record stale after decommission. Fixed with `nltest /dsregdns` on the DC." |
| **Junior Engineer (teaching)** | Mental model first, then commands, then "why this works" | "Before we run the fix, let me show you how replication topology is built by KCC so you understand *why* this error happens at the network layer." |
