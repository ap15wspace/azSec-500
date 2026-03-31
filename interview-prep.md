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
