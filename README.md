# DelegationCanvas

### Map Every Permission in Your Active Directory

**Author:** Santhosh Sivarajan, Microsoft MVP
**GitHub:** [https://github.com/SanthoshSivarajan/DelegationCanvas](https://github.com/SanthoshSivarajan/DelegationCanvas)

---

## Overview

DelegationCanvas scans every OU across all forest domains and trusts, parses the full ACL on each OU, translates every GUID to human-readable names, classifies risk, and produces a comprehensive delegation report. It also audits built-in privileged groups to identify misuse of legacy operator groups like Print Operators, Account Operators, Server Operators, and Backup Operators.

If you need to answer "who has access to what in my AD" -- this is the tool.

## What DelegationCanvas Discovers

### Delegation Analysis
- Full ACL parsing on every OU across all forest domains
- GUID translation for object types, properties, and extended rights
- Explicit vs inherited permission separation
- Risk classification (Critical/High/Medium/Low) per ACE
- Human-readable permission summaries
- Cross-domain and trust delegation detection
- Top delegated principals and OUs

### Built-In Privileged Group Audit
- Member enumeration for 10 high-risk built-in groups
- Identification of groups that should be empty but have members
- Disabled accounts still in privileged groups
- Service accounts in privileged groups
- Per-member risk flags

### Groups Audited

| Group | Expected State | Risk if Populated |
|---|---|---|
| Account Operators | EMPTY | Critical -- can create/modify users |
| Server Operators | EMPTY | Critical -- can log on to DCs |
| Print Operators | EMPTY | Critical -- can load kernel drivers on DCs |
| Backup Operators | EMPTY or minimal | Critical -- can read NTDS.dit |
| Schema Admins | EMPTY | Critical -- can modify AD schema |
| Enterprise Admins | EMPTY day-to-day | Critical -- full forest control |
| Domain Admins | 2-5 members | High if >5 |
| DnsAdmins | Tightly controlled | High -- can load DLLs on DNS/DC |
| Group Policy Creator Owners | Controlled | Medium -- can create domain GPOs |
| Administrators (builtin) | Domain Admins only | Review nested membership |

### Risk Classification

| Risk | Rights Pattern |
|---|---|
| **Critical** | GenericAll, WriteDACL, WriteOwner |
| **High** | GenericWrite, sensitive WriteProperty (member, SPN, KeyCredentialLink, RBCD), ExtendedRight on All/Replication |
| **Medium** | ExtendedRight (Reset Password), CreateChild, DeleteChild, WriteProperty |
| **Low** | ReadProperty, ReadControl, ListChildren |

## Report Sections (11)

1. Executive Summary with counts and risk breakdown
2. Domain Statistics (OUs, explicit, inherited, built-in per domain)
3. High-Risk Delegations (Critical + High)
4. Top Delegated Principals (who has the most permissions)
5. Top Delegated OUs (delegation hotspots)
6. Cross-Domain Delegations (trust-related)
7. Built-In Privileged Group Audit (summary)
8. Misused Built-In Groups (should be empty but aren't)
9. Privileged Group Member Details (per-member risk)
10. All Custom Delegations (complete table)
11. Charts (7 charts)

## Performance

Optimized for large environments:
- `[System.Collections.Generic.List[object]]` instead of array append
- GUID maps built once, reused across all domains
- Built-in principals filtered from main view (reduces data 60-70%)
- Table limits (500 for high-risk, 1000 for all delegations)
- Inherited permissions excluded by default (use `-IncludeInherited` to include)

## Usage

```powershell
# Default: explicit delegations only (recommended for large environments)
.\DelegationCanvas.ps1

# Include inherited permissions (larger report)
.\DelegationCanvas.ps1 -IncludeInherited

# Custom output path
.\DelegationCanvas.ps1 -OutputPath C:\Reports
```

## Requirements

- Windows PowerShell 5.1+ or PowerShell 7+
- **ActiveDirectory module** (RSAT)
- Domain user account (Domain Admin or delegated read access recommended)

## License

MIT -- Free to use, modify, and distribute.

## Related Projects

- [ADCanvas](https://github.com/SanthoshSivarajan/ADCanvas) -- Active Directory documentation
- [EntraIDCanvas](https://github.com/SanthoshSivarajan/EntraIDCanvas) -- Entra ID documentation
- [IntuneCanvas](https://github.com/SanthoshSivarajan/IntuneCanvas) -- Intune documentation
- [ZeroTrustCanvas](https://github.com/SanthoshSivarajan/ZeroTrustCanvas) -- Zero Trust posture assessment
- [NHICanvas](https://github.com/SanthoshSivarajan/NHICanvas) -- Non-Human Identity governance

---

*Developed by Santhosh Sivarajan, Microsoft MVP*
