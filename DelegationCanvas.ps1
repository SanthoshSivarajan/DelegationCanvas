<#
================================================================================
  DelegationCanvas -- Map Every Permission in Your Active Directory
  Version: 1.0
  Author : Santhosh Sivarajan, Microsoft MVP
  Purpose: Comprehensive AD delegation and permission report across all forest
           domains and trusts. Full ACL parsing with GUID translation, risk
           classification, explicit vs inherited separation, cross-domain
           delegation detection, OU hierarchy visualization, and built-in
           privileged group audit.
  License: MIT -- Free to use, modify, and distribute.
  GitHub : https://github.com/SanthoshSivarajan/DelegationCanvas
================================================================================
#>

#Requires -Modules ActiveDirectory

param(
    [string]$OutputPath = $PSScriptRoot,
    [switch]$IncludeInherited
)

$ReportDate = Get-Date -Format "yyyy-MM-dd_HHmmss"
$OutputFile = Join-Path $OutputPath "DelegationCanvas_$ReportDate.html"

Write-Host ""
Write-Host "  +============================================================+" -ForegroundColor Cyan
Write-Host "  |                                                            |" -ForegroundColor Cyan
Write-Host "  |   DelegationCanvas -- AD Delegation & Permission Map v1.0  |" -ForegroundColor Cyan
Write-Host "  |                                                            |" -ForegroundColor Cyan
Write-Host "  |   Author : Santhosh Sivarajan, Microsoft MVP              |" -ForegroundColor Cyan
Write-Host "  |   Web    : github.com/SanthoshSivarajan/DelegationCanvas  |" -ForegroundColor Cyan
Write-Host "  |                                                            |" -ForegroundColor Cyan
Write-Host "  +============================================================+" -ForegroundColor Cyan
Write-Host ""

Import-Module ActiveDirectory -ErrorAction Stop

$now = Get-Date
$Forest = Get-ADForest -ErrorAction Stop
$ForestName = $Forest.Name

Write-Host "  [*] Forest    : $ForestName" -ForegroundColor White
Write-Host "  [*] Timestamp : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor White
Write-Host ""

# --- Helpers ------------------------------------------------------------------
Add-Type -AssemblyName System.Web
function HtmlEncode($s) { if ($null -eq $s) { return "--" }; return [System.Web.HttpUtility]::HtmlEncode([string]$s) }

# Built-in principals to filter from main delegation view
$BuiltInPrincipals = @(
    'NT AUTHORITY\SYSTEM','NT AUTHORITY\SELF','NT AUTHORITY\Authenticated Users',
    'NT AUTHORITY\NETWORK SERVICE','NT AUTHORITY\LOCAL SERVICE',
    'BUILTIN\Administrators','BUILTIN\Account Operators','BUILTIN\Server Operators',
    'BUILTIN\Print Operators','BUILTIN\Backup Operators','BUILTIN\Pre-Windows 2000 Compatible Access',
    'CREATOR OWNER','Everyone','ENTERPRISE DOMAIN CONTROLLERS'
)
$BuiltInPatterns = @('S-1-5-9','S-1-3-0','S-1-5-18','S-1-5-10','S-1-5-11','S-1-1-0','S-1-5-20','S-1-5-19','S-1-5-32-')

function Test-BuiltInPrincipal {
    param([string]$Identity)
    if ([string]::IsNullOrWhiteSpace($Identity)) { return $true }
    foreach ($bi in $BuiltInPrincipals) { if ($Identity -eq $bi) { return $true } }
    foreach ($pat in $BuiltInPatterns) { if ($Identity -like "$pat*") { return $true } }
    # Domain Admins / Enterprise Admins / Schema Admins (any domain)
    if ($Identity -match '\\Domain Admins$|\\Enterprise Admins$|\\Schema Admins$|\\Administrators$') { return $true }
    return $false
}

function Get-RiskLevel {
    param([string]$Rights, [string]$ObjectTypeName)
    if ($Rights -match 'GenericAll') { return 'Critical' }
    if ($Rights -match 'WriteDacl|WriteOwner') { return 'Critical' }
    if ($Rights -match 'GenericWrite|WriteAllProperties') { return 'High' }
    if ($Rights -match 'ExtendedRight' -and $ObjectTypeName -match 'All|DS-Replication') { return 'High' }
    if ($Rights -match 'WriteProperty' -and $ObjectTypeName -match 'member|servicePrincipalName|msDS-AllowedToActOnBehalfOfOtherIdentity|msDS-KeyCredentialLink') { return 'High' }
    if ($Rights -match 'ExtendedRight' -and $ObjectTypeName -match 'Reset Password|User-Change-Password|User-Force-Change-Password') { return 'Medium' }
    if ($Rights -match 'CreateChild|DeleteChild|DeleteTree|Delete') { return 'Medium' }
    if ($Rights -match 'WriteProperty|Self') { return 'Medium' }
    if ($Rights -match 'ReadProperty|ReadControl|ListChildren|ListObject') { return 'Low' }
    return 'Low'
}

function Get-RiskColor($risk) {
    switch ($risk) { 'Critical' { '#f87171' } 'High' { '#fb923c' } 'Medium' { '#fbbf24' } 'Low' { '#34d399' } default { '#94a3b8' } }
}

# ==============================================================================
# PHASE 1: BUILD GUID MAPS
# ==============================================================================
Write-Host "  [*] Building GUID translation maps ..." -ForegroundColor Yellow

$rootDSE = Get-ADRootDSE
$GUIDMap = @{}

# Schema attribute/class GUIDs
try {
    Get-ADObject -SearchBase $rootDSE.schemaNamingContext -LDAPFilter "(schemaIDGUID=*)" -Properties lDAPDisplayName,schemaIDGUID -Server $rootDSE.dnsHostName -ErrorAction Stop | ForEach-Object {
        if ($_.schemaIDGUID) { $GUIDMap[([System.GUID]$_.schemaIDGUID).Guid.ToLower()] = $_.lDAPDisplayName }
    }
    Write-Host "  [+] Schema GUID map: $($GUIDMap.Count) entries" -ForegroundColor Green
} catch { Write-Host "  [i] Schema GUID map failed: $($_.Exception.Message)" -ForegroundColor Gray }

# Extended Rights GUIDs
$ExtRightsCount = 0
try {
    Get-ADObject -SearchBase "CN=Extended-Rights,$($rootDSE.configurationNamingContext)" -LDAPFilter "(objectClass=controlAccessRight)" -Properties displayName,rightsGuid -Server $rootDSE.dnsHostName -ErrorAction Stop | ForEach-Object {
        if ($_.rightsGuid) { $GUIDMap[$_.rightsGuid.ToLower()] = $_.displayName; $ExtRightsCount++ }
    }
    Write-Host "  [+] Extended rights map: $ExtRightsCount entries" -ForegroundColor Green
} catch { Write-Host "  [i] Extended rights map failed" -ForegroundColor Gray }

$GUIDMap['00000000-0000-0000-0000-000000000000'] = 'All'

function Resolve-GUID {
    param([string]$Guid)
    if ([string]::IsNullOrWhiteSpace($Guid)) { return 'All' }
    $key = $Guid.ToLower()
    if ($GUIDMap.ContainsKey($key)) { return $GUIDMap[$key] }
    return $Guid
}

# ==============================================================================
# PHASE 2: DISCOVER DOMAINS AND TRUSTS
# ==============================================================================
Write-Host ""
Write-Host "  [*] Discovering domains and trusts ..." -ForegroundColor Yellow

$allDomains = @()
foreach ($d in $Forest.Domains) {
    $allDomains += @{Name=$d; Type='Forest'}
}

try {
    $trusts = Get-ADTrust -Filter * -ErrorAction SilentlyContinue
    foreach ($t in $trusts) {
        if ($t.Target -notin $allDomains.Name) {
            $allDomains += @{Name=$t.Target; Type="Trust ($($t.Direction))"; TrustDirection=$t.Direction}
            Write-Host "  [+] Trusted domain: $($t.Target) ($($t.Direction))" -ForegroundColor Yellow
        }
    }
} catch { Write-Host "  [i] Trust enumeration: $($_.Exception.Message)" -ForegroundColor Gray }

Write-Host "  [+] Domains to scan: $($allDomains.Count)" -ForegroundColor Green

# ==============================================================================
# PHASE 3: COLLECT DELEGATIONS PER DOMAIN
# ==============================================================================
Write-Host ""
Write-Host "  [*] Scanning OU delegations ..." -ForegroundColor Yellow

$AllDelegations     = [System.Collections.Generic.List[object]]::new()
$BuiltInACECount    = 0
$InheritedACECount  = 0
$ExplicitACECount   = 0
$CrossDomainCount   = 0
$OUCountTotal       = 0
$DomainStats        = @()

foreach ($domainEntry in $allDomains) {
    $domainName = $domainEntry.Name
    Write-Host "  [*] Domain: $domainName" -ForegroundColor White

    $server = $null
    $domainDN = $null
    try {
        $domObj = Get-ADDomain -Identity $domainName -ErrorAction Stop
        $server = $domObj.PDCEmulator
        $domainDN = $domObj.DistinguishedName
    } catch {
        Write-Host "  [i] Cannot reach domain $domainName -- skipping" -ForegroundColor Gray
        continue
    }

    # Get NetBIOS name for this domain
    $domNetBIOS = $domObj.NetBIOSName

    # Get all OUs
    $ous = @()
    try {
        $ous = @(Get-ADOrganizationalUnit -Filter * -Server $server -Properties CanonicalName -ErrorAction Stop)
        Write-Host "  [+] OUs found: $($ous.Count)" -ForegroundColor Green
    } catch {
        Write-Host "  [i] OU enumeration failed for $domainName" -ForegroundColor Gray
        continue
    }

    $OUCountTotal += $ous.Count
    $domExplicit = 0; $domInherited = 0; $domBuiltIn = 0

    foreach ($ou in $ous) {
        $ouDN = $ou.DistinguishedName

        # Use Get-ADObject with nTSecurityDescriptor (works cross-domain via -Server)
        $ouObj = $null
        try {
            $ouObj = Get-ADObject -Identity $ouDN -Server $server -Properties nTSecurityDescriptor,CanonicalName -ErrorAction Stop
        } catch {
            continue
        }
        if (-not $ouObj.nTSecurityDescriptor) { continue }
        $acl = $ouObj.nTSecurityDescriptor
        $objectPath = $ouObj.CanonicalName

        foreach ($ace in $acl.Access) {
            $identity = $ace.IdentityReference.Value
            if ([string]::IsNullOrWhiteSpace($identity)) { continue }

            # Resolve well-known SIDs that appear as raw SIDs
            if ($identity -match '^S-1-') {
                try {
                    $sidObj = New-Object System.Security.Principal.SecurityIdentifier($identity)
                    $resolved = $sidObj.Translate([System.Security.Principal.NTAccount]).Value
                    $identity = $resolved
                } catch { }
            }

            $isBuiltIn = Test-BuiltInPrincipal -Identity $identity
            $isInherited = $ace.IsInherited

            if ($isBuiltIn) { $domBuiltIn++; $BuiltInACECount++ }
            if ($isInherited) { $domInherited++; $InheritedACECount++ }
            if (-not $isInherited) { $domExplicit++; $ExplicitACECount++ }

            # For main report: skip built-in and (optionally) inherited
            if ($isBuiltIn) { continue }
            if ($isInherited -and -not $IncludeInherited) { continue }

            $rights = $ace.ActiveDirectoryRights.ToString()
            $objectTypeName = Resolve-GUID -Guid $ace.ObjectType.Guid
            $inheritedObjTypeName = Resolve-GUID -Guid $ace.InheritedObjectType.Guid
            $risk = Get-RiskLevel -Rights $rights -ObjectTypeName $objectTypeName

            # Determine domain context of principal
            $principalDomain = '--'
            $isCrossDomain = $false
            if ($identity -match '^(?<dom>[^\\]+)\\') {
                $principalDomain = $Matches['dom']
                if ($principalDomain -ne $domNetBIOS -and $principalDomain -notin @('NT AUTHORITY','BUILTIN')) {
                    $isCrossDomain = $true
                    $CrossDomainCount++
                }
            } elseif ($identity -match '^S-1-') {
                $principalDomain = 'Unresolved SID'
                $isCrossDomain = $true
                $CrossDomainCount++
            }

            # Build human-readable permission summary
            $permSummary = $rights
            if ($objectTypeName -ne 'All') { $permSummary = "$rights on '$objectTypeName'" }
            if ($inheritedObjTypeName -ne 'All') { $permSummary += " (applies to $inheritedObjTypeName)" }

            $AllDelegations.Add([PSCustomObject]@{
                Domain            = $domainName
                OU                = $objectPath
                OUDN              = $ouDN
                Principal         = $identity
                PrincipalDomain   = $principalDomain
                IsCrossDomain     = $isCrossDomain
                AccessType        = $ace.AccessControlType.ToString()
                Rights            = $rights
                ObjectType        = $objectTypeName
                InheritedObjType  = $inheritedObjTypeName
                IsInherited       = $isInherited
                InheritanceType   = $ace.InheritanceType.ToString()
                PermissionSummary = $permSummary
                Risk              = $risk
            })
        }
    }

    $DomainStats += [PSCustomObject]@{
        Domain=$domainName; OUs=$ous.Count; Explicit=$domExplicit;
        Inherited=$domInherited; BuiltIn=$domBuiltIn
    }
}

Write-Host ""
Write-Host "  [+] Delegation scan complete." -ForegroundColor Green
Write-Host "      Total OUs: $OUCountTotal | Custom ACEs: $($AllDelegations.Count) | Built-in (excluded): $BuiltInACECount" -ForegroundColor White

# ==============================================================================
# PHASE 4: BUILT-IN PRIVILEGED GROUP AUDIT
# ==============================================================================
Write-Host ""
Write-Host "  [*] Auditing built-in privileged groups ..." -ForegroundColor Yellow

$PrivGroupAudit = [System.Collections.Generic.List[object]]::new()
$PrivGroupSummary = [System.Collections.Generic.List[object]]::new()

$GroupsToAudit = @(
    @{Name='Domain Admins';       Scope='Domain';  Guidance='Keep 2-5 members. Use for domain-level administration only.'}
    @{Name='Enterprise Admins';   Scope='Forest';  Guidance='Should be EMPTY day-to-day. Add members only when needed.'}
    @{Name='Schema Admins';       Scope='Forest';  Guidance='Should be EMPTY. Only populate for schema changes.'}
    @{Name='Administrators';      Scope='Domain';  Guidance='Should only contain Domain Admins as nested member.'}
    @{Name='Account Operators';   Scope='Domain';  Guidance='Should be EMPTY. Can create/modify users and groups.'}
    @{Name='Server Operators';    Scope='Domain';  Guidance='Should be EMPTY. Can log on to DCs and manage services.'}
    @{Name='Print Operators';     Scope='Domain';  Guidance='Should be EMPTY. Can log on to DCs and load kernel drivers.'}
    @{Name='Backup Operators';    Scope='Domain';  Guidance='Should be EMPTY or minimal. Can read any file on DCs including NTDS.dit.'}
    @{Name='DnsAdmins';           Scope='Domain';  Guidance='Tightly control. Can load arbitrary DLLs on DNS server (often a DC).'}
    @{Name='Group Policy Creator Owners'; Scope='Domain'; Guidance='Control carefully. Can create GPOs that affect entire domain.'}
)

foreach ($domainEntry in $allDomains) {
    $domainName = $domainEntry.Name
    $server = $null
    try {
        $domObj = Get-ADDomain -Identity $domainName -ErrorAction Stop
        $server = $domObj.PDCEmulator
    } catch { continue }

    foreach ($grp in $GroupsToAudit) {
        # Forest-scoped groups only in root domain
        if ($grp.Scope -eq 'Forest' -and $domainName -ne $Forest.RootDomain) { continue }

        try {
            $directMembers = @(Get-ADGroupMember -Identity $grp.Name -Server $server -ErrorAction Stop)

            # Also get recursive members to find actual humans behind nested groups
            $allEffectiveMembers = @()
            try { $allEffectiveMembers = @(Get-ADGroupMember -Identity $grp.Name -Server $server -Recursive -ErrorAction SilentlyContinue) } catch { $allEffectiveMembers = $directMembers }
            $effectiveUserCount = @($allEffectiveMembers | Where-Object { $_.objectClass -eq 'user' }).Count

            $memberCount = $directMembers.Count

            # Determine risk
            $risk = 'Low'
            if ($grp.Name -in @('Account Operators','Server Operators','Print Operators','Backup Operators','Schema Admins','Enterprise Admins')) {
                if ($effectiveUserCount -gt 0) { $risk = 'Critical' }
            } elseif ($grp.Name -eq 'Domain Admins') {
                if ($effectiveUserCount -gt 5) { $risk = 'High' }
                elseif ($effectiveUserCount -ge 2) { $risk = 'Low' }
                else { $risk = 'Medium' }
            } elseif ($grp.Name -eq 'DnsAdmins') {
                if ($effectiveUserCount -gt 2) { $risk = 'High' }
                elseif ($effectiveUserCount -gt 0) { $risk = 'Medium' }
            } elseif ($grp.Name -eq 'Group Policy Creator Owners') {
                if ($effectiveUserCount -gt 3) { $risk = 'Medium' }
            }

            $memberNames = ($directMembers | ForEach-Object { $_.Name }) -join ', '

            $PrivGroupSummary.Add([PSCustomObject]@{
                Domain=$domainName; Group=$grp.Name; DirectMembers=$memberCount;
                EffectiveUsers=$effectiveUserCount;
                MemberNames=$memberNames; Scope=$grp.Scope; Risk=$risk;
                Guidance=$grp.Guidance
            })

            # Detailed per-member entries (direct members)
            foreach ($m in $directMembers) {
                $mType = $m.objectClass
                $isDisabled = $false
                $isServiceAcct = $false
                $nestedCount = 0
                try {
                    if ($mType -eq 'user') {
                        $usr = Get-ADUser $m.SID -Server $server -Properties Enabled,servicePrincipalName -ErrorAction SilentlyContinue
                        $isDisabled = -not $usr.Enabled
                        $isServiceAcct = ($usr.servicePrincipalName -and @($usr.servicePrincipalName).Count -gt 0)
                    } elseif ($mType -eq 'group') {
                        try { $nestedCount = @(Get-ADGroupMember -Identity $m.SID -Server $server -Recursive -ErrorAction SilentlyContinue).Count } catch { }
                    }
                } catch { }

                $memberRisk = 'Low'
                if ($isDisabled) { $memberRisk = 'High' }
                if ($isServiceAcct) { $memberRisk = 'High' }
                if ($grp.Name -in @('Account Operators','Server Operators','Print Operators','Backup Operators')) { $memberRisk = 'Critical' }

                $finding = 'Active member'
                if ($isDisabled) { $finding = 'DISABLED account still in privileged group' }
                elseif ($isServiceAcct) { $finding = 'SERVICE ACCOUNT in privileged group' }
                elseif ($mType -eq 'group') { $finding = "Nested group ($nestedCount effective members inside)" }

                $PrivGroupAudit.Add([PSCustomObject]@{
                    Domain=$domainName; Group=$grp.Name; MemberName=$m.Name;
                    MemberType=$mType; IsDisabled=$isDisabled; IsServiceAccount=$isServiceAcct;
                    NestedMembers=if($mType -eq 'group'){$nestedCount}else{'--'};
                    Risk=$memberRisk; Finding=$finding
                })
            }
        } catch {
            # Group may not exist in this domain
        }
    }
}

Write-Host "  [+] Privileged group audit complete ($($PrivGroupSummary.Count) groups, $($PrivGroupAudit.Count) members)" -ForegroundColor Green

# ==============================================================================
# PHASE 5: ANALYSIS & TABLE BUILDING
# ==============================================================================
Write-Host ""
Write-Host "  [*] Building report ..." -ForegroundColor Yellow

# Stats
$TotalCustom  = $AllDelegations.Count
$CriticalDel  = @($AllDelegations | Where-Object { $_.Risk -eq 'Critical' }).Count
$HighDel      = @($AllDelegations | Where-Object { $_.Risk -eq 'High' }).Count
$MediumDel    = @($AllDelegations | Where-Object { $_.Risk -eq 'Medium' }).Count
$LowDel       = @($AllDelegations | Where-Object { $_.Risk -eq 'Low' }).Count
$ExplicitDel  = @($AllDelegations | Where-Object { -not $_.IsInherited }).Count
$InheritedDel = @($AllDelegations | Where-Object { $_.IsInherited }).Count

# Top 15 principals by delegation count
$TopPrincipals = $AllDelegations | Group-Object Principal | Sort-Object Count -Descending | Select-Object -First 15 |
    ForEach-Object { [PSCustomObject]@{Principal=$_.Name; Count=$_.Count; Domains=($_.Group.Domain | Sort-Object -Unique) -join ', '} }

# Top 15 delegated OUs
$TopOUs = $AllDelegations | Where-Object { -not $_.IsInherited } | Group-Object OUDN | Sort-Object Count -Descending | Select-Object -First 15 |
    ForEach-Object { [PSCustomObject]@{OU=$_.Name; DelegationCount=$_.Count; Principals=(@($_.Group.Principal | Sort-Object -Unique | Select-Object -First 5) -join ', ')} }

# Cross-domain delegations
$CrossDomainDel = @($AllDelegations | Where-Object { $_.IsCrossDomain })

# High-risk table (Critical + High only)
$HighRiskDel = @($AllDelegations | Where-Object { $_.Risk -in @('Critical','High') } | Sort-Object Risk, Domain, OU)

# Rights distribution
$RightsDist = @{}
$AllDelegations | ForEach-Object {
    $r = $_.Rights -replace ',.*',''
    $r = $r.Trim()
    if ($RightsDist.ContainsKey($r)) { $RightsDist[$r]++ } else { $RightsDist[$r] = 1 }
}

# Build HTML tables using StringBuilder for performance
function Build-HtmlTable {
    param($Data, [string[]]$Props, [int]$Limit=500)
    if (-not $Data -or @($Data).Count -eq 0) { return '<p class="empty-note">No data found.</p>' }
    $rows = @($Data) | Select-Object -First $Limit
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.Append('<div class="table-wrap"><table><thead><tr>')
    foreach ($p in $Props) { [void]$sb.Append("<th>$(HtmlEncode $p)</th>") }
    [void]$sb.Append('</tr></thead><tbody>')
    foreach ($row in $rows) {
        [void]$sb.Append('<tr>')
        foreach ($p in $Props) {
            $val = $row.$p
            if ($val -is [System.Collections.IEnumerable] -and $val -isnot [string]) { $val = ($val | ForEach-Object { [string]$_ }) -join ", " }
            if ($p -eq 'Risk') {
                $color = Get-RiskColor $val
                [void]$sb.Append("<td><span style=`"color:$color;font-weight:700`">$(HtmlEncode $val)</span></td>")
            } else {
                [void]$sb.Append("<td>$(HtmlEncode $val)</td>")
            }
        }
        [void]$sb.Append('</tr>')
    }
    [void]$sb.Append('</tbody></table></div>')
    if (@($Data).Count -gt $Limit) { [void]$sb.Append("<p class=`"empty-note`">Showing first $Limit of $(@($Data).Count) entries.</p>") }
    return $sb.ToString()
}

$HighRiskTable     = Build-HtmlTable -Data $HighRiskDel -Props @('Domain','OU','Principal','Rights','ObjectType','InheritedObjType','PermissionSummary','Risk') -Limit 500
$TopPrincTable     = Build-HtmlTable -Data $TopPrincipals -Props @('Principal','Count','Domains')
$TopOUTable        = Build-HtmlTable -Data $TopOUs -Props @('OU','DelegationCount','Principals')
$CrossDomTable     = Build-HtmlTable -Data $CrossDomainDel -Props @('Domain','OU','Principal','PrincipalDomain','Rights','ObjectType','Risk') -Limit 200
$DomainStatsTable  = Build-HtmlTable -Data $DomainStats -Props @('Domain','OUs','Explicit','Inherited','BuiltIn')
$AllDelTable       = Build-HtmlTable -Data ($AllDelegations | Sort-Object Risk -Descending) -Props @('Domain','OU','Principal','AccessType','Rights','ObjectType','InheritedObjType','IsInherited','PermissionSummary','Risk') -Limit 1000

# Privileged group tables
$PrivSummaryTable  = Build-HtmlTable -Data ($PrivGroupSummary | Sort-Object Risk -Descending) -Props @('Domain','Group','DirectMembers','EffectiveUsers','MemberNames','Scope','Risk','Guidance')
$PrivDetailTable   = Build-HtmlTable -Data ($PrivGroupAudit | Sort-Object Risk -Descending) -Props @('Domain','Group','MemberName','MemberType','IsDisabled','IsServiceAccount','NestedMembers','Risk','Finding')

# Misused groups (non-empty groups that should be empty)
$MisusedGroups = @($PrivGroupSummary | Where-Object { $_.EffectiveUsers -gt 0 -and $_.Group -in @('Account Operators','Server Operators','Print Operators','Backup Operators','Schema Admins') })
$MisusedTable  = Build-HtmlTable -Data $MisusedGroups -Props @('Domain','Group','DirectMembers','EffectiveUsers','MemberNames','Risk','Guidance')

# Chart JSON
$RiskChartJSON    = '{"Critical":' + $CriticalDel + ',"High":' + $HighDel + ',"Medium":' + $MediumDel + ',"Low":' + $LowDel + '}'
$ExplInhJSON      = '{"Explicit":' + $ExplicitDel + ',"Inherited":' + $InheritedDel + '}'
$TopPrincJSON     = '{' + (($TopPrincipals | Select-Object -First 10 | ForEach-Object { '"' + ($_.Principal -replace '"','') + '":' + $_.Count }) -join ',') + '}'
if ($TopPrincJSON -eq '{}') { $TopPrincJSON = '{"None":0}' }
$TopOUJSON        = '{' + (($TopOUs | Select-Object -First 10 | ForEach-Object { $ouShort = ($_.OU -split ',')[0] -replace 'OU=',''; '"' + $ouShort + '":' + $_.DelegationCount }) -join ',') + '}'
if ($TopOUJSON -eq '{}') { $TopOUJSON = '{"None":0}' }
$DomainDelJSON    = '{' + (($DomainStats | ForEach-Object { '"' + $_.Domain + '":' + $_.Explicit }) -join ',') + '}'
if ($DomainDelJSON -eq '{}') { $DomainDelJSON = '{"None":0}' }
$RightsJSON       = '{' + (($RightsDist.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 8 | ForEach-Object { '"' + ($_.Key -replace '"','') + '":' + $_.Value }) -join ',') + '}'
if ($RightsJSON -eq '{}') { $RightsJSON = '{"None":0}' }

$PrivGrpRiskJSON = '{"Critical":' + @($PrivGroupSummary | Where-Object {$_.Risk -eq 'Critical'}).Count + ',"High":' + @($PrivGroupSummary | Where-Object {$_.Risk -eq 'High'}).Count + ',"Medium":' + @($PrivGroupSummary | Where-Object {$_.Risk -eq 'Medium'}).Count + ',"Low":' + @($PrivGroupSummary | Where-Object {$_.Risk -eq 'Low'}).Count + '}'

# ==============================================================================
# HTML REPORT
# ==============================================================================
$HTML = @"
<!--
================================================================================
  DelegationCanvas -- AD Delegation & Permission Report
  Generated : $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
  Author    : Santhosh Sivarajan, Microsoft MVP
  GitHub    : https://github.com/SanthoshSivarajan/DelegationCanvas
================================================================================
-->
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<meta name="author" content="Santhosh Sivarajan, Microsoft MVP"/>
<title>DelegationCanvas -- $ForestName</title>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{--bg:#0f172a;--surface:#1e293b;--surface2:#273548;--border:#334155;--text:#e2e8f0;--text-dim:#94a3b8;--accent:#60a5fa;--accent2:#22d3ee;--green:#34d399;--red:#f87171;--amber:#fbbf24;--purple:#a78bfa;--pink:#f472b6;--orange:#fb923c;--radius:8px;--shadow:0 1px 3px rgba(0,0,0,.3);--font-body:'Segoe UI',system-ui,sans-serif}
html{scroll-behavior:smooth;font-size:15px}body{font-family:var(--font-body);background:var(--bg);color:var(--text);line-height:1.65;min-height:100vh}a{color:var(--accent);text-decoration:none}a:hover{text-decoration:underline}
.wrapper{display:flex;min-height:100vh}.sidebar{position:fixed;top:0;left:0;width:260px;height:100vh;background:var(--surface);border-right:1px solid var(--border);overflow-y:auto;padding:20px 0;z-index:100;box-shadow:2px 0 12px rgba(0,0,0,.3)}.sidebar::-webkit-scrollbar{width:4px}.sidebar::-webkit-scrollbar-thumb{background:var(--border);border-radius:4px}.sidebar .logo{padding:0 18px 14px;border-bottom:1px solid var(--border);margin-bottom:8px}.sidebar .logo h2{font-size:1.05rem;color:var(--accent);font-weight:700}.sidebar .logo p{font-size:.68rem;color:var(--text-dim);margin-top:2px}.sidebar nav a{display:block;padding:5px 18px 5px 22px;font-size:.78rem;color:var(--text-dim);border-left:3px solid transparent;transition:all .15s}.sidebar nav a:hover,.sidebar nav a.active{color:var(--accent);background:rgba(96,165,250,.08);border-left-color:var(--accent);text-decoration:none}.sidebar nav .nav-group{font-size:.62rem;text-transform:uppercase;letter-spacing:.08em;color:var(--accent2);padding:10px 18px 2px;font-weight:700}
.main{margin-left:260px;flex:1;padding:24px 32px 50px;max-width:1200px}.section{margin-bottom:36px}.section-title{font-size:1.25rem;font-weight:700;color:var(--text);margin-bottom:4px;padding-bottom:8px;border-bottom:2px solid var(--border);display:flex;align-items:center;gap:8px}.section-title .icon{width:24px;height:24px;border-radius:6px;display:flex;align-items:center;justify-content:center;font-size:.8rem;flex-shrink:0}.sub-header{font-size:.92rem;color:var(--text);margin:16px 0 8px;padding-bottom:4px;border-bottom:1px solid var(--border)}.section-desc{color:var(--text-dim);font-size:.84rem;margin-bottom:14px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:10px;margin-bottom:16px}.card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:14px 16px;box-shadow:var(--shadow)}.card:hover{border-color:var(--accent)}.card .card-val{font-size:1.5rem;font-weight:800;line-height:1.1}.card .card-label{font-size:.68rem;color:var(--text-dim);margin-top:2px;text-transform:uppercase;letter-spacing:.05em}
.table-wrap{overflow-x:auto;margin-bottom:8px;border-radius:var(--radius);border:1px solid var(--border);box-shadow:var(--shadow)}table{width:100%;border-collapse:collapse;font-size:.75rem}thead{background:rgba(96,165,250,.1)}th{text-align:left;padding:8px 10px;font-weight:600;color:var(--accent);white-space:nowrap;border-bottom:2px solid var(--border)}td{padding:6px 10px;border-bottom:1px solid var(--border);color:var(--text-dim);max-width:320px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}tbody tr:hover{background:rgba(96,165,250,.06)}tbody tr:nth-child(even){background:var(--surface2)}.empty-note{color:var(--text-dim);font-style:italic;padding:8px 0}
.exec-summary{background:linear-gradient(135deg,#1e293b 0%,#1e3a5f 100%);border:1px solid #334155;border-radius:var(--radius);padding:22px 26px;margin-bottom:28px;box-shadow:var(--shadow)}.exec-summary h2{font-size:1.1rem;color:var(--accent);margin-bottom:8px}.exec-summary p{color:var(--text-dim);font-size:.86rem;line-height:1.7;margin-bottom:6px}.exec-kv{display:inline-block;background:var(--surface2);border:1px solid var(--border);border-radius:6px;padding:2px 8px;margin:2px;font-size:.78rem;color:var(--text)}.exec-kv strong{color:var(--accent2)}
.footer{margin-top:36px;padding:18px 0;border-top:1px solid var(--border);text-align:center;color:var(--text-dim);font-size:.74rem}.footer a{color:var(--accent)}
@media print{.sidebar{display:none}.main{margin-left:0}body{background:#fff;color:#222}.card,.exec-summary{background:#f9f9f9;border-color:#ccc;color:#222}.card-val,.section-title{color:#222}th{color:#333;background:#eee}td{color:#444}}
@media(max-width:900px){.sidebar{display:none}.main{margin-left:0;padding:14px}}
</style>
</head>
<body>
<div class="wrapper">
<aside class="sidebar">
  <div class="logo"><h2>DelegationCanvas</h2><p>Developed by Santhosh Sivarajan</p><p style="margin-top:6px">Forest: <strong style="color:#e2e8f0">$ForestName</strong></p></div>
  <nav>
    <div class="nav-group">Overview</div>
    <a href="#summary">Executive Summary</a>
    <a href="#domain-stats">Domain Statistics</a>
    <div class="nav-group">Delegations</div>
    <a href="#high-risk">High-Risk Delegations</a>
    <a href="#top-principals">Top Principals</a>
    <a href="#top-ous">Top Delegated OUs</a>
    <a href="#cross-domain">Cross-Domain</a>
    <div class="nav-group">Built-In Audit</div>
    <a href="#priv-groups">Privileged Group Audit</a>
    <a href="#misused-groups">Misused Groups</a>
    <a href="#priv-members">Member Details</a>
    <div class="nav-group">Details</div>
    <a href="#all-delegations">All Delegations</a>
    <a href="#charts">Charts</a>
  </nav>
</aside>
<main class="main">

<div id="summary" class="section">
  <div class="exec-summary">
    <h2>AD Delegation Report -- $ForestName</h2>
    <p>Comprehensive delegation and permission analysis across <strong>$($allDomains.Count)</strong> domains, generated on <strong>$(Get-Date -Format "MMMM dd, yyyy 'at' HH:mm")</strong>.</p>
    <p>
      <span class="exec-kv"><strong>Forest:</strong> $ForestName</span>
      <span class="exec-kv"><strong>Domains:</strong> $($allDomains.Count)</span>
      <span class="exec-kv"><strong>OUs Scanned:</strong> $OUCountTotal</span>
      <span class="exec-kv"><strong>Custom Delegations:</strong> $TotalCustom</span>
      <span class="exec-kv"><strong>Built-In (excluded):</strong> $BuiltInACECount</span>
      <span class="exec-kv" style="color:#f87171"><strong>Critical:</strong> $CriticalDel</span>
      <span class="exec-kv" style="color:#fb923c"><strong>High:</strong> $HighDel</span>
      <span class="exec-kv" style="color:#fbbf24"><strong>Medium:</strong> $MediumDel</span>
      <span class="exec-kv" style="color:#34d399"><strong>Low:</strong> $LowDel</span>
      <span class="exec-kv"><strong>Cross-Domain:</strong> $CrossDomainCount</span>
      <span class="exec-kv"><strong>Explicit:</strong> $ExplicitDel</span>
      <span class="exec-kv"><strong>Inherited:</strong> $InheritedDel</span>
    </p>
  </div>
</div>

<div id="domain-stats" class="section">
  <h2 class="section-title"><span class="icon" style="background:rgba(96,165,250,.15);color:var(--accent)">&#127760;</span> Domain Statistics</h2>
  $DomainStatsTable
</div>

<div id="high-risk" class="section">
  <h2 class="section-title"><span class="icon" style="background:rgba(248,113,113,.15);color:var(--red)">&#9888;</span> High-Risk Delegations ($($HighRiskDel.Count))</h2>
  <p class="section-desc">Delegations with Critical or High risk: GenericAll, WriteDACL, WriteOwner, GenericWrite, sensitive WriteProperty, and ExtendedRight on replication or all objects.</p>
  <div class="cards">
    <div class="card"><div class="card-val" style="color:#f87171">$CriticalDel</div><div class="card-label">Critical</div></div>
    <div class="card"><div class="card-val" style="color:#fb923c">$HighDel</div><div class="card-label">High</div></div>
    <div class="card"><div class="card-val" style="color:#fbbf24">$MediumDel</div><div class="card-label">Medium</div></div>
    <div class="card"><div class="card-val" style="color:#34d399">$LowDel</div><div class="card-label">Low</div></div>
  </div>
  $HighRiskTable
</div>

<div id="top-principals" class="section">
  <h2 class="section-title"><span class="icon" style="background:rgba(167,139,250,.15);color:var(--purple)">&#128101;</span> Top Delegated Principals</h2>
  <p class="section-desc">Principals with the most custom delegation entries across the forest. Review for excessive permissions.</p>
  $TopPrincTable
</div>

<div id="top-ous" class="section">
  <h2 class="section-title"><span class="icon" style="background:rgba(251,191,36,.15);color:var(--amber)">&#128193;</span> Top Delegated OUs</h2>
  <p class="section-desc">OUs with the most explicit (non-inherited) delegation entries. These are delegation hotspots.</p>
  $TopOUTable
</div>

<div id="cross-domain" class="section">
  <h2 class="section-title"><span class="icon" style="background:rgba(34,211,238,.15);color:var(--accent2)">&#128260;</span> Cross-Domain Delegations ($CrossDomainCount)</h2>
  <p class="section-desc">Permissions granted to principals from other domains or unresolved SIDs (trust-related).</p>
  $CrossDomTable
</div>

<div id="priv-groups" class="section">
  <h2 class="section-title"><span class="icon" style="background:rgba(248,113,113,.15);color:var(--red)">&#128737;</span> Built-In Privileged Group Audit</h2>
  <p class="section-desc">Audit of built-in AD groups that grant elevated privileges. Groups like Account Operators, Print Operators, Server Operators, and Backup Operators should have ZERO members in most environments.</p>
  $PrivSummaryTable
</div>

<div id="misused-groups" class="section">
  <h2 class="section-title"><span class="icon" style="background:rgba(248,113,113,.15);color:var(--red)">&#9888;</span> Misused Built-In Groups</h2>
  <p class="section-desc">Built-in groups that should be empty but have members. These are commonly abused by attackers and are often misconfigured.</p>
  $MisusedTable
</div>

<div id="priv-members" class="section">
  <h2 class="section-title"><span class="icon" style="background:rgba(251,146,60,.15);color:var(--orange)">&#128100;</span> Privileged Group Member Details ($($PrivGroupAudit.Count))</h2>
  <p class="section-desc">Every member in audited privileged groups with risk flags for disabled accounts and service accounts.</p>
  $PrivDetailTable
</div>

<div id="all-delegations" class="section">
  <h2 class="section-title"><span class="icon" style="background:rgba(96,165,250,.15);color:var(--accent)">&#128220;</span> All Custom Delegations ($TotalCustom)</h2>
  <p class="section-desc">Complete list of custom (non-built-in) delegations with GUID-translated permissions.$(if(-not $IncludeInherited){' Inherited permissions are excluded -- use -IncludeInherited to include them.'}else{''})</p>
  $AllDelTable
</div>

<div id="charts" class="section">
  <h2 class="section-title"><span class="icon" style="background:rgba(96,165,250,.15);color:var(--accent)">&#128202;</span> Charts</h2>
  <div id="chartsContainer" style="display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:14px"></div>
</div>

<div class="footer">
  DelegationCanvas v1.0 -- AD Delegation & Permission Report -- $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")<br>
  Developed by <a href="https://github.com/SanthoshSivarajan">Santhosh Sivarajan</a>, Microsoft MVP --
  <a href="https://github.com/SanthoshSivarajan/DelegationCanvas">github.com/SanthoshSivarajan/DelegationCanvas</a>
</div>
</main>
</div>
<script>
var COLORS=['#60a5fa','#34d399','#f87171','#fbbf24','#a78bfa','#f472b6','#22d3ee','#fb923c','#a3e635','#e879f9'];
function buildBarChart(t,d,c){var b=document.createElement('div');b.style.cssText='background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:16px;box-shadow:var(--shadow)';var h=document.createElement('h3');h.style.cssText='font-size:.86rem;margin-bottom:10px;color:#e2e8f0';h.textContent=t;b.appendChild(h);var tot=Object.values(d).reduce(function(a,b){return a+b},0);if(!tot){b.innerHTML+='<p style="color:#94a3b8">No data.</p>';c.appendChild(b);return}var g=document.createElement('div');g.style.cssText='display:flex;flex-direction:column;gap:6px';var e=Object.entries(d),ci=0;for(var i=0;i<e.length;i++){var p=((e[i][1]/tot)*100).toFixed(1);var r=document.createElement('div');r.style.cssText='display:flex;align-items:center;gap:8px';r.innerHTML='<span style="width:140px;font-size:.72rem;color:#94a3b8;text-align:right;flex-shrink:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">'+e[i][0]+'</span><div style="flex:1;height:20px;background:#273548;border-radius:4px;overflow:hidden;border:1px solid #334155"><div style="height:100%;border-radius:3px;width:'+p+'%;background:'+COLORS[ci%COLORS.length]+';display:flex;align-items:center;padding:0 6px;font-size:.66rem;font-weight:600;color:#fff;white-space:nowrap">'+p+'%</div></div><span style="width:44px;font-size:.74rem;color:#94a3b8;text-align:right">'+e[i][1]+'</span>';g.appendChild(r);ci++}b.appendChild(g);c.appendChild(b)}
function buildDonut(t,d,c){var b=document.createElement('div');b.style.cssText='background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:16px;box-shadow:var(--shadow)';var h=document.createElement('h3');h.style.cssText='font-size:.86rem;margin-bottom:10px;color:#e2e8f0';h.textContent=t;b.appendChild(h);var tot=Object.values(d).reduce(function(a,b){return a+b},0);if(!tot){b.innerHTML+='<p style="color:#94a3b8">No data.</p>';c.appendChild(b);return}var dc=document.createElement('div');dc.style.cssText='display:flex;align-items:center;gap:18px;flex-wrap:wrap';var sz=130,cx=65,cy=65,r=48,cf=2*Math.PI*r;var s='<svg width="'+sz+'" height="'+sz+'" viewBox="0 0 '+sz+' '+sz+'">';var off=0,ci=0,e=Object.entries(d);for(var i=0;i<e.length;i++){var pc=e[i][1]/tot,da=pc*cf,ga=cf-da;s+='<circle cx="'+cx+'" cy="'+cy+'" r="'+r+'" fill="none" stroke="'+COLORS[ci%COLORS.length]+'" stroke-width="14" stroke-dasharray="'+da.toFixed(2)+' '+ga.toFixed(2)+'" stroke-dashoffset="'+(-off).toFixed(2)+'" transform="rotate(-90 '+cx+' '+cy+')" />';off+=da;ci++}s+='<text x="'+cx+'" y="'+cy+'" text-anchor="middle" dominant-baseline="central" fill="#e2e8f0" font-size="18" font-weight="700">'+tot+'</text></svg>';dc.innerHTML=s;var lg=document.createElement('div');lg.style.cssText='display:flex;flex-direction:column;gap:3px';ci=0;for(var i=0;i<e.length;i++){var pc=((e[i][1]/tot)*100).toFixed(1);var it=document.createElement('div');it.style.cssText='display:flex;align-items:center;gap:6px;font-size:.74rem;color:#94a3b8';it.innerHTML='<span style="width:10px;height:10px;border-radius:2px;background:'+COLORS[ci%COLORS.length]+';flex-shrink:0"></span>'+e[i][0]+': '+e[i][1]+' ('+pc+'%)';lg.appendChild(it);ci++}dc.appendChild(lg);b.appendChild(dc);c.appendChild(b)}
(function(){var c=document.getElementById('chartsContainer');if(!c)return;
buildDonut('Risk Distribution',$RiskChartJSON,c);
buildDonut('Explicit vs Inherited',$ExplInhJSON,c);
buildBarChart('Top Principals by Delegation Count',$TopPrincJSON,c);
buildBarChart('Top Delegated OUs',$TopOUJSON,c);
buildBarChart('Delegations per Domain',$DomainDelJSON,c);
buildBarChart('Rights Distribution',$RightsJSON,c);
buildDonut('Privileged Group Risk',$PrivGrpRiskJSON,c);
})();
(function(){var lk=document.querySelectorAll('.sidebar nav a');var sc=[];for(var i=0;i<lk.length;i++){var id=lk[i].getAttribute('href');if(id&&id.charAt(0)==='#'){var el=document.querySelector(id);if(el)sc.push({el:el,link:lk[i]})}}window.addEventListener('scroll',function(){var cur=sc[0];for(var i=0;i<sc.length;i++){if(sc[i].el.getBoundingClientRect().top<=120)cur=sc[i]}for(var i=0;i<lk.length;i++)lk[i].classList.remove('active');if(cur)cur.link.classList.add('active')})})();
</script>
</body>
</html>
<!--
================================================================================
  DelegationCanvas -- AD Delegation & Permission Report
  Author : Santhosh Sivarajan, Microsoft MVP
  GitHub : https://github.com/SanthoshSivarajan/DelegationCanvas
================================================================================
-->
"@

$HTML | Out-File -FilePath $OutputFile -Encoding UTF8 -Force
$FileSize = [math]::Round((Get-Item $OutputFile).Length / 1KB, 1)

Write-Host ""
Write-Host "  +============================================================+" -ForegroundColor Green
Write-Host "  |   DelegationCanvas -- Report Generation Complete           |" -ForegroundColor Green
Write-Host "  +============================================================+" -ForegroundColor Green
Write-Host ""
Write-Host "  DELEGATION SUMMARY" -ForegroundColor White
Write-Host "  -------------------" -ForegroundColor Gray
Write-Host "    Forest             : $ForestName" -ForegroundColor White
Write-Host "    Domains Scanned    : $($allDomains.Count)" -ForegroundColor White
Write-Host "    OUs Scanned        : $OUCountTotal" -ForegroundColor White
Write-Host "    Custom Delegations : $TotalCustom (Explicit: $ExplicitDel)" -ForegroundColor White
Write-Host "    Built-In (excl.)   : $BuiltInACECount" -ForegroundColor White
Write-Host "    Critical Risk      : $CriticalDel" -ForegroundColor $(if($CriticalDel -gt 0){'Red'}else{'Green'})
Write-Host "    High Risk          : $HighDel" -ForegroundColor $(if($HighDel -gt 0){'Yellow'}else{'Green'})
Write-Host "    Cross-Domain       : $CrossDomainCount" -ForegroundColor White
Write-Host "    Priv Group Members : $($PrivGroupAudit.Count)" -ForegroundColor White
Write-Host "    Misused Groups     : $($MisusedGroups.Count)" -ForegroundColor $(if($MisusedGroups.Count -gt 0){'Red'}else{'Green'})
Write-Host ""
Write-Host "    Report File : $OutputFile" -ForegroundColor White
Write-Host "    File Size   : $FileSize KB" -ForegroundColor White
Write-Host ""
Write-Host "  +============================================================+" -ForegroundColor Cyan
Write-Host "  |  This report was generated using DelegationCanvas v1.0     |" -ForegroundColor Cyan
Write-Host "  |  Developed by Santhosh Sivarajan, Microsoft MVP            |" -ForegroundColor Cyan
Write-Host "  |  https://github.com/SanthoshSivarajan/DelegationCanvas     |" -ForegroundColor Cyan
Write-Host "  +============================================================+" -ForegroundColor Cyan
Write-Host ""

<#
================================================================================
  DelegationCanvas v1.0 -- AD Delegation & Permission Map
  Author : Santhosh Sivarajan, Microsoft MVP
  GitHub : https://github.com/SanthoshSivarajan/DelegationCanvas
================================================================================
#>
