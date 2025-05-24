<#
.SYNOPSIS
    Detects Domain Controllers running Windows Server 2025 and checks
    Active Directory OUs for identities that can create delegated Managed
    Service Accounts (dMSA), exposing the BadSuccessor privilege-escalation path.

.NOTES
    Requires RSAT / ActiveDirectory PowerShell module.
    Run as a user that can read AD ACLs (Domain Admins or equivalent is safest).

.EXAMPLE
    .\Find-BadSuccessor.ps1
#>

Import-Module ActiveDirectory

# ---------- SECTION 1 : quick sanity checks -------------------------------

Write-Host "`n=== Domain Controllers on Windows Server 2025 ==="
$dcNames2025 = Get-ADComputer -Filter {
        OperatingSystem -like '*2025*' -and
        Enabled -eq $true -and
        PrimaryGroupID -eq 516        # Domain Controllers group RID
    } -Properties OperatingSystem, DistinguishedName |
    Select-Object Name, DistinguishedName

if ($dcNames2025) {
    $dcNames2025 | ForEach-Object {
        Write-Host "$($_.Name) [$($_.DistinguishedName)]  <-- DC is running 2025 (BadSuccessor-capable)" -ForegroundColor Yellow
    }
} else {
    Write-Host "No DCs reporting an OS string that contains '2025'. Continuing anyway…" -ForegroundColor Gray
}

# ---------- SECTION 2 : is the dMSA schema present? -----------------------

$dmsaClass = Get-ADObject `
                 -LDAPFilter '(objectClass=classSchema)(lDAPDisplayName=msDS-DelegatedManagedServiceAccount)' `
                 -SearchBase (Get-ADRootDSE).schemaNamingContext

if (-not $dmsaClass) {
    Write-Warning "dMSA class not found in schema – Windows Server 2025 schema upgrade is absent. BadSuccessor not applicable."
    return
}

# ---------- SECTION 3 : enumerate risky ACLs (BadSuccessor exposure) ------

function Test-IsExcludedSID {
    param([string]$IdRef)
    if ($script:SidCache[$IdRef]) { return $script:SidCache[$IdRef] }

    try {
        $sid = if ($IdRef -match '^S-\d(-\d+)+$') { $IdRef }
               else { (New-Object Security.Principal.NTAccount($IdRef)).Translate([Security.Principal.SecurityIdentifier]).Value }
    } catch { $sid = $null }

    $domainSID = (Get-ADDomain).DomainSID.Value
    $builtIns  = @("$domainSID-512","$domainSID-516","S-1-5-32-544","S-1-5-18","S-1-5-32-548") # Domain Admins, DCs grp, Built-in Admins, SYSTEM, Account Operators
    $isExc = $sid -and ($builtIns -contains $sid -or $sid.EndsWith('-519')) # Enterprise Admins
    $script:SidCache[$IdRef] = $isExc
    return $isExc
}

Write-Host "`n=== Scanning OUs for BadSuccessor exposure ==="
$SidCache          = @{}
$objectGuid_dMSA   = '0feb936f-47b3-49f2-9386-1dedc2c23765'
$relevantRights    = 'CreateChild|GenericAll|WriteDACL|WriteOwner'
$findings          = @()

Get-ADOrganizationalUnit -Filter * -Properties ntSecurityDescriptor |
ForEach-Object {
    $ouDN  = $_.DistinguishedName
    $acl   = $_.ntSecurityDescriptor

    # 1. explicit ACEs
    foreach ($ace in $acl.Access) {
        if ($ace.AccessControlType -ne 'Allow') { continue }
        if ($ace.ActiveDirectoryRights -notmatch $relevantRights) { continue }
        # “All objects” == 0000… or explicit dMSA class GUID
        if ($ace.ObjectType -and $ace.ObjectType.Guid -notin @($objectGuid_dMSA,'00000000-0000-0000-0000-000000000000')) { continue }

        $id = $ace.IdentityReference.Value
        if (-not (Test-IsExcludedSID $id)) {
            $findings += [PSCustomObject]@{
                Identity = $id
                OU       = $ouDN
                Via      = "ACE ($($ace.ActiveDirectoryRights))"
            }
        }
    }

    # 2. OU owners (owning an OU lets you write the DACL => effective)
    $owner = $acl.Owner
    if (-not (Test-IsExcludedSID $owner)) {
        $findings += [PSCustomObject]@{
            Identity = $owner
            OU       = $ouDN
            Via      = 'Owner'
        }
    }
}

if ($findings) {
    Write-Host "`n!!! VULNERABLE – identities below can create a dMSA and trigger BadSuccessor:" -ForegroundColor Red
    $findings | Sort-Object Identity, OU | Format-Table -AutoSize
} else {
    Write-Host "`nNo non-privileged identities with dMSA-creation rights were found. Environment not obviously exposed to BadSuccessor." -ForegroundColor Green
}

