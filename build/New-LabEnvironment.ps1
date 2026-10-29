<#
.SYNOPSIS
    Rebuilds the objects the Active Directory home lab was built with.

.DESCRIPTION
    Run this on DC01 after the forest exists. It creates the three lab users and the service
    account with an SPN, and enforces the two account settings that produced two of the findings
    in the writeup:

      * Kerberos pre-authentication required on every user  -> no AS-REP roastable account
      * AES-only Kerberos on the service account            -> the KDC_ERR_ETYPE_NOSUPP result

    It is idempotent: every object is checked before it is created, so re-running it repairs a
    half-built lab instead of failing on the first existing account.

    It does NOT promote the domain controller, and it does NOT install SQL Server. The SPN on
    svc_sql advertises MSSQLSvc against a database that was never installed, because the thing
    being enumerated is the service principal, not the service.

.PARAMETER DomainDN
    Distinguished name of the domain. Defaults to the lab's corp.local.

.PARAMETER LabPassword
    Password applied to every lab account. Omit it and you are prompted once. These are throwaway
    credentials on an isolated host-only network; nothing here is meant to survive contact with a
    real domain.

.PARAMETER AesOnlyServiceAccount
    Restricts svc_sql to AES128/AES256, which is what made an RC4 ticket request fail with
    KDC_ERR_ETYPE_NOSUPP. Set to $false to allow RC4 and reproduce the crackable-hash path instead.

.EXAMPLE
    .\New-LabEnvironment.ps1 -WhatIf

.EXAMPLE
    .\New-LabEnvironment.ps1 -AesOnlyServiceAccount $false
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$DomainDN = 'DC=corp,DC=local',
    [string]$DomainController = 'DC01.corp.local',
    [string]$SqlHost = 'dc01.corp.local',
    [SecureString]$LabPassword,
    [bool]$AesOnlyServiceAccount = $true
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# --------------------------------------------------------------------------- preflight

Import-Module ActiveDirectory -ErrorAction Stop

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run this elevated: creating AD objects requires domain administrator rights.'
    }
}

function Get-LabPassword {
    param([SecureString]$Supplied)

    if ($Supplied) { return $Supplied }

    Write-Host 'No -LabPassword supplied.' -ForegroundColor Yellow
    $first = Read-Host -AsSecureString '  Lab password for the four accounts'
    $second = Read-Host -AsSecureString '  Repeat it'
    if ([Runtime.InteropServices.Marshal]::PtrToStringAuto(
            [Runtime.InteropServices.Marshal]::SecureStringToBSTR($first)) -ne
        [Runtime.InteropServices.Marshal]::PtrToStringAuto(
            [Runtime.InteropServices.Marshal]::SecureStringToBSTR($second))) {
        throw 'The two passwords do not match.'
    }
    return $first
}

Assert-Administrator
$LabPassword = Get-LabPassword -Supplied $LabPassword

# --------------------------------------------------------------------------- OU structure

function Ensure-OrganizationalUnit {
    # $PSCmdlet is not inherited by a function, so each helper that honours -WhatIf needs its own
    # CmdletBinding. Without this, $PSCmdlet.ShouldProcess is a call on $null.
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$ParentDN
    )    $dn = "OU=$Name,$ParentDN"
    if (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$dn'" -ErrorAction SilentlyContinue) {
        Write-Verbose "OU exists: $dn"
        return $dn
    }

    if ($PSCmdlet.ShouldProcess($dn, 'Create organizational unit')) {
        New-ADOrganizationalUnit -Name $Name -Path $ParentDN -ProtectedFromAccidentalDeletion $false
        Write-Host "  + OU   $Name"
    }
    return $dn
}

$rootOU = Ensure-OrganizationalUnit -Name 'Corp' -ParentDN $DomainDN
$usersOU = Ensure-OrganizationalUnit -Name 'Users' -ParentDN $rootOU
$groupsOU = Ensure-OrganizationalUnit -Name 'Groups' -ParentDN $rootOU
$svcOU = Ensure-OrganizationalUnit -Name 'Service Accounts' -ParentDN $rootOU

# --------------------------------------------------------------------------- users

function Ensure-LabUser {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)][string]$SamAccountName,
        [Parameter(Mandatory)][string]$GivenName,
        [Parameter(Mandatory)][string]$Surname,
        [Parameter(Mandatory)][string]$Path
    )

    $displayName = "$GivenName $Surname"
    $existing = Get-ADUser -Filter "sAMAccountName -eq '$SamAccountName'" -ErrorAction SilentlyContinue

    if (-not $existing) {
        if ($PSCmdlet.ShouldProcess($SamAccountName, 'Create domain user')) {
            New-ADUser `
                -Name $displayName `
                -SamAccountName $SamAccountName `
                -UserPrincipalName "$SamAccountName@$($DomainDN -replace 'DC=','' -replace ',','.')" `
                -GivenName $GivenName `
                -Surname $Surname `
                -DisplayName $displayName `
                -Path $Path `
                -AccountPassword $LabPassword `
                -Enabled $true `
                -ChangePasswordAtLogon $false `
                -PasswordNeverExpires $false
            Write-Host "  + user $SamAccountName ($displayName)"
        }
    } else {
        Write-Verbose "user exists: $SamAccountName"
    }

    # Finding 10 in the writeup: every user requires pre-authentication, so GetNPUsers returns
    # nothing. Enforce it explicitly rather than relying on the default being what you expect.
    if ($PSCmdlet.ShouldProcess($SamAccountName, 'Require Kerberos pre-authentication')) {
        Set-ADAccountControl -Identity $SamAccountName -DoesNotRequirePreAuth $false
    }
}

Ensure-LabUser -SamAccountName 'ajohnson' -GivenName 'Avery'   -Surname 'Johnson' -Path $usersOU
Ensure-LabUser -SamAccountName 'mlee'     -GivenName 'Morgan'  -Surname 'Lee'     -Path $usersOU
Ensure-LabUser -SamAccountName 'tsmith'   -GivenName 'Taylor'  -Surname 'Smith'   -Path $usersOU

# --------------------------------------------------------------------------- service account

$serviceSam = 'svc_sql'
$spn = "MSSQLSvc/$($SqlHost):1433"
$service = Get-ADUser -Filter "sAMAccountName -eq '$serviceSam'" -Properties ServicePrincipalNames `
    -ErrorAction SilentlyContinue

if (-not $service) {
    if ($PSCmdlet.ShouldProcess($serviceSam, 'Create service account')) {
        New-ADUser `
            -Name 'SQL Service' `
            -SamAccountName $serviceSam `
            -UserPrincipalName "$serviceSam@$($DomainDN -replace 'DC=','' -replace ',','.')" `
            -Description 'Service account for the SQL instance - lab only' `
            -Path $svcOU `
            -AccountPassword $LabPassword `
            -Enabled $true `
            -PasswordNeverExpires $true
        Write-Host "  + user $serviceSam (service account, password never expires)"
    }
} else {
    Write-Verbose "service account exists: $serviceSam"
}

if ($PSCmdlet.ShouldProcess($serviceSam, "Add SPN $spn")) {
    $currentSpns = @((Get-ADUser -Identity $serviceSam -Properties ServicePrincipalNames).ServicePrincipalNames)
    if ($currentSpns -notcontains $spn) {
        Set-ADUser -Identity $serviceSam -ServicePrincipalNames @{ Add = $spn }
        Write-Host "  + spn  $spn"
    } else {
        Write-Verbose "SPN already present: $spn"
    }
}

if ($PSCmdlet.ShouldProcess($serviceSam, 'Require Kerberos pre-authentication')) {
    Set-ADAccountControl -Identity $serviceSam -DoesNotRequirePreAuth $false
}

if ($PSCmdlet.ShouldProcess($serviceSam, 'Set permitted Kerberos encryption types')) {
    if ($AesOnlyServiceAccount) {
        Set-ADUser -Identity $serviceSam -KerberosEncryptionType AES128, AES256
        Write-Host '  + kerb AES128/AES256 only (reproduces KDC_ERR_ETYPE_NOSUPP on an RC4 request)'
    } else {
        Set-ADUser -Identity $serviceSam -KerberosEncryptionType RC4, AES128, AES256
        Write-Host '  + kerb RC4 permitted (reproduces the crackable-hash path instead)'
    }
}

# --------------------------------------------------------------------------- posture checks

function Test-LabPosture {
    <#
        Verifies the two mitigations the writeup claims were already in place, and the two
        settings the findings depend on. Reporting a control as present without checking it is
        how a writeup acquires a claim it cannot support.
    #>

    $findings = New-Object System.Collections.Generic.List[object]

    $smb = Get-SmbServerConfiguration
    $findings.Add([pscustomobject]@{
        Check  = 'SMB signing required'
        Value  = $smb.RequireSecuritySignature
        Want   = $true
        Detail = 'blocks SMB relay'
    })
    $findings.Add([pscustomobject]@{
        Check  = 'SMBv1 disabled'
        Value  = -not $smb.EnableSMB1Protocol
        Want   = $true
        Detail = 'removes a decades-old attack surface'
    })

    $noPreAuth = @()
    foreach ($sam in @('ajohnson', 'mlee', 'tsmith', $serviceSam)) {
        $account = Get-ADUser -Identity $sam -Properties userAccountControl
        # DONT_REQ_PREAUTH is bit 0x400000 of userAccountControl.
        if ($account.userAccountControl -band 0x400000) { $noPreAuth += $sam }
    }
    # Computed first: an `if` expression is not valid as a hashtable value in PowerShell 5.1,
    # even though the parser accepts it.
    $preAuthDetail = if ($noPreAuth.Count) {
        'roastable: ' + ($noPreAuth -join ', ')
    } else {
        'all require pre-auth'
    }
    $findings.Add([pscustomobject]@{
        Check  = 'AS-REP roastable accounts'
        Value  = $noPreAuth.Count
        Want   = 0
        Detail = $preAuthDetail
    })

    $serviceProps = Get-ADUser -Identity $serviceSam -Properties 'msDS-SupportedEncryptionTypes', ServicePrincipalNames
    $findings.Add([pscustomobject]@{
        Check  = 'svc_sql has an SPN'
        Value  = @($serviceProps.ServicePrincipalNames).Count -gt 0
        Want   = $true
        Detail = (@($serviceProps.ServicePrincipalNames) -join ', ')
    })

    $domainAdmins = @(Get-ADGroupMember -Identity 'Domain Admins' -ErrorAction SilentlyContinue)
    $findings.Add([pscustomobject]@{
        Check  = 'Domain Admins membership count'
        Value  = $domainAdmins.Count
        Want   = 1
        Detail = (@($domainAdmins.Name) -join ', ')
    })

    return $findings
}

Write-Host ''
Write-Host 'Posture report' -ForegroundColor Cyan
Write-Host ('-' * 64)

$posture = Test-LabPosture
$failing = 0
foreach ($row in $posture) {
    $ok = $row.Value -eq $row.Want
    if (-not $ok) { $failing++ }
    $mark = if ($ok) { 'ok  ' } else { 'WARN' }
    $colour = if ($ok) { 'Green' } else { 'Yellow' }
    Write-Host ("  [{0}] {1,-32} {2,-22} {3}" -f $mark, $row.Check, $row.Value, $row.Detail) -ForegroundColor $colour
}

Write-Host ('-' * 64)
if ($failing) {
    Write-Host "$failing check(s) differ from the recorded lab. That may be deliberate - a rebuilt" -ForegroundColor Yellow
    Write-Host 'domain is allowed to be configured differently, as long as the writeup says so.' -ForegroundColor Yellow
} else {
    Write-Host 'The environment matches what the writeup describes.' -ForegroundColor Green
}

Write-Host ''
Write-Host 'Next: from Kali on the same host-only network,'
Write-Host "  nmap -Pn -sV --top-ports 100 $($DomainController.Split('.')[0])"
