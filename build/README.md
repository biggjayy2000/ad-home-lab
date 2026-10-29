# Rebuilding the lab

The writeup describes a lab that already existed. This directory makes it repeatable: two VMs on a
host-only network, one forest, four accounts.

`New-LabEnvironment.ps1` is a **reconstruction** of the recorded build, written after the fact from the
writeup and the screenshots. It is not a capture of the original session, and where the original setup
details were never recorded, the script says so rather than inventing them.

## What you need

| | |
|---|---|
| Hypervisor | VirtualBox (VMware Workstation works identically) |
| Domain controller | Windows Server 2025 evaluation, 4 GB RAM, 2 vCPU |
| Attacker | Kali Linux, 2 GB RAM |
| Network | Host-only adapter, `192.168.56.0/24`, no NAT, no bridged adapter |

The host-only network is the important part. A lab that can reach your physical LAN is a lab that can
reach someone else's.

## 1. Build the domain controller

Create the VM, install Server 2025, then set a static address on the host-only adapter:

```powershell
New-NetIPAddress -InterfaceAlias 'Ethernet 2' -IPAddress 192.168.56.10 -PrefixLength 24
Set-DnsClientServerAddress -InterfaceAlias 'Ethernet 2' -ServerAddresses 127.0.0.1
Rename-Computer -NewName DC01 -Restart
```

Install the role and promote a new forest:

```powershell
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
Install-ADDSForest -DomainName corp.local -DomainNetbiosName CORP -InstallDns -Force
```

The server reboots twice. Log back in as `CORP\Administrator`.

`Install-ADDSForest` sets the DSRM password interactively and creates the default OUs, `Domain Admins`,
and the built-in Administrator account. Those defaults are what the writeup's "Domain Admins contains
exactly one account" observation depends on — do not add anyone to that group while building.

## 2. Seed the lab objects

```powershell
.\New-LabEnvironment.ps1 -WhatIf      # preview, no changes
.\New-LabEnvironment.ps1              # prompts once for the lab password
```

The script is idempotent — it checks for each object before creating it, so a second run repairs a
half-built lab instead of failing. It also prints a posture report and refuses to claim a control is in
place without reading it back:

```
Posture report
----------------------------------------------------------------
  [ok  ] SMB signing required             True    blocks SMB relay
  [ok  ] SMBv1 disabled                   True    removes a decades-old attack surface
  [ok  ] AS-REP roastable accounts        0       all require pre-auth
  [ok  ] svc_sql has an SPN               True    MSSQLSvc/dc01.corp.local:1433
  [ok  ] Domain Admins membership count   1       Administrator
----------------------------------------------------------------
```

Two deliberate settings in there:

- **Every account requires Kerberos pre-authentication.** That is the Windows default, and the script
  enforces it explicitly because finding 10 in the writeup is the *absence* of a roastable account.
- **`svc_sql` is AES-only by default.** That is what made an RC4 service-ticket request fail with
  `KDC_ERR_ETYPE_NOSUPP`. Pass `-AesOnlyServiceAccount $false` to allow RC4 instead, which reproduces the
  other half of that finding: a crackable hash rather than a refused request.

There is no SQL Server on that host. The SPN advertises `MSSQLSvc` against a database that does not
exist, on purpose — the thing being enumerated is the service principal, not the service.

## 3. Build the attacker

Kali on the same host-only network, `192.168.56.20`. Then confirm the DC is visible:

```bash
nmap -Pn -sV --top-ports 100 192.168.56.10
```

Six ports should answer: `53`, `88`, `135`, `139`, `389`, `445`. If you see more, the firewall profile
differs from the recorded build — that is worth knowing before you start, because the writeup's "94 of
100 ports filtered" line is a statement about the firewall, not the host.

## Teardown

Delete both VMs and the host-only adapter. Nothing in this lab is meant to persist, and a rebuilt domain
starts clean, which is what makes it useful practice for the second run.

## Limits of this script

- It seeds **objects only**. It does not promote the forest, set the firewall profile, or install SQL
  Server.
- It was parse-checked and dry-run against stubbed AD cmdlets on a workstation, not executed against a
  live domain controller. The cmdlets are standard (`New-ADUser`, `Set-ADAccountControl`, `Set-ADUser`)
  and the report logic runs, but the honest statement is "validated as far as it can be off a DC".
- Passwords are prompted for, never stored. The accounts are throwaway and the network is isolated;
  nothing here should be reused on a real domain.
