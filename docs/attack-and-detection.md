# What this lab looks like from the defender's side

The [writeup](../README.md) is written the way an attacker experiences the lab: what answered, what it
gave away, what it refused. This page is the same engagement read from the other end — which Windows
events each step leaves behind, what a detection rule would key on, and which control would have made
the step pointless.

That inversion is the point. Enumeration is quiet, and a lab that only records what was found is half a
lab. Everything below is tied to a step that actually happened.

## Step by step

| Writeup step | Attacker action | MITRE ATT&CK | Telemetry it leaves | Detection logic | Control that would beat it |
|---|---|---|---|---|---|
| §1 `nmap --top-ports 100` | Port sweep | **T1046** Network Service Discovery | No host event; firewall or flow logs only | One source touching 100 ports inside a minute | Scope DC ports to the management subnet; alert on sweep rate |
| §2 DNS queries | Resolve SRV/A records | **T1018** Remote System Discovery | DNS Server debug log (**off by default**) | Burst of `_kerberos._tcp` / `_ldap._tcp` SRV queries from one host | Enable DNS debug logging; restrict recursion to internal clients |
| §3 Anonymous RootDSE | LDAP base-scope search | **T1018** | `1644` LDAP search (needs diagnostic level 2) | LDAP search with an empty base DN and `scope=base` from an unauthenticated source | LDAP signing; restrict 389/636 to management hosts |
| §4 SMB null session | Anonymous share enumeration | **T1135** Network Share Discovery | `4624` logon type 3 with `ANONYMOUS LOGON`; `5140` | `4624` where TargetUserName = `ANONYMOUS LOGON` and LogonType = 3 | `RestrictNullSessAccess=1`, `RestrictAnonymous=1` |
| §5 Authenticate as `ajohnson` | Valid-account network logon | **T1078** Valid Accounts | `4624` logon type 3 | First network logon for that account from a non-domain host | Tiered admin; separate admin workstations |
| §6 Group enumeration | Permission group discovery | **T1069.002** Domain Groups | `4662` (needs a SACL on the object) or `1644` | `1644` filter containing `adminCount=1` or `memberOf` | Audit read access on privileged groups |
| §6 Delegation query | Delegation discovery | **T1069.002** *(no dedicated technique)* | `1644` LDAP search | Filter referencing `userAccountControl` bit `0x80000` (TRUSTED_FOR_DELEGATION) | Inventory unconstrained delegation; move to constrained or RBCD |
| §7 SYSVOL read | Policy discovery | **T1615** Group Policy Discovery | `5145` detailed file share access | `5145` with ShareName matching `\\*\SYSVOL` and a target ending `.pol` or `Groups.xml` | Remove `cpassword` (MS14-025); monitor policy reads |
| §8 `GetNPUsers -no-pass` | AS-REQ without pre-auth | **T1558.004** AS-REP Roasting | `4768` with `PreAuthType = 0` | `4768` where PreAuthType is 0 — there is no legitimate reason for it | Require pre-authentication (the default; the lab confirmed it) |
| §8 `GetUserSPNs -request` | TGS-REQ for a service account | **T1558.003** Kerberoasting | `4769` with `TicketEncryptionType = 0x17` (RC4) | `4769` where encryption is `0x17` **and** ServiceName does not end in `$` | gMSA, or a 25+ character password; AES-only also breaks the RC4 path |
| §8 Clock-skew failure | Failed AS/TGS attempt | *(not a technique — a symptom)* | `4771` with Failure Code `0x25` (`KRB_AP_ERR_SKEW`) | A burst of `4771` / `0x25` from one host | Nothing to fix on the DC: this is the attacker's clock drifting, and it lights up the log |

Three details in that table are worth stating plainly, because they are the parts that are easy to get
wrong:

**`4769` with RC4 is the Kerberoasting signature, and it is not the same as "someone asked for a
ticket".** AES tickets are normal; an RC4 ticket for an account that is not a computer is an attacker
asking for something it can crack offline. The `$` matters — computer accounts end with it, and
machine-account RC4 is routine.

**`4768` with `PreAuthType = 0` means the KDC handed out an AS-REP with no proof of identity.** The lab
found no such accounts, which is why row 9 is a *control that worked* rather than a finding. The rule
is still worth writing, because the next domain will not be this one.

**The clock-skew failure is the loudest thing the whole engagement produced.** Everything that actually
gathered information — LDAP queries, SYSVOL reads, share listings — left either no event or a normal-looking
one. The only entry that stands out is the one that failed. That is the uncomfortable lesson of the lab.

## What you cannot see without changing defaults

| Event | Why it is missing by default |
|---|---|
| `4662` directory object access | Requires an audit SACL on the object. Default SACLs do not audit reads, so LDAP enumeration produces no `4662` |
| `5140` / `5145` share access | Requires "Audit File Share" and object-access auditing to be enabled |
| `1644` LDAP search | Requires `HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics` → `16 LDAP Interface Events` set to `2` |
| DNS query log | Requires DNS Server debug logging to be turned on, and it is verbose enough that most shops leave it off |

So the honest baseline is: on a default domain controller, **five of the eleven steps above leave no
usable event at all.** Detection here is a configuration project before it is a rule-writing project.

## Three rules, written out

Field names differ between collectors (Winlogbeat, Splunk UF, Sentinel), so these are stated as logic
rather than as vendor syntax.

> **Kerberoasting**
> ```
> event:     4769
> filter:    TicketEncryptionType = 0x17  AND  ServiceName does not end with "$"
> group by:  TargetUserName, ServiceName, IpAddress
> alert on:  any single occurrence for a user account
>             OR one account requesting many distinct SPNs in a short window
> ```
> The single-occurrence case is the one that matters. Service accounts are requested on a schedule; a
> workstation asking for eight of them in a minute is not an application.

> **AS-REP roasting**
> ```
> event:     4768
> filter:    PreAuthType = 0
> group by:  TargetUserName, IpAddress
> alert on:  any occurrence
> ```
> Zero legitimate baseline. An account that requires no pre-authentication exists only because someone
> unticked a box.

> **SYSVOL policy harvesting**
> ```
> event:     5145
> filter:    ShareName matches "\\*\SYSVOL"  AND  RelativeTargetName ends with ".pol" or is "Groups.xml"
> group by:  SubjectUserName, IpAddress
> alert on:  reads of policy files from a host that is not a domain controller
> ```
> Domain controllers read SYSVOL constantly. A Kali box reading `Registry.pol` is the anomaly.

## The gap in my own tooling

`logtriage` parses SSH authentication logs and web access logs. **None of the events above appear in
its input.** That is a scoping fact, not a defect — but it is the honest headline of this page: the
enumeration in this lab would be invisible to the detection tool I built, because the tool watches the
wrong surface for this attack.

The fix is a Windows event parser with the same shape as the existing log parsers, and rule families
for `4768`/`4769`/`4771`/`5145`. That is the next piece of work, and it is written down here rather than
quietly left out.

## Limits

- These rules are written from documented event fields and the events this lab would produce. **They
  have not been run against a live SIEM**, and I am not going to claim a detection rate for a rule that
  has only ever been reasoned about.
- Event field names (`TicketEncryptionType`, `PreAuthType`, `Failure Code`) come from the Windows
  Security event schema and are surfaced differently by each collector.
- The lab is one DC, one workstation, no users doing real work. A production domain has a baseline of
  legitimate `4769` traffic that this one does not, which makes threshold tuning a real exercise rather
  than an afterthought.
