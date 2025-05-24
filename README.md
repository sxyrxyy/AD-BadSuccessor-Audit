# AD-BadSuccessor-Audit
> Detects Active Directory environments that are vulnerable to **BadSuccessor** (Akamai Security Labs, 2025) by auditing  
> *Domain Controllers*, *schema*, and *OU ACLs* for dangerous dMSA permissions.

![PowerShell](https://img.shields.io/badge/PowerShell-7+-blue?logo=powershell)
---

## ✨ What it does
* Lists every **enabled Domain Controller** running a Windows build whose *OperatingSystem* string contains **“2025”**.  
* Confirms the **msDS-DelegatedManagedServiceAccount** class is present in the schema (Windows Server 2025 schemas only).  
* Walks every **OU ACL** and flags any non-privileged identity that can:
  * **CreateChild** a dMSA *(object-type GUID `0feb936f-47b3-49f2-9386-1dedc2c23765`)*, or  
  * **GenericAll / WriteDACL / WriteOwner** on the OU (all of which indirectly allow dMSA creation).  
* Prints a concise table: `Identity`, `OU`, `Via` and colours the result **RED** if exposure exists.

## 🗝️ Why you should care
> Attackers with the above rights can craft a delegated Managed Service Account, set  
> `msDS-ManagedAccountPrecededByLink`, flip `msDS-DelegatedMSAState = 2`, then log on as the target -  
> effectively **impersonating Domain Admins** without touching a DC.  
> - “Abusing dMSA for Privilege Escalation”, Akamai (2025)

## 📋 Prerequisites
| Requirement | Notes |
|-------------|-------|
| Windows 10/11 or Server with **RSAT / ActiveDirectory** module installed | `Install-WindowsFeature RSAT-AD-PowerShell` (Server) or *Optional Features* (Workstation) |
| Account able to **read AD ACLs** (Domain Admin or equivalent) | Reading ACLs requires higher privileges than plain user |

## 🚀 Quick start
```powershell
git clone https://github.com/sxyrxyy/AD-BadSuccessor-Audit.git
cd AD-BadSuccessor-Audit
.\Find-BadSuccessor.ps1
