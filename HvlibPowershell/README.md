#
# Hyper-V Memory Manager module for Powershell
#

Installation instructions:

1. Copy **Hvlib** directory with library files to C:\Program Files\WindowsPowerShell\Modules
2. Install Powershell 7 using winget or download it from https://github.com/PowerShell/PowerShell/releases/ 

```
winget list --id Microsoft.PowerShell
winget install --id Microsoft.PowerShell --source winget
winget upgrade --id Microsoft.PowerShell
```

3. Import module in Powershell console:
```
Import-Module -FullyQualifiedName @{ModuleName = 'Hvlib'; ModuleVersion = '1.3.0' }   
```
1. Execute cmdlets:

![](./images/image001.png)

See examples cmdlets usages in Hvlib-Examples.ps.  
See cmdlets usages description [Link](Hvlib_Functions_Reference.md)  
See additional recommendation for AI code generation [Link](AI_DOCUMENTATION_GUIDE.md)  

I set to 1.3.0 version "beta" status, because of many new functions.
The good variant to share powershell module with LiveCloudKd distributive, because of similar functions in hvlib.dll and Hvlib Powershell module. I will upload it later, after more count of testing.
If you need some fixes to beta variant - you can open issue.
 