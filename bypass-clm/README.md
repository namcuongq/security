# PowerShell Constrained Language Mode Bypass

This will build an executable which executes a Full Language Mode powershell session even when Constrained Language Mode is enabled. At the time of writing, the only bypass methods I have found are downgrading to PowerShell version 2 or using Runspaces from .Net. PowerShell version 2 is not commonly available now, and Runspaces do not natively provide an interactive interface. This method will provide a full powershell session just like running `powershell.exe`, but will *always* be in Full Language Mode.

```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U "C:\Windows\Tasks\bypass-clm.exe"
```