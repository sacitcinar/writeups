# Day-O

### Scenario

Sophia Reyes opened a document review package, but the preview application froze. A Windows memory image was provided to investigate the suspicious activity and recover the document left behind.

| Field | Details |
| --- | --- |
| Platform | TryHackMe |
| Difficulty | Medium |
| Category | Memory Forensics / Malware Analysis |
| Evidence | `memory.mem` |
| Tools | Volatility 3, Speakeasy, Python |
| Author | dmncdcco |

## Overview

The memory analysis identified suspicious executable code in `ReviewClient.exe`. The code was extracted and emulated with Speakeasy, revealing a PowerShell command that decrypts a local document cache. The encrypted file was then recovered from memory, decrypted, and examined for the flag.

## Tasks

### Task 1 — Suspicious Executable

**Question:** Which executable contains the suspicious payload?

- **Answer:** `ReviewClient.exe`

The memory image was examined using Volatility 3's `malfind` plugin:

```bash
cd ~/Desktop/artifacts
vol -f memory.mem windows.malfind
```

The output contained numerous entries, so the results were filtered for memory regions with read-write-execute permissions:

```bash
vol -f memory.mem windows.malfind | grep 'PAGE_EXECUTE_READWRITE'
```

One of the matching entries belonged to `ReviewClient.exe`:

```text
PID   Process          Start VPN   End VPN     Tag   Protection             CommitCharge  PrivateMemory  File output  Notes
6260  ReviewClient.e   0x8e0000    0x8e0fff   VadS  PAGE_EXECUTE_READWRITE 1             1              Disabled     Function prologue
```

The process name was truncated in the Volatility output. Its private executable memory region made it the primary target for further analysis.

### Task 2 — Memory Address

**Question:** What is the starting virtual address of its private executable memory region?

- **Answer:** `0x8e0000`

The address is shown in the **`Start VPN`** column of the same `malfind` result:

```text
Process          Start VPN   End VPN
ReviewClient.e   0x8e0000    0x8e0fff
```

The memory region was extracted for analysis:

```bash
mkdir -p dumps
vol -f memory.mem -o dumps windows.malfind --pid 6260 --dump
```

The extracted file was named:

```text
pid.6260.vad.0x8e0000-0x8e0fff.dmp
```

### Task 3 — Associated File

**Question:** Which file associated with the process also contains the same payload?

- **Answer:** `review-cover.png`

The file handles of PID `6260` were listed to identify the documents accessed by the process:

```bash
vol -f memory.mem windows.handles --pid 6260 | grep -i 'File'
```

```text
PID   Process          Object           Handle  Type  Access    Name
6260  ReviewClient.e   0xbd8fdbca2640   0x40    File  0x100020  \Device\HarddiskVolume1\Windows
6260  ReviewClient.e   0xbd8fdbcb0bf0   0x84    File  0x100020  \Device\HarddiskVolume1\Users\s.reyes\Downloads\DocumentReview
6260  ReviewClient.e   0x9389f8b1b5e0   0xcc    Key   0x9       MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\IMAGE FILE EXECUTION OPTIONS
6260  ReviewClient.e   0xbd8fdbcb3c60   0x108   File  0x120089  \Device\HarddiskVolume1\Users\s.reyes\Downloads\DocumentReview\review-cache.dat
6260  ReviewClient.e   0xbd8fdbcb5a10   0x10c   File  0x120089  \Device\HarddiskVolume1\Users\s.reyes\Downloads\DocumentReview\review-cover.png
6260  ReviewClient.e   0xbd8fdbcb7180   0x1a0   File  0x100001  \Device\HarddiskVolume1\Windows\SysWOW64\en-US\user32.dll.mui
6260  ReviewClient.e   0xbd8fdbcb77c0   0x1b8   File  0x100001  \Device\CNG
6260  ReviewClient.e   0xbd8fdbcbb190   0x254   File  0x120089  \Device\HarddiskVolume1\Windows\Fonts\StaticCache.dat
```

Two files in the `DocumentReview` directory stood out: `review-cover.png` and `review-cache.dat`. The PNG was the file associated with the embedded payload; the `.dat` file was used by the next-stage PowerShell command.

The PNG could be recovered using its file-object address:

```bash
mkdir -p recovered
vol -f memory.mem -o recovered windows.dumpfiles --virtaddr 0xbd8fdbcb5a10
```

### Task 4 — MITRE ATT&CK Technique

**Question:** Which MITRE ATT&CK sub-technique best describes how the payload is stored in the recovered PNG file?

- **Answer:** [T1027.009 — Embedded Payloads](https://attack.mitre.org/techniques/T1027/009/)

The payload was embedded in `review-cover.png`, a file presented as a normal image. This matches **T1027.009 (Embedded Payloads)** under *Obfuscated Files or Information*.

### Task 5 — Windows API

**Question:** Which Windows API does the payload call to launch its next stage?

- **Answer:** `kernel32.WinExec`

The memory dump from Task 2 was emulated with Speakeasy:

```bash
cd ~/Desktop/artifacts/dumps
speakeasy \
  -t pid.6260.vad.0x8e0000-0x8e0fff.dmp \
  --raw \
  --arch x86 \
  -o speakeasy-report.json
```

Speakeasy recorded a call to `kernel32.WinExec`, passing a PowerShell command with the `-EncodedCommand` argument.

<details>
<summary>Full Speakeasy output</summary>

```text
/home/ubuntu/Desktop/artifacts/tools/venv/lib/python3.12/site-packages/unicorn/unicorn.py:6: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.
  import pkg_resources
* exec: shellcode
0x153d: 'kernel32.WinExec("powershell.exe -NoProfile -EncodedCommand JABrAD0AWwBDAG8AbgB2AGUAcgB0AF0AOgA6AEYAcgBvAG0AQgBhAHMAZQA2ADQAUwB0AHIAaQBuAGcAKAAnAGYAWABGAEsAYwBtAGYAbwBpAHIAdwBhAC8AUwBJADQATQBNAHQAMAAxADgAaABBADkAbgBmAC8ARgBsACsAKwB5AGMARQAwAFcAVgA4AEcAKwBxAGcAPQAnACkAOwAkAGIAPQBbAEkATwAuAEYAaQBsAGUAXQA6ADoAUgBlAGEAZABBAGwAbABCAHkAdABlAHMAKAAnAHIAZQB2AGkAZQB3AC0AYwBhAGMAaABlAC4AZABhAHQAJwApADsAJABhAD0AWwBTAGUAYwB1AHIAaQB0AHkALgBDAHIAeQBwAHQAbwBnAHIAYQBwAGgAeQAuAEEAZQBzAF0AOgA6AEMAcgBlAGEAdABlACgAKQA7ACQAYQAuAEsAZQB5AD0AJABrADsAJABhAC4ASQBWAD0AJABiAFsAMAAuAC4AMQA1AF0AOwAkAGEALgBNAG8AZABlAD0AJwBDAEIAQwAnADsAJABhAC4AUABhAGQAZABpAG4AZwA9ACcAUABLAEMAUwA3ACcAOwAkAGQAPQAkAGEALgBDAHIAZQBhAHQAZQBEAGUAYwByAHkAcAB0AG8AcgAoACkALgBUAHIAYQBuAHMAZgBvAHIAbQBGAGkAbgBhAGwAQgBsAG8AYwBrACgAJABiACwAMQA2ACwAJABiAC4ATABlAG4AZwB0AGgALQAxADYAKQA7AFsASQBPAC4ARgBpAGwAZQBdADoAOgBXAHIAaQB0AGUAQQBsAGwAQgB5AHQAZQBzACgAJwByAGUAdgBpAGUAdwAtAGMAYQBjAGgAZQAuAHoAaQBwACcALAAkAGQAKQA=", 0x5)' -> 0x20
* Finished emulating
* Saving emulation report to speakeasy-report.json
```

</details>

### Task 6 — Encryption Key

**Question:** What encryption key does the decoded stage use to decrypt the document cache?

- **Answer:** `7d714a7267e88abc1afd223830cb74d7c840f677ff165fbec9c134595f06faa8`

The `-EncodedCommand` argument contained Base64-encoded UTF-16LE PowerShell. Decoding it revealed the decryption routine:

```powershell
$k = [Convert]::FromBase64String('fXFKcmfoirwa/SI4MMt018hA9nf/Fl++ycE0WV8G+qg=')
$b = [IO.File]::ReadAllBytes('review-cache.dat')
$a = [Security.Cryptography.Aes]::Create()
$a.Key = $k
$a.IV = $b[0..15]
$a.Mode = 'CBC'
$a.Padding = 'PKCS7'
$d = $a.CreateDecryptor().TransformFinalBlock($b, 16, $b.Length-16)
[IO.File]::WriteAllBytes('review-cache.zip', $d)
```

The script reads `review-cache.dat`, uses its first 16 bytes as the IV, and decrypts the remaining data with AES-256-CBC. The Base64 key was converted to hexadecimal:

```bash
python3 -c "import base64; print(base64.b64decode('fXFKcmfoirwa/SI4MMt018hA9nf/Fl++ycE0WV8G+qg=').hex())"
```

```text
7d714a7267e88abc1afd223830cb74d7c840f677ff165fbec9c134595f06faa8
```

### Task 7 — Flag Recovery

**Question:** What is the flag?

- **Answer:** `THM{REDACTED}`

The encrypted `review-cache.dat` file was extracted from memory using the file-object address found in Task 3:

```bash
cd ~/Desktop/artifacts
mkdir -p recovered
vol -f memory.mem -o recovered windows.dumpfiles --virtaddr 0xbd8fdbcb3c60
ls -lh recovered/
```

Volatility recovered a 256 KB `.vacb` cache file and a 4 KB `.dat` file. The `.vacb` file contained the data needed to reconstruct the encrypted archive.

The AES key from Task 6 was used to decrypt the cache with Python. The first 16 bytes served as the IV, and PKCS7 padding was removed after decryption.

```python
import base64
from pathlib import Path
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

key = base64.b64decode('fXFKcmfoirwa/SI4MMt018hA9nf/Fl++ycE0WV8G+qg=')
b = next(Path('recovered').glob('*.review-cache.dat.vacb')).read_bytes()
b = b.rstrip(b'\x00')
b += b'\x00' * (-len(b) % 16)

d = AES.new(key, AES.MODE_CBC, b[:16]).decrypt(b[16:])
Path('recovered/review-cache.zip').write_bytes(unpad(d, 16))
```

The script uses the `pycryptodome` package. After decryption, the resulting archive was extracted:

```bash
cd recovered
unzip review-cache.zip
cat release/approval.txt
```

```text
Archive:  review-cache.zip
  inflating: release/approval.txt
  inflating: release/contacts.csv
```

The flag was found in `release/approval.txt`:

```text
INTERNAL - DOCUMENT CONTROL
Prepared by Michelle Smith
Reviewer: Sophia Reyes
Approval reference: THM{REDACTED}
Do not distribute externally.
```

## Findings and Indicators

The analysis identified executable shellcode in `ReviewClient.exe`, an encoded PowerShell stage, and an AES-encrypted document cache.

| Indicator | Value |
| --- | --- |
| Process / PID | `ReviewClient.exe` / `6260` |
| Executable memory | `0x8e0000–0x8e0fff` (`PAGE_EXECUTE_READWRITE`) |
| Embedded payload | `review-cover.png` — [T1027.009](https://attack.mitre.org/techniques/T1027/009/) |
| API | `kernel32.WinExec` |
| Encrypted file | `review-cache.dat` (AES-256-CBC) |
| Recovered archive | `review-cache.zip` |

---

*This write-up is intended for educational purposes and authorized security research.*
