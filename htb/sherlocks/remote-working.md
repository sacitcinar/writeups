# Remote_Working

| Field | Details |
| --- | --- |
| Platform | [Hack The Box — Sherlocks](https://app.hackthebox.com/sherlocks/Remote_Working) |
| Difficulty | Easy |
| Category | Malware Analysis |
| Tools | VirusTotal, sha256sum |
| Author | dmncdcco |

## Overview

The challenge provides `ORDER_SHEET_SPEC.zip`, containing a macro-enabled Excel workbook named `ORDER SHEET & SPEC.xlsm`.

The investigation focuses on the workbook's metadata, antivirus detections, dropped files and contacted URLs. These details can be examined through its existing VirusTotal report without opening the workbook in Excel.

## Identifying the Sample

On Linux, the workbook's SHA-256 hash can be calculated with:

```bash
sha256sum "ORDER SHEET & SPEC.xlsm"
```

The sample's SHA-256 is:

```text
7bcd31bd41686c32663c7cabf42b18c50399e3b3b4533fc2ff002d9f2e058813
```

Searching this hash on VirusTotal identifies the report used for the following tasks.

## Tasks

### Task 0 — File Creation Time

**Question:** What is the date the file was created? (UTC)

**Answer format:** `YYYY-MM-DD HH:MM:SS`

- **Answer:** `2020-02-01 18:28:07`

- Under **Details → History**, the report lists the sample's **Creation Time** as:

```text
2020-02-01 18:28:07 UTC
```

- This is the creation timestamp recorded in the report, rather than its first submission or last analysis time.

- Document metadata can be modified, so this value should be treated as a reported timestamp rather than independent proof of when the file was originally created.

### Task 1 — Bitdefender Detection

**Question:** With what name is the file detected by Bitdefender antivirus?

- **Answer:** `trojan.generickd.36266294`

- The **Detection** tab lists the results returned by individual security vendors. The Bitdefender entry identifies the sample as:

```text
Trojan.GenericKD.36266294
```

- The challenge accepts the lowercase form shown in the answer.

- This is a vendor-specific detection label. It identifies Bitdefender's classification of the sample but does not, by itself, explain the workbook's execution behavior.

### Task 2 — Dropped File Count

**Question:** How many files are dropped on the disk?

- **Answer:** `29`

- The **Behavior** tab includes a **Files Dropped** section containing artifacts recorded during sandbox execution.

- The analysis used by the challenge lists **29 dropped files**.

- This count refers to the reported sandbox activity. It does not mean that all 29 files are separate malicious payloads; dropped artifacts can also include temporary files and application-generated content.

### Task 3 — Dropped EMF File Hash

**Question:** What is the sha-256 hash of the file with emf extension it drops?

- **Answer:** `979dde2aed02f077c16ae53546c6df9eed40e8386d6db6fc36aee9f966d2cb82`

- Within **Behavior → Files Dropped**, locate the entry with the `.emf` extension and expand its details.

- Its **SHA-256** field contains the value above. The hash identifies the specific dropped artifact and allows it to be searched separately.

- EMF stands for **Enhanced Metafile**, a Windows graphics format. The extension alone does not establish whether this particular artifact is malicious.

### Task 4 — Spyware Download URL

**Question:** What is the exact url to which the relevant file goes to download spyware?

- **Answer:** `https://multiwaretecnologia.com.br/js/podaliri4.exe`

- Under **Relations → Contacted URLs**, the report identifies a contacted address pointing to an executable:

```text
https://multiwaretecnologia.com.br/js/Podaliri4.exe
```

- The challenge accepts the lowercase form, `podaliri4.exe`. Investigation notes should preserve the capitalization displayed in the report because URL paths can be case-sensitive.

- The address is the download endpoint requested by the question. A contacted URL alone does not confirm that the download completed or that the executable successfully ran.

---

*This write-up is intended for educational purposes and authorized security research.*
