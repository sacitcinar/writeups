# Dead Endpoint

### Scenario

An internal photo gallery became unusable, and its images could no longer be opened. A preserved Linux disk image was provided to investigate the compromise, identify the responsible executable, understand its encryption mechanism, and recover the affected images.

| Field | Details |
| --- | --- |
| Platform | TryHackMe |
| Challenge | Dead Endpoint |
| Difficulty | Hard |
| Category | Disc Forensics, Malware Analysis, Data Recovery |
| Evidence | `disk.img` |
| Tools | The Sleuth Kit, Ghidra, Python (`cryptography`) |
| Author | dmncdcco |

## Overview

The investigation started with the disk image and the gallery's Nginx access logs. A suspicious executable was identified under the application's hidden `.cache` directory. Static analysis revealed an AES-256-GCM encryption routine and a timestamp-seeded SplitMix64 key generator. By correlating the encrypted file's metadata with the key generation logic, the seed was recovered and the affected images were decrypted.

## Tasks

### Task 1 — Abused Application Endpoint

**Question:** Which application endpoint was abused to execute commands on the server?

- **Answer:** `/api/albums/1/export`

The disk image was first examined with `mmls` to identify its partition layout.

```bash
mmls disk.img
```

```text
GUID Partition Table (EFI)
Offset Sector: 0
Units are in 512-byte sectors

      Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Safety Table
001:  -------   0000000000   0000002047   0000002048   Unallocated
002:  Meta      0000000001   0000000001   0000000001   GPT Header
003:  Meta      0000000002   0000000033   0000000032   Partition Table
004:  013       0000002048   0000010239   0000008192
005:  014       0000010240   0000227327   0000217088
006:  015       0000227328   0002097152   0001869825
007:  -------   0002097153   0002099199   0000002047   Unallocated
008:  000       0002099200   0025165790   0023066591
009:  -------   0025165791   0025165823   0000000033   Unallocated
```

Partition `008` was the largest partition and started at sector `2099200`. It was examined with `fls` to determine whether it contained the Linux root filesystem. The `-o` option specifies the partition's starting sector.

```bash
fls -o 2099200 disk.img
```

```text
d/d 1684:   home
d/d 11:     lost+found
l/l 12:     bin
d/d 13:     bin.usr-is-merged
d/d 14:     boot
d/d 27:     dev
d/d 42:     etc
l/l 1685:   lib
d/d 1686:   lib.usr-is-merged
l/l 1687:   lib64
d/d 1688:   media
d/d 1689:   mnt
d/d 1690:   opt
d/d 1691:   proc
d/d 1692:   root
d/d 1696:   run
l/l 1697:   sbin
d/d 1698:   sbin.usr-is-merged
l/l 1699:   snap
d/d 1700:   srv
d/d 1701:   sys
d/d 1702:   tmp
d/d 1703:   usr
d/d 81159:  var
V/V 1441793: $OrphanFiles
```

The presence of `/etc`, `/srv`, and `/var` confirmed the Linux root filesystem. To browse its contents normally, the partition was mounted read-only. Its byte offset was calculated as `2099200 × 512 = 1074790400`.

```bash
sudo mkdir -p /mnt/ctf
sudo mount -o ro,noload,loop,offset=1074790400 disk.img /mnt/ctf
```

The Nginx access log at `/var/log/nginx/gallery-access.log` showed repeated requests to the album-export endpoint:

```text
10.0.2.2 - - [20/Oct/2026:05:36:37 +0000] "POST /api/albums/1/export HTTP/1.1" 202 43 "-" "MeridianUploader/1.3"
10.0.2.2 - - [20/Oct/2026:05:36:38 +0000] "GET /api/exports/8452cfc730ed4198 HTTP/1.1" 200 89 "-" "MeridianUploader/1.3"
10.0.2.2 - - [20/Oct/2026:05:36:38 +0000] "GET /exports/8452cfc730ed4198 HTTP/1.1" 200 286720 "-" "MeridianUploader/1.3"
```

The `202 Accepted` response was followed by requests for the generated export. Matching `.tar` files were also present in `/srv/gallery/exports/`. These records identified `/api/albums/1/export` as the endpoint associated with the suspicious export activity.

### Task 2 — Encryption Executable

**Question:** What was the full path of the executable responsible for encrypting the images?

- **Answer:** `/srv/gallery/.cache/.indexd`

The gallery service files were examined using `tree -la`, which also displayed hidden directories and files.

```bash
cd /mnt/ctf/srv/gallery
tree -la
```

The directory structure revealed an unusual `.indexd` file inside the hidden `.cache` directory, alongside the application files, export archives, and encrypted images:

```text
/srv/gallery/
├── .cache/
│   └── .indexd
├── app/
│   ├── gallery.py
│   ├── static/
│   └── templates/
├── data/
│   └── gallery.sqlite3
├── exports/
│   ├── 13efec482c8a4ccc.tar
│   ├── 27ee23c277fb4bc9.tar
│   └── 8452cfc730ed4198.tar
└── media/
    └── originals/
        ├── RESTORE.txt
        ├── yard_0147.jpg.locked
        ├── yard_0148.jpg.locked
        └── yard_0152.jpg.locked
```

The file type was checked without executing it:

```bash
file /mnt/ctf/srv/gallery/.cache/.indexd
```

```text
ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=f8f0e4efdd56a53819f0b57035bf9483ef3cf96f, for GNU/Linux 3.2.0, stripped
```

The hidden executable was selected for further static analysis.

### Task 3 — Executable SHA-256

**Question:** What is the SHA-256 hash of that executable?

- **Answer:** `6a0e5b25a919a94952b34e38d8e8b595036d1ef6a026bf5cca38a0d34459102f`

The executable's SHA-256 hash was calculated directly from the preserved file:

```bash
sha256sum /mnt/ctf/srv/gallery/.cache/.indexd
```

```text
6a0e5b25a919a94952b34e38d8e8b595036d1ef6a026bf5cca38a0d34459102f  /mnt/ctf/srv/gallery/.cache/.indexd
```

### Task 4 — Encryption Algorithm and Mode

**Question:** Which encryption algorithm and mode protected the images?

- **Answer:** `AES-256-GCM`

The `.indexd` executable was examined using `strings` to identify readable text, imported function names, and references to cryptographic operations.

```bash
strings .indexd
```

Relevant output included:

```text
EVP_EncryptUpdate
EVP_CIPHER_CTX_ctrl
EVP_EncryptInit_ex
RAND_bytes
OPENSSL_cleanse
EVP_CIPHER_CTX_new
EVP_aes_256_gcm
EVP_CIPHER_CTX_free
EVP_EncryptFinal_ex
gethostname
clock_gettime
renameat2
futimens
libcrypto.so.3
%s.locked
gallery
/srv/gallery/media/originals
yard_0147.jpg
yard_0148.jpg
yard_0152.jpg
RESTORE.txt
Your image library has been locked.
Keep the affected files and their names unchanged.
For recovery instructions contact restore@notice.invalid.
```

The OpenSSL function name `EVP_aes_256_gcm` identified AES-256 in Galois/Counter Mode (GCM). The strings also exposed the targeted image filenames, the `.locked` extension, and the ransom note text.

### Task 5 — Initial Encryption Seed

**Question:** What initial seed value was used to generate the encryption key?

- **Answer:** `1792474614662`

The `.indexd` executable was imported into **Ghidra** for static analysis. Its **Symbol Table** contained imported OpenSSL functions such as `EVP_aes_256_gcm` and `EVP_EncryptInit_ex`.

Using **Show References to Address**, the references to `EVP_aes_256_gcm` were followed through the PLT entry to the actual call in `FUN_00101574`. The decompiled encryption routine showed that the AES key was supplied through `param_3`:

```c
cipher = EVP_aes_256_gcm();
EVP_EncryptInit_ex(ctx, (EVP_CIPHER *)0x0,
                   (ENGINE *)0x0, param_3, in_00 + 0x10);
```

The function's caller, `FUN_001019fe`, was then examined to find where that key came from. It used `clock_gettime()` and converted the current Unix timestamp to milliseconds:

```c
clock_gettime(0, &local_1f8);
local_200 = local_1f8.tv_sec * 1000 +
            (ulong)local_1f8.tv_nsec / 1000000;
```

The timestamp value was passed repeatedly to `FUN_00101509`. Its constants and bitwise operations matched **SplitMix64**:

```c
uVar1 = *param_1 + 0x9e3779b97f4a7c15;
*param_1 = uVar1;
uVar1 = (uVar1 >> 0x1e ^ uVar1) * -0x40a7b892e31b1a47;
uVar1 = (uVar1 >> 0x1b ^ uVar1) * -0x6b2fb644ecceee15;
return uVar1 >> 0x1f ^ uVar1;
```

`FUN_00101554` stored each 64-bit output in little-endian order. Four consecutive outputs formed the 32-byte AES key.

To narrow down the original seed, the metadata of `yard_0147.jpg.locked` was examined. This image was the first file processed by the encryption routine.

```bash
sudo stat /mnt/ctf/srv/gallery/media/originals/yard_0147.jpg.locked
```

```text
Access: 2026-10-20 05:36:55.415528003 +0000
Modify: 2026-10-20 05:36:37.358996439 +0000
Change: 2026-10-20 05:36:54.696546666 +0000
Birth:  2026-10-20 05:36:37.357996465 +0000
```

The `ctime` value was especially useful because the executable restored the original access and modification times after encryption. A short Python script tested millisecond seed candidates around `ctime`: each candidate generated a SplitMix64 key, which was checked against the file's AES-GCM authentication tag.

<details>
<summary>Show Python seed recovery script</summary>

```python
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

path = "/mnt/ctf/srv/gallery/media/originals/yard_0147.jpg.locked"
data = open(path, "rb").read()
nonce = data[0x10:0x1c]
tag = data[0x1c:0x2c]
aad = data[:0x1c]
ciphertext = data[0x30:]
MASK = (1 << 64) - 1

def next_splitmix64(state):
    state = (state + 0x9e3779b97f4a7c15) & MASK
    z = state
    z = ((z ^ (z >> 30)) * 0xbf58476d1ce4e5b9) & MASK
    z = ((z ^ (z >> 27)) * 0x94d049bb133111eb) & MASK
    return state, z ^ (z >> 31)

def derive_key(seed):
    state, key = seed, b""
    for _ in range(4):
        state, value = next_splitmix64(state)
        key += value.to_bytes(8, "little")
    return key

ctime_ms = os.stat(path).st_ctime_ns // 1_000_000
for seed in range(ctime_ms - 10000, ctime_ms + 1000):
    key = derive_key(seed)
    try:
        AESGCM(key).decrypt(nonce, ciphertext + tag, aad)
        print("SEED FOUND:", seed)
        print("KEY:", key.hex())
        break
    except InvalidTag:
        continue
```

</details>

The matching seed was **`1792474614662`**, corresponding to **20 October 2026, 05:36:54.662 UTC**. This was approximately **34.55 milliseconds before** the file's `ctime`, consistent with key generation occurring before the file was rewritten and renamed.

### Task 6 — Recovered Inspection Checklist

**Question:** What flag appears in the recovered inspection checklist?

- **Answer:** `THM{REDACTED}`

The seed recovered in Task 5 was used to reconstruct the AES-256 key. As observed in Ghidra, SplitMix64 was called four times, and each 64-bit output was stored in little-endian order:

| Iteration | 8-byte output (little-endian) |
| --- | --- |
| 1 | `2cd60b8474eba174` |
| 2 | `4f19b0e537ff0ecb` |
| 3 | `d1ae03d2d9ed24dd` |
| 4 | `ab3bd9729d7c0190` |

Concatenating these four values produced the 32-byte AES-256 key:

```text
2cd60b8474eba1744f19b0e537ff0ecbd1ae03d2d9ed24ddab3bd9729d7c0190
```

Ghidra analysis of `FUN_00101574` had also established the structure of each encrypted file. A header check with `xxd` confirmed the `GPH1` signature:

```bash
sudo xxd -l 64 /mnt/ctf/srv/gallery/media/originals/yard_0147.jpg.locked
```

| Offset | Content |
| --- | --- |
| `0x00` | `GPH1` signature and version |
| `0x08` | Original file size |
| `0x10` | 12-byte nonce |
| `0x1C` | 16-byte authentication tag |
| `0x30` | Encrypted image data |

The reconstructed key and these offsets were used with Python's `cryptography` library to decrypt the `.locked` files. Recovered images were written to a separate directory, leaving the mounted evidence unchanged.

<details>
<summary>Show Python recovery script</summary>

```python
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

src = Path("/mnt/ctf/srv/gallery/media/originals")
out = Path("/home/ubuntu/Desktop/recovered")
out.mkdir(parents=True, exist_ok=True)

key = bytes.fromhex(
    "2cd60b8474eba1744f19b0e537ff0ecbd1ae03d2d9ed24ddab3bd9729d7c0190"
)

for f in src.glob("*.locked"):
    data = f.read_bytes()
    image = AESGCM(key).decrypt(
        data[16:28],
        data[48:] + data[28:44],
        data[:28]
    )
    (out / f.name.removesuffix(".locked")).write_bytes(image)
    print("Recovered:", f.name)
```

</details>

The following JPEG files were recovered:

```text
yard_0147.jpg
yard_0148.jpg
yard_0152.jpg
```

The recovered inspection checklist contained the flag: **`THM{REDACTED}`**.

## Findings and Indicators

The hidden ELF executable encrypted three JPEG images with AES-256-GCM. Although the per-file nonces were random, the shared key was generated from a predictable millisecond timestamp. Filesystem metadata made it possible to reconstruct and verify the key, then recover the affected images.

| Indicator | Value |
| --- | --- |
| Abused endpoint | `/api/albums/1/export` |
| Executable | `/srv/gallery/.cache/.indexd` |
| SHA-256 | `6a0e5b25a919a94952b34e38d8e8b595036d1ef6a026bf5cca38a0d34459102f` |
| Encryption | `AES-256-GCM` |
| Affected files | `yard_0147.jpg.locked`, `yard_0148.jpg.locked`, `yard_0152.jpg.locked` |

---

*This write-up is intended for educational purposes and authorized security research.*
