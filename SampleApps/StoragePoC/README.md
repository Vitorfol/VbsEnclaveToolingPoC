# StoragePoC - Enclave Data Persistence (VTL1)

This proof of concept demonstrates a persistence flow where plaintext is handled only inside the enclave (VTL1), while the host (VTL0) stores only encrypted artifacts.

## Overview

### Goal

- Generate a symmetric key `S` inside the enclave.
- Protect `S` in a persistable encrypted key artifact (`encrypted_key.txt`) using enclave sealing.
- Persist encrypted application data in `data.txt`.
- On later executions, recover `S` inside the enclave, read/update data, and persist again without exposing plaintext to VTL0.

### Components

- `HostApp` (VTL0): loads the enclave, invokes ECALLs, and persists files.
- `Trusted` (VTL1): generates/protects `S`, encrypts/decrypts text, and applies business logic.
- `PoC.edl`: VTL0 <-> VTL1 contract used by code generation.

## PoC Flow

### Common steps

1. Host creates/loads/initializes the enclave.
2. Host registers VTL0 callbacks.
3. Host invokes an ECALL to obtain MRENCLAVE hash material (diagnostics and protected blob binding).

### Setup (one-time per path)

1. VTL1 generates the symmetric key `S`.
2. VTL1 protects `S` using enclave sealing.
3. VTL1 encrypts the initial text "Hello, world" using `S`.
4. VTL0 persists:
   - `encrypted_key.txt` (protected key `S`)
   - `data.txt` (encrypted data)
5. If `encrypted_key.txt` or `data.txt` already exists, setup fails with `already exists`.

### Post-setup

1. VTL0 reads `encrypted_key.txt` and `data.txt`.
2. VTL0 sends both artifacts to VTL1.
3. VTL1 recovers `S` from `encrypted_key.txt`.
4. VTL1 decrypts `data.txt`, applies business logic to plaintext, and re-encrypts.
5. VTL0 overwrites `data.txt`.
6. `encrypted_key.txt` remains unchanged unless a reseal blob is returned by the enclave.

## Persisted File Formats

### encrypted_key.txt

Text key-value file:

- `format=SPOC_BLOB_V1`
- `wrapped_s_hex=<hex>`

`wrapped_s_hex` is the opaque sealed representation of `S`.

### data.txt

Text key-value file:

- `format=SPOC_DATA_V1`
- `ciphertext_hex=<hex>`
- `tag_hex=<hex>`
- `metadata_hex=<hex>`

`metadata_hex` schema (PoC, no nonce):

- bytes `[magic:4][version:1][cipher_id:1]`
- `magic = META`
- `version = 1`
- `cipher_id = 1` (AES-GCM PoC v1)

## Prerequisites

### Environment

- Windows 11 with VBS enclave support
- Virtualization enabled in BIOS
- Memory Integrity enabled
- Visual Studio 2022 with C++ Desktop + Windows SDK

### Test-signing mode

Run in an elevated prompt:

```cmd
bcdedit /set testsigning on
```

Reboot after changing this setting.

## Build (output in _build/x64/Debug)

Use a **Developer Command Prompt for VS 2022**.

### Step 1 - go to the PoC folder

```powershell
cd SampleApps\StoragePoC
```

### Step 2 - restore NuGet packages

Recommended:

```powershell
msbuild StoragePoC.sln /t:Restore /p:Configuration=Debug /p:Platform=x64
```

Alternative (if you prefer NuGet CLI):

```powershell
nuget restore StoragePoC.sln
```

Note: restoring NuGet packages is required for the native C++ projects. If packages are not restored you may see build errors such as missing targets (e.g. `Microsoft.Windows.ImplementationLibrary.targets`). The repository now includes a versioned compatibility shim at `compat/gsl/gsl_util`, so no manual GSL header patching inside `packages` is needed.

Troubleshooting:

- If `msbuild /t:Restore` does not fetch packages, try the NuGet CLI:
  `nuget restore StoragePoC.sln`
- If a specific package is reported missing (for example `Microsoft.Windows.ImplementationLibrary.1.0.240803.1`), you can install it directly to the `packages` folder:
  `nuget install Microsoft.Windows.ImplementationLibrary -Version 1.0.240803.1 -OutputDirectory packages`
- If you see missing include errors such as `gsl/gsl_util`, ensure the `packages` folder is present at the solution root and the include paths were restored. Consider deleting the `packages` folder and restoring again.
- In Visual Studio: right-click the solution -> `Restore NuGet Packages` and then rebuild the solution.

After successful package restore, continue with Step 3 to build the solution.

### Step 3 - build Debug x64

```powershell
$out = Join-Path (Get-Location) "_build\x64\Debug\"
msbuild StoragePoC.sln /p:Configuration=Debug /p:Platform=x64 /p:OutDir=$out
```

Note: this keeps artifacts consistently in the solution root under `./_build/x64/Debug` (instead of project-local output folders).

Expected outputs in `_build\x64\Debug\`:

- `HostApp.exe`
- `storagepoc.dll`

### Step 4 - verify build artifacts (optional)

```powershell
dir .\_build\x64\Debug\HostApp.exe
dir .\_build\x64\Debug\storagepoc.dll
```

## Enclave Signing

Use the script:

```powershell
.\SignAndRunEnclave.ps1
```

It performs:

1. Windows SDK tool discovery (`veiid.exe`, `signtool.exe`)
2. Certificate creation/validation with VBS enclave EKUs
3. Certificate import into Root/TrustedPeople/TrustedPublisher
4. VEIID application to `storagepoc.dll`
5. Signing and signature verification

## Run

After build + signing:

No argument (uses current directory for `encrypted_key.txt` and `data.txt`):

```powershell
.\_build\x64\Debug\HostApp.exe
```

With persistence path:

```powershell
.\_build\x64\Debug\HostApp.exe C:\temp\storagepoc
```

### Recommended persistence path on disk

To keep persisted artifacts outside the repo, create a dedicated folder and pass it explicitly:

```powershell
mkdir C:\Users\necta\Desktop\Content\PoC -Force
.\_build\x64\Debug\HostApp.exe C:\Users\necta\Desktop\Content\PoC
```

In this case the files will always be written to:

- `C:\Users\necta\Desktop\Content\PoC\encrypted_key.txt`
- `C:\Users\necta\Desktop\Content\PoC\data.txt`

Quick validation:

```powershell
dir C:\Users\necta\Desktop\Content\PoC
Get-Content C:\Users\necta\Desktop\Content\PoC\encrypted_key.txt
Get-Content C:\Users\necta\Desktop\Content\PoC\data.txt
```

### Host menu

1. Setup one-time (creates `encrypted_key.txt` and `data.txt`)
2. Read (decrypts and shows current plaintext)
3. Write/Update (encrypts new text and overwrites `data.txt`)
4. Show storage paths
5. Exit

## Current PoC Scope

- This is not a production design.
- No per-record nonce at this stage (explicit PoC decision).
- Anti-tamper validation can be hardened in a future phase.

## Main Files

- `PoC.edl`
- `HostApp/main.cpp`
- `HostApp/StorageFlowHandler.h`
- `HostApp/StorageFlowHandler.cpp`
- `Trusted/storage_setup.cpp`
- `Trusted/storage_post_setup.cpp`
- `Trusted/trusted_exports.cpp`
- `Trusted/utils.cpp`
