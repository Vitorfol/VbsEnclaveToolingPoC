# StoragePoC - Enclave Data Persistence (VTL1)

This proof of concept demonstrates a persistence flow where plaintext is handled only inside the enclave (VTL1), while the host (VTL0) stores only encrypted artifacts.

## Table of Contents

- [Overview](#overview)
- [PoC Tree](#poc-tree)
- [PoC Flow](#poc-flow)
- [Persisted File Formats](#persisted-file-formats)
- [Prerequisites](#prerequisites)
- [Build (output in _build/x64/Debug)](#build-output-in-_buildx64debug)
- [Enclave Signing](#enclave-signing)
- [Run](#run)
- [Host Menu](#host-menu)
- [Observations and Limitations](#observations-and-limitations)

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

### Key generation and sealing source

The key lifecycle is implemented with enclave SDK APIs (via VEIL wrappers) in `Trusted`:

- Key generation: `veil::vtl1::crypto::generate_symmetric_key_bytes()`
- Sealing: `veil::vtl1::crypto::seal_data(...)`
- Unsealing: `veil::vtl1::crypto::unseal_data(...)`

So yes: the symmetric keys are generated inside VTL1 using the enclave SDK crypto path, not in host code.

## PoC Tree

```text
./
├── StoragePoC.sln                  # Visual Studio solution file
├── PoC.edl                         # Enclave Definition Language (VTL0↔VTL1 interface)
├── SignAndRunEnclave.ps1           # Signs enclave DLL with test cert + VEIID
├── README.md                       
├── PoC_storage.png                 # Optional architecture/flow image
│
├── compat/
│   └── gsl/
│       └── gsl_util                # Compatibility shim for GSL include
│
├── HostApp/                        # VTL0 host application
│   ├── main.cpp                    # CLI/menu, enclave load/init, flow entry
│   ├── StorageFlowHandler.cpp      # Setup/read/write orchestration and file persistence
│   ├── StorageFlowHandler.h        # Host flow API contracts
│   ├── HostApp.vcxproj             # Host project definition
│   ├── HostApp.vcxproj.filters     # VS filter organization
│   ├── Directory.Build.props       # Shared MSBuild properties (host)
│   └── packages.config             # NuGet dependencies (host)
│
├── Trusted/                        # VTL1 enclave code
│   ├── dllmain.cpp                 # Enclave entrypoint
│   ├── trusted_exports.cpp         # Exported ECALL implementations
│   ├── storage_setup.cpp           # Key provisioning/setup logic
│   ├── storage_setup.h             # Setup declarations
│   ├── storage_post_setup.cpp      # Encrypt/decrypt post-setup operations
│   ├── storage_post_setup.h        # Post-setup declarations
│   ├── utils.cpp                   # Sealing/unsealing, hashing, blob helpers
│   ├── utils.h                     # Utility declarations
│   ├── pch.h                       # Shared enclave headers/macros
│   ├── pch.cpp                     # Precompiled header source
│   ├── Trusted.vcxproj             # Enclave project (/ENCLAVE)
│   ├── Trusted.vcxproj.filters     # VS filter organization
│   ├── Directory.Build.props       # Shared MSBuild properties (trusted)
│   └── packages.config             # NuGet dependencies (trusted)
│
└── _build/                         # Build outputs (generated)
    └── x64/
        └── Debug/
            ├── HostApp.exe         # Host binary
            ├── storagepoc.dll      # Signed enclave binary (VTL1)
            └── Generated Files/    # Auto-generated stubs/headers (if generated)
```

## PoC Flow

### Common steps

1. Host creates/loads/initializes the enclave.
2. Host registers VTL0 callbacks.
3. Host invokes an ECALL to obtain MRENCLAVE-derived hash material (diagnostics and binding visibility).

### Trust material used by the flow

- `S`: symmetric data key, generated in VTL1.
- `K`: effective sealing key material derived by enclave sealing from hardware-protected secrets and enclave identity policy.
- `MRENCLAVE hash material`: explicit identity binding stored inside the sealed payload and validated during recovery.

### Setup (one-time per path)

1. VTL1 generates the symmetric key `S`.
2. VTL1 computes MRENCLAVE hash material.
3. VTL1 builds a payload containing `S` + MRENCLAVE hash material.
4. VTL1 seals this payload (hardware-rooted + enclave identity policy), producing `encrypted_key.txt` content.
5. VTL1 encrypts the initial text "Hello, world" using `S`.
6. VTL0 persists:
   - `encrypted_key.txt` (protected key `S`)
   - `data.txt` (encrypted data)
7. If `encrypted_key.txt` or `data.txt` already exists, setup fails with `already exists`.

### Post-setup

1. VTL0 reads `encrypted_key.txt` and `data.txt`.
2. VTL0 sends both artifacts to VTL1.
3. VTL1 unseals `encrypted_key.txt` using enclave sealing (same trust roots as setup).
4. VTL1 validates embedded MRENCLAVE hash material against the running enclave identity.
5. VTL1 recovers `S` and decrypts `data.txt`.
6. VTL1 applies business logic in plaintext and re-encrypts using `S`.
7. VTL0 overwrites `data.txt`.
8. `encrypted_key.txt` remains unchanged unless a reseal blob is returned by the enclave.

## Persisted File Formats

Both files use a simple key-value text format.

### encrypted_key.txt (sealed key blob)

- `format=SPOC_BLOB_V1`
- `wrapped_s_hex=<hex>` (opaque sealed representation of `S`)

### data.txt (encrypted payload)

- `format=SPOC_DATA_V1`
- `ciphertext_hex=<hex>`
- `tag_hex=<hex>`
- `metadata_hex=<hex>`

`metadata_hex` (PoC v1, no nonce) stores `[magic:4][version:1][cipher_id:1]`, where `magic=META`, `version=1`, and `cipher_id=1` (AES-GCM PoC v1).

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

Note: restoring NuGet packages is required for the native C++ projects. If packages are not restored you may see build errors such as missing targets (e.g. `Microsoft.Windows.ImplementationLibrary.targets`). The repository includes a versioned compatibility shim at `compat/gsl/gsl_util`, so no manual GSL header patching inside `packages` is needed.

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
.\_build\x64\Debug\HostApp.exe <persistence_dir>
```

### Recommended persistence path on disk

To keep persisted artifacts outside the repo, create a dedicated folder and pass it explicitly:

```powershell
$persistDir = Join-Path $env:USERPROFILE "StoragePoC\Data"
New-Item -ItemType Directory -Path $persistDir -Force | Out-Null
.\_build\x64\Debug\HostApp.exe $persistDir
```

In this case the files will always be written to:

- `$persistDir\encrypted_key.txt`
- `$persistDir\data.txt`

Quick validation:

```powershell
dir $persistDir
Get-Content (Join-Path $persistDir "encrypted_key.txt")
Get-Content (Join-Path $persistDir "data.txt")
```

## Host Menu

1. Setup one-time (creates `encrypted_key.txt` and `data.txt`)
2. Read (decrypts and shows current plaintext)
3. Write/Update (encrypts new text and overwrites `data.txt`)
4. Show storage paths
5. Exit

## Observations and Limitations

- No per-record nonce at this stage (explicit PoC decision).
- No anti-tamper validation implemented.

