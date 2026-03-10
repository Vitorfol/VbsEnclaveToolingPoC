# VBS Enclave Memory Protection - Proof of Concept

This PoC demonstrates hardware-backed memory isolation provided by VBS (Virtualization-Based Security) enclaves on Windows. It shows that memory allocated inside a VTL1 (Virtual Trust Level 1) enclave cannot be read by processes running in VTL0, even with Administrator privileges.

## Table of Contents

- [Overview](#overview)
- [Project Structure](#project-structure)
- [Prerequisites](#prerequisites)
- [Build and Run](#build-and-run)
- [Understanding the Results](#understanding-the-results)

## Overview

### What This PoC Demonstrates

The PoC proves that **VTL1 enclave memory is hardware-isolated from VTL0** by:

1. Loading a VBS enclave (`Trusted.dll`) into VTL1
2. Storing a secret string in VTL1 memory
3. Attempting to read that VTL1 memory address from a VTL0 process using `ReadProcessMemory()`
4. Showing that the read fails with `ERROR_PARTIAL_COPY` (299)

### Components

- **HostApp.exe** (VTL0): Loads the enclave and stores data in VTL1
- **Trusted.dll** (VTL1): VBS enclave binary that runs in protected memory
- **MemoryScanner.exe**: Attacker tool that attempts to read process memory
- **NormalApp.exe**: Optional control process (normal VTL0 memory, readable by scanner)

## Structure

```
MemoryProtectionPoC/
├── MemoryProtectionPoC.sln        # Visual Studio solution file
├── PoC.edl                        # Enclave Definition Language - defines VTL0↔VTL1 interface
├── SignAndRunEnclave.ps1          # Script to sign enclave with test certificate
├── MemoryScanner.cpp              # Attacker tool - attempts to read process memory
├── NormalApp.cpp                  # Control app - normal VTL0 process (optional)
│
├── HostApp/                       # VTL0 Host Application
│   ├── HostApp.cpp                # Loads enclave, calls VTL1 functions
│   ├── HostApp.vcxproj            # Project file (VbsEnclaveVtl0ClassName=PoCEnclave)
│   └── packages.config            # NuGet dependencies (SDK, CodeGenerator)
│
├── Trusted/                       # VTL1 Enclave (runs in protected memory)
│   ├── dllmain.cpp                # Enclave entry point and configuration
│   ├── TrustedImplementation.cpp  # Implementation of StoreSecret/ReadSecret
│   ├── pch.h / pch.cpp            # Precompiled headers
│   ├── Trusted.vcxproj            # Project file with /ENCLAVE linker flag
│   └── packages.config            # NuGet dependencies (SDK, WIL)
│
└── _build/                        # Build outputs (generated)
    └── x64/
        └── Debug/
            ├── HostApp.exe        # Host application
            ├── Trusted.dll        # Signed enclave binary (VTL1)
            └── Generated Files/   # Auto-generated stubs and headers
```

### Key Files Explained

| File | Purpose |
|------|---------|
| **PoC.edl** | Defines the enclave interface (`StoreSecret`, `ReadSecret`). Processed by `edlcodegen.exe` to generate marshalling code. |
| **HostApp.cpp** | VTL0 application that creates the enclave, loads `Trusted.dll`, and calls enclave functions via generated stubs (`PoCEnclave`). |
| **TrustedImplementation.cpp** | VTL1 implementation - stores secret data in enclave memory (inaccessible from VTL0). |
| **MemoryScanner.cpp** | Simulates an attacker using `ReadProcessMemory()` to read another process. Fails on VTL1 memory. |
| **SignAndRunEnclave.ps1** | Creates test certificate with VBS EKUs, applies VEIID protection, signs the enclave DLL. |

## Prerequisites

### Hardware & OS Requirements

- **Windows 11 24H2** (build 26100 or later)
- **TPM 2.0** enabled in BIOS
- **Virtualization** enabled in BIOS (Intel VT-x or AMD-V)
- **Memory Integrity** enabled:
  - Settings → Privacy & Security → Windows Security → Device security → Core isolation → Memory integrity

### Development Requirements

- **Visual Studio 2022** with:
  - Desktop development with C++
  - Windows 11 SDK (10.0.26100 or later)
  - MSVC v143 toolset
- **Test signing enabled** (run as Administrator):
  ```cmd
  bcdedit /set testsigning on
  ```
  Then reboot.

## Build and Run

### Step 1: Build the Solution

From a **Developer Command Prompt for VS 2022**:

```powershell
cd SampleApps\MemoryProtectionPoC
msbuild MemoryProtectionPoC.sln /p:Configuration=Debug /p:Platform=x64
```

**What happens:**
- NuGet restores packages (SDK, CodeGenerator)
- `edlcodegen.exe` processes `PoC.edl` and generates host stubs and enclave headers
- Compiles `HostApp.exe` and `Trusted.dll` (enclave binary)

### Step 2: Sign the Enclave

VBS enclaves must be code-signed with a certificate that has the correct **Extended Key Usage (EKU)** values. The enclave requires:
- Code Signing EKU (`1.3.6.1.5.5.7.3.3`)
- VBS Enclave-specific EKU (`1.3.6.1.4.1.311.76.57.1.15`)

Run the provided script (PowerShell as Administrator):

```powershell
.\SignAndRunEnclave.ps1
```

**What `SignAndRunEnclave.ps1` does:**
1. Creates a self-signed test certificate with the required EKUs (if it doesn't already exist)
2. Imports the certificate into system trust stores (Root, TrustedPeople, TrustedPublisher)
3. Applies **VEIID protection** to `Trusted.dll` (marks it as a VBS enclave binary)
4. Signs `Trusted.dll` with the test certificate using `signtool.exe`
5. Verifies the signature is valid

> **Note**: The certificate and signing are necessary because VBS enclaves validate code signatures before loading into VTL1.

### Step 3: Compile the Memory Scanner

```cmd
cl.exe MemoryScanner.cpp /Fe:MemoryScanner.exe /EHsc
```

Optionally, compile the normal app for comparison:

```cmd
cl.exe NormalApp.cpp /Fe:NormalApp.exe /EHsc
```

### Step 4: Run the PoC

**Terminal 1** - Start HostApp:

```powershell
.\_build\x64\Debug\HostApp.exe
```

**Terminal 2** (Administrator) - Run the scanner with the PID and VTL1 address printed by HostApp:

```powershell
.\MemoryScanner.exe <PID> <VTL1_address>
```

**Example:**
```powershell
.\MemoryScanner.exe 12345 0x1a0000c3f40
```


## Understanding the Results

### Success (VBS Protection Working)

When the MemoryScanner targets VTL1 memory, it should **fail** with:
- **Error 299** (`ERROR_PARTIAL_COPY`) 

This proves VTL1 memory is **hardware-isolated** from VTL0 processes — `ReadProcessMemory()` cannot cross the VTL boundary.

### What If It Succeeds?

If the scanner successfully reads VTL1 memory, check:
- Memory Integrity is enabled in Windows Security
- Build used Debug configuration
- HostApp loaded the enclave successfully (check console output)
- Enclave was signed correctly (re-run `SignAndRunEnclave.ps1`)

### EDL Interface

The `PoC.edl` file defines the enclave interface:

```cpp
enclave {
    trusted {
        uint64_t StoreSecret(wstring secret);  // VTL0 → VTL1 call
        wstring ReadSecret();                  // VTL0 → VTL1 call
    };
};
```

Code generation (`edlcodegen.exe`) produces:
- **Host stubs** (`VbsEnclave::Trusted::Stubs::PoCEnclave`) - VTL0 wrapper to call into VTL1
- **Enclave implementation** (`VbsEnclave::Trusted::Implementation`) - VTL1 function headers
