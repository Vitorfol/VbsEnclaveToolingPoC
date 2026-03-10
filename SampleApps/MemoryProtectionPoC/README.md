# VBS Enclave Memory Protection - Proof of Concept

This PoC demonstrates hardware-backed memory isolation provided by VBS (Virtualization-Based Security) enclaves on Windows. It shows that data stored in VTL1 (Virtual Trust Level 1) enclave memory cannot be read by processes running in VTL0, even with memory scanning capabilities.

## Overview

The PoC consists of three components:

1. **HostApp** (VTL0): Normal Windows application that stores public data in regular memory
2. **Trusted.dll** (VTL1): VBS enclave that stores secret data in protected memory
3. **MemoryScanner** (Attacker): Attempts to read both public and secret data

### Expected Results

- ✅ **VTL0 Memory**: Scanner successfully reads public data (`PUBLIC_DATA_READABLE_123456`)
- ❌ **VTL1 Memory**: Scanner fails to read enclave data (`SECRET_IN_VTL1_987654`)

This demonstrates that **VBS enclave memory is hardware-isolated** and cannot be accessed from VTL0, providing real memory protection.

## Prerequisites

### Hardware & OS Requirements

- **Windows 11 24H2** (build 26100.3916 or later)
- **TPM 2.0** enabled in BIOS
- **Virtualization** enabled in BIOS (Intel VT-x or AMD-V)
- **Memory Integrity** enabled (Settings → Privacy & Security → Windows Security → Device Security → Core isolation)

### Development Requirements

- **Visual Studio 2022** with:
  - Desktop development with C++
  - Windows 11 SDK (10.0.26100.7463 or later)
  - MSVC v143 toolset
- **Test Signing** enabled (see below)
- **vcpkg** installed and integrated

### ⚠️ Important: Test Signing Setup

VBS enclaves must be signed, even for development. You need to:

1. **Create a test certificate** (one-time setup):
   ```powershell
   # Run PowerShell as Administrator
   New-SelfSignedCertificate `
       -CertStoreLocation Cert:\CurrentUser\My `
       -DnsName "TheDefaultTestEnclaveCertName" `
       -Subject "CN=TheDefaultTestEnclaveCertName" `
       -Type CodeSigningCert `
       -KeyUsage DigitalSignature `
       -KeyAlgorithm RSA `
       -KeyLength 2048 `
       -NotAfter (Get-Date).AddYears(5)
   ```

2. **Enable Test Signing**:
   ```cmd
   :: Run Command Prompt as Administrator
   bcdedit /set testsigning on
   ```

3. **Reboot** your machine

   > ⚠️ **Warning**: Enabling test signing disables Secure Boot. Back up your BitLocker recovery keys before proceeding!

## Build Instructions

## Quick Start

If you just want to try the PoC quickly, follow these three steps. See the full sections below for details.

1. Sign and prepare the enclave (one command):

```powershell
.\SignAndRunEnclave.ps1
```

2. Build the Memory Scanner (Attacker):

```cmd
cl.exe attacker.c /Fe:MemoryScanner.exe
```

3. Run the PoC:

- In one terminal, start the HostApp (from your build output folder):

```powershell
cd x64\Release
.\HostApp.exe
```

- In a second terminal (as Administrator), run the MemoryScanner with the printed PID and addresses:

```powershell
.\MemoryScanner.exe <PID> <VTL0_addr> <VTL1_addr>
```

Expected outcome: the scanner can read the public VTL0 data but cannot read the VTL1 enclave data. For full build and run details, see the "Build Instructions" and "Running the PoC" sections below.

### Step 1: Build SDK and CodeGenerator NuGet Packages

From the repository root:

```powershell
cd VbsEnclaveTooling
.\buildScripts\build.ps1
```

This creates NuGet packages in `_build\`:
- `Microsoft.Windows.VbsEnclave.SDK.*.nupkg`
- `Microsoft.Windows.VbsEnclave.CodeGenerator.*.nupkg`

The local `nuget.config` is already configured to use `_build` as a package source.

### Step 2: Build MemoryProtectionPoC Solution

```powershell
cd SampleApps\MemoryProtectionPoC
```

Open `MemoryProtectionPoC.sln` in Visual Studio 2022.

**Build Configuration**:
- Select **Release** configuration (required for full VBS protection)
- Select **x64** platform
- Build → Build Solution (Ctrl+Shift+B)

**What happens during build**:
1. NuGet restores packages from `_build\`
2. `edlcodegen.exe` processes `PoC.edl` and generates:
   - `HostApp\Generated Files\VbsEnclave\HostApp\` - Host stubs to call enclave
   - `Trusted\Generated Files\VbsEnclave\Enclave\` - Enclave implementation headers
3. Code compiles with special `/ENCLAVE` linker flag
4. Post-build: `veiid.exe` applies VBS protection to `Trusted.dll`
5. Post-build: `signtool.exe` signs `Trusted.dll` with your test certificate

**Verify signing**:
```cmd
dumpbin /headers x64\Release\Trusted.dll | findstr ENCLAVE
```

Should show `IMAGE_ENCLAVE_FLAG_PRIMARY_IMAGE`.

### Step 3: Compile Memory Scanner (Attacker)

```cmd
cd SampleApps\MemoryProtectionPoC

:: Option 1: Using Visual Studio Developer Command Prompt
cl.exe attacker.c /Fe:MemoryScanner.exe

:: Option 2: Add to separate console project in Visual Studio
```

### Complete Build Flow (recommended)

Use this flow to build the solution and the helper binaries used by the PoC.

1. From a Developer Command Prompt (or PowerShell with msbuild on PATH), build the solution:

```powershell
cd SampleApps\MemoryProtectionPoC
msbuild MemoryProtectionPoC.sln /p:Configuration=Release /p:Platform=x64
```

2. The solution build will produce `HostApp.exe`, `Trusted.dll` and related outputs under the solution `_build`/project output folders. If you prefer to compile the simple helper apps manually, run:

```cmd
:: Compile Normal control app
cl.exe NormalApp.c /Fe:NormalApp.exe

:: Compile attacker as MemoryScanner.exe (rename via /Fe)
cl.exe attacker.c /Fe:MemoryScanner.exe
```

3. Sign and prepare the enclave (if not already done):

```powershell
.\SignAndRunEnclave.ps1
```

4. Run the HostApp from the build output (example path):

```powershell
cd x64\Release
.\HostApp.exe
```

5. In a second terminal (Administrator), run the scanner using the printed PID and addresses:

```powershell
.\MemoryScanner.exe <PID> <VTL0_addr> <VTL1_addr>
```

Notes:
- Building the solution with `msbuild` will normally handle the enclave generation and packaging steps. Manual `cl.exe` compilation is supported for quick testing of `NormalApp.exe` and `MemoryScanner.exe`.
- Naming: compile `attacker.c` with `/Fe:MemoryScanner.exe` so the binary matches the README examples.

## Running the PoC

### Step 1: Start the Host Application

```cmd
cd x64\Release
.\HostApp.exe
```

**Expected output**:
```
=== VBS Enclave Memory Protection PoC ===

[VTL0] Process ID: 12345
[VTL0] Public data address: 0x7FF6A2B01000
[VTL0] Public data content: PUBLIC_DATA_READABLE_123456

[VTL0] Loading VBS Enclave...
[VTL0] Enclave loaded successfully!

[VTL0] Calling enclave to store secret...
[VTL1] Secret data address: 0x1A0000C3F40
[VTL1] Secret verified via enclave: SECRET_IN_VTL1_987654

======================================
PoC is ready for memory scanning test!
======================================

Run the memory scanner in another terminal:
  MemoryScanner.exe 12345 0x7FF6A2B01000 0x1A0000C3F40

Expected results:
  - VTL0 address: Scanner WILL read: "PUBLIC_DATA_READABLE_123456"
  - VTL1 address: Scanner CANNOT read (protected by VBS)

Press Ctrl+C to exit...
```

**Take note of**:
- **Process ID** (e.g., `12345`)
- **VTL0 address** (public data, e.g., `0x7FF6A2B01000`)
- **VTL1 address** (secret data, e.g., `0x1A0000C3F40`)

### Step 2: Attack with Memory Scanner

Open a **second terminal** (as Administrator):

```cmd
:: Mode 1: Direct address read
MemoryScanner.exe <PID> <vtl0_address> <vtl1_address>

:: Mode 2: Full memory scan only
MemoryScanner.exe <PID>
```

**Example**:
```cmd
MemoryScanner.exe 12345 0x7FF6A2B01000 0x1A0000C3F40
```

### Expected Results

**Direct Read Mode**:
```
========================================
DIRECT READ MODE
========================================

[DIRECT READ] Attempting to read VTL0 (Host Memory) at 0x7FF6A2B01000...
[SUCCESS] Read 1024 bytes from 0x7FF6A2B01000
[CONTENT] First 128 chars: PUBLIC_DATA_READABLE_123456

[DIRECT READ] Attempting to read VTL1 (Enclave Memory) at 0x1A0000C3F40...
[FAILED] Cannot read from 0x1A0000C3F40 - Error: 299 (ERROR_PARTIAL_COPY)

--- Direct Read Results ---
VTL0 Read: SUCCESS (Expected)
VTL1 Read: BLOCKED (Expected - VBS Protected)
```

**Memory Scan Mode**:
```
========================================
MEMORY SCAN MODE
========================================
Scanning memory regions for patterns...
Looking for: 'PUBLIC_DATA_READABLE' and 'SECRET_IN_VTL1'

[FOUND] PUBLIC pattern at 0x7FF6A2B01000
        Content: PUBLIC_DATA_READABLE_123456

--- Scan Summary ---
Regions scanned: 1847
Readable regions: 423
PUBLIC pattern found: YES
SECRET pattern found: NO (VTL1 PROTECTED)
```

## Understanding the Results

### ✅ Success Scenario (VBS Protection Working)

- **VTL0 read**: Success → Public data visible (normal behavior)
- **VTL1 read**: Failed → Secret data protected (VBS working!)
- **Memory scan**: Finds PUBLIC, does NOT find SECRET

### ❌ Failure Scenario (VBS Protection Bypassed)

If the scanner successfully reads VTL1 memory or finds the SECRET pattern:
- **VBS is not properly enabled** → Check Memory Integrity settings
- **Wrong build configuration** → Rebuild in Release mode
- **Enclave not loaded** → Check HostApp logs for errors

## Troubleshooting

### "Cannot load Trusted.dll"

**Cause**: Enclave DLL not signed or signing failed.

**Solution**:
```cmd
:: Verify certificate exists
certutil -store -user My | findstr TheDefaultTestEnclaveCertName

:: Re-sign manually
signtool sign /ph /fd SHA256 /n "TheDefaultTestEnclaveCertName" Trusted.dll
```

### "Memory Integrity is not enabled"

**Solution**:
1. Open Windows Security
2. Device Security → Core isolation details
3. Enable "Memory Integrity"
4. Reboot

### "Test signing is not enabled"

**Solution**:
```cmd
bcdedit /set testsigning on
```
Reboot required.

### "ReadProcessMemory fails with Access Denied"

**Solution**: Run MemoryScanner.exe as Administrator.

### Build Error: "Cannot find SDK packages"

**Solution**:
```powershell
# Rebuild SDK packages from repository root
cd ..\..\..\
.\buildScripts\build.ps1
```

## Architecture Details

### EDL File (PoC.edl)

Defines the enclave interface:
```cpp
enclave {
    trusted {
        uint64_t StoreSecret(wstring secret);  // VTL0 → VTL1 call
        wstring ReadSecret();                   // VTL0 → VTL1 call
    };
};
```

### Code Generation

`edlcodegen.exe` generates:
- **Host side**: Stubs to marshal calls into VTL1
- **Enclave side**: Headers for implementing trusted functions
- **FlatBuffers schemas**: For serialization across VTL boundary

### Memory Layout

```
VTL0 (Normal Memory)
├── HostApp.exe code
├── g_public_data[]       ← Readable by everyone
└── Enclave management

VTL1 (Protected Memory) ← Hardware-isolated
└── Trusted.dll
    └── g_secret_data[]   ← Cannot be read from VTL0
```

### Protection Mechanism

- **VTL isolation**: Hardware-enforced by Windows hypervisor
- **Enclave memory**: Allocated in VTL1 address space
- **ReadProcessMemory**: Cannot cross VTL boundary
- **Memory Integrity**: Enables VTL support via Hyper-V

## References

- [VBS Enclaves Documentation](../../README.md)
- [EDL Syntax Reference](../../docs/Edl.md)
- [Code Generation Guide](../../docs/CodeGeneration.md)
- [Hello World Walkthrough](../../docs/HelloWorldWalkthrough.md)

## License

This Proof of Concept follows the repository license (MIT).

---

**Questions or Issues?**

If this PoC demonstrates successful VTL1 memory access (which should NOT happen), please file an issue with:
- OS version (`winver`)
- Memory Integrity status
- Build configuration (Debug/Release)
- Complete scanner output
