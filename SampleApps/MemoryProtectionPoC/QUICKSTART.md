# Quick Start - Memory Protection PoC

## 📋 Pré-requisitos

1. Windows 11 24H2+ com VBS habilitado
2. Visual Studio 2022 com C++ tools
3. Test Signing habilitado (`bcdedit /set testsigning on`)

## 🚀 Como executar (3 passos)

### 1. Compilar e assinar o Enclave

```powershell
.\SignAndRunEnclave.ps1
```

Este script:
- ✅ Cria/verifica certificado com EKU correto para VBS Enclave
- ✅ Importa certificado para stores confiáveis
- ✅ Aplica VEIID protection
- ✅ Assina o Trusted.dll

### 2. Compilar o Memory Scanner (Attacker)

Em um **Developer Command Prompt for VS 2022**:

```cmd
cl.exe attacker.c /Fe:MemoryScanner.exe
```

### 3. Executar o teste

**Terminal 1** - Execute o HostApp:
```powershell
cd _build\x64\Debug
.\HostApp.exe
```

O HostApp mostrará algo como:
```
=== VBS Enclave Memory Protection PoC ===

[VTL0] Process ID: 12345
[VTL0] Public data address: 0x7ff6f3f08008
[VTL1] Secret data address: 0x1a2b3c4d5e6f

Run the memory scanner in another terminal:
  MemoryScanner.exe 12345 0x7ff6f3f08008 0x1a2b3c4d5e6f
```

**Terminal 2** - Execute o Memory Scanner com os valores exibidos:
```powershell
.\MemoryScanner.exe <PID> <VTL0_addr> <VTL1_addr>
```

## ✅ Resultado esperado

- **VTL0 Memory**: Scanner consegue ler "PUBLIC_DATA_READABLE_123456" ✅
- **VTL1 Memory**: Scanner **FALHA** ao ler (protegido por VBS) ❌

Isso demonstra que a memória do enclave VBS é **hardware-isolated** e não pode ser lida por processos normais!

## 📁 Scripts auxiliares

Scripts auxiliares foram movidos para `Scripts/` e não são necessários para execução normal.

## ⚠️ Troubleshooting

Se o HostApp falhar com erro de assinatura:
1. Execute `.\SignAndRunEnclave.ps1` novamente
2. Verifique se test signing está habilitado
3. Verifique se Memory Integrity está habilitado no Windows Security
