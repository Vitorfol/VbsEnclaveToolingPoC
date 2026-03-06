# Script para Verificar e Configurar Test Signing para VBS Enclave
# Execute como Administrador

Write-Host "=== Verificação de Requisitos para VBS Enclave ===" -ForegroundColor Cyan
Write-Host ""

# Verifica se está executando como Admin
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "❌ ERRO: Este script precisa ser executado como Administrador!" -ForegroundColor Red
    Write-Host "   Clique com botão direito no PowerShell e selecione 'Executar como Administrador'" -ForegroundColor Yellow
    exit 1
}

Write-Host "✅ Executando como Administrador" -ForegroundColor Green
Write-Host ""

# 1. Verificar Certificado de Teste
Write-Host "[1/4] Verificando certificado de teste..." -ForegroundColor Yellow
$cert = Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Subject -like "*TheDefaultTestEnclaveCertName*" } | Select-Object -First 1

if ($cert) {
    Write-Host "✅ Certificado de teste encontrado:" -ForegroundColor Green
    Write-Host "    Subject: $($cert.Subject)" -ForegroundColor Gray
    Write-Host "    Thumbprint: $($cert.Thumbprint)" -ForegroundColor Gray
} else {
    Write-Host "❌ Certificado de teste NÃO encontrado!" -ForegroundColor Red
    Write-Host "   Criando certificado..." -ForegroundColor Yellow
    
    try {
        $newCert = New-SelfSignedCertificate `
            -CertStoreLocation Cert:\CurrentUser\My `
            -DnsName "TheDefaultTestEnclaveCertName" `
            -Subject "CN=TheDefaultTestEnclaveCertName" `
            -Type CodeSigningCert `
            -KeyUsage DigitalSignature `
            -KeyAlgorithm RSA `
            -KeyLength 2048 `
            -NotAfter (Get-Date).AddYears(5)
        
        Write-Host "✅ Certificado criado com sucesso!" -ForegroundColor Green
        Write-Host "    Thumbprint: $($newCert.Thumbprint)" -ForegroundColor Gray
    } catch {
        Write-Host "❌ Erro ao criar certificado: $_" -ForegroundColor Red
        exit 1
    }
}
Write-Host ""

# 2. Verificar Test Signing
Write-Host "[2/4] Verificando Test Signing..." -ForegroundColor Yellow
$testSigningStatus = cmd /c bcdedit /enum `{current`} 2>&1 | Select-String "testsigning"

if ($testSigningStatus -match "Yes") {
    Write-Host "✅ Test Signing JÁ ESTÁ HABILITADO" -ForegroundColor Green
    $needsReboot = $false
} else {
    Write-Host "⚠️  Test Signing NÃO está habilitado" -ForegroundColor Red
    Write-Host ""
    Write-Host "⚠️  AVISO IMPORTANTE:" -ForegroundColor Yellow
    Write-Host "   - Habilitar Test Signing desabilitará o Secure Boot" -ForegroundColor Yellow
    Write-Host "   - Se você usa BitLocker, faça backup das chaves de recuperação" -ForegroundColor Yellow
    Write-Host "   - Será necessário REINICIAR o computador" -ForegroundColor Yellow
    Write-Host ""
    
    $response = Read-Host "Deseja habilitar Test Signing? (S/N)"
    
    if ($response -eq "S" -or $response -eq "s") {
        try {
            cmd /c bcdedit /set testsigning on
            Write-Host "✅ Test Signing habilitado com sucesso!" -ForegroundColor Green
            $needsReboot = $true
        } catch {
            Write-Host "❌ Erro ao habilitar Test Signing: $_" -ForegroundColor Red
            Write-Host "   Tente executar manualmente: bcdedit /set testsigning on" -ForegroundColor Yellow
            exit 1
        }
    } else {
        Write-Host "❌ Test Signing é necessário para executar VBS Enclaves em modo de desenvolvimento" -ForegroundColor Red
        exit 1
    }
}
Write-Host ""

# 3. Verificar Virtualização
Write-Host "[3/4] Verificando suporte a virtualização..." -ForegroundColor Yellow
$vmPlatform = Get-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform -ErrorAction SilentlyContinue

if ($vmPlatform -and $vmPlatform.State -eq "Enabled") {
    Write-Host "✅ Plataforma de Máquina Virtual habilitada" -ForegroundColor Green
} else {
    Write-Host "⚠️  Plataforma de Máquina Virtual pode não estar habilitada" -ForegroundColor Yellow
    Write-Host "   VBS Enclaves requerem virtualização habilitada no BIOS" -ForegroundColor Yellow
}
Write-Host ""

# 4. Verificar Memory Integrity (Core Isolation)
Write-Host "[4/4] Verificando Memory Integrity..." -ForegroundColor Yellow
Write-Host "   (Opcional, mas recomendado para VBS)" -ForegroundColor Gray
Write-Host "   Vá em: Configurações → Privacidade e Segurança → Segurança do Windows → Segurança do dispositivo → Isolamento de núcleo" -ForegroundColor Gray
Write-Host ""

# Resumo
Write-Host "=== RESUMO ===" -ForegroundColor Cyan
Write-Host ""

if ($needsReboot) {
    Write-Host "⚠️  REINICIALIZAÇÃO NECESSÁRIA" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Próximos passos:" -ForegroundColor White
    Write-Host "1. Salve todo o seu trabalho" -ForegroundColor Gray
    Write-Host "2. Reinicie o computador" -ForegroundColor Gray
    Write-Host "3. Após reiniciar, você verá 'Modo de Teste' no canto da tela" -ForegroundColor Gray
    Write-Host "4. Recompile o projeto Trusted.dll" -ForegroundColor Gray
    Write-Host "5. Execute o HostApp.exe" -ForegroundColor Gray
    Write-Host ""
    
    $reboot = Read-Host "Deseja reiniciar AGORA? (S/N)"
    if ($reboot -eq "S" -or $reboot -eq "s") {
        Write-Host "Reiniciando em 10 segundos..." -ForegroundColor Yellow
        shutdown /r /t 10 /c "Reiniciando para ativar Test Signing para VBS Enclave"
    }
} else {
    Write-Host "✅ Sistema configurado corretamente!" -ForegroundColor Green
    Write-Host ""
    Write-Host "Você pode compilar e executar o VBS Enclave agora." -ForegroundColor White
    Write-Host ""
    Write-Host "Para desabilitar Test Signing no futuro:" -ForegroundColor Gray
    Write-Host "  bcdedit /set testsigning off" -ForegroundColor Gray
    Write-Host "  (e reinicie o computador)" -ForegroundColor Gray
}

Write-Host ""
