# Script para adicionar o certificado de teste às lojas confiáveis
# Execute como Administrador

Write-Host "=== Corrigindo Certificado para VBS Enclave ===" -ForegroundColor Cyan
Write-Host ""

# Verificar se está executando como Admin
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "ERRO: Este script precisa ser executado como Administrador!" -ForegroundColor Red
    Write-Host "Clique com botao direito no PowerShell e selecione 'Executar como Administrador'" -ForegroundColor Yellow
    exit 1
}

Write-Host "OK - Executando como Administrador" -ForegroundColor Green
Write-Host ""

# Buscar o certificado
Write-Host "[1/3] Buscando certificado de teste..." -ForegroundColor Yellow
$cert = Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Subject -like "*TheDefaultTestEnclaveCertName*" } | Select-Object -First 1

if (-not $cert) {
    Write-Host "ERRO: Certificado nao encontrado!" -ForegroundColor Red
    exit 1
}

Write-Host "OK - Certificado encontrado:" -ForegroundColor Green
Write-Host "  Subject: $($cert.Subject)" -ForegroundColor Gray
Write-Host "  Thumbprint: $($cert.Thumbprint)" -ForegroundColor Gray
Write-Host ""

# Exportar certificado para arquivo temporário
Write-Host "[2/3] Exportando certificado..." -ForegroundColor Yellow
$tempCer = "$env:TEMP\TestEnclaveCert.cer"
Export-Certificate -Cert $cert -FilePath $tempCer -Force | Out-Null
Write-Host "OK - Exportado para: $tempCer" -ForegroundColor Green
Write-Host ""

# Importar para lojas confiáveis
Write-Host "[3/3] Importando para lojas confiaveis..." -ForegroundColor Yellow

try {
    # Adicionar à loja TrustedPublisher (Local Machine)
    Write-Host "  -> Importando para TrustedPublisher (LocalMachine)..." -ForegroundColor Gray
    Import-Certificate -FilePath $tempCer -CertStoreLocation Cert:\LocalMachine\TrustedPublisher -ErrorAction SilentlyContinue | Out-Null
    
    # Adicionar à loja Root (Local Machine)
    Write-Host "  -> Importando para Root (LocalMachine)..." -ForegroundColor Gray
    Import-Certificate -FilePath $tempCer -CertStoreLocation Cert:\LocalMachine\Root -ErrorAction SilentlyContinue | Out-Null
    
    # Adicionar à loja TrustedPublisher (Current User)
    Write-Host "  -> Importando para TrustedPublisher (CurrentUser)..." -ForegroundColor Gray
    Import-Certificate -FilePath $tempCer -CertStoreLocation Cert:\CurrentUser\TrustedPublisher -ErrorAction SilentlyContinue | Out-Null
    
    # Adicionar à loja Root (Current User)
    Write-Host "  -> Importando para Root (CurrentUser)..." -ForegroundColor Gray
    Import-Certificate -FilePath $tempCer -CertStoreLocation Cert:\CurrentUser\Root -ErrorAction SilentlyContinue | Out-Null
    
    Write-Host "OK - Certificado adicionado as lojas confiaveis" -ForegroundColor Green
} catch {
    Write-Host "ERRO ao importar: $_" -ForegroundColor Red
    exit 1
}

# Limpar arquivo temporário
Remove-Item $tempCer -Force -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "=== SUCESSO ===" -ForegroundColor Green
Write-Host ""
Write-Host "O certificado foi adicionado as seguintes lojas:" -ForegroundColor White
Write-Host "  - LocalMachine\TrustedPublisher" -ForegroundColor Gray
Write-Host "  - LocalMachine\Root" -ForegroundColor Gray
Write-Host "  - CurrentUser\TrustedPublisher" -ForegroundColor Gray
Write-Host "  - CurrentUser\Root" -ForegroundColor Gray
Write-Host ""
Write-Host "Agora execute novamente:" -ForegroundColor Yellow
Write-Host "  cd _build\x64\Debug" -ForegroundColor Cyan
Write-Host "  .\HostApp.exe" -ForegroundColor Cyan
Write-Host ""
