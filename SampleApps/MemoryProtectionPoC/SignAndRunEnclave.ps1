# SignAndRunEnclave.ps1
# Script para assinar o DLL do VBS Enclave e executar o host
# Execute como Administrador

param(
    [string]$CertName = "TheDefaultTestEnclaveCertName",
    [string]$DllName = "Trusted.dll",
    [string]$HostExe = "HostApp.exe"
)

Write-Host "=====================================" -ForegroundColor Cyan
Write-Host " VBS Enclave - Sign and Run Script" -ForegroundColor Cyan
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host ""

# 1. Localizar ferramentas do Windows SDK
Write-Host "[1/6] Localizando ferramentas do Windows SDK..." -ForegroundColor Yellow
$sdkPath = "C:\Program Files (x86)\Windows Kits\10\bin"
$versions = Get-ChildItem $sdkPath | Where-Object { $_.Name -match '10\.0\.' } | Sort-Object Name -Descending
if ($versions.Count -eq 0) {
    Write-Error "Windows SDK não encontrado em $sdkPath"
    exit 1
}
$latestVersion = $versions[0].Name
$toolsPath = "$sdkPath\$latestVersion\x64"

if (-not (Test-Path "$toolsPath\veiid.exe") -or -not (Test-Path "$toolsPath\signtool.exe")) {
    Write-Error "veiid.exe ou signtool.exe não encontrados em $toolsPath"
    exit 1
}

Write-Host "   SDK Versão: $latestVersion" -ForegroundColor Green
Write-Host "   Ferramentas: $toolsPath" -ForegroundColor Green
Write-Host ""

# 2. Criar/verificar certificado com EKUs corretas
Write-Host "[2/6] Verificando certificado..." -ForegroundColor Yellow
$existingCert = Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Subject -like "*$CertName*" } | Select-Object -First 1

if ($existingCert) {
    $hasCorrectEku = $existingCert.EnhancedKeyUsageList | Where-Object { $_.ObjectId -eq "1.3.6.1.4.1.311.76.57.1.15" }
    
    if (-not $hasCorrectEku) {
        Write-Host "   Certificado existente não tem EKUs corretas. Removendo..." -ForegroundColor Yellow
        Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Subject -like "*$CertName*" } | Remove-Item
        $existingCert = $null
    }
}

if (-not $existingCert) {
    Write-Host "   Criando novo certificado com EKUs para VBS Enclave..." -ForegroundColor Yellow
    $newCert = New-SelfSignedCertificate `
        -CertStoreLocation Cert:\CurrentUser\My `
        -DnsName $CertName `
        -KeyUsage DigitalSignature `
        -KeySpec Signature `
        -KeyLength 2048 `
        -KeyAlgorithm RSA `
        -HashAlgorithm SHA256 `
        -TextExtension "2.5.29.37={text}1.3.6.1.5.5.7.3.3,1.3.6.1.4.1.311.76.57.1.15,1.3.6.1.4.1.311.97.814040577.346743379.4783502.105532346"
    
    Write-Host "   Certificado criado: $($newCert.Thumbprint)" -ForegroundColor Green
} else {
    Write-Host "   Certificado válido encontrado: $($existingCert.Thumbprint)" -ForegroundColor Green
}
Write-Host ""

# 3. Exportar e importar certificado para stores do sistema
Write-Host "[3/6] Importando certificado para stores confiáveis..." -ForegroundColor Yellow
$cert = Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Subject -like "*$CertName*" } | Select-Object -First 1

$tempCertPath = "$env:TEMP\vbs_enclave_cert.cer"
Export-Certificate -Cert $cert -FilePath $tempCertPath -Force | Out-Null

# Importar para Root
$existingInRoot = Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.Thumbprint -eq $cert.Thumbprint }
if (-not $existingInRoot) {
    Import-Certificate -FilePath $tempCertPath -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
    Write-Host "   Importado para Root" -ForegroundColor Green
} else {
    Write-Host "   Já existe em Root" -ForegroundColor Gray
}

# Importar para TrustedPeople
$existingInTrustedPeople = Get-ChildItem Cert:\LocalMachine\TrustedPeople | Where-Object { $_.Thumbprint -eq $cert.Thumbprint }
if (-not $existingInTrustedPeople) {
    Import-Certificate -FilePath $tempCertPath -CertStoreLocation Cert:\LocalMachine\TrustedPeople | Out-Null
    Write-Host "   Importado para TrustedPeople" -ForegroundColor Green
} else {
    Write-Host "   Já existe em TrustedPeople" -ForegroundColor Gray
}

# Importar para TrustedPublisher
certutil -addstore -f TrustedPublisher $tempCertPath 2>&1 | Out-Null
Write-Host "   Importado para TrustedPublisher" -ForegroundColor Green

Remove-Item $tempCertPath -Force
Write-Host ""

# 4. Localizar DLL e aplicar VEIID
Write-Host "[4/6] Aplicando VEIID no DLL..." -ForegroundColor Yellow
$buildPath = Join-Path $PSScriptRoot "_build\x64\Debug"
$dllPath = Join-Path $buildPath $DllName

if (-not (Test-Path $dllPath)) {
    Write-Error "DLL não encontrado: $dllPath"
    exit 1
}

Push-Location $buildPath
& "$toolsPath\veiid.exe" $DllName 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Error "Falha ao aplicar VEIID"
    Pop-Location
    exit 1
}
Write-Host "   VEIID aplicado com sucesso" -ForegroundColor Green
Write-Host ""

# 5. Assinar o DLL
Write-Host "[5/6] Assinando o DLL..." -ForegroundColor Yellow
$signOutput = & "$toolsPath\signtool.exe" sign /ph /fd SHA256 /n $CertName $DllName 2>&1
$signOutputStr = $signOutput -join "`n"

# Verificar se a assinatura foi bem-sucedida (ignorar warnings)
if ($signOutputStr -notmatch "Successfully signed") {
    Write-Error "Falha ao assinar DLL"
    Write-Host $signOutputStr
    Pop-Location
    exit 1
}
Write-Host "   DLL assinado com sucesso" -ForegroundColor Green
Write-Host ""

# 6. Verificar assinatura
Write-Host "[6/6] Verificando assinatura..." -ForegroundColor Yellow
$sig = Get-AuthenticodeSignature $DllName
if ($sig.Status -ne "Valid") {
    Write-Error "Assinatura inválida: $($sig.StatusMessage)"
    Pop-Location
    exit 1
}
Write-Host "   Status: $($sig.Status)" -ForegroundColor Green
Write-Host "   Certificado: $($sig.SignerCertificate.Subject)" -ForegroundColor Green
Write-Host ""

Write-Host "=====================================" -ForegroundColor Cyan
Write-Host " Pronto para executar!" -ForegroundColor Cyan
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Execute agora: .\$HostExe" -ForegroundColor Yellow
Write-Host ""

Pop-Location
