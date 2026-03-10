# SignAndRunEnclave.ps1
# Script to sign the VBS Enclave DLL and run the host
# Run as Administrator

param(
    [string]$CertName = "TheDefaultTestEnclaveCertName",
    [string]$DllName = "Trusted.dll",
    [string]$HostExe = "HostApp.exe"
)

# Header
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host " VBS Enclave - Sign and Run Script" -ForegroundColor Cyan
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host ""

# 1. Locate Windows SDK tools
Write-Host "[1/6] Locating Windows SDK tools..." -ForegroundColor Yellow
$sdkPath = "C:\Program Files (x86)\Windows Kits\10\bin"
$versions = Get-ChildItem $sdkPath | Where-Object { $_.Name -match '10\.0\.' } | Sort-Object Name -Descending
if ($versions.Count -eq 0) {
    Write-Error "Windows SDK not found at $sdkPath"
    exit 1
}
$latestVersion = $versions[0].Name
$toolsPath = "$sdkPath\$latestVersion\x64"

if (-not (Test-Path "$toolsPath\veiid.exe") -or -not (Test-Path "$toolsPath\signtool.exe")) {
    Write-Error "veiid.exe or signtool.exe not found in $toolsPath"
    exit 1
}

Write-Host "   SDK Versão: $latestVersion" -ForegroundColor Green
Write-Host "   Ferramentas: $toolsPath" -ForegroundColor Green
Write-Host ""

# 2. Create/verify certificate with correct EKUs
Write-Host "[2/6] Verifying certificate..." -ForegroundColor Yellow
$existingCert = Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Subject -like "*$CertName*" } | Select-Object -First 1

if ($existingCert) {
    $hasCorrectEku = $existingCert.EnhancedKeyUsageList | Where-Object { $_.ObjectId -eq "1.3.6.1.4.1.311.76.57.1.15" }
    
    if (-not $hasCorrectEku) {
        Write-Host "   Existing certificate does not have correct EKUs. Removing..." -ForegroundColor Yellow
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
    
    Write-Host "   Certificate created: $($newCert.Thumbprint)" -ForegroundColor Green
} else {
    Write-Host "   Valid certificate found: $($existingCert.Thumbprint)" -ForegroundColor Green
}
Write-Host ""

# 3. Export and import certificate into system stores
Write-Host "[3/6] Importing certificate into system stores..." -ForegroundColor Yellow
$cert = Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Subject -like "*$CertName*" } | Select-Object -First 1

$tempCertPath = "$env:TEMP\vbs_enclave_cert.cer"
Export-Certificate -Cert $cert -FilePath $tempCertPath -Force | Out-Null

# Importar para Root
$existingInRoot = Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.Thumbprint -eq $cert.Thumbprint }
if (-not $existingInRoot) {
    Import-Certificate -FilePath $tempCertPath -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
    Write-Host "   Imported to Root" -ForegroundColor Green
} else {
    Write-Host "   Already present in Root" -ForegroundColor Gray
}

# Importar para TrustedPeople
$existingInTrustedPeople = Get-ChildItem Cert:\LocalMachine\TrustedPeople | Where-Object { $_.Thumbprint -eq $cert.Thumbprint }
if (-not $existingInTrustedPeople) {
    Import-Certificate -FilePath $tempCertPath -CertStoreLocation Cert:\LocalMachine\TrustedPeople | Out-Null
    Write-Host "   Imported to TrustedPeople" -ForegroundColor Green
} else {
    Write-Host "   Already present in TrustedPeople" -ForegroundColor Gray
}

# Importar para TrustedPublisher
certutil -addstore -f TrustedPublisher $tempCertPath 2>&1 | Out-Null
Write-Host "   Imported to TrustedPublisher" -ForegroundColor Green

Remove-Item $tempCertPath -Force
Write-Host ""

# 4. Locate DLL and apply VEIID
Write-Host "[4/6] Applying VEIID to DLL..." -ForegroundColor Yellow
$buildPath = Join-Path $PSScriptRoot "_build\x64\Debug"
$dllPath = Join-Path $buildPath $DllName

if (-not (Test-Path $dllPath)) {
    Write-Error "DLL not found: $dllPath"
    exit 1
}

Push-Location $buildPath
& "$toolsPath\veiid.exe" $DllName 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Failed to apply VEIID"
        Pop-Location
        exit 1
    }
    Write-Host "   VEIID applied successfully" -ForegroundColor Green
    Write-Host ""

# 5. Sign the DLL
Write-Host "[5/6] Signing the DLL..." -ForegroundColor Yellow
$signOutput = & "$toolsPath\signtool.exe" sign /ph /fd SHA256 /n $CertName $DllName 2>&1
$signOutputStr = $signOutput -join "`n"

# Check that signing succeeded (ignore warnings)
if ($signOutputStr -notmatch "Successfully signed") {
    Write-Error "Failed to sign DLL"
    Write-Host $signOutputStr
    Pop-Location
    exit 1
}
Write-Host "   DLL signed successfully" -ForegroundColor Green
Write-Host ""

# 6. Verify signature
Write-Host "[6/6] Verifying signature..." -ForegroundColor Yellow
$sig = Get-AuthenticodeSignature $DllName
if ($sig.Status -ne "Valid") {
    Write-Error "Invalid signature: $($sig.StatusMessage)"
    Pop-Location
    exit 1
}
Write-Host "   Status: $($sig.Status)" -ForegroundColor Green
Write-Host "   Certificate: $($sig.SignerCertificate.Subject)" -ForegroundColor Green
Write-Host ""

Write-Host "=====================================" -ForegroundColor Cyan
Write-Host " Ready to run!" -ForegroundColor Cyan
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Run now: .\$HostExe" -ForegroundColor Yellow
Write-Host ""

Pop-Location
