# SignAndRunEnclave.ps1
# StoragePoC - sign VBS enclave DLL in _build/x64/Debug and show how to run host app
# Run this script as Administrator

param(
	[string]$CertName = "StoragePoCTestEnclaveCert",
	[string]$DllName = "storagepoc.dll",
	[string]$HostExe = "HostApp.exe",
	[string]$BuildPath = "_build\x64\Debug"
)

$ErrorActionPreference = "Stop"

Write-Host "=====================================" -ForegroundColor Cyan
Write-Host " StoragePoC - Sign and Run Script" -ForegroundColor Cyan
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host ""

# 0. Admin check
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
	Write-Error "Run this script as Administrator."
	exit 1
}

# 1. Locate Windows SDK tools
Write-Host "[1/6] Locating Windows SDK tools..." -ForegroundColor Yellow
$sdkPath = "C:\Program Files (x86)\Windows Kits\10\bin"
$versions = Get-ChildItem $sdkPath | Where-Object { $_.Name -match '10\.0\.' } | Sort-Object Name -Descending
if ($versions.Count -eq 0) {
	Write-Error "Windows SDK not found at $sdkPath"
	exit 1
}

$latestVersion = $versions[0].Name
$toolsPath = Join-Path $sdkPath "$latestVersion\x64"

if (-not (Test-Path (Join-Path $toolsPath "veiid.exe")) -or -not (Test-Path (Join-Path $toolsPath "signtool.exe"))) {
	Write-Error "veiid.exe or signtool.exe not found in $toolsPath"
	exit 1
}

Write-Host "   SDK Version: $latestVersion" -ForegroundColor Green
Write-Host "   Tools Path : $toolsPath" -ForegroundColor Green
Write-Host ""

# 2. Create/verify certificate with VBS enclave EKUs
Write-Host "[2/6] Verifying certificate..." -ForegroundColor Yellow
$existingCert = Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Subject -like "*$CertName*" } | Select-Object -First 1

if ($existingCert) {
	$hasVbsEku = $existingCert.EnhancedKeyUsageList | Where-Object { $_.ObjectId -eq "1.3.6.1.4.1.311.76.57.1.15" }
	if (-not $hasVbsEku) {
		Write-Host "   Existing cert missing VBS EKU. Recreating..." -ForegroundColor Yellow
		Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Subject -like "*$CertName*" } | Remove-Item
		$existingCert = $null
	}
}

if (-not $existingCert) {
	Write-Host "   Creating new certificate with enclave EKUs..." -ForegroundColor Yellow
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

# 3. Import certificate into trust stores
Write-Host "[3/6] Importing certificate into system stores..." -ForegroundColor Yellow
$cert = Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Subject -like "*$CertName*" } | Select-Object -First 1

$tempCertPath = Join-Path $env:TEMP "storagepoc_enclave_cert.cer"
Export-Certificate -Cert $cert -FilePath $tempCertPath -Force | Out-Null

$existingInRoot = Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.Thumbprint -eq $cert.Thumbprint }
if (-not $existingInRoot) {
	Import-Certificate -FilePath $tempCertPath -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
	Write-Host "   Imported to Root" -ForegroundColor Green
} else {
	Write-Host "   Already present in Root" -ForegroundColor Gray
}

$existingInTrustedPeople = Get-ChildItem Cert:\LocalMachine\TrustedPeople | Where-Object { $_.Thumbprint -eq $cert.Thumbprint }
if (-not $existingInTrustedPeople) {
	Import-Certificate -FilePath $tempCertPath -CertStoreLocation Cert:\LocalMachine\TrustedPeople | Out-Null
	Write-Host "   Imported to TrustedPeople" -ForegroundColor Green
} else {
	Write-Host "   Already present in TrustedPeople" -ForegroundColor Gray
}

certutil -addstore -f TrustedPublisher $tempCertPath 2>&1 | Out-Null
Write-Host "   Imported to TrustedPublisher" -ForegroundColor Green

Remove-Item $tempCertPath -Force
Write-Host ""

# 4. Apply VEIID to enclave DLL
Write-Host "[4/6] Applying VEIID to enclave DLL..." -ForegroundColor Yellow
$resolvedBuildPath = Join-Path $PSScriptRoot $BuildPath
$dllPath = Join-Path $resolvedBuildPath $DllName

if (-not (Test-Path $dllPath)) {
	Write-Error "DLL not found: $dllPath"
	Write-Host "Build Host/Trusted outputs to _build/x64/Debug before signing." -ForegroundColor Yellow
	exit 1
}

Push-Location $resolvedBuildPath
& (Join-Path $toolsPath "veiid.exe") $DllName 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) {
	Write-Error "Failed to apply VEIID to $DllName"
	Pop-Location
	exit 1
}

Write-Host "   VEIID applied successfully" -ForegroundColor Green
Write-Host ""

# 5. Sign enclave DLL
Write-Host "[5/6] Signing enclave DLL..." -ForegroundColor Yellow
$stdOutFile = Join-Path $env:TEMP "storagepoc_signtool_stdout.txt"
$stdErrFile = Join-Path $env:TEMP "storagepoc_signtool_stderr.txt"

if (Test-Path $stdOutFile) { Remove-Item $stdOutFile -Force }
if (Test-Path $stdErrFile) { Remove-Item $stdErrFile -Force }

$signProcess = Start-Process `
	-FilePath (Join-Path $toolsPath "signtool.exe") `
	-ArgumentList @("sign", "/ph", "/fd", "SHA256", "/n", $CertName, $DllName) `
	-NoNewWindow `
	-Wait `
	-PassThru `
	-RedirectStandardOutput $stdOutFile `
	-RedirectStandardError $stdErrFile

$signExitCode = $signProcess.ExitCode
$signOutputStr = ""
if (Test-Path $stdOutFile) { $signOutputStr += (Get-Content $stdOutFile -Raw) }
if (Test-Path $stdErrFile) {
	if ($signOutputStr.Length -gt 0) { $signOutputStr += "`n" }
	$signOutputStr += (Get-Content $stdErrFile -Raw)
}

if (Test-Path $stdOutFile) { Remove-Item $stdOutFile -Force }
if (Test-Path $stdErrFile) { Remove-Item $stdErrFile -Force }

if ($signOutputStr -notmatch "Successfully signed") {
	Write-Error "Failed to sign $DllName"
	Write-Host $signOutputStr
	Pop-Location
	exit 1
}

if ($signExitCode -ne 0) {
	Write-Host "   signtool returned exit code $signExitCode (warning). Continuing because file was signed." -ForegroundColor Yellow
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

Write-Host "   Status      : $($sig.Status)" -ForegroundColor Green
Write-Host "   Certificate : $($sig.SignerCertificate.Subject)" -ForegroundColor Green
Write-Host ""

Write-Host "=====================================" -ForegroundColor Cyan
Write-Host " Ready to run!" -ForegroundColor Cyan
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Run now:" -ForegroundColor Yellow
Write-Host "  .\$HostExe" -ForegroundColor Yellow
Write-Host ""

Pop-Location
