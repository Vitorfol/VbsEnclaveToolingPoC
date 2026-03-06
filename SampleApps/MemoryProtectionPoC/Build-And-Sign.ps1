# Script para compilar e assinar manualmente o Trusted.dll
# Execute este script do diretorio raiz do projeto MemoryProtectionPoC

Write-Host "=== Build e Assinatura Manual do VBS Enclave ===" -ForegroundColor Cyan
Write-Host ""

# Compilar (ignora erro do PostBuildEvent)
Write-Host "[1/5] Compilando Trusted.dll..." -ForegroundColor Yellow
msbuild Trusted\Trusted.vcxproj /t:Build /p:Configuration=Debug /p:Platform=x64 /v:minimal 2>&1 | Out-Null

# Verificar se a DLL foi criada
if (Test-Path "_build\x64\Debug\Trusted.dll") {
    Write-Host "OK - Trusted.dll compilada com sucesso" -ForegroundColor Green
} else {
    Write-Host "ERRO: Trusted.dll nao foi criada" -ForegroundColor Red
    exit 1
}

# Ir para o diretorio de output
Push-Location "_build\x64\Debug"

# Aplicar VEIID
Write-Host "[2/5] Aplicando protecao VEIID..." -ForegroundColor Yellow
$veiidPath = "C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\veiid.exe"

if (Test-Path $veiidPath) {
    & $veiidPath Trusted.dll 2>&1 | Out-Null
    Write-Host "OK - VEIID aplicado" -ForegroundColor Green
} else {
    Write-Host "Aviso: VEIID nao encontrado em: $veiidPath" -ForegroundColor Yellow
    Write-Host "Tentando encontrar automaticamente..." -ForegroundColor Yellow
    
    $veiidPath = Get-ChildItem "C:\Program Files (x86)\Windows Kits\10\bin" -Recurse -Filter "veiid.exe" | 
                 Where-Object { $_.FullName -like "*\x64\*" } | 
                 Select-Object -First 1 -ExpandProperty FullName
    
    if ($veiidPath) {
        Write-Host "Encontrado em: $veiidPath" -ForegroundColor Gray
        & $veiidPath Trusted.dll 2>&1 | Out-Null
        Write-Host "OK - VEIID aplicado" -ForegroundColor Green
    } else {
        Write-Host "ERRO: veiid.exe nao encontrado" -ForegroundColor Red
        Pop-Location
        exit 1
    }
}

# Encontrar signtool
Write-Host "[3/5] Localizando signtool..." -ForegroundColor Yellow
$signtoolPath = Get-ChildItem "C:\Program Files (x86)\Windows Kits\10\bin" -Recurse -Filter "signtool.exe" | 
                Where-Object { $_.FullName -like "*\x64\*" } | 
                Select-Object -First 1 -ExpandProperty FullName

if (-not $signtoolPath) {
    Write-Host "ERRO: signtool.exe nao encontrado" -ForegroundColor Red
    Pop-Location
    exit 1
}

Write-Host "Encontrado: $signtoolPath" -ForegroundColor Gray

# Assinar
Write-Host "[4/5] Assinando com certificado de teste..." -ForegroundColor Yellow
try {
    $signOutput = & $signtoolPath sign /ph /fd SHA256 /n "TheDefaultTestEnclaveCertName" Trusted.dll 2>&1 | Out-String
    
    if ($signOutput -like "*Successfully signed*") {
        Write-Host "OK - Trusted.dll assinada com sucesso" -ForegroundColor Green
    } else {
        Write-Host "Aviso durante assinatura:" -ForegroundColor Yellow
        Write-Host $signOutput -ForegroundColor Gray
    }
} catch {
    Write-Host "ERRO ao assinar: $_" -ForegroundColor Red
    Pop-Location
    exit 1
}

# Verificar HostApp
Write-Host "[5/5] Verificando HostApp.exe..." -ForegroundColor Yellow
if (Test-Path "HostApp.exe") {
    Write-Host "OK - HostApp.exe encontrado" -ForegroundColor Green
} else {
    Write-Host "Aviso: HostApp.exe nao encontrado. Compilando..." -ForegroundColor Yellow
    Pop-Location
    msbuild HostApp\HostApp.vcxproj /t:Build /p:Configuration=Debug /p:Platform=x64 /v:minimal
    Push-Location "_build\x64\Debug"
    
    if (Test-Path "HostApp.exe") {
        Write-Host "OK - HostApp.exe compilado" -ForegroundColor Green
    } else {
        Write-Host "ERRO: Falha ao compilar HostApp.exe" -ForegroundColor Red
        Pop-Location
        exit 1
    }
}

# Resumo
Write-Host ""
Write-Host "=== PRONTO PARA EXECUTAR ===" -ForegroundColor Green
Write-Host ""
Write-Host "Arquivos prontos em: _build\x64\Debug\" -ForegroundColor White
Write-Host ""
Write-Host "Execute agora:" -ForegroundColor Yellow
Write-Host "  .\HostApp.exe" -ForegroundColor Cyan
Write-Host ""

# Perguntar se quer executar automaticamente
$run = Read-Host "Deseja executar HostApp.exe agora? (S/N)"
if ($run -eq "S" -or $run -eq "s") {
    Write-Host ""
    Write-Host "=== EXECUTANDO HOSTAPP ===" -ForegroundColor Cyan
    Write-Host ""
    .\HostApp.exe
}

Pop-Location
