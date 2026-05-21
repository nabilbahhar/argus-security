# install_tools.ps1
# ===================
# Télécharge les outils OSS dont Pupelmet a besoin.
#
# Outils installés :
#   - subfinder : trouve les sous-domaines (passive OSINT)
#   - httpx    : probing HTTP + détection techno
#   - nuclei   : scanner de vulnérabilités CVE (12k+ templates YAML)
#   - tlsx     : analyse TLS/SSL approfondie (certs, ciphers, protocoles)
#                (= dit si un site utilise un certificat expiré, du TLS 1.0 obsolète, etc.)
#
# Source : ProjectDiscovery (https://projectdiscovery.io/)

$ErrorActionPreference = "Stop"

$BinDir = Join-Path $PSScriptRoot "bin"
New-Item -ItemType Directory -Force -Path $BinDir | Out-Null

Write-Host ""
Write-Host "Installation des outils OSS pour Pupelmet..." -ForegroundColor Cyan
Write-Host "Destination : $BinDir" -ForegroundColor Gray
Write-Host ""

$SubfinderVersion = "2.6.7"
$HttpxVersion = "1.6.10"
$NucleiVersion = "3.3.7"
$TlsxVersion = "1.1.8"
# === PENTEST MODE (opt-in) ===
$NaabuVersion = "2.3.3"      # Port scan (top 1000)
$FfufVersion = "2.1.0"       # Directory/file fuzzing
$DnsxVersion = "1.2.2"       # DNS resolution at scale
$KatanaVersion = "1.1.2"     # Crawler intelligent (endpoints JS/API)

$Tools = @(
    @{
        Name = "subfinder"
        Url  = "https://github.com/projectdiscovery/subfinder/releases/download/v$SubfinderVersion/subfinder_${SubfinderVersion}_windows_amd64.zip"
        Zip  = "subfinder.zip"
    },
    @{
        Name = "httpx"
        Url  = "https://github.com/projectdiscovery/httpx/releases/download/v$HttpxVersion/httpx_${HttpxVersion}_windows_amd64.zip"
        Zip  = "httpx.zip"
    },
    @{
        Name = "nuclei"
        Url  = "https://github.com/projectdiscovery/nuclei/releases/download/v$NucleiVersion/nuclei_${NucleiVersion}_windows_amd64.zip"
        Zip  = "nuclei.zip"
    },
    @{
        Name = "tlsx"
        Url  = "https://github.com/projectdiscovery/tlsx/releases/download/v$TlsxVersion/tlsx_${TlsxVersion}_windows_amd64.zip"
        Zip  = "tlsx.zip"
    },
    # === PENTEST MODE — outils additionnels (opt-in côté UI) ===
    @{
        Name = "naabu"
        Url  = "https://github.com/projectdiscovery/naabu/releases/download/v$NaabuVersion/naabu_${NaabuVersion}_windows_amd64.zip"
        Zip  = "naabu.zip"
    },
    @{
        Name = "ffuf"
        Url  = "https://github.com/ffuf/ffuf/releases/download/v$FfufVersion/ffuf_${FfufVersion}_windows_amd64.zip"
        Zip  = "ffuf.zip"
    },
    @{
        Name = "dnsx"
        Url  = "https://github.com/projectdiscovery/dnsx/releases/download/v$DnsxVersion/dnsx_${DnsxVersion}_windows_amd64.zip"
        Zip  = "dnsx.zip"
    },
    @{
        Name = "katana"
        Url  = "https://github.com/projectdiscovery/katana/releases/download/v$KatanaVersion/katana_${KatanaVersion}_windows_amd64.zip"
        Zip  = "katana.zip"
    }
)

foreach ($Tool in $Tools) {
    $ZipPath = Join-Path $BinDir $Tool.Zip
    $ExePath = Join-Path $BinDir "$($Tool.Name).exe"

    if (Test-Path $ExePath) {
        Write-Host "[OK] $($Tool.Name) deja installe -> $ExePath" -ForegroundColor Green
        continue
    }

    Write-Host "[...] Telechargement de $($Tool.Name)..." -ForegroundColor Yellow
    Invoke-WebRequest -Uri $Tool.Url -OutFile $ZipPath -UseBasicParsing
    Expand-Archive -Path $ZipPath -DestinationPath $BinDir -Force
    Remove-Item $ZipPath -Force

    if (Test-Path $ExePath) {
        Write-Host "[OK] $($Tool.Name) installe -> $ExePath" -ForegroundColor Green
    } else {
        Write-Host "[ERREUR] $($Tool.Name) installation echouee." -ForegroundColor Red
        exit 1
    }
}

# Première fois : nuclei doit télécharger ses templates (12 000+ YAML)
$NucleiTemplatesDir = Join-Path $env:USERPROFILE "nuclei-templates"
if (-not (Test-Path $NucleiTemplatesDir)) {
    Write-Host ""
    Write-Host "[...] Premier lancement nuclei : telechargement des templates CVE..." -ForegroundColor Yellow
    & (Join-Path $BinDir "nuclei.exe") -update-templates -silent
    Write-Host "[OK] Templates Nuclei prets" -ForegroundColor Green
}

Write-Host ""
Write-Host "Tous les outils sont installes." -ForegroundColor Green
Write-Host ""
Write-Host "Test rapide :" -ForegroundColor Cyan
Write-Host "  .\tools\bin\subfinder.exe -version" -ForegroundColor Gray
Write-Host "  .\tools\bin\httpx.exe -version" -ForegroundColor Gray
Write-Host "  .\tools\bin\nuclei.exe -version" -ForegroundColor Gray
Write-Host "  .\tools\bin\tlsx.exe -version" -ForegroundColor Gray
Write-Host ""
