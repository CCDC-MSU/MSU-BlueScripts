[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$BaselinePath = "C:\Temp\cert_baseline.xml",
    
    [Parameter(Mandatory=$false)]
    [switch]$CreateBaseline,
    
    [Parameter(Mandatory=$false)]
    [switch]$ExportCSV,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = "C:\Temp\MaliciousCerts_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
)

$suspiciousCerts = @()
$findings = 0

# Known legitimate root CAs - these are expected to be self-signed
$knownLegitimateRootCAs = @(
    # Major CAs
    "DigiCert", "VeriSign", "Thawte", "GeoTrust", "Baltimore CyberTrust",
    "GlobalSign", "Entrust", "Comodo", "Sectigo", "IdenTrust",
    "Go Daddy", "GoDaddy", "USERTrust", "AAA Certificate Services",
    "Starfield", "QuoVadis", "SecureTrust", "AddTrust",
    # Let's Encrypt / ISRG
    "ISRG Root", "Internet Security Research Group",
    # Other legitimate CAs
    "DST Root CA", "SSL.com", "Certum", "Telia",
    "SECOM Trust", "Hellenic Academic",
    # Microsoft legitimate roots (note: very specific names)
    "Microsoft Root Certificate Authority 2011",
    "Microsoft Root Certificate Authority 2010", 
    "Microsoft Root Authority",
    "Microsoft Authenticode(tm) Root Authority",
    "Microsoft ECC TS Root Certificate Authority 2018",
    "Microsoft ECC Product Root Certificate Authority 2018",
    "Microsoft Time Stamp Root Certificate Authority 2014",
    "Microsoft Identity Verification Root Certificate Authority 2020",
    "Microsoft RSA Root Certificate Authority 2017",
    "Microsoft Root Certificate Authority, DC=microsoft, DC=com",
    "Microsoft Time Stamping Service Root",
    "Symantec Enterprise Mobile Root for Microsoft"
)

# Organizations that red team might impersonate with NEW certificates
$impersonationTargets = @(
    "Microsoft Corporation" # but not the known legitimate roots above
)

function Test-SelfSigned {
    param($cert)
    return ($cert.Issuer -eq $cert.Subject)
}

function Test-KnownLegitimateRootCA {
    param($cert)
    foreach ($knownCA in $knownLegitimateRootCAs) {
        if ($cert.Subject -like "*$knownCA*") {
            return $true
        }
    }
    return $false
}

function Test-SuspiciousImpersonation {
    param($cert)
    # Check if it looks like impersonation of a known org
    # but is NOT one of the known legitimate roots
    
    if (Test-KnownLegitimateRootCA $cert) {
        return $false  # It's a known legitimate root
    }
    
    # Check for generic impersonation attempts
    foreach ($target in $impersonationTargets) {
        if ($cert.Subject -like "*$target*") {
            return $true
        }
    }
    
    # Also flag very generic/suspicious names
    $suspiciousNames = @(
        "Internal", "Test", "Fake", "Demo", "Temp",
        "Development", "Dev CA", "Corporate CA"
    )
    
    foreach ($name in $suspiciousNames) {
        if ($cert.Subject -like "*$name*") {
            return $true
        }
    }
    
    return $false
}

function Add-Finding {
    param($cert, $store, $reason, $severity = "High")
    
    $script:findings++
    
    $certInfo = [PSCustomObject]@{
        Finding = $script:findings
        Severity = $severity
        Subject = $cert.Subject
        Issuer = $cert.Issuer
        Thumbprint = $cert.Thumbprint
        Store = $store
        NotBefore = $cert.NotBefore
        NotAfter = $cert.NotAfter
        HasPrivateKey = $cert.HasPrivateKey
        EnhancedKeyUsage = ($cert.EnhancedKeyUsageList.FriendlyName -join ", ")
        Reason = $reason
    }
    
    $script:suspiciousCerts += $certInfo
    return $certInfo
}

# Create baseline mode
if ($CreateBaseline) {
    Write-Host "[*] Creating baseline of all certificates..." -ForegroundColor Yellow
    
    $baseline = @{
        Created = Get-Date
        LocalMachineRoot = @()
        CurrentUserRoot = @()
        CurrentUserMy = @()
    }
    
    try {
        $baseline.LocalMachineRoot = Get-ChildItem Cert:\LocalMachine\Root -ErrorAction Stop | 
            Select-Object Thumbprint, Subject, Issuer, NotBefore
        
        $baseline.CurrentUserRoot = Get-ChildItem Cert:\CurrentUser\Root -ErrorAction SilentlyContinue | 
            Select-Object Thumbprint, Subject, Issuer, NotBefore
        
        $baseline.CurrentUserMy = Get-ChildItem Cert:\CurrentUser\My -ErrorAction SilentlyContinue | 
            Select-Object Thumbprint, Subject, Issuer, NotBefore
        
        $baseline | Export-Clixml -Path $BaselinePath
        
        Write-Host "[+] Baseline created: $BaselinePath" -ForegroundColor Green
        Write-Host "    LocalMachine\Root: $($baseline.LocalMachineRoot.Count) certificates" -ForegroundColor Gray
        Write-Host "    CurrentUser\Root: $($baseline.CurrentUserRoot.Count) certificates" -ForegroundColor Gray
        Write-Host "    CurrentUser\My: $($baseline.CurrentUserMy.Count) certificates" -ForegroundColor Gray
        Write-Host ""
        Write-Host "[!] Run this script again WITHOUT -CreateBaseline to detect changes" -ForegroundColor Yellow
        
        return
    } catch {
        Write-Host "[!] ERROR: Failed to create baseline: $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
}

# Load baseline if it exists
$baseline = $null
if (Test-Path $BaselinePath) {
    Write-Host "[*] Loading baseline from: $BaselinePath" -ForegroundColor Yellow
    try {
        $baseline = Import-Clixml -Path $BaselinePath
        Write-Host "[+] Baseline loaded (created: $($baseline.Created))" -ForegroundColor Green
        Write-Host ""
    } catch {
        Write-Host "[!] WARNING: Could not load baseline, will only detect self-signed certs" -ForegroundColor Yellow
        Write-Host ""
    }
}

# Scan LocalMachine\Root
Write-Host "[*] Scanning LocalMachine\Root..." -ForegroundColor Yellow

try {
    $currentCerts = Get-ChildItem Cert:\LocalMachine\Root -ErrorAction Stop
    $baselineThumbprints = @{}
    
    if ($baseline) {
        $baseline.LocalMachineRoot | ForEach-Object { $baselineThumbprints[$_.Thumbprint] = $true }
    }
    
    foreach ($cert in $currentCerts) {
        # Check against baseline first (most reliable)
        if ($baseline -and -not $baselineThumbprints.ContainsKey($cert.Thumbprint)) {
            $severity = "Critical"
            $reason = "NEW CERTIFICATE not in baseline"
            
            if (Test-SuspiciousImpersonation $cert) {
                $reason += " - SUSPICIOUS IMPERSONATION ATTEMPT"
            }
            
            $finding = Add-Finding $cert "LocalMachine\Root" $reason $severity
            Write-Host "  [CRITICAL] NEW CERTIFICATE DETECTED!" -ForegroundColor Magenta
            Write-Host "      $($cert.Subject)" -ForegroundColor Magenta
            Write-Host "      $reason" -ForegroundColor Magenta
        }
        # If no baseline, only flag suspicious self-signed certs
        elseif (-not $baseline -and (Test-SelfSigned $cert)) {
            # Skip known legitimate root CAs
            if (Test-KnownLegitimateRootCA $cert) {
                continue
            }
            
            $severity = "High"
            $reason = "Unknown self-signed certificate in LocalMachine\Root"
            
            if (Test-SuspiciousImpersonation $cert) {
                $severity = "Critical"
                $reason = "SUSPICIOUS CERTIFICATE - possible impersonation"
            }
            
            $finding = Add-Finding $cert "LocalMachine\Root" $reason $severity
            Write-Host "  [$severity] $($cert.Subject)" -ForegroundColor $(if ($severity -eq "Critical") { "Magenta" } else { "Yellow" })
            Write-Host "      $reason" -ForegroundColor Gray
        }
    }
} catch {
    Write-Host "  [!] ERROR: $($_.Exception.Message)" -ForegroundColor Red
}

# Scan CurrentUser\Root (highly suspicious in competition)
Write-Host "[*] Scanning CurrentUser\Root..." -ForegroundColor Yellow

try {
    $currentCerts = Get-ChildItem Cert:\CurrentUser\Root -ErrorAction Stop
    $baselineThumbprints = @{}
    $machineRootThumbprints = @{}
    
    # Get machine root thumbprints to filter duplicates
    try {
        Get-ChildItem Cert:\LocalMachine\Root -ErrorAction SilentlyContinue | ForEach-Object {
            $machineRootThumbprints[$_.Thumbprint] = $true
        }
    } catch {}
    
    if ($baseline) {
        $baseline.CurrentUserRoot | ForEach-Object { $baselineThumbprints[$_.Thumbprint] = $true }
    }
    
    foreach ($cert in $currentCerts) {
        # Skip if also in machine root (legitimate duplication)
        if ($machineRootThumbprints.ContainsKey($cert.Thumbprint)) {
            continue
        }
        
        # Check against baseline
        if ($baseline -and -not $baselineThumbprints.ContainsKey($cert.Thumbprint)) {
            $severity = "Critical"
            $reason = "NEW CERTIFICATE in CurrentUser\Root (RED TEAM INDICATOR!)"
            
            if (Test-SuspiciousImpersonation $cert) {
                $reason += " - SUSPICIOUS IMPERSONATION"
            }
            
            $finding = Add-Finding $cert "CurrentUser\Root" $reason $severity
            Write-Host "  [CRITICAL] RED TEAM CERTIFICATE DETECTED!" -ForegroundColor Magenta
            Write-Host "      $($cert.Subject)" -ForegroundColor Magenta
            Write-Host "      $reason" -ForegroundColor Magenta
        }
        # If no baseline, ANY cert only in CurrentUser\Root is suspicious
        elseif (-not $baseline) {
            $severity = "High"
            $reason = "Certificate in CurrentUser\Root but NOT in LocalMachine\Root"
            
            if (Test-SelfSigned $cert) {
                $severity = "Critical"
                $reason += " - SELF-SIGNED"
            }
            
            if (Test-SuspiciousImpersonation $cert) {
                $severity = "Critical" 
                $reason += " - SUSPICIOUS IMPERSONATION"
            }
            
            $finding = Add-Finding $cert "CurrentUser\Root" $reason $severity
            Write-Host "  [$severity] $($cert.Subject)" -ForegroundColor $(if ($severity -eq "Critical") { "Magenta" } else { "Yellow" })
            Write-Host "      $reason" -ForegroundColor Gray
        }
    }
} catch {
    Write-Host "  [!] ERROR: $($_.Exception.Message)" -ForegroundColor Red
}

# Scan CurrentUser\My for code signing certs
Write-Host "[*] Scanning CurrentUser\My (code signing certificates)..." -ForegroundColor Yellow

try {
    $currentCerts = Get-ChildItem Cert:\CurrentUser\My -ErrorAction Stop | 
        Where-Object { $_.EnhancedKeyUsageList.FriendlyName -contains "Code Signing" }
    
    $baselineThumbprints = @{}
    if ($baseline) {
        $baseline.CurrentUserMy | ForEach-Object { $baselineThumbprints[$_.Thumbprint] = $true }
    }
    
    foreach ($cert in $currentCerts) {
        # Check against baseline
        if ($baseline -and -not $baselineThumbprints.ContainsKey($cert.Thumbprint)) {
            $severity = "Critical"
            $reason = "NEW CODE SIGNING CERTIFICATE (likely used to sign malware)"
            
            if (Test-SelfSigned $cert) {
                $reason += " - SELF-SIGNED"
            }
            
            if (Test-SuspiciousImpersonation $cert) {
                $reason += " - SUSPICIOUS IMPERSONATION"
            }
            
            $finding = Add-Finding $cert "CurrentUser\My" $reason $severity
            Write-Host "  [CRITICAL] NEW CODE SIGNING CERT!" -ForegroundColor Magenta
            Write-Host "      $($cert.Subject)" -ForegroundColor Magenta
            Write-Host "      $reason" -ForegroundColor Magenta
        }
        # If no baseline, flag self-signed code signing certs with private keys
        elseif (-not $baseline -and (Test-SelfSigned $cert) -and $cert.HasPrivateKey) {
            $severity = "High"
            $reason = "Self-signed code signing certificate with private key"
            
            if (Test-SuspiciousImpersonation $cert) {
                $severity = "Critical"
                $reason = "SUSPICIOUS CODE SIGNING CERT - possible impersonation"
            }
            
            $finding = Add-Finding $cert "CurrentUser\My" $reason $severity
            Write-Host "  [$severity] $($cert.Subject)" -ForegroundColor $(if ($severity -eq "Critical") { "Magenta" } else { "Yellow" })
            Write-Host "      $reason" -ForegroundColor Gray
        }
    }
} catch {
    Write-Host "  [!] ERROR: $($_.Exception.Message)" -ForegroundColor Red
}

# Check registry timestamps for recent modifications
Write-Host ""
Write-Host "[*] Checking certificate store modification times..." -ForegroundColor Yellow

try {
    $rootRegPath = "HKCU:\Software\Microsoft\SystemCertificates\Root"
    $myRegPath = "HKCU:\Software\Microsoft\SystemCertificates\My"
    
    $rootReg = Get-Item $rootRegPath -ErrorAction SilentlyContinue
    $myReg = Get-Item $myRegPath -ErrorAction SilentlyContinue
    
    $recentThreshold = (Get-Date).AddHours(-24)
    
    if ($rootReg -and $rootReg.LastWriteTime -gt $recentThreshold) {
        Write-Host "  [!] CurrentUser\Root store modified recently: $($rootReg.LastWriteTime)" -ForegroundColor Yellow
    }
    
    if ($myReg -and $myReg.LastWriteTime -gt $recentThreshold) {
        Write-Host "  [!] CurrentUser\My store modified recently: $($myReg.LastWriteTime)" -ForegroundColor Yellow
    }
} catch {
    Write-Host "  [!] Could not check registry timestamps" -ForegroundColor Gray
}

# Summary
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Scan Complete" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

if ($findings -gt 0) {
    Write-Host "Total suspicious certificates: $findings" -ForegroundColor Red
    Write-Host ""
    
    $suspiciousCerts | Sort-Object Severity, Store | 
        Format-Table Severity, Subject, Store, Thumbprint -AutoSize
    
    if ($ExportCSV) {
        try {
            $suspiciousCerts | Export-Csv -Path $OutputPath -NoTypeInformation
            Write-Host "[+] Results exported to: $OutputPath" -ForegroundColor Green
        } catch {
            Write-Host "[!] Failed to export CSV: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    
    Write-Host ""
    Write-Host "Next Steps:" -ForegroundColor Yellow
    Write-Host "  1. Investigate Critical findings immediately" -ForegroundColor White
    Write-Host "  2. Search for binaries signed by these certificates:" -ForegroundColor White
    Write-Host "     Get-ChildItem C:\ -Recurse -Include *.exe,*.dll -ErrorAction SilentlyContinue | Get-AuthenticodeSignature | Where-Object {`$_.SignerCertificate.Thumbprint -eq 'THUMBPRINT'}" -ForegroundColor Gray
    Write-Host "  3. Remove malicious certificates:" -ForegroundColor White
    Write-Host "     Remove-Item 'Cert:\CurrentUser\Root\THUMBPRINT' -Force" -ForegroundColor Gray
    Write-Host "     Remove-Item 'Cert:\LocalMachine\Root\THUMBPRINT' -Force  # (requires admin)" -ForegroundColor Gray
} else {
    if ($baseline) {
        Write-Host "No certificate changes detected since baseline!" -ForegroundColor Green
    } else {
        Write-Host "No suspicious certificates found." -ForegroundColor Green
        Write-Host ""
        Write-Host "IMPORTANT: You're running without a baseline!" -ForegroundColor Yellow
        Write-Host "For best results in competition:" -ForegroundColor Yellow
        Write-Host "  1. Run with -CreateBaseline BEFORE the competition starts" -ForegroundColor White
        Write-Host "  2. Run again during/after to detect ANY new certificates" -ForegroundColor White
        Write-Host ""
        Write-Host "Without a baseline, this script can only detect:" -ForegroundColor Yellow
        Write-Host "  - Obvious impersonation attempts (fake Microsoft, etc.)" -ForegroundColor White
        Write-Host "  - Certificates only in CurrentUser stores" -ForegroundColor White
        Write-Host "  - Self-signed code signing certs with private keys" -ForegroundColor White
    }
}

Write-Host ""

return $suspiciousCerts
