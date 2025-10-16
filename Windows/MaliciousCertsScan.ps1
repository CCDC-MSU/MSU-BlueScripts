<#
.SYNOPSIS
    Hunts for suspicious self-signed certificates on Windows systems
.DESCRIPTION
    This script focuses on finding self-signed certificates that could indicate compromise:
    - Self-signed certificates in Trusted Root stores
    - Recent self-signed certificates with code signing capability
    - Self-signed certs mimicking legitimate organizations
.NOTES
    Author: Blue Team
    Requires: PowerShell 5.0+, Administrator privileges recommended
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [int]$DaysRecent = 30,
    
    [Parameter(Mandatory=$false)]
    [switch]$ExportCSV,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = "C:\Temp\SelfSignedCerts_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv",
    
    [Parameter(Mandatory=$false)]
    [switch]$IncludeKnownCAs
)

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Self-Signed Certificate Hunter v2.0" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$suspiciousCerts = @()
$findings = 0

# Well-known legitimate root CAs (these are self-signed but legitimate)
# Significantly expanded list to reduce false positives
$knownLegitimateRoots = @(
    # Microsoft
    "Microsoft Root Certificate Authority",
    "Microsoft Root Authority",
    "Microsoft Authenticode(tm) Root Authority",
    # Digicert/Verisign/Thawte/GeoTrust
    "DigiCert", "VeriSign", "Thawte", "GeoTrust", "Baltimore CyberTrust Root",
    # Other major CAs
    "GlobalSign", "Entrust", "Comodo", "Sectigo", "IdenTrust",
    "Go Daddy", "GoDaddy", "USERTrust", "AAA Certificate Services",
    "Starfield", "Amazon Root CA", "Apple Root CA", "Google Trust Services",
    # Government
    "DoD Root", "US Government", "Federal Common Policy CA"
)

# Organizations that are commonly spoofed
$highValueTargets = @(
    "Microsoft", "Google", "Apple", "Amazon", "Adobe", 
    "Oracle", "VMware", "Cisco", "Dell", "HP"
)

function Test-SelfSigned {
    param($cert)
    return ($cert.Issuer -eq $cert.Subject)
}

function Test-KnownLegitimateCA {
    param($cert)
    foreach ($knownCA in $knownLegitimateRoots) {
        if ($cert.Subject -like "*$knownCA*") {
            return $true
        }
    }
    return $false
}

function Test-HighValueTarget {
    param($cert)
    foreach ($target in $highValueTargets) {
        if ($cert.Subject -like "*$target*") {
            return $true
        }
    }
    return $false
}

function Test-SelfSigned {
    param($cert)
    return ($cert.Issuer -eq $cert.Subject)
}

function Test-RecentlyAdded {
    param($cert, $days)
    return ($cert.NotBefore -gt (Get-Date).AddDays(-$days))
}

function Test-CodeSigning {
    param($cert)
    if ($cert.EnhancedKeyUsageList) {
        return ($cert.EnhancedKeyUsageList.FriendlyName -contains "Code Signing")
    }
    return $false
}

function Add-SuspiciousCert {
    param(
        $cert,
        $store,
        $reason,
        $severity = "Medium"
    )
    
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
        ValidityDays = ($cert.NotAfter - $cert.NotBefore).Days
        SerialNumber = $cert.SerialNumber
        HasPrivateKey = $cert.HasPrivateKey
        EnhancedKeyUsage = ($cert.EnhancedKeyUsageList.FriendlyName -join ", ")
        SuspicionReason = $reason
    }
    
    $script:suspiciousCerts += $certInfo
    return $certInfo
}

Write-Host "[*] Scanning LocalMachine\Root (Trusted Root CAs)..." -ForegroundColor Yellow
Write-Host "    Focus: Self-signed certs that shouldn't be in Root store" -ForegroundColor Gray

try {
    $rootCerts = Get-ChildItem Cert:\LocalMachine\Root -ErrorAction Stop
    
    foreach ($cert in $rootCerts) {
        # Only process self-signed certificates
        if (-not (Test-SelfSigned $cert)) {
            continue
        }
        
        # Skip known legitimate CAs unless user wants to see them
        if (-not $IncludeKnownCAs -and (Test-KnownLegitimateCA $cert)) {
            continue
        }
        
        $reasons = @()
        $severity = "Medium"
        
        # High severity: Recent AND mimicking high-value targets
        if ((Test-RecentlyAdded $cert $DaysRecent) -and (Test-HighValueTarget $cert)) {
            $reasons += "CRITICAL: Recent self-signed cert mimicking trusted organization"
            $severity = "Critical"
        }
        # High severity: Code signing capability
        elseif (Test-CodeSigning $cert) {
            $reasons += "Self-signed with code signing capability"
            $severity = "High"
        }
        # Medium severity: Recently added
        elseif (Test-RecentlyAdded $cert $DaysRecent) {
            $reasons += "Recently added self-signed certificate"
            $severity = "Medium"
        }
        # Low severity: Old self-signed (might be legitimate internal CA)
        else {
            $reasons += "Self-signed certificate in Root store"
            $severity = "Low"
        }
        
        $finding = Add-SuspiciousCert $cert "LocalMachine\Root" ($reasons -join "; ") $severity
        
        $color = switch ($severity) {
            "Critical" { "Magenta" }
            "High" { "Red" }
            "Medium" { "Yellow" }
            "Low" { "Gray" }
        }
        
        Write-Host "  [$severity] $($cert.Subject)" -ForegroundColor $color
        Write-Host "      Reason: $($reasons -join '; ')" -ForegroundColor $color
        Write-Host "      Created: $($cert.NotBefore)" -ForegroundColor Gray
    }
} catch {
    Write-Host "  [!] Error accessing LocalMachine\Root: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "[*] Scanning CurrentUser\Root..." -ForegroundColor Yellow
Write-Host "    Focus: Any self-signed cert here is unusual" -ForegroundColor Gray

try {
    $userRootCerts = Get-ChildItem Cert:\CurrentUser\Root -ErrorAction Stop
    
    foreach ($cert in $userRootCerts) {
        if (-not (Test-SelfSigned $cert)) {
            continue
        }
        
        if (-not $IncludeKnownCAs -and (Test-KnownLegitimateCA $cert)) {
            continue
        }
        
        $reasons = @("Self-signed in user root store")
        $severity = "Medium"
        
        if (Test-RecentlyAdded $cert $DaysRecent) {
            $reasons += "Recently added"
            $severity = "High"
        }
        
        if (Test-HighValueTarget $cert) {
            $reasons += "Mimicking trusted organization"
            $severity = "Critical"
        }
        
        $finding = Add-SuspiciousCert $cert "CurrentUser\Root" ($reasons -join "; ") $severity
        
        $color = switch ($severity) {
            "Critical" { "Magenta" }
            "High" { "Red" }
            "Medium" { "Yellow" }
            "Low" { "Gray" }
        }
        
        Write-Host "  [$severity] $($cert.Subject)" -ForegroundColor $color
        Write-Host "      Reason: $($reasons -join '; ')" -ForegroundColor $color
    }
} catch {
    Write-Host "  [!] Error accessing CurrentUser\Root: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "[*] Scanning CurrentUser\My (Personal certificates)..." -ForegroundColor Yellow
Write-Host "    Focus: Self-signed code signing certs with private keys" -ForegroundColor Gray

try {
    $userMyCerts = Get-ChildItem Cert:\CurrentUser\My -ErrorAction Stop
    
    foreach ($cert in $userMyCerts) {
        if (-not (Test-SelfSigned $cert)) {
            continue
        }
        
        # Only flag if it's a code signing cert with private key (red team indicator)
        if (-not ($cert.HasPrivateKey -and (Test-CodeSigning $cert))) {
            continue
        }
        
        $reasons = @("Self-signed code signing cert with private key")
        $severity = "Medium"
        
        if (Test-RecentlyAdded $cert $DaysRecent) {
            $reasons += "Recently created"
            $severity = "High"
        }
        
        if (Test-HighValueTarget $cert) {
            $reasons += "Mimicking trusted organization"
            $severity = "Critical"
        }
        
        $finding = Add-SuspiciousCert $cert "CurrentUser\My" ($reasons -join "; ") $severity
        
        $color = switch ($severity) {
            "Critical" { "Magenta" }
            "High" { "Red" }
            "Medium" { "Yellow" }
            "Low" { "Gray" }
        }
        
        Write-Host "  [$severity] $($cert.Subject)" -ForegroundColor $color
        Write-Host "      Reason: $($reasons -join '; ')" -ForegroundColor $color
    }
} catch {
    Write-Host "  [!] Error accessing CurrentUser\My: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Scan Complete" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Total self-signed certificates flagged: $findings" -ForegroundColor $(if ($findings -gt 0) { "Red" } else { "Green" })

if ($findings -gt 0) {
    Write-Host ""
    Write-Host "Summary of Findings:" -ForegroundColor Yellow
    $suspiciousCerts | Sort-Object Severity, NotBefore -Descending | 
        Format-Table Severity, Subject, Store, NotBefore, SuspicionReason -AutoSize
    
    # Show severity breakdown
    Write-Host ""
    Write-Host "Severity Breakdown:" -ForegroundColor Yellow
    $suspiciousCerts | Group-Object Severity | 
        Select-Object Name, Count | 
        Format-Table -AutoSize
    
    if ($ExportCSV) {
        try {
            $suspiciousCerts | Export-Csv -Path $OutputPath -NoTypeInformation
            Write-Host ""
            Write-Host "[+] Results exported to: $OutputPath" -ForegroundColor Green
        } catch {
            Write-Host "[!] Failed to export CSV: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    
    Write-Host ""
    Write-Host "Recommended Actions:" -ForegroundColor Yellow
    Write-Host "  1. Prioritize Critical and High severity findings" -ForegroundColor White
    Write-Host "  2. Investigate certificates mimicking known organizations" -ForegroundColor White
    Write-Host "  3. Check Event Logs for certificate installation events" -ForegroundColor White
    Write-Host "  4. Search for binaries signed with these certificates:" -ForegroundColor White
    Write-Host "     Get-ChildItem C:\ -Recurse -Include *.exe,*.dll | Get-AuthenticodeSignature | Where-Object {`$_.SignerCertificate.Thumbprint -eq 'THUMBPRINT'}" -ForegroundColor Gray
    Write-Host "  5. Remove unauthorized certificates if confirmed malicious:" -ForegroundColor White
    Write-Host "     Remove-Item 'Cert:\LocalMachine\Root\THUMBPRINT' -Force" -ForegroundColor Gray
} else {
    Write-Host ""
    Write-Host "[+] No suspicious self-signed certificates detected." -ForegroundColor Green
    Write-Host "    Note: This script focuses on high-confidence indicators to reduce false positives." -ForegroundColor Yellow
    Write-Host "    Run with -IncludeKnownCAs to see all self-signed certificates including legitimate CAs." -ForegroundColor Yellow
}

Write-Host ""

# Return the suspicious certs for further processing
return $suspiciousCerts