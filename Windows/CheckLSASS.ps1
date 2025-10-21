<#
.SYNOPSIS
    Enumerate DLLs loaded into lsass.exe and check Authenticode signatures.

.DESCRIPTION
    Attempts to enumerate loaded modules for lsass.exe and runs Get-AuthenticodeSignature on
    each module file if a disk path is available. Prints results to the console and can export to CSV.

    NOTE: Requires Administrator (or SYSTEM) privileges to reliably enumerate lsass modules.
    Protected Process Light (PPL) and some EDRs may prevent module enumeration or dumping.

.PARAMETER OutCsv
    Optional path to export results as CSV.

.PARAMETER VerboseOutput
    When supplied, shows more detail about each signature certificate.

.EXAMPLE
    .\Get-LsassModulesAndSignatures.ps1
    Runs and prints results to console.

.EXAMPLE
    .\Get-LsassModulesAndSignatures.ps1 -OutCsv C:\temp\lsass_modules.csv -VerboseOutput
#>

[CmdletBinding()]
param(
    [string] $OutCsv,
    [switch] $VerboseOutput
)

function Ensure-Elevation {
    if (-not ([bool]([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))) {
        Write-Warning "This script should be run in an elevated PowerShell session (Administrator). Some module enumerations may fail without elevation."
    }
}

function Get-ModuleSignatureInfo {
    param(
        [string] $FilePath
    )

    if (-not $FilePath) {
        return [pscustomobject]@{
            SignatureStatus = 'NoPathInModule'
            SignatureStatusDetail = 'Module has no on-disk path (in-memory or mapped)'
            Signer = $null
            Issuer = $null
            Thumbprint = $null
            Timestamp = $null
        }
    }

    if (-not (Test-Path -LiteralPath $FilePath)) {
        return [pscustomobject]@{
            SignatureStatus = 'FileNotFound'
            SignatureStatusDetail = "File not found on disk: $FilePath"
            Signer = $null
            Issuer = $null
            Thumbprint = $null
            Timestamp = $null
        }
    }

    try {
        $sig = Get-AuthenticodeSignature -FilePath $FilePath -ErrorAction Stop
        $status = $sig.Status
        $detail = $sig.StatusMessage
        $cert = $sig.SignerCertificate

        if ($cert) {
            $signer = $cert.Subject
            $issuer = $cert.Issuer
            $thumb = $cert.Thumbprint
            # Timestamped signing info is available via $sig.SignerCertificate.NotBefore / NotAfter, or $sig.TimeStamperCertificate
            $ts = if ($sig.TimeStamperCertificate) { $sig.TimeStamperCertificate.Subject } else { $null }
        } else {
            $signer = $null; $issuer = $null; $thumb = $null; $ts = $null
        }

        return [pscustomobject]@{
            SignatureStatus = $status
            SignatureStatusDetail = $detail
            Signer = $signer
            Issuer = $issuer
            Thumbprint = $thumb
            Timestamp = $ts
        }
    } catch {
        return [pscustomobject]@{
            SignatureStatus = 'SignatureCheckError'
            SignatureStatusDetail = $_.Exception.Message
            Signer = $null
            Issuer = $null
            Thumbprint = $null
            Timestamp = $null
        }
    }
}

# Start
Ensure-Elevation

# Attempt to get lsass process
try {
    $lsass = Get-Process -Name lsass -ErrorAction Stop
} catch {
    Write-Error "Could not find lsass.exe process: $_"
    return
}

Write-Host "Found lsass.exe (Id: $($lsass.Id)). Attempting to enumerate modules..." -ForegroundColor Cyan

$moduleList = @()
try {
    # Accessing .Modules may throw due to permissions or PPL protection
    $mods = $lsass.Modules
} catch {
    Write-Warning "Failed to enumerate lsass modules via Get-Process.Modules: $($_.Exception.Message)"
    Write-Warning "This is commonly due to insufficient privileges or LSASS being a protected process (PPL)."
    Write-Warning "Try running as SYSTEM or use an EDR/kernel-capable tool for reliable enumeration."
    $mods = $null
}

if (-not $mods) {
    Write-Warning "No module list available. Exiting."
    return
}

foreach ($m in $mods) {
    # Some Module objects may not expose all properties; guard accesses
    $moduleName = $m.ModuleName 2>$null
    $fileName   = $m.FileName 2>$null
    $baseAddr   = $m.BaseAddress 2>$null
    $moduleSize = $m.ModuleMemorySize 2>$null

    # Attempt to gather file version info
    $fileVersion = $null
    if ($fileName -and (Test-Path -LiteralPath $fileName)) {
        try {
            $fi = Get-Item -LiteralPath $fileName -ErrorAction Stop
            # FileVersionInfo accessible via [System.Diagnostics.FileVersionInfo]
            $fvi = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($fileName)
            $fileVersion = $fvi.FileVersion
        } catch {
            $fileVersion = $null
        }
    }

    # Get signature info (handles missing file and exceptions)
    $sigInfo = Get-ModuleSignatureInfo -FilePath $fileName

    $obj = [pscustomobject]@{
        TimestampUTC          = (Get-Date).ToUniversalTime().ToString("o")
        ProcessName           = "lsass.exe"
        ProcessId             = $lsass.Id
        ModuleName            = $moduleName
        FileName              = $fileName
        BaseAddress           = $baseAddr
        ModuleSizeBytes       = $moduleSize
        FileVersion           = $fileVersion
        SignatureStatus       = $sigInfo.SignatureStatus
        SignatureDetail       = $sigInfo.SignatureStatusDetail
        Signer                = $sigInfo.Signer
        Issuer                = $sigInfo.Issuer
        CertificateThumbprint = $sigInfo.Thumbprint
        TimeStamper           = $sigInfo.Timestamp
    }

    $moduleList += $obj
}

# Print a concise table
$moduleList | Select-Object ModuleName, @{N='File';E={$_.FileName -replace '\\\\','\\'}}, SignatureStatus, Signer | Format-Table -AutoSize

if ($VerboseOutput) {
    Write-Host ""
    Write-Host "---- Verbose certificate details (where available) ----" -ForegroundColor Yellow
    foreach ($row in $moduleList) {
        Write-Host "`nModule: $($row.ModuleName)" -ForegroundColor Gray
        Write-Host " Path: $($row.FileName)"
        Write-Host " SigStatus: $($row.SignatureStatus) - $($row.SignatureDetail)"
        if ($row.Signer) {
            Write-Host " Signer: $($row.Signer)"
            Write-Host " Issuer: $($row.Issuer)"
            Write-Host " Thumbprint: $($row.CertificateThumbprint)"
            Write-Host " TimeStamper: $($row.TimeStamper)"
        }
    }
}

# Export CSV if requested
if ($OutCsv) {
    try {
        $moduleList | Export-Csv -Path $OutCsv -NoTypeInformation -Force
        Write-Host "`nResults exported to: $OutCsv" -ForegroundColor Green
    } catch {
        Write-Warning "Failed to export CSV: $($_.Exception.Message)"
    }
}

Write-Host "`nDone." -ForegroundColor Cyan
