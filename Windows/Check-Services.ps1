# ----------------------------------------
# Functions
# ----------------------------------------

# Extract only the EXE path from a service PathName (remove arguments)
function GetExecutablePath($rawPath) {
    if ([string]::IsNullOrWhiteSpace($rawPath)) {
        return $null
    }

    $rawPath = $rawPath.Trim()

    if ($rawPath.StartsWith('"')) {
        # Quoted path: "C:\Program Files\Example\example.exe" -arg
        $firstQuote = $rawPath.IndexOf('"')
        $secondQuote = $rawPath.IndexOf('"', $firstQuote + 1)
        if ($secondQuote -gt $firstQuote) {
            return $rawPath.Substring($firstQuote + 1, $secondQuote - $firstQuote - 1)
        } else {
            return $null
        }
    } else {
        # Unquoted path: C:\Windows\System32\svchost.exe -k netsvcs
        return $rawPath.Split(' ')[0]
    }
}

# Check if service binary path is suspicious
function IsSuspiciousPath($path) {
    return ($path -like "C:\Users\*")
}

# Check if file is unsigned (or path invalid)
function IsUnsigned($path) {
    try {
        if ([string]::IsNullOrWhiteSpace($path) -or -not (Test-Path $path)) {
            return $true
        }

        $item = Get-Item $path
        if ($item.PSIsContainer) {
            return $true
        }

        $signature = Get-AuthenticodeSignature -FilePath $path
        return ($signature.Status -ne "Valid")
    } catch {
        return $true
    }
}

# Calculate Shannon entropy of a string
function CalculateEntropy($input) {
    if ([string]::IsNullOrEmpty($input)) {
        return 0
    }

    $inputChars = $input.ToCharArray()
    $charCount = $inputChars.Length
    $charFrequency = @{}

    foreach ($char in $inputChars) {
        $charFrequency[$char]++
    }

    [double]$entropy = 0
    foreach ($frequency in $charFrequency.Values) {
        $probability = $frequency / $charCount
        $entropy -= $probability * [Math]::Log($probability, 2)
    }
    return $entropy
}

# Check if name is high entropy
function IsHighEntropyName($name) {
    $entropy = CalculateEntropy($name)
    return ($entropy -gt 3.5)
}

# Check for suspicious file extensions
function HasSuspiciousExtension($path) {
    $suspiciousExtensions = @('.vbs', '.js', '.bat', '.cmd', '.scr')
    $extension = [IO.Path]::GetExtension($path)
    return ($suspiciousExtensions -contains $extension)
}

# ----------------------------------------
# Main script
# ----------------------------------------

$enableExtraChecks = Read-Host "Enable checks more likely to result in false positives? (yes/no)"
$extraChecks = $enableExtraChecks -eq "yes"

$AllServices = Get-WmiObject -Class Win32_Service
$DetectedServices = @()

foreach ($Service in $AllServices) {
    $RawPathName = $Service.PathName
    $ExecutablePath = GetExecutablePath($RawPathName)

    # Skip services with no usable executable path
    if ([string]::IsNullOrWhiteSpace($ExecutablePath)) {
        continue
    }

    # Evaluate checks
    $Flags = [ordered]@{}

    $Flags.PathSuspicious = IsSuspiciousPath($ExecutablePath)
    $Flags.LocalSystemAccount = ($Service.StartName -eq "LocalSystem")
    $Flags.NoDescription = [string]::IsNullOrEmpty($Service.Description)
    $Flags.Unsigned = IsUnsigned($ExecutablePath)

    if ($extraChecks) {
        $Flags.ShortName = ($Service.Name.Length -le 5)
        $Flags.ShortDisplayName = ($Service.DisplayName.Length -le 5)
        $Flags.HighEntropyName = IsHighEntropyName($Service.Name)
        $Flags.HighEntropyDisplayName = IsHighEntropyName($Service.DisplayName)
        $Flags.SuspiciousExtension = HasSuspiciousExtension($ExecutablePath)
    } else {
        $Flags.ShortName = $false
        $Flags.ShortDisplayName = $false
        $Flags.HighEntropyName = $false
        $Flags.HighEntropyDisplayName = $false
        $Flags.SuspiciousExtension = $false
    }
    # Define which flags actually *trigger* suspicion
    $OtherFlags = @{
        PathSuspicious = $Flags.PathSuspicious
        NoDescription = $Flags.NoDescription
        Unsigned = $Flags.Unsigned
        ShortName = $Flags.ShortName
        ShortDisplayName = $Flags.ShortDisplayName
        HighEntropyName = $Flags.HighEntropyName
        HighEntropyDisplayName = $Flags.HighEntropyDisplayName
        SuspiciousExtension = $Flags.SuspiciousExtension
    }

    $Flags.LocalSystemAccount = ($Service.StartName -eq "LocalSystem")
    $isSuspicious = $OtherFlags.Values -contains $true
  

    if ($isSuspicious) {
        $DetectedServices += [PSCustomObject]@{
            Service = $Service
            ExecutablePath = $ExecutablePath
            Flags = $Flags
        }
    }
}

# ----------------------------------------
# Output results
# ----------------------------------------

if ($DetectedServices.Count -gt 0) {
    Write-Host "Potentially Suspicious Services Detected"
    Write-Host "----------------------------------------"

    foreach ($Entry in $DetectedServices) {
        $Service = $Entry.Service
        $Flags = $Entry.Flags

        Write-Host "Name: $($Service.Name)"
        Write-Host "Display Name: $($Service.DisplayName)"
        Write-Host "Status: $($Service.State)"
        Write-Host "Start Name: $($Service.StartName)"
        Write-Host "Description: $($Service.Description)"
        Write-Host "Binary Path: $($Entry.ExecutablePath)"
        Write-Host "Flags triggered:"

        foreach ($key in $Flags.Keys) {
            if ($Flags[$key]) {
                Write-Host ("`t- {0}" -f $key)
            }
        }

        Write-Host ""
    }
} else {
    Write-Host "No potentially suspicious services detected."
}

