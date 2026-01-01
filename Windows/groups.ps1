# Active Directory User Audit Script with Remediation
# Requires Active Directory PowerShell module
# Run with appropriate AD permissions

param(
    [Parameter(Mandatory=$true)]
    [string]$CsvPath,
    
    [Parameter(Mandatory=$false)]
    [switch]$AutoRemediate,
    
    [Parameter(Mandatory=$false)]
    [switch]$WhatIf
)

# Import Active Directory module
Import-Module ActiveDirectory -ErrorAction Stop

# Verify CSV file exists
if (-not (Test-Path $CsvPath)) {
    Write-Error "CSV file not found: $CsvPath"
    exit 1
}

# Read CSV file and normalize usernames
$csvContent = Get-Content -Path $CsvPath
$csvUsers = @()

# Check if first line looks like a header
$firstLine = $csvContent[0]
if ($firstLine -match '^Username,Permission$|^username,permission$') {
    # Has header, use Import-Csv
    $csvUsers = Import-Csv -Path $CsvPath | ForEach-Object {
        $_.Username = $_.Username.Trim()
        $_
    }
} else {
    # No header, manually parse
    foreach ($line in $csvContent) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        
        $parts = $line -split ','
        if ($parts.Count -ge 2) {
            $csvUsers += [PSCustomObject]@{
                Username = $parts[0].Trim()
                Permission = $parts[1].Trim()
            }
        }
    }
}

Write-Host "Starting Active Directory Audit..." -ForegroundColor Cyan
Write-Host "Reading from: $CsvPath" -ForegroundColor Cyan
Write-Host "Loaded $($csvUsers.Count) users from CSV file" -ForegroundColor Cyan
if ($AutoRemediate) {
    Write-Host "Auto-Remediation: ENABLED" -ForegroundColor Yellow
    if ($WhatIf) {
        Write-Host "WhatIf Mode: ENABLED (no changes will be made)" -ForegroundColor Yellow
    }
} else {
    Write-Host "Auto-Remediation: DISABLED (report only)" -ForegroundColor Yellow
}
Write-Host ""

# Define group mappings
$permissionGroups = @{
    2 = "Domain Admins"
    1 = "Domain Users"
    0 = "Ignore"
}

# Initialize tracking arrays
$issues = @()
$remediations = @()
$csvUsernames = @()

# Process each user in the CSV
foreach ($csvUser in $csvUsers) {
    # Skip if Username is null or empty
    if ([string]::IsNullOrWhiteSpace($csvUser.Username)) {
        Write-Host "Skipping empty row in CSV" -ForegroundColor DarkGray
        continue
    }
    
    $username = $csvUser.Username.Trim()
    
    # Skip if Permission is null or empty
    if ([string]::IsNullOrWhiteSpace($csvUser.Permission)) {
        Write-Host "Skipping user $username (no permission specified)" -ForegroundColor Yellow
        continue
    }
    
    $permission = [int]$csvUser.Permission
    
    # Skip if permission is 0 (ignore)
    if ($permission -eq 0) {
        Write-Host "Skipping user: $username (Permission = 0)" -ForegroundColor Yellow
        continue
    }
    
    $csvUsernames += $username.ToLower()
    $targetGroup = $permissionGroups[$permission]
    
    # Try to get the AD user
    try {
        $adUser = Get-ADUser -Identity $username -Properties MemberOf -ErrorAction Stop
        
        # Get all group memberships (CN names only)
        $userGroups = $adUser.MemberOf | ForEach-Object {
            if ($_ -match 'CN=([^,]+)') { $matches[1] }
        }
        
        # Check group membership based on permission level
        if ($permission -eq 2) {
            # Should be Domain Admin
            $isInDomainAdmins = $userGroups -contains "Domain Admins"
            
            if ($isInDomainAdmins) {
                Write-Host "[OK] $username is in Domain Admins" -ForegroundColor Green
            } else {
                Write-Host "[ISSUE] $username should be Domain Admin but isn't" -ForegroundColor Red
                $issues += [PSCustomObject]@{
                    Type = "Missing Privileges"
                    Username = $username
                    ExpectedGroup = "Domain Admins"
                    ActualGroups = ($userGroups -join ", ")
                    Details = "User should be Domain Admin but lacks membership"
                    Remediated = $false
                }
                
                # Add to Domain Admins if AutoRemediate is enabled
                if ($AutoRemediate) {
                    try {
                        if ($WhatIf) {
                            Write-Host "  [WHATIF] Would add $username to Domain Admins" -ForegroundColor Cyan
                        } else {
                            Add-ADGroupMember -Identity "Domain Admins" -Members $username -ErrorAction Stop
                            Write-Host "  [REMEDIATED] Added $username to Domain Admins" -ForegroundColor Green
                            $remediations += "Added $username to Domain Admins"
                            $issues[-1].Remediated = $true
                        }
                    } catch {
                        Write-Host "  [FAILED] Could not add $username to Domain Admins: $($_.Exception.Message)" -ForegroundColor Red
                    }
                }
            }
        }
        elseif ($permission -eq 1) {
            # Should be Domain User only (NOT Domain Admin)
            $isInDomainAdmins = $userGroups -contains "Domain Admins"
            
            if ($isInDomainAdmins) {
                Write-Host "[OVER-PRIVILEGED] $username should be Domain User but is in Domain Admins" -ForegroundColor Red
                $issues += [PSCustomObject]@{
                    Type = "Over-Privileged"
                    Username = $username
                    ExpectedGroup = "Domain Users"
                    ActualGroups = ($userGroups -join ", ")
                    Details = "User has Domain Admin rights but should only be Domain User"
                    Remediated = $false
                }
                
                # Remove from Domain Admins if AutoRemediate is enabled
                if ($AutoRemediate) {
                    try {
                        if ($WhatIf) {
                            Write-Host "  [WHATIF] Would remove $username from Domain Admins" -ForegroundColor Cyan
                        } else {
                            Remove-ADGroupMember -Identity "Domain Admins" -Members $username -Confirm:$false -ErrorAction Stop
                            Write-Host "  [REMEDIATED] Removed $username from Domain Admins" -ForegroundColor Green
                            $remediations += "Removed $username from Domain Admins"
                            $issues[-1].Remediated = $true
                        }
                    } catch {
                        Write-Host "  [FAILED] Could not remove $username from Domain Admins: $($_.Exception.Message)" -ForegroundColor Red
                    }
                }
            } else {
                Write-Host "[OK] $username is Domain User (not over-privileged)" -ForegroundColor Green
            }
        }
    }
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
        Write-Host "[MISSING] $username not found in Active Directory" -ForegroundColor Red
        $issues += [PSCustomObject]@{
            Type = "User Not in AD"
            Username = $username
            ExpectedGroup = $targetGroup
            ActualGroups = "N/A"
            Details = "User in CSV but not found in AD"
            Remediated = $false
        }
    }
    catch {
        Write-Host "[ERROR] Failed to process $username : $($_.Exception.Message)" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "Checking for users in AD not listed in CSV..." -ForegroundColor Cyan

# Get all AD users and find those not in CSV (normalize for comparison)
$allADUsers = Get-ADUser -Filter * | Select-Object -ExpandProperty SamAccountName
$allADUsersLower = $allADUsers | ForEach-Object { $_.ToLower() }
$usersNotInCsv = $allADUsersLower | Where-Object { $_ -notin $csvUsernames }

foreach ($adUsername in $usersNotInCsv) {
    Write-Host "[NOT IN CSV] $adUsername exists in AD but not in CSV file" -ForegroundColor Magenta
    $issues += [PSCustomObject]@{
        Type = "User Not in CSV"
        Username = $adUsername
        ExpectedGroup = "N/A"
        ActualGroups = "Unknown"
        Details = "User exists in AD but not documented in CSV"
        Remediated = $false
    }
}

# Summary Report
Write-Host ""
Write-Host "==================== AUDIT SUMMARY ====================" -ForegroundColor Cyan
Write-Host "Total users in CSV (excluding ignored): $($csvUsernames.Count)" -ForegroundColor White
Write-Host "Total users in AD: $($allADUsers.Count)" -ForegroundColor White
Write-Host "Users in AD but not CSV (ignored): $($usersNotInCsv.Count)" -ForegroundColor White
Write-Host "Total issues found: $($issues.Count)" -ForegroundColor $(if ($issues.Count -gt 0) { "Red" } else { "Green" })

if ($AutoRemediate -and -not $WhatIf) {
    Write-Host "Remediations performed: $($remediations.Count)" -ForegroundColor Green
}

# Break down issues by type
if ($issues.Count -gt 0) {
    $issuesByType = $issues | Group-Object -Property Type
    Write-Host ""
    Write-Host "Issues by Type:" -ForegroundColor Yellow
    foreach ($group in $issuesByType) {
        Write-Host "  - $($group.Name): $($group.Count)" -ForegroundColor Yellow
    }
}

Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host ""

if ($issues.Count -gt 0) {
    Write-Host "Issues Details:" -ForegroundColor Yellow
    $issues | Format-Table -AutoSize -Wrap
    
    # Export issues to CSV
    $reportPath = "AD_Audit_Issues_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    $issues | Export-Csv -Path $reportPath -NoTypeInformation
    Write-Host "Issues exported to: $reportPath" -ForegroundColor Yellow
    
    if ($AutoRemediate -and $remediations.Count -gt 0) {
        Write-Host ""
        Write-Host "Remediations performed:" -ForegroundColor Green
        $remediations | ForEach-Object { Write-Host "  - $_" -ForegroundColor Green }
    }
} else {
    Write-Host "No issues found! All users are properly configured." -ForegroundColor Green
}

Write-Host ""
Write-Host "Audit completed." -ForegroundColor Cyan
