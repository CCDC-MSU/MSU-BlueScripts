# CONFIGURATION
$gpoDisplayName = "clemson-gpo"                              # Name of the GPO in the backup
$targetName = "clemson-gpo"                                  # Desired name of the GPO in your domain
$backupPath = ".\ClemsonGPO"                            # Folder that contains manifest.xml and backup
$domainDn = (Get-ADDomain).DistinguishedName              # Automatically detects domain DN

# Import modules
Import-Module GroupPolicy
Import-Module ActiveDirectory

# Check if GPO already exists
$existingGpo = Get-GPO -Name $targetName -ErrorAction SilentlyContinue

if (-not $existingGpo) {
    Write-Host "Creating new GPO '$targetName' and importing settings..." -ForegroundColor Cyan

    # Create empty GPO
    New-GPO -Name $targetName | Out-Null

    # Import backup into the new GPO
    Import-GPO -BackupGpoName $gpoDisplayName -Path $backupPath -TargetName $targetName
} else {
    Write-Host "GPO '$targetName' already exists. Skipping creation/import." -ForegroundColor Yellow
}

# Link the GPO to the domain
Write-Host "Linking GPO '$targetName' to domain root..." -ForegroundColor Cyan
New-GPLink -Name $targetName -Target "LDAP://$domainDn" -LinkEnabled Yes

# OPTIONAL: Enforce the GPO link
#$gplink = Get-GPLink -Target "LDAP://$domainDn" | Where-Object { $_.GPOName -eq $targetName }
#Set-GPLink -Guid $gplink.GPOId -Target "LDAP://$domainDn" -Enforced Yes

Write-Host "`nDone! GPO '$targetName' is linked to the domain." -ForegroundColor Green

gpupdate /force

Write-Host "`nRemember to run gpupdate /force on all other domain-joined machines."

Get-GPOReport -All -ReportType Html -Path "C:\AllGPOs.html"

Write-Host "View Report at C:\AllGPOs.html"
