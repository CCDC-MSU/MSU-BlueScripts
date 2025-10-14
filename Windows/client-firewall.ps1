param(
    [String]$ScriptArgs = @("")
)
$ErrorActionPreference = "SilentlyContinue"

$Argsarray = $ScriptArgs -Split ";"
if ($Argsarray.Count -lt 4) {
    Write-Host 'Usage - .\Firewall.ps1 "<Remote Management Subnet>;<CCDC Subnet>;<Port List>;NoPassthru"'
    Write-Host 'Example: .\Firewall.ps1 "192.168.1.0/24;10.0.0.0/8;445,3389,80,443;NoPassthru"'
    break
}
$Dispatcher = $Argsarray[0];
$allowedNetworks = $Argsarray[1];
$allowedNetworks = $allowedNetworks -split ','
$portList = $Argsarray[2];
$ports = $portList -split ',' | ForEach-Object { $_.Trim() }
$Passthru = $Argsarray[3];

Write-Host "Allowed networks:" $allowedNetworks
Write-Host "Allowed ports:" $ports

netsh advfirewal export "C:\Firewall.wfw"

if (-not (Get-Command -Name New-NetFirewallRule -ErrorAction SilentlyContinue) -or -not (Get-Command Get-ScheduledTask)) {
    if (schtasks /Query /TN FWRevert) {
        schtasks /delete /tn FWRevert /f
        $startTime = (Get-Date).AddMinutes(5).ToString("HH:mm")
        schtasks /create /tn "FWRevert" /tr "netsh advfirewall import 'C:\Firewall.wfw'" /ru "NT AUTHORITY\SYSTEM" /sc once /st $startTime /f
    }
    else {
        $startTime = (Get-Date).AddMinutes(5).ToString("HH:mm")
        schtasks /create /tn "FWRevert" /tr "netsh advfirewall import 'C:\Firewall.wfw'" /ru "NT AUTHORITY\SYSTEM" /sc once /st $startTime /f
    }

    netsh advfirewall set allprofiles state off
    cmd.exe /c "netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound"
    netsh advfirewall firewall delete rule name=all

    # Allow RDP from Dispatcher
    netsh advfirewall firewall add rule name="RDP Inbound" dir=in protocol=TCP localport=3389 remoteip=$Dispatcher action=allow
    netsh advfirewall firewall add rule name="RDP Outbound" dir=out protocol=TCP localport=3389 remoteip=$Dispatcher action=allow

    # Allow custom ports for allowed networks
    foreach ($network in $allowedNetworks) {
        foreach ($port in $ports) {
            netsh advfirewall firewall add rule name="Port $port Inbound" dir=in protocol=TCP localport=$port remoteip=$network action=allow
            netsh advfirewall firewall add rule name="Port $port Outbound" dir=out protocol=TCP localport=$port remoteip=$network action=allow
        }
    }

    if ($Passthru -ne "NoPassthru") {
        netsh advfirewall firewall add rule name="Passthru Inbound" dir=in protocol=any remoteip=$Passthru action=allow
        netsh advfirewall firewall add rule name="Passthru Outbound" dir=out protocol=any remoteip=$Passthru action=allow
    }

    netsh advfirewall set allprofiles state on
}
else {
    if (Get-ScheduledTask -TaskName "FWRevert" -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName "FWRevert" -Confirm:$false
        $taskaction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "netsh advfirewall import 'C:\Firewall.wfw'"
        $starttime = (Get-Date).AddMinutes(5)
        $trigger = New-ScheduledTaskTrigger -At $starttime -Once
        Register-ScheduledTask -Action $taskaction -Trigger $trigger -TaskName FWRevert -User "NT AUTHORITY\SYSTEM" -Force
    }
    else {
        $taskaction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "netsh advfirewall import 'C:\Firewall.wfw'"
        $starttime = (Get-Date).AddMinutes(5)
        $trigger = New-ScheduledTaskTrigger -At $starttime -Once
        Register-ScheduledTask -Action $taskaction -Trigger $trigger -TaskName FWRevert -Description "Reverts Firewall" -User "NT AUTHORITY\SYSTEM" -Force
    }

    Set-NetFirewallProfile -All -Enabled False

    Set-NetFirewallProfile -DefaultInboundAction Block -DefaultOutboundAction Block -Name Domain -Enabled False
    Set-NetFirewallProfile -DefaultInboundAction Block -DefaultOutboundAction Block -Name Private -Enabled False
    Set-NetFirewallProfile -DefaultInboundAction Block -DefaultOutboundAction Block -Name Public -Enabled False

    Remove-NetFirewallRule -All

    # RDP from Dispatcher
    New-NetFirewallRule -DisplayName "RDP Inbound" -Direction Inbound -Protocol TCP -LocalPort 3389 -RemoteAddress $Dispatcher
    New-NetFirewallRule -DisplayName "RDP Outbound" -Direction Outbound -Protocol TCP -LocalPort 3389 -RemoteAddress $Dispatcher

    # Custom ports for allowed networks
    foreach ($network in $allowedNetworks) {
        foreach ($port in $ports) {
            New-NetFirewallRule -DisplayName "Port $port Inbound" -Direction Inbound -Protocol TCP -LocalPort $port -RemoteAddress $network
            New-NetFirewallRule -DisplayName "Port $port Outbound" -Direction Outbound -Protocol TCP -LocalPort $port -RemoteAddress $network
        }
    }

    if ($Passthru -ne "NoPassthru") {
        New-NetFirewallRule -DisplayName "Passthru Inbound" -Direction Inbound -Protocol Any -RemoteAddress $Passthru
        New-NetFirewallRule -DisplayName "Passthru Outbound" -Direction Outbound -Protocol Any -RemoteAddress $Passthru
    }

    Set-NetFirewallProfile -All -Enabled $true
}