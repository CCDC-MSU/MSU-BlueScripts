param(
    [String]$ScriptArgs = @("")
)
$ErrorActionPreference = "SilentlyContinue"

$Argsarray = $ScriptArgs -Split ";"
if ($Argsarray.Count -lt 3) {
    Write-Host 'Usage - .\Firewall.ps1 "<Remote Management Subnet>;<Network Subnet>;NoPassthru"'
    break
}
$Dispatcher = $Argsarray[0];
$allowedNetworks = $Argsarray[1];
$allowedNetworks = $allowedNetworks -split ','
write-Host "Allowed networks:" $allowedNetworks
$Passthru = $Argsarray[2];

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

    # Allow WinRM (80, 5985, 5986) inbound from Dispatcher
    netsh advfirewall firewall add rule name="WINRM 80" dir=in protocol=TCP localport=80 remoteip=$Dispatcher action=allow
    netsh advfirewall firewall add rule name="WINRM 5985" dir=in protocol=TCP localport=5985 remoteip=$Dispatcher action=allow
    netsh advfirewall firewall add rule name="WINRM 5986" dir=in protocol=TCP localport=5986 remoteip=$Dispatcher action=allow

    # Allow RDP 3389 inbound and outbound from Dispatcher
    netsh advfirewall firewall add rule name="RDP Inbound" dir=in protocol=TCP localport=3389 remoteip=$Dispatcher action=allow
    netsh advfirewall firewall add rule name="RDP Outbound" dir=out protocol=TCP localport=3389 remoteip=$Dispatcher action=allow

    # Allow essential DC ports inbound for allowed networks
    foreach ($network in $allowedNetworks) {
        # Kerberos
        netsh advfirewall firewall add rule name="Kerberos TCP" dir=in protocol=TCP localport=88 remoteip=$network action=allow
        netsh advfirewall firewall add rule name="Kerberos UDP" dir=in protocol=UDP localport=88 remoteip=$network action=allow
        # DNS
        netsh advfirewall firewall add rule name="DNS TCP" dir=in protocol=TCP localport=53 remoteip=$network action=allow
        netsh advfirewall firewall add rule name="DNS UDP" dir=in protocol=UDP localport=53 remoteip=$network action=allow
        # LDAP
        netsh advfirewall firewall add rule name="LDAP TCP" dir=in protocol=TCP localport=389 remoteip=$network action=allow
        netsh advfirewall firewall add rule name="LDAP UDP" dir=in protocol=UDP localport=389 remoteip=$network action=allow
        # LDAPS
        netsh advfirewall firewall add rule name="LDAPS" dir=in protocol=TCP localport=636 remoteip=$network action=allow
        # Global Catalog
        netsh advfirewall firewall add rule name="GC" dir=in protocol=TCP localport=3268 remoteip=$network action=allow
        netsh advfirewall firewall add rule name="GC SSL" dir=in protocol=TCP localport=3269 remoteip=$network action=allow
        # SMB
        netsh advfirewall firewall add rule name="SMB" dir=in protocol=TCP localport=445 remoteip=$network action=allow
        # RPC Endpoint Mapper
        netsh advfirewall firewall add rule name="RPC Endpoint Mapper" dir=in protocol=TCP localport=135 remoteip=$network action=allow
        # RPC Dynamic Range (default 49152-65535)
        netsh advfirewall firewall add rule name="RPC Dynamic Ports" dir=in protocol=TCP localport=49152-65535 remoteip=$network action=allow
        # NetBIOS
        netsh advfirewall firewall add rule name="NetBIOS Name Service" dir=in protocol=UDP localport=137 remoteip=$network action=allow
        netsh advfirewall firewall add rule name="NetBIOS Datagram Service" dir=in protocol=UDP localport=138 remoteip=$network action=allow
        netsh advfirewall firewall add rule name="NetBIOS Session Service" dir=in protocol=TCP localport=139 remoteip=$network action=allow
        # Optional: NTP (UDP 123) inbound/outbound
        netsh advfirewall firewall add rule name="NTP" dir=in protocol=UDP localport=123 remoteip=$network action=allow
        netsh advfirewall firewall add rule name="NTP Outbound" dir=out protocol=UDP localport=123 remoteip=$network action=allow

        # Also allow outbound TCP to allowed networks (if needed)
        netsh advfirewall firewall add rule name="Outbound TCP to Allowed Network" dir=out protocol=TCP remoteip=$network action=allow
        netsh advfirewall firewall add rule name="Outbound UDP to Allowed Network" dir=out protocol=UDP remoteip=$network action=allow
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

    # WinRM inbound from Dispatcher
    New-NetFirewallRule -DisplayName "WinRM" -Direction Inbound -Protocol TCP -LocalPort 80,5985,5986 -RemoteAddress $Dispatcher

    # RDP inbound/outbound from Dispatcher
    New-NetFirewallRule -DisplayName "RDP Inbound" -Direction Inbound -Protocol TCP -LocalPort 3389 -RemoteAddress $Dispatcher
    New-NetFirewallRule -DisplayName "RDP Outbound" -Direction Outbound -Protocol TCP -LocalPort 3389 -RemoteAddress $Dispatcher

    foreach ($network in $allowedNetworks) {
        # Kerberos
        New-NetFirewallRule -DisplayName "Kerberos TCP" -Direction Inbound -Protocol TCP -LocalPort 88 -RemoteAddress $network
        New-NetFirewallRule -DisplayName "Kerberos UDP" -Direction Inbound -Protocol UDP -LocalPort 88 -RemoteAddress $network
        # DNS
        New-NetFirewallRule -DisplayName "DNS TCP" -Direction Inbound -Protocol TCP -LocalPort 53 -RemoteAddress $network
        New-NetFirewallRule -DisplayName "DNS UDP" -Direction Inbound -Protocol UDP -LocalPort 53 -RemoteAddress $network
        # LDAP
        New-NetFirewallRule -DisplayName "LDAP TCP" -Direction Inbound -Protocol TCP -LocalPort 389 -RemoteAddress $network
        New-NetFirewallRule -DisplayName "LDAP UDP" -Direction Inbound -Protocol UDP -LocalPort 389 -RemoteAddress $network
        # LDAPS
        New-NetFirewallRule -DisplayName "LDAPS" -Direction Inbound -Protocol TCP -LocalPort 636 -RemoteAddress $network
        # Global Catalog
        New-NetFirewallRule -DisplayName "GC" -Direction Inbound -Protocol TCP -LocalPort 3268 -RemoteAddress $network
        New-NetFirewallRule -DisplayName "GC SSL" -Direction Inbound -Protocol TCP -LocalPort 3269 -RemoteAddress $network
        # SMB
        New-NetFirewallRule -DisplayName "SMB" -Direction Inbound -Protocol TCP -LocalPort 445 -RemoteAddress $network
        # RPC Endpoint Mapper
        New-NetFirewallRule -DisplayName "RPC Endpoint Mapper" -Direction Inbound -Protocol TCP -LocalPort 135 -RemoteAddress $network
        # RPC Dynamic Ports
        New-NetFirewallRule -DisplayName "RPC Dynamic Ports" -Direction Inbound -Protocol TCP -LocalPort 49152-65535 -RemoteAddress $network
        # NetBIOS
        New-NetFirewallRule -DisplayName "NetBIOS Name Service" -Direction Inbound -Protocol UDP -LocalPort 137 -RemoteAddress $network
        New-NetFirewallRule -DisplayName "NetBIOS Datagram Service" -Direction Inbound -Protocol UDP -LocalPort 138 -RemoteAddress $network
        New-NetFirewallRule -DisplayName "NetBIOS Session Service" -Direction Inbound -Protocol TCP -LocalPort 139 -RemoteAddress $network
        # NTP inbound/outbound
        New-NetFirewallRule -DisplayName "NTP Inbound" -Direction Inbound -Protocol UDP -LocalPort 123 -RemoteAddress $network
        New-NetFirewallRule -DisplayName "NTP Outbound" -Direction Outbound -Protocol UDP -LocalPort 123 -RemoteAddress $network

        # Outbound TCP/UDP allowed to allowed networks
        New-NetFirewallRule -DisplayName "Outbound TCP to Allowed Network" -Direction Outbound -Protocol TCP -RemoteAddress $network
        New-NetFirewallRule -DisplayName "Outbound UDP to Allowed Network" -Direction Outbound -Protocol UDP -RemoteAddress $network
    }

    if ($Passthru -ne "NoPassthru") {
        New-NetFirewallRule -DisplayName "Passthru Inbound" -Direction Inbound -Protocol Any -RemoteAddress $Passthru
        New-NetFirewallRule -DisplayName "Passthru Outbound" -Direction Outbound -Protocol Any -RemoteAddress $Passthru
    }

    Set-NetFirewallProfile -All -Enabled $true
}

