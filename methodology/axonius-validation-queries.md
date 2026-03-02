
# Axonius Asset Validation Queries (Examples)

## ClickFix / Script execution exposure
- where process.name = "powershell.exe" AND process.command_line contains_any ("-w hidden","-enc","IEX","DownloadString")
- where user.last_seen_clipboard_execution = true (if enrichment exists)

## External attack surface
- where network_interfaces.public_ip exists
- where device.internet_exposed = true

## RMM / Remote support tooling footprint
- where installed_software.name contains_any ("Quick Assist","ScreenConnect","NetSupport","AnyDesk","TeamViewer")
- where process.name contains_any ("QuickAssist.exe","client32.exe","netsupport") OR service.name contains_any ("ScreenConnect","NetSupport")

## Identity controls (UNC3944 focus)
- where identity.mfa_enabled = false
- where identity.auth_methods contains "sms" AND identity.is_privileged = true
- where identity.password_last_changed > 180d AND identity.is_enabled = true

## Crown jewels
- where asset.tags contains_any ("Tier0","CrownJewel","DomainController","ADFS","Okta","Entra","SSO")
