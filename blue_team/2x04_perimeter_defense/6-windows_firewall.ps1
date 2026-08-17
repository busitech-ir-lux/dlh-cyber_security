# 6-windows_firewall.ps1

$SegmentationFile = ".\segmentation_rules.json"
$OutputFile = ".\windows_firewall_rules.json"

# This Windows host is in the INTERNAL zone
$LocalZone = "INTERNAL"

Write-Host "[*] Reading segmentation_rules.json..."

if (-not (Test-Path $SegmentationFile)) {
    Write-Host "segmentation_rules.json not found"
    exit 1
}

$Data = Get-Content $SegmentationFile -Raw | ConvertFrom-Json


# -------------------------------------------------
# Set firewall profile defaults
# -------------------------------------------------

Write-Host "[*] Setting profile defaults..."

$Profiles = @("Domain", "Private", "Public")

foreach ($Profile in $Profiles) {

    Set-NetFirewallProfile `
        -Profile $Profile `
        -DefaultInboundAction Block `
        -DefaultOutboundAction Allow `
        -LogBlocked True `
        -LogFileName "%systemroot%\system32\LogFiles\Firewall\meddefense.log"

    Write-Host "  $Profile : DefaultInboundAction=Block LogBlocked=True [SET]"
}


# -------------------------------------------------
# Remove old MedDefense rules
# -------------------------------------------------

Write-Host "[*] Clearing previous MedDefense-* rules..."

$OldRules = Get-NetFirewallRule |
    Where-Object { $_.DisplayName -like "MedDefense-*" }

$RemovedCount = @($OldRules).Count

if ($RemovedCount -gt 0) {
    $OldRules | Remove-NetFirewallRule
}

Write-Host "  [$RemovedCount removed]"


# -------------------------------------------------
# Find zone CIDRs
# -------------------------------------------------

$ZoneCIDRs = @{}

foreach ($Zone in $Data.zones) {
    $ZoneCIDRs[$Zone.name] = $Zone.cidr
}


# -------------------------------------------------
# Create inbound firewall rules
# -------------------------------------------------

Write-Host "[*] Creating rules from flow matrix..."

$CreatedRules = @()

foreach ($Flow in $Data.flows) {

    # Only allow rules
    if ($Flow.action -ne "allow") {
        continue
    }

    # Only flows terminating on this Windows host
    if ($Flow.dst_zone -ne $LocalZone) {
        continue
    }

    $Protocol = $Flow.proto.ToUpper()
    $Port = $Flow.dport
    $SourceZone = $Flow.src_zone


    # Get source CIDR
    if ($SourceZone -eq "ALL") {
        $RemoteAddress = "Any"
    }
    elseif ($ZoneCIDRs.ContainsKey($SourceZone)) {
        $RemoteAddress = $ZoneCIDRs[$SourceZone]
    }
    else {
        Write-Host "Skipping unknown source zone: $SourceZone"
        continue
    }


    # Example:
    # MedDefense-MGMT-TCP-22
    $DisplayName = "MedDefense-$SourceZone-$Protocol-$Port"


    New-NetFirewallRule `
        -DisplayName $DisplayName `
        -Direction Inbound `
        -Action Allow `
        -Protocol $Protocol `
        -LocalPort $Port `
        -RemoteAddress $RemoteAddress `
        -Profile Any | Out-Null


    Write-Host "  $DisplayName Inbound Allow $Protocol $Port [CREATED]"


    # Save information for JSON output
    $CreatedRules += [PSCustomObject]@{
        DisplayName   = $DisplayName
        Direction     = "Inbound"
        Action        = "Allow"
        Protocol      = $Protocol
        LocalPort     = $Port
        RemoteAddress = $RemoteAddress
        Profile       = "Any"
        SourceZone    = $SourceZone
        DestinationZone = $LocalZone
    }
}


# -------------------------------------------------
# Export rules as JSON
# -------------------------------------------------

$Result = [PSCustomObject]@{
    generated_at = (Get-Date).ToString("o")
    hostname = $env:COMPUTERNAME
    local_zone = $LocalZone
    rules = $CreatedRules
    summary = [PSCustomObject]@{
        rule_count = $CreatedRules.Count
    }
}

$Result |
    ConvertTo-Json -Depth 5 |
    Set-Content $OutputFile


Write-Host ""
Write-Host "Windows Firewall configuration complete."
Write-Host "Rules created: $($CreatedRules.Count)"
Write-Host "Output: $OutputFile"
