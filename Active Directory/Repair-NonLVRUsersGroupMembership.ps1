<#
Script that remediates Active Directory members that don't support LVR

Based on https://devblogs.microsoft.com/scripting/remediate-active-directory-members-that-dont-support-lvr/

Version: 0.1.0
#>

using namespace System.Collections.Generic

[CmdletBinding(DefaultParameterSetName='GroupListFile')]
    Param(
        [Parameter(
            Mandatory = $false,
            Position = 0,
            HelpMessage = "Enter a valid FQDN with optional port number separated by a colon. E.g., contoso.com or contoso.local:5000"
        )]
        [System.String]$Server = "adsandboxdc.adsandbox.com",

        [Parameter(
            Mandatory = $true,
            Position = 1,
            ParameterSetName = 'GroupListFile'
        )]
        [ValidateScript({
            if (-not ($_ | Test-Path -PathType Leaf)) {
                throw "The file does not exist"
            }
            if ($_ -notmatch "(\.txt)") {
                throw "The file type must be txt"
            }
            return $true
        })]
        [System.IO.FileInfo]$GroupListFile,

        [Parameter(
            Mandatory = $false,
            Position = 1,
            ParameterSetName = 'SearchBase'
        )]
        [System.String]$SearchBase = (Get-ADDomainController | Select-Object -ExpandProperty DefaultPartition)
    )

#Requires -Modules ActiveDirectory
#Requires -Version 5.1
#Requires -RunAsAdministrator

$ErrorActionPreference = "Stop"


$groups = [List[System.Object]]::new()

if ($GroupListFile) {
    $dnRegex = '^(?:(?<cn>CN=(?<name>[^,]*)),)?(?:(?<path>(?:(?:CN|OU)=[^,]+,?)+),)?(?<domain>(?:DC=[^,]+,?)+)$'
    
    Get-Content -Path $GroupListFile | ForEach-Object {
        if ($_ -match $dnRegex) {
            $groups.Add(@($_))
        }
    }

    if ($groups.Count -eq 0) {
        Write-Warning "No group DNs were imported from the group list file. Make sure the file contains at least one valid group DN and that each entry is on a new line"

        Exit
    }
} else {
    try {
        $groups.AddRange(@(Get-ADGroup -Filter * -Server $server -SearchBase $SearchBase | 
            Get-ADReplicationAttributeMetadata -Server $server -Properties Member -ShowAllLinkedValues | 
            Where-Object {$_.Version -eq 0} | Select-Object -ExpandProperty Object -Unique | Sort-Object
        ))
    }
    catch {
        Write-Host "Failed to get groups containing non-LVR users. Exception details: $($_.Exception.Message)"

        Exit
    }

    if ($groups.Count -eq 0) {
        Write-Warning "No non-LVR users were found in any groups under searchbase '$SearchBase'"

        Exit
    }
}

$progressBarCounter = 0
$groupsCount = $groups.Count

foreach ($group in $groups) {
    $progressBarCounter++
    $progressBarActivity = "Remediating non-LVR users in $group"
    $progressBarStatus = "Processed $progressBarCounter of $groupsCount groups"
    $progressBarPercentComplete = ($progressBarCounter/$groupsCount)*100
    
    Write-Progress -Activity $progressBarActivity -Status $progressBarStatus -PercentComplete $progressBarPercentComplete
    
    $nonLVRMembers = [List[System.Object]]::new()
    
    $nonLVRMembers.AddRange(@(Get-ADReplicationAttributeMetadata -Object $group -Server $server -Properties Member -ShowAllLinkedValues | 
        Where-Object {$_.Version -eq 0} | Select-Object -ExpandProperty AttributeValue | Sort-Object
    ))

    if ($nonLVRMembers.Count -eq 0) {
        Write-Warning "No non-LVR users were found in $group"
    } else {
        try {
            Remove-ADGroupMember -Identity $group -Members $nonLVRMembers -Server $server
        }
        catch {
            Write-Host "A problem was encountered while attempting to remove one or more users from group '$group'. Exception details: $($_.Exception.Message)" -ForegroundColor Red -BackgroundColor Black
        }
        
        try {
            Add-ADGroupMember -Identity $group -Members $nonLVRMembers -Server $server
        }
        catch {
            Write-Host "A problem was encountered while attempting to add one or more users to group '$group'. Exception details: $($_.Exception.Message)" -ForegroundColor Red -BackgroundColor Black
        }
    }
}