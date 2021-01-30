<#
.SYNOPSIS
Sets or clears the value for a specific ServiceNow attribute in an Active Directory forest based on group 
membership.

.DESCRIPTION
We start by getting the forest name. If this fails, the script is aborted, as whatever caused the failure will 
most likely cause other crucial parts of the script to fail. If it succeeds, we check to ensure that the 
supplied group and attribute exist. If this succeeds, we get a list of every user in the forest. If not, we 
abort. We then get a list of members of the group. Members of the group will have the supplied attribute value 
for the supplied attribute set. If the user is not a member, the value for the attribute is cleared. If the 
user account running the script doesn’t have permission to change user attributes, the script will abort on 
the first failure. I intend to move the account permission check to where the other pre-run scripts live and 
base it on actual permissions instead of an exception.

After the operation is complete, a uniquely named csv report of the set and clear operation is automatically 
created in the same directory the script is run from. The csv report contains the following information:

Forest
Group
GroupDN
Attribute Name
Attribute Value

User             | AttributeState | Success  | ErrorMessage
----------------------------------------------------------------
[sAMAccountName] | [Set/Clear]    | [Yes/No] | [Blank/Exception]

.PARAMETER Group
The group name as a SAM account name, DN, GUID, or SID.

.PARAMETER AttributeName
The ServiceNow attribute. The script supports the following ServiceNow attributes which all take a string 
value.
-serviceNowCity
-serviceNowCorID
-serviceNowCorName
-serviceNowDirectorate
-serviceNowHireDate
-serviceNowJobCode
-serviceNowJobLocation
-serviceNowLineSupervisor
-serviceNowOrganizationID
-serviceNowOrgCodeLowestLevel
-serviceNowStateProvince
-serviceNowSupervisorID
-serviceNowTitle
-serviceNowUserID
-serviceNowUserName

.PARAMETER AttributeValue
The attribute value as a string.

.PARAMETER Server
Specifies the Active Directory Domain Services instance to connect to, by providing one of the following 
values for a corresponding domain name or directory server. The service may be any of the following: Active 
Directory Lightweight Domain Services, Active Directory Domain Services or Active Directory Snapshot instance.

Domain name values:
-Fully qualified domain name (FQDN)
-NetBIOS name

Directory server values:
-Fully qualified directory server name
-NetBIOS name
-Fully qualified directory server name and port

.PARAMETER AuthType
Specifies the authentication method to use. The acceptable values for this parameter are:
-Negotiate or 0
-Basic or 1

The default authentication method is Negotiate.

A Secure Sockets Layer (SSL) connection is required for the Basic authentication method.

.PARAMETER Credential
Specifies the user account credentials to use to perform this task. The default credentials are the 
credentials of the currently logged on user unless the cmdlet is run from an Active Directory PowerShell 
provider drive. If the cmdlet is run from such a provider drive, the account associated with the drive is the 
default.

.EXAMPLE
.\Set-ADserviceNowAttribute.ps1 -Group group1 -AttributeName serviceNowJobCode -AttributeValue 1234

.EXAMPLE
.\Set-ADserviceNowAttribute.ps1 -Group group1 -AttributeName serviceNowJobCode -AttributeValue 1234 -Credential user1

.EXAMPLE
.\Set-ADserviceNowAttribute.ps1 -Group group1 -AttributeName serviceNowJobCode -AttributeValue 1234 -Server DC01.contoso.com -AuthType 0 -Credential azadmin

.EXAMPLE
.\Set-ADserviceNowAttribute.ps1 -Group group1 -AttributeName serviceNowJobCode -AttributeValue 1234 -Server DC01.contoso.com:5000 -AuthType Negotiate -Credential azadmin

.NOTES
Tested on Windows Server 2016 running AD forest functional level Windows Server 2016.

TODO:
- Implement a better user permissions check.

Version: 0.1.0
#>

[CmdletBinding()]
    Param(
        [Parameter(
            Mandatory = $true,
            Position = 0,
            HelpMessage = "Enter a SAM account name, DN, GUID, or SID."
        )]
        [System.String]$Group,

        [Parameter(
            Mandatory = $true,
            Position = 1
        )]
        [ValidateSet(
            'serviceNowCity',
            'serviceNowCorID',
            'serviceNowCorName',
            'serviceNowDirectorate',
            'serviceNowHireDate',
            'serviceNowJobCode',
            'serviceNowJobLocation',
            'serviceNowLineSupervisor',
            'serviceNowOrganizationID',
            'serviceNowOrgCodeLowestLevel',
            'serviceNowStateProvince',
            'serviceNowSupervisorID',
            'serviceNowTitle',
            'serviceNowUserID',
            'serviceNowUserName'
        )]
        [System.String]$AttributeName,

        [Parameter(
            Mandatory = $true,
            Position = 2
        )]
        [System.String]$AttributeValue,

        [Parameter(
            Mandatory = $false,
            Position = 3,
            HelpMessage = "Enter a valid FQDN with optional port number separated by a colon. E.g., contoso.com or contoso.local:5000"
        )]
        [System.String]$Server,

        [Parameter(
            Mandatory = $false,
            Position = 4,
            HelpMessage = "Specifies the authentication method to use."
        )]
        [ValidateSet('Negotiate', '0', 'Basic', '1')]
        [System.String]$AuthType,

        [Parameter(
            Mandatory = $false,
            Position = 5
        )]
        [System.Management.Automation.PSCredential]$Credential
    )

#Requires -Modules ActiveDirectory
#Requires -Version 5.1
#Requires -RunAsAdministrator

$ErrorActionPreference = "SilentlyContinue"


$optionalParamVars = @{
    Server = $Server
    AuthType = $AuthType
    Credential = $Credential
}

$optionalArgs = @{}

foreach ($paramVar in $optionalParamVars.GetEnumerator()) {
    if (-not ([System.String]::IsNullOrWhiteSpace($paramVar.Value))) {
        $optionalArgs.Add($paramVar.Name, $paramVar.Value)
    }
}


# Perform some checks before starting
try {
    # Get forest name. If this fails, we abort script execution because whatever caused the error will probably break the rest of the script
    $forestName = "'$(Get-ADDomain @optionalArgs | Select-Object -ExpandProperty Forest)'"

    # Check if group exists
    Get-ADGroup -Identity $Group @optionalArgs | Out-Null

    #region Check if attribute exists
    # Code snippet based on https://www.easy365manager.com/how-to-get-all-active-directory-user-object-/
    $className = "User"
    $classArray = [System.Collections.ArrayList]@()
    $user = [System.Collections.ArrayList]@()
    $searchBase =  Get-ADRootDSE | Select-Object -ExpandProperty SchemaNamingContext
    $classParams = @{
        SearchBase = $searchBase
        Filter = {ldapDisplayName -like $className}
        Properties = 'AuxiliaryClass',
                     'SystemAuxiliaryClass',
                     'mayContain',
                     'mustContain',
                     'systemMayContain',
                     'systemMustContain',
                     'subClassOf',
                     'ldapDisplayName'
    }

    # Retrieve the User class and any parent classes
    do {
        $class = Get-ADObject @classParams @optionalArgs
        $classArray.Add($class) | Out-Null
        $className = $class.subClassOf
    } while ($class.ldapDisplayName -ne $class.subClassOf)

    # Loop through all the classes and get all auxiliary class  and direct 
    $ClassArray | ForEach-Object {
        $auxParams = @{
            Searchbase = $searchBase
            Filter = {ldapDisplayName -like $_}
            Properties = 'mayContain',
                         'mustContain',
                         'systemMayContain',
                         'systemMustContain'
        }
        $sysAuxParams = @{
            SearchBase = $searchBase
            Filter = {ldapDisplayName -like $_}
            Properties = 'MayContain',
                         'SystemMayContain',
                         'systemMustContain'
        }

        # Get Auxiliary class 
        $aux = $_.AuxiliaryClass | ForEach-Object { 
            Get-ADObject @auxParams @optionalArgs | Select-Object @{
                Name = "Attributes"
                Expression = {$_.mayContain + $_.mustContain + $_.systemMaycontain + $_.systemMustContain}
            } | Select-Object -ExpandProperty Attributes
        
        }
        # Get SystemAuxiliary class 
        $sysAux = $_.SystemAuxiliaryClass | ForEach-Object {
            Get-ADObject @sysAuxParams @optionalArgs | Select-Object @{
                Name = "Attributes"
                Expression = {$_.mayContain + $_.systemMayContain + $_.systemMustContain}
            } | Select-Object -ExpandProperty Attributes
        }
  
      # Get direct attributes
      $User += $aux + $sysAux + $_.mayContain + $_.mustContain + $_.systemMayContain + $_.systemMustContain
    }

    $user = $user | Sort-Object | Get-Unique

    if (-not ($User -contains $AttributeName)) {
        Write-Host "`nThe attribute '$attributeName' was not found. This probably means the ServiceNow extensions haven't been added to the schema`n" -ForegroundColor Red

        Exit
    }
    #endregion Check if attribute exists
}
catch {
    Write-Host "`nScript execution failed. Reason: $($_.Exception.Message)`n" -ForegroundColor Red

    Exit
}

# Get all users in the forest
Write-Host "`n- Getting all users in forest $($forestName). This could take a while if you have a lot of users. To abort, press Ctrl+C" -ForegroundColor Cyan

try {
    $allUsers = [System.Collections.Generic.List[System.String]]::New()
    $allUsers += Get-ADUser -Filter * @optionalArgs | Select-Object -ExpandProperty DistinguishedName

    Write-Host "- Got all the users" -ForegroundColor Green
}
catch {
    Write-Host "`nFailed to get users. Reason: $($_.Exception.Message)`n" -ForegroundColor Red

    Exit
}

#region Set user attributes

# Init Write-Progress counter
$progressBarCounter = 0

# Init table for Set-ADUser results report
$reportTable = [System.Collections.Generic.List[System.Object]]::New()

# Error handling stuff for access rights
$accessRightsException = "Insufficient access rights to perform the operation"
$accessRightsExceptionMsg = "`nThe account running this script isn't allowed to modify user attributes. Script execution aborted`n"

Write-Host "- Applying attribute settings to users..." -ForegroundColor Cyan

foreach ($user in $allUsers) {
    $progressBarCounter++
    $progressBarPercent = ($progressCounter/$allUsers.Count)*100
    $progressBarActivity = "Applying attribute settings to users"
    $progressBarStatus = "Process $progressBarCounter of $($allUsers.Count) users"
    
    Write-Progress -Activity $progressBarActivity -Status $progressBarStatus -PercentComplete $progressBarPercent

    try {
        # Convert DN to SAM account name
        try {
            $userName = Get-ADUser -Identity $user @optionalArgs | Select-Object -ExpandProperty SamAccountName
        }
        catch {
            $userName = $user
        }

        if ((Get-ADGroup -Identity $Group -Properties Members @optionalArgs -ErrorAction Stop | Select-Object -ExpandProperty Members) -contains $user) {
            try {
                Set-ADUser -Identity $user -Replace @{$AttributeName = $AttributeValue} @optionalArgs -ErrorAction Stop

                $reportTable += [PSCustomObject]@{
                    User = $userName
                    AttributeState = "Set"
                    Success = "Yes"
                    ErrorMessage = ""
                }
            }
            catch {
                # This is an extremely lazy way of checking if the user running the script can set/clear attributes. Will change in the future
                if ($_.Exception.Message -eq $accessRightsException) {
                    Write-Host $accessRightsExceptionMsg -ForegroundColor Red

                    Exit
                } else {
                    $reportTable += [PSCustomObject]@{
                        User = $userName
                        AttributeState = "Set"
                        Success = "No"
                        ErrorMessage = "Failed to set the attribute value. Reason: $($_.Exception.Message)"
                    }
                }
            }
        } else {
            try {
                Set-ADUser -Identity $user -Clear $AttributeName @optionalArgs -ErrorAction Stop

                $reportTable += [PSCustomObject]@{
                    User = "$userName"
                    AttributeState = "Clear"
                    Success = "Yes"
                    ErrorMessage = ""
                }
            }
            catch {
                if ($_.Exception.Message -eq $accessRightsException) {
                    Write-Host $accessRightsExceptionMsg -ForegroundColor Red

                    Exit
                } else {
                    $reportTable += [PSCustomObject]@{
                        User = "$userName"
                        AttributeState = "Clear"
                        Success = "No"
                        ErrorMessage = "Failed to clear the attribute value. Reason: $($_.Exception.Message)"
                    }
                }
            }
        }
    }
    catch {
        Write-Host "`nThere was a problem getting the group membership. Reason: $($_.Exception.Message)`n" -ForegroundColor Red
        
        Exit
    }


}

#endregion Set user attributes

# Generate report
$csvTable = $reportTable | ConvertTo-Csv -NoTypeInformation
$csvTableString = [System.String]$csvTable -replace '\"\s', """`n"

# Get group DN
$groupDN = Get-ADGroup -Identity $Group @optionalArgs | Select-Object -ExpandProperty DistinguishedName

$csvOutput = @"
Forest: $($forestName -replace '[\s'']')
Group: $Group
"Group DN: $groupDN"
"Attribute Name: $attributeName"
"Attribute Value: $attributeValue"`n
$csvTableString
"@

$DateTime = Get-Date -Format FileDateTime
$csvFileName = "ADserviceNowAttributeChangeReport"
$csvReportFilePath = "$PSScriptRoot\$csvFileName`_$DateTime.csv"

try {
    $csvOutput | Out-File -FilePath $csvReportFilePath -Encoding utf8 -NoNewline -Force -ErrorAction Stop
}
catch {
    Write-Host "`nFailed to generate report. Reason: $($_.Exception.Message)`n" -ForegroundColor Red

    Exit
}

Write-Host "- Operation complete`n- Report generated at: $csvReportFilePath`n" -ForegroundColor Green