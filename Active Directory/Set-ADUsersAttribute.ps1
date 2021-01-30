<#
.SYNOPSIS
Sets or clears the value for a string-based Active Directory attribute based on group membership.
 
.DESCRIPTION
This script is intended to be run as a scheduled task that sets or clears the value for a string-based 
Active Directory attribute based on group membership. It can, however, be run standalone. If running 
standalone, it's recommended to include the -Verbose parameter to display script operation. This method is 
also useful for troubleshooting issues. The script logs messages in the Event Viewer and produces a csv
report containing the results of the attribute set/clear operation.

WARNING: This script only supports string-based attribute values. Attempting to set a non-string attribute 
value with this script could cause unexpected and/or potentially destructive results. You've been warned!

EVENT VIEWER INFO
-----------------
Success and errors are reported in the Event Viewer on the machine running the script. Error messages with 
exit codes 1-6 will not appear in the Event Viewer. The source and log name will be created if they don't 
exist. Below are the event details:
-Location: Applications and Services Logs > Directory Service
-Source: The name of the script. If the script is renamed (not recommended) the source will automatically 
reflect this change
-EventID: The exit code
-Task Category:(1)


OPERATIONS REPORT
-----------------
After the set user attribute operation is complete a csv report is created. The default csv report path is: 
$PSScriptRoot\Set-ADUsersAttributeReport.csv. This can be changed in the parameters section. A unique timestamp 
is automatically appended to the report file name. If a valid custom path is supplied and it doesn't exist, 
it'll be created. Network paths are not supported at this time.

The csv report contains the following information:

Forest
Group
GroupDN
Attribute Name
Attribute Value

User             | AttributeState | Success  | ErrorMessage
----------------------------------------------------------------
[sAMAccountName] | [Set/Clear]    | [Yes/No] | [Blank/Exception]


TASK SCHEDULER INFO
-------------------
When setting up the task in the Task Scheduler, make sure the account running the task is a local 
administrator and has permission to set and clear user attributes in AD. Under the task Actions, set the 
following options:
-Action: Start a program
-Program/script: powershell.exe
-Add arguments: -ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -Command "& {C:\Path\To\Set-ADUsersAttribute.ps1 -Group "<value>" -AttributeName "<value>" -AttributeValue "<value>"; exit $LASTEXITCODE}"


EXIT CODES
----------
The script uses the following exit codes which will appear under Last Run Result of the scheduled task:
0x0 = Successful run
0x1 = The script can't continue because the script must be run as an administrator
0x2 = The script can't continue because the minimum PowerShell version required is 5.1
0x3 = The script can't continue because the ActiveDirectory module isn't installed
0x4 = Invalid report file path. Enter a valid path. E.g., C:\Reports\report.csv
0x5 = Invalid AuthType value. Supported values are: 'Negotiate', '0', 'Basic', '1'
0x6 = Failed to create source. Reason: <exception message>
0x7 = Failed to create folder. Reason: <exception message>
0x8 = Failed to create the csv file. Reason: <exception message>
0x9 = Script execution failed because the attribute '<attributeName>' was not found
0x10 = Script execution failed. Reason: <exception message>
0x11 = Failed to get users. Reason: <exception message>
0x12 = Failed to set the attribute value. Reason: <exception message>
0x13 = There was a problem getting the group membership. Reason: <exception message>
0x14 = Failed to write results to report. Reason: <exception message>

.PARAMETER Group
The group name as a SAM account name, DN, GUID, or SID.

.PARAMETER AttributeName
The name of the attribute.

.PARAMETER AttributeValue
The attribute value as a string. The script only supports string-based attributes values. You've been warned!

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
.\Set-ADUsersAttribute.ps1 -Group group1 -AttributeName EmployeeID -AttributeValue 1234

.EXAMPLE
.\Set-ADUsersAttribute.ps1 -Group group1 -AttributeName EmployeeID -AttributeValue 1234 -Credential user1

.EXAMPLE
.\Set-ADUsersAttribute.ps1 -Group group1 -AttributeName EmployeeID -AttributeValue 1234 -Server DC01.contoso.com -AuthType 0 -Credential admin

.EXAMPLE
.\Set-ADUsersAttribute.ps1 -Group group1 -AttributeName EmployeeID -AttributeValue 1234 -Server DC01.contoso.com:5000 -AuthType Negotiate -Credential admin

.NOTES
Tested on Windows Server 2016 and 2019 running AD forest functional level Windows Server 2016.

Version: 0.2.0
#>

using namespace System.Collections.Generic

[CmdletBinding()]
    Param(
        [Parameter(
            Mandatory = $true,
            Position = 0
        )]
        [System.String]$Group,

        [Parameter(
            Mandatory = $true,
            Position = 1
        )]
        [System.String]$AttributeName,

        [Parameter(
            Mandatory = $true,
            Position = 2
        )]
        [System.String]$AttributeValue,

        [Parameter(
            Mandatory = $false,
            Position = 3
        )]
        [System.String]$ReportFilePath = "$PSScriptRoot\Set-ADUsersAttributeReport.csv",

        [Parameter(
            Mandatory = $false,
            Position = 4
        )]
        [System.String]$Server,

        [Parameter(
            Mandatory = $false,
            Position = 5
        )]
        [System.String]$AuthType,

        [Parameter(
            Mandatory = $false,
            Position = 6
        )]
        [System.Management.Automation.PSCredential]$Credential
    )


$ErrorActionPreference = "Stop"

function Remove-CsvReport {

    try {
        Remove-Item -Path $ReportFullPath

        Write-Verbose -Message "Deleted unused report file"
    }
    catch {
        Write-Verbose -Message "Couldn't delete report. Reason: $($_.Exception.Message)"
    }
}

# Check if script is ran as an Admin
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
if(-not ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))) {
    Write-Verbose -Message = "The script can't continue because the script must be run as an administrator"

    Exit 1
}

# Check if PS version is at least 5.1
$PSVersion = 5.1
if (-not ($PSVersionTable.PSVersion -ge $PSVersion)) {
    Write-Verbose -Message "The script can't continue because the minimum PowerShell version required is 5.1"

    Exit 2
}

# Check if AD module is installed
if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Verbose -Message "The script can't continue because the ActiveDirectory module isn't installed"

    Exit 3
}

# Check params. We use a custom param value check so we can work with exit codes
# PARAM: ReportFilePath
if ($ReportFilePath -notmatch '^[a-z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]+\.csv$') {
    Write-Verbose -Message "Invalid report file path. Enter a valid path. E.g., C:\Reports\report.csv"

    Exit 4
}

# PARAM: AuthType
if ($AuthType) {
    if ($AuthType -notmatch '^(Negotiate|0|Basic|1)$') {
        Write-Verbose -Message "Invalid AuthType value. Supported values are: 'Negotiate', '0', 'Basic', '1'"

        Exit 5
    }
}

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

#region Create event log
$eventLogSource = "$($MyInvocation.MyCommand.Name)" # Name of script
$eventLogName = "Directory Service"

$writeEventLogParams = @{
    LogName = $eventLogName
    Source = $eventLogSource
}

Write-Verbose -Message "Checking if event source '$eventLogSource' exists"

if ([System.Diagnostics.EventLog]::SourceExists($eventLogSource)) {
    Write-Verbose -Message "Event source found"
} else {
    Write-Verbose -Message "Source not found. Attempting to create it"

    try {
        New-EventLog -LogName $eventLogName -Source $eventLogSource

        Write-Verbose -Message "Source created"
    }
    catch {
        Write-Verbose -Message "Failed to create source. Reason: $($_.Exception.Message)"
        
        Exit 6
    }
}
#endregion Create event log


#region Create csv report
$DateTime = Get-Date -Format FileDateTime
$reportFullPath = $ReportFilePath -replace '.csv', "_$DateTime.csv"
$reportDir = Split-Path -Path $reportFullPath -Parent

# Create csv folder if it doesn't exist
try {
    if (-not (Test-Path -Path $reportDir)) {
        Write-Verbose -Message "The csv report folder '$reportDir' doesn't exist. Attempting to create it"

        New-Item -Path $reportDir -ItemType Directory | Out-Null

        Write-Verbose -Message "Folder created"
    }
}
catch {
    $statusMessage = "Failed to create folder. Reason: $($_.Exception.Message)"
    
    Write-Verbose -Message $statusMessage
    
    Write-EventLog @writeEventLogParams -EntryType Error -EventId 7 -Message $statusMessage
    
    Exit 7
}

# Check if we can write the csv to ensure we always get a csv report
try {
    Write-Verbose -Message "Attempting to create empty csv report file to test for write access"
    
    Out-File -FilePath $reportFullPath -Encoding utf8
    
    Write-Verbose -Message "CSV report created: $reportFullPath"
}
catch {
    $statusMessage = "Failed to create the csv file. Reason: $($_.Exception.Message)"
    
    Write-Verbose -Message $statusMessage

    Write-EventLog @writeEventLogParams -EntryType Error -EventId 8 -Message $statusMessage
    
    Exit 8
}
#endregion Create csv report


# Perform some checks before starting
try {
    # Get forest name. If this fails, we abort script execution because whatever caused the error will probably break the rest of the script
    $forestName = "'$(Get-ADDomain @optionalArgs | Select-Object -ExpandProperty Forest)'"
    
    # Check if group exists
    Get-ADGroup -Identity $Group @optionalArgs | Out-Null
    
    #region Check if attribute exists
    # Code snippet based on https://www.easy365manager.com/how-to-get-all-active-directory-user-object-/
    $className = "User"
    $classArray = [List[System.Object]]::new()
    $user = [List[System.Object]]::new()
    $searchBase =  Get-ADRootDSE @optionalArgs | Select-Object -ExpandProperty SchemaNamingContext
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

    # Loop through all the classes and get all auxiliary class attributes and direct attributes
    $aux = [List[System.Object]]::new()
    $sysAux = [List[System.Object]]::new()
    
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

        # Get Auxiliary class attributes
        $_.AuxiliaryClass | ForEach-Object {
            $aux.AddRange(@(Get-ADObject @auxParams @optionalArgs| Select-Object @{
                Name = "Attributes"
                Expression = {$_.mayContain + $_.mustContain + $_.systemMaycontain + $_.systemMustContain}
            } | Select-Object -ExpandProperty Attributes))
        }
 
        # Get SystemAuxiliary class attributes
        $_.SystemAuxiliaryClass | ForEach-Object {
            $sysAux.AddRange(@(Get-ADObject @sysAuxParams @optionalArgs | Select-Object @{
                Name = "Attributes"
                Expression = {$_.mayContain + $_.systemMayContain + $_.systemMustContain}
            } | Select-Object -ExpandProperty Attributes))
        }
  
        # Get direct attributes
        $User.AddRange($aux + $sysAux + $_.mayContain + $_.mustContain + $_.systemMayContain + $_.systemMustContain)
    }

    $user = $user | Sort-Object | Get-Unique

    if (-not ($user -contains $AttributeName)) {
        $statusMessage = "Script execution failed because the attribute '$attributeName' was not found"

        Write-Verbose -Message $statusMessage
    
        Write-EventLog @writeEventLogParams -EntryType Error -EventId 9 -Message $statusMessage
    
        Remove-CsvReport

        Exit 9
    }
    #endregion Check if attribute exists
}
catch {
    $statusMessage = "Script execution failed. Reason: $($_.Exception.Message)"

    Write-Verbose -Message $statusMessage

    Write-EventLog @writeEventLogParams -EntryType Error -EventId 10 -Message $statusMessage

    Remove-CsvReport

    Exit 10
}


# Get all users in the forest
Write-Verbose -Message "Getting all users in forest $($forestName). This could take a while"

try {
    $allUsers = [List[System.Object]]::new()
    $allUsers.AddRange(@(Get-ADUser -Filter * @optionalArgs | Select-Object -ExpandProperty DistinguishedName))

    Write-Verbose -Message "Got all the users"
}
catch {
    $statusMessage = "Failed to get users. Reason: $($_.Exception.Message)"

    Write-Verbose -Message $statusMessage

    Write-EventLog @writeEventLogParams -EntryType Error -EventId 11 -Message $statusMessage

    Remove-CsvReport

    Exit 11
}


#region Set user attributes
# Init table for Set-ADUser results report
$reportTable = [List[System.Object]]::new()

# Error handling stuff for access rights
$accessRightsException = "Insufficient access rights to perform the operation"
$accessRightsExceptionMsg = "The account running this script isn't allowed to modify user attributes. Script execution aborted"

Write-Verbose -Message "Applying attribute settings to users"

foreach ($user in $allUsers) {
    try {
        # Convert DN to SAM account name
        try {
            $userName = Get-ADUser -Identity $user @optionalArgs | Select-Object -ExpandProperty SamAccountName
        }
        catch {
            $userName = $user
        }

        if ((Get-ADGroup -Identity $Group -Properties Members @optionalArgs | Select-Object -ExpandProperty Members) -contains $user) {
            try {
                Set-ADUser -Identity $user -Replace @{$AttributeName = $AttributeValue} @optionalArgs

                $reportTable.Add([PSCustomObject]@{
                    User = $userName
                    AttributeState = "Set"
                    Success = "Yes"
                    ErrorMessage = ""
                })
            }
            catch {
                # This seems like the best way
                if ($_.Exception.Message -eq $accessRightsException) {
                    Write-Verbose -Message $accessRightsExceptionMsg

                    Write-EventLog @writeEventLogParams -EntryType Error -EventId 12 -Message $accessRightsExceptionMsg

                    Remove-CsvReport

                    Exit 12
                } else {
                    $reportTable.Add([PSCustomObject]@{
                        User = $userName
                        AttributeState = "Set"
                        Success = "No"
                        ErrorMessage = "Failed to set the attribute value. Reason: $($_.Exception.Message)"
                    })
                }
            }
        } else {
            try {
                Set-ADUser -Identity $user -Clear $AttributeName @optionalArgs

                $reportTable.Add([PSCustomObject]@{
                    User = "$userName"
                    AttributeState = "Clear"
                    Success = "Yes"
                    ErrorMessage = ""
                })
            }
            catch {
                if ($_.Exception.Message -eq $accessRightsException) {
                    Write-Verbose -Message $accessRightsExceptionMsg
                   
                    Write-EventLog @writeEventLogParams -EntryType Error -EventId 12 -Message $accessRightsExceptionMsg

                    Remove-CsvReport

                    Exit 12
                } else {
                    $reportTable.Add([PSCustomObject]@{
                        User = "$userName"
                        AttributeState = "Clear"
                        Success = "No"
                        ErrorMessage = "Failed to clear the attribute value. Reason: $($_.Exception.Message)"
                    })
                }
            }
        }
    }
    catch {
        $statusMessage = "There was a problem getting the group membership. Reason: $($_.Exception.Message)"
        
        Write-Verbose -Message $statusMessage

        Write-EventLog @writeEventLogParams -EntryType Error -EventId 13 -Message $statusMessage

        Remove-CsvReport

        Exit 13
    }
}
#endregion Set user attributes

# Generate report
$csvTable = $reportTable | ConvertTo-Csv -NoTypeInformation
$csvTableString = [System.String]$csvTable -replace '\"\s', """`n"

$groupDN = Get-ADGroup -Identity $Group @optionalArgs | Select-Object -ExpandProperty DistinguishedName

$csvOutput = @"
Forest: $($forestName -replace '[\s'']')
Group: $Group
"Group DN: $groupDN"
"Attribute Name: $attributeName"
"Attribute Value: $attributeValue"`n
$csvTableString
"@

try {
    $csvOutput | Out-File -FilePath $reportFullPath -Encoding utf8 -NoNewline -Force

    $statusMessage = "Operation complete. Report location: $reportFullPath"

    Write-Verbose -Message $statusMessage

    Write-EventLog @writeEventLogParams -EntryType Information -EventId 0 -Message $statusMessage

    Exit 0
}
catch {
    $statusMessage = "Failed to write results to report. Reason: $($_.Exception.Message)"

    Write-Verbose -Message $statusMessage

    Write-EventLog @writeEventLogParams -EntryType Error -EventId 14 -Message $statusMessage

    Remove-CsvReport

    Exit 14
}