<#
TODO
- Add support for getting extended/custom attributes
- Add support for all attribute types when setting an attribute value 
#>
 

[CmdletBinding()]
    Param(
        [Parameter(
            Mandatory = $true,
            Position = 0
        )]
        [System.String]$User,

        [Parameter(
            Mandatory = $false,
            Position = 1,
            HelpMessage = "Enter an Active Directory path to search. E.g., CN=Group1,OU=Groups,DC=contoso,DC=com" 
        )]
        [System.String]$SearchBase,

        [Parameter(
            Mandatory = $false,
            Position = 2,
            HelpMessage = "Specifies the scope of an Active Directory search."
        )]
        [ValidateSet('Base', '0', 'OneLevel', '1', 'Subtree', '2')]
        [System.String]$SearchScope,

        [Parameter(
            Mandatory = $true,
            Position = 3,
            HelpMessage = "Enter a SAM account name, DN, GUID, or SID."
        )]
        [System.String]$Group,
        
        [Parameter(
            Mandatory = $true,
            Position = 4
        )]
        [System.String]$Attribute,

        [Parameter(
            Mandatory = $true,
            Position = 5
        )]
        [System.String]$AttributeValue,

        [Parameter(
            Mandatory = $false,
            Position = 6,
            HelpMessage = "Enter a valid FQDN with optional port number separated by a colon. E.g., contoso.com or contoso.local:5000"
        )]
        [System.String]$Server,

        [Parameter(
            Mandatory = $false,
            Position = 7,
            HelpMessage = "Specifies the authentication method to use."
        )]
        [ValidateSet('Negotiate', '0', 'Basic', '1')]
        [System.String]$AuthType,

        [Parameter(
            Mandatory = $false,
            Position = 8
        )]
        [System.Management.Automation.PSCredential]$Credential
    )

#Requires -Modules ActiveDirectory
#Requires -RunAsAdministrator

$ErrorActionPreference = "Stop"


# Check if $User value is a SAM account name, DN, GUID, or SID. This will allow us to select the correct -Filter query for Get-ADUser.
# Get-ADUser -Identity doesn't support the -SearchBase option so we use -Filter instead.

# Regex patterns to decide which -Filter syntax to use
$dnPattern = '^(?:(?<cn>CN=(?<name>[^,]*)),)?(?:(?<path>(?:(?:CN|OU)=[^,]+,?)+),)?(?<domain>(?:DC=[^,]+,?)+)$'
$guidPattern = '^[{]?[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}[}]?$'
$sidPattern = '^S-1-[0-59]-\d{2}-\d{8,10}-\d{8,10}-\d{8,10}-[1-9]\d{3}'

switch ($User) {
    # Distinguished Name
    {$_ -match $dnPattern} {
        $filterQuery = "DistinguishedName -eq '$User'"
        
        break
    }
    # GUID
    {$_ -match $guidPattern} {
        $filterQuery = "ObjectGUID -eq '$User'"

        break
    }
    # SID
    {$_ -match $sidPattern} {
        $filterQuery = "SID -eq '$User'"

        break
    }
    # SAM account name/all other input
    Default {
        $filterQuery = "Name -eq '$User'"

        break
    }
}

# Build param set for Get-ADUser from script params variables that were used when the script was run
$optParamVars = @{
    SearchBase = $SearchBase
    SearchScope = $SearchScope
    Server = $Server
    AuthType = $AuthType
    Credential = $Credential
}

$getADUserParams = @{
    Filter = $filterQuery
}

foreach ($param in $optParamVars.GetEnumerator()) {
    if (-not ([System.String]::IsNullOrWhiteSpace($param.Value))) {
        $getADUserParams.Add($param.Name, $param.Value)
    }
}


# Get user attributes
Write-Host "Getting attributes for user '$User'..." -ForegroundColor Cyan

try {
    $userAttributes = Get-ADUser @getADUserParams -Properties *

    if ($userAttributes) { # If the user isn't found using Get-ADUser -Filter, no errors will be thrown
        Write-Host "`tGot the attributes" -ForegroundColor Cyan
    } else {
        Write-Host "`Failed to get attributes because the user was not found" -ForegroundColor Red
        exit
    }
}
catch {
    Write-Host "Failed to get attributes. Reason: $($_.Exception.Message)" -ForegroundColor Red
    exit
}


# We reuse the param hash table for Get-ADUser so we can pass -Server, -AuthType, and -Credential to Set-ADUser, if applicable.
# We remove the following unneeded keys from the hash table because they aren't applicable to Set-ADUser.
$getADUserParams.Remove('Filter')
$getADUserParams.Remove('SearchBase')
$getADUserParams.Remove('SearchScope')
$setADUserParams = $getADUserParams

# Check if the user is a member of the specified group
Write-Host "Checking if they are a member of group '$Group'..." -ForegroundColor Cyan

try {
    if (((Get-ADGroup -Identity $Group).DistinguishedName) -eq $userAttributes.MemberOf) { # The group 'Domain Users' appears under the PrimaryGroup property, not MemberOf 
        Write-Host "`tThey are a member" -ForegroundColor Cyan
        
        Write-Host "Checking if attribute '$attribute' exists and is set to '$attributeValue'" -ForegroundColor Cyan
        
        if ($userAttributes.PSObject.Properties.Name -contains $attribute) {
            Write-Host "`tThe attribute exists" -ForegroundColor Cyan
            Write-Host "`tChecking if attribute value is set" -ForegroundColor Cyan
            
            if ($userAttributes.$attribute -eq $attributeValue) {
                Write-Host "`tThe value is already set to the value specified" -ForegroundColor Green
            } else {
                Write-Host "`tThe attribute is not set" -ForegroundColor Yellow
                Write-Host "`tSetting the attribute '$attribute' value to '$attributeValue'" -ForegroundColor Cyan

                # Add Set-ADUser params to param hash table for splatting
                $setADUserParams.Add('Identity', $User)
                $setADUserParams.Add($attribute, $attributeValue)

                try {
                    Set-ADUser @setADUserParams
            
                    Write-Host "`tSUCCESS. Value set" -ForegroundColor Green
                }
                catch {
                    Write-Host "`tFAIL. Value could not be set. Reason: $($_.Exception.Message)" -ForegroundColor Red
                    exit
                }
            }
        } else {
            Write-Host "`tThe attribute doesn't exist" -ForegroundColor Red
        }
    } else {
        Write-Host "`tThey are not a member. Attempting to clear the value for attribute '$attribute'" -ForegroundColor Yellow

        # Add Set-ADUser params to param hash table for splatting
        $setADUserParams.Add('Identity', $User)
        $setADUserParams.Add('Clear', $attribute)

        try {
            Set-ADUser @setADUserParams

            Write-Host "`tSUCCESS. Value cleared" -ForegroundColor Green
        }
        catch {
            Write-Host "`tFAIL. Value could not be cleared. Reason: $($_.Exception.Message)" -ForegroundColor Red
            exit
        }
    }
}
catch {
    Write-Host "`tThere was a problem checking group membership. Reason: $($_.Exception.Message)" -ForegroundColor Red
}
