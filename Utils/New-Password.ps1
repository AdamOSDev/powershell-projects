function New-Password {
    <#
    .SYNOPSIS
    Generates a random password.

    .DESCRIPTION
    Generates a random plaintext or SecureString password consisting of either alphanumeric characters and
    non-alphanumeric (special) characters or only alphanumeric characters. The length can be changed and special
    characters can be omitted. The password is always output directly to a SecureString object. It's a good idea to use
    the SecureString.Dispose method to securely dispose of SecureString objects stored in memory once they have been
    processed and are no longer needed (see example 4).

    .PARAMETER Length
    Specifies the password length. The default password length is 20 characters. The minimum character length is 16 and
    the maximum is 2048.

    .PARAMETER NoSpecialChars
    Excludes non-alphanumeric (special) characters.

    .PARAMETER AsSecureString
    Outputs the password as a SecureString object.

    .INPUTS
    None

    .OUTPUTS
    System.String
    System.SecureString

    .EXAMPLE
    New-Password

    .EXAMPLE
    New-Password -Length 32

    .EXAMPLE
    New-Password -NoSpecialChars

    .EXAMPLE
    $password = New-Password -AsSecureString
    $password.Dispose()

    .NOTES
    Requires PowerShell 7.0 or greater.
    
    #>

    [CmdletBinding()]
    Param(
        [Parameter(
            Position = 0,
            Mandatory = $false
        )]
        [ValidateRange(16, 2048)]
        [Int]$Length = 20,
        
        [Parameter(
            Position = 1,
            Mandatory = $false
        )]
        [switch]$NoSpecialChars,

        [Parameter(
            Position = 2,
            Mandatory = $false
        )]
        [switch]$AsSecureString
    )

    # The Requires statement doesn't work in all execution cases so we do it this way
    if ($PSVersionTable.PSVersion.Major -ge 7) {

        # Define ASCII character set in decimal format
        $chars = @{
            Alphanumeric = @(
                48..57
                65..90
                97..122
            )
            NonAlphanumeric = @(
                33
                35..38
                40..47
                60..64
                91..95
            )
        }

        # Generate secure password
        if (-not $NoSpecialChars) {
            $password = ConvertTo-SecureString -String (-join (($chars.Alphanumeric + $chars.NonAlphanumeric)*26 | Get-Random -Count $Length | ForEach-Object {[System.Char]$_})) -AsPlainText -Force
        } else {
            $password = ConvertTo-SecureString -String (-join (($chars.Alphanumeric)*26 | Get-Random -Count $Length | ForEach-Object {[System.Char]$_})) -AsPlainText -Force
        }

        # Output password as plaintext string or SecureString object
        if (-not $AsSecureString) {
            ConvertFrom-SecureString -SecureString $password -AsPlainText
            $password.Dispose()
        } else {
            return $password
        }
    } else {
        Write-Warning -Message "The function New-Password requires at least version 7.0 of PowerShell to run. You are running version $($PSVersionTable.PSVersion.ToString())."
    }
}