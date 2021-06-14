function New-Password {

    <#
    .SYNOPSIS
    Generates a random password.

    .DESCRIPTION
    Generates a random plain text password consisting of either alphanumeric characters and non-alphanumeric characters
    or only alphanumeric characters. To generate an encrypted password, pass the function to the ConvertTo-SecureString
    cmdlet (see example). The default password length is 20 characters. The minimum character length is 16 and the
    maximum is 2048.

    .PARAMETER Length
    Specifies the password length. The default password length is 20 characters. The minimum character length is 16 and
    the maximum is 2048.

    .PARAMETER NoSpecialChars
    Excludes non-alphanumeric (special) characters.

    .INPUTS
    None

    .OUTPUTS
    System.String

    .EXAMPLE
    New-Password

    .EXAMPLE
    New-Password -Length 32

    .EXAMPLE
    New-Password -NoSpecialChars

    .EXAMPLE
    $p = ConvertTo-SecureString -String (New-Password) -AsPlainText -Force

    #>

    [CmdletBinding()]
    param(
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
        [switch]$NoSpecialChars
    )

    begin {
    # ASCII chars in decimal notation

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
    }

    process {
        if (-not $NoSpecialChars) {
            $password = -join (($chars.Alphanumeric + $chars.NonAlphanumeric)*26 | Get-Random -Count $Length | ForEach-Object {[System.Char]$_})
        } else {
            $password = -join (($chars.Alphanumeric)*26 | Get-Random -Count $Length | ForEach-Object {[System.Char]$_})
        }
    }

    end {
        return $password
    }
}