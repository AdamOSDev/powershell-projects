function Write-Log {

    <#
    .SYNOPSIS
    Writes messages to a log file, the console, or both.

    .DESCRIPTION
    Writes messages to a log file, the console, or both with optional timestamp and log level information.

    This function operates in one of the three modes listed below:
    
    - WriteLog: Writes message to a log file only
    - WriteConsole: Writes message to the console only
    - WriteLogAndConsole: Writes message to a log file and the console

    The timestamp uses the following date and time format: yyyy-MM-dd HH:mm:ss.

    Log files are encoded in utf8.

    .PARAMETER WriteLog
    Writes message to a log file only

    .PARAMETER WriteConsole
    Writes message to the console only

    .PARAMETER WriteLogAndConsole
    Writes message to a log file and the console

    .PARAMETER LogPath
    Takes a full path to the log file (e.g., C:\Path\To\Log.log). If the path doesn't exist, it'll be automatically
    created.

    .PARAMETER LogLevel
    An optional log level can be specified with the 'LogLevel' parameter. Valid levels are:
    -INFORMATION
    -WARNING
    -ERROR

    .PARAMETER Message
    A message string can be passed to the function either by using the 'Message' parameter or by piping it
    in.

    .PARAMETER NoTimeStamp
    The timestamp is, by default, added to messages in all write modes but can be omitted by adding the
    'NoTimeStamp' parameter to the end of the argument list. This is useful for writing headers and footers to
    a log.

    .EXAMPLE
    Write-Log -WriteLog -LogPath "C:\Path\To\Log.log" -LogLevel INFORMATION -Message "This is an information message"

    .EXAMPLE
    Write-Log -WriteConsole -LogLevel WARNING -Message "This is a warning message"

    .EXAMPLE
    Write-Log -WriteLogAndConsole -LogPath "C:\Path\To\Log.log" -LogLevel ERROR -Message "This is an error message"

    .EXAMPLE
    "This is an information message" | Write-Log -WriteLog -LogPath "C:\Path\To\Log.log" -LogLevel INFORMATION

    .EXAMPLE
    Write-Log -WriteLog -LogPath "C:\Path\To\Log.log" -Message "----------[HEADER]----------" -NoTimeStamp

    .NOTES
    Version: 0.0.1
    #>

    [CmdletBinding(DefaultParameterSetName='WriteLog')]
    Param(
        [Parameter(
            Mandatory = $true,
            Position = 0,
            ParameterSetName = 'WriteLog'
        )]
        [switch]$WriteLog,

        [Parameter(
            Mandatory = $true,
            Position = 0,
            ParameterSetName = 'WriteConsole'
        )]
        [switch]$WriteConsole,

        [Parameter(
            Mandatory = $true,
            Position = 0,
            ParameterSetName = 'WriteLogAndConsole'
        )]
        [switch]$WriteLogAndConsole,


        [Parameter(
            Mandatory = $true,
            Position = 2,
            ParameterSetName = 'WriteLog'
        )]
        [Parameter(
            Mandatory = $true,
            Position = 2,
            ParameterSetName = 'WriteLogAndConsole'
        )]
        [System.String]$LogPath,


        [Parameter(
            Mandatory = $false,
            Position = 3,
            ParameterSetName = 'WriteLog'
        )]
        [Parameter(
            Mandatory = $false,
            Position = 3,
            ParameterSetName = 'WriteConsole'
        )]
        [Parameter(
            Mandatory = $false,
            Position = 3,
            ParameterSetName = 'WriteLogAndConsole'
        )]
        [ValidateSet('INFORMATION', 'WARNING', 'ERROR')]
        [System.String]$LogLevel,


        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [System.String]$Message,


        [switch]$NoTimeStamp
    )

    #Requires -Version 5.1
    #Requires -RunAsAdministrator


    Begin {
        $TimeStamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

        if ($LogLevel) {
            $LogLevel = $LogLevel.ToUpper()
        }
    }

    Process {
        function WriteLog {

            Param(
                $LogLevel,
                $LogPath,
                $Message,
                $NoTimeStamp,
                $TimeStamp
            )

            $LogFolder = Split-Path -Path $LogPath

            if (-not (Test-Path -Path $LogFolder -PathType Container)) {
                New-Item -Path $LogFolder -ItemType Directory -ErrorAction Stop | Out-Null
            }

            if ($NoTimeStamp) {
                if ($LogLevel) {
                    $LogOutput = "[{0}] {1}" -f $LogLevel, $Message
                } else {
                    $LogOutput = $Message
                }
            } else {
                if ($LogLevel) {
                    $LogOutput = "[{0}] [{1}] {2}" -f $TimeStamp, $LogLevel, $Message
                } else {
                    $LogOutput = "[{0}] {1}" -f $TimeStamp, $Message
                }
            }

            $LogOutput | Out-File -FilePath $LogPath -Encoding utf8 -Append -Force
        }

        function WriteConsole {

            Param(
                $LogLevel,
                $Message,
                $NoTimeStamp,
                $TimeStamp
            )

            if ($NoTimeStamp) {
                if ($LogLevel) {
                    $LogOutput = "[{0}] {1}" -f $LogLevel, $Message
                    
                    switch ($LogLevel) {
                        "INFORMATION" {
                            Write-Host $LogOutput -ForegroundColor Green
                            
                            break
                        }
                        "WARNING" {
                            Write-Host $LogOutput -ForegroundColor Yellow
                            
                            break
                        }
                        "ERROR" {
                            Write-Host $LogOutput -ForegroundColor Red
                           
                            break
                        }
                    }
                } else {
                    $LogOutput = $Message
                    
                    Write-Host $LogOutput
                }
            } else {
                if ($LogLevel) {
                    $LogOutput = "[{0}] [{1}] {2}" -f $TimeStamp, $LogLevel, $Message
                    switch ($LogLevel) {
                        "INFORMATION" {
                            Write-Host $LogOutput -ForegroundColor Green
                            
                            break
                        }
                        "WARNING" {
                            Write-Host $LogOutput -ForegroundColor Yellow
                            
                            break
                        }
                        "ERROR" {
                            Write-Host $LogOutput -ForegroundColor Red
                            
                            break
                        }
                    }
                } else {
                    $LogOutput = "[{0}] {1}" -f $TimeStamp, $Message
                    
                    Write-Host $LogOutput
                }
            }
        }

        $WriteLogArgs = @{
            LogLevel = $LogLevel
            LogPath = $LogPath
            Message = $Message
            NoTimeStamp = $NoTimeStamp
            TimeStamp = $TimeStamp
        }

        $WriteConsoleArgs = @{
            LogLevel = $LogLevel
            Message = $Message
            NoTimeStamp = $NoTimeStamp
            TimeStamp = $TimeStamp
        }

        if ($WriteLog) {
            WriteLog @WriteLogArgs
        }
        if ($WriteConsole) {
            WriteConsole @WriteConsoleArgs
        }
        if ($WriteLogAndConsole) {
            WriteLog @WriteLogArgs
            WriteConsole @WriteConsoleArgs
        }
    }
}