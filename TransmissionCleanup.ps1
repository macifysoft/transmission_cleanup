
<#
.SYNOPSIS
    Transmission Auto-Cleanup with Full Automation - Final Version
.DESCRIPTION
    - Self-installs to AppData\Transmission
    - Creates organized Start Menu shortcuts with relevant icons
    - Local credential storage in installation folder
    - Reliable file organization by type (Apps, Media, Music, Archives, Other)
    - Scheduled task configuration with weekly/daily options
    - Complete self-uninstallation with cleanup
    - Self-elevating when double-clicked
.NOTES
    Version: 10.2.0 (Adds dedicated Music folder for better organization)
#>

# Parameters must be declared before the self-execution wrapper
param (
    [switch]$Uninstall,
    [switch]$RunOnly,
    [switch]$Reinitialize,
    [ValidateRange(1,10)][int]$MaxRetries = 3,
    [ValidateRange(1,60)][int]$RetryDelay = 2,
    [switch]$WhatIf,
    [switch]$Verbose,
    [switch]$NoElevation
)


$ScriptVersion = "10.4.2"
# Create a debug log file in the installed Logs folder for troubleshooting self-elevation issues
function Write-DebugLog {
    param(
        [string]$Message
    )

    # Only write debug logs if $Verbose is specified
    if (-not $Verbose) { return }

    try {
        $logsDir = Join-Path -Path $env:APPDATA -ChildPath "Transmission\AutoCleanup\Logs"
        if (-not (Test-Path -LiteralPath $logsDir)) {
            New-Item -ItemType Directory -Path $logsDir -Force | Out-Null
        }
        $debugLogFile = Join-Path -Path $logsDir -ChildPath "TransmissionCleanupDebug.log"

        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $logEntry = "[$timestamp] $Message"

        Add-Content -Path $debugLogFile -Value $logEntry -ErrorAction Stop
    }
    catch {
        # Silent failure - we don't want to cause more errors while logging
    }
}

# Basic Wait-ForKeyPress function (full version defined later)
function Wait-ForKeyPress {
    param(
        [string]$Message = "Press any key to continue..."
    )
    
    Write-Host "`n$Message" -ForegroundColor Yellow
    try {
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    }
    catch {
        # If ReadKey fails, use a simple timeout
        Start-Sleep -Seconds 5
    }
}

# Check if running from ISE or other problematic contexts and show a message
$isISE = $Host.Name -eq "Windows PowerShell ISE Host"
$isConsole = $Host.Name -eq "ConsoleHost"
$hasScriptPath = -not [string]::IsNullOrEmpty($MyInvocation.MyCommand.Path)
# Detect different execution methods
$isRightClickExecution = ($Host.Name -eq "ConsoleHost") -and ([string]::IsNullOrEmpty($MyInvocation.InvocationName))
$isOpenWithPowerShell = ($Host.Name -eq "ConsoleHost") -and ($MyInvocation.Line -like "*powershell*" -or $env:PSExecutionContext -like "*powershell*")

if ($isISE) {
    Write-Host "WARNING: PowerShell ISE detected. This script is not fully supported in ISE." -ForegroundColor Red
    Write-Host "SOLUTION: Right-click the script file and select 'Run with PowerShell'" -ForegroundColor Green
    Write-Host "Or run from a regular PowerShell prompt." -ForegroundColor Green
    Write-Host ""
}
elseif ($isRightClickExecution -or $isOpenWithPowerShell) {
    if ($isRightClickExecution) {
        Write-Host "Detected right-click 'Run with PowerShell' execution." -ForegroundColor Green
    } else {
        Write-Host "Detected 'Open with > Windows PowerShell' execution." -ForegroundColor Green
    }
    Write-Host "This is the recommended way to run the script." -ForegroundColor Green
    Write-Host ""
}
elseif ($isConsole -and -not $hasScriptPath) {
    Write-Host "NOTICE: Script appears to be copy-pasted or running in an unusual context." -ForegroundColor Yellow
    Write-Host "For best results, save as .ps1 file and right-click 'Run with PowerShell'" -ForegroundColor Yellow
    Write-Host ""
}

# Add error handling for common execution problems
$errorLogsDir = Join-Path -Path $env:APPDATA -ChildPath "Transmission\AutoCleanup\Logs"
$errorLogPath = Join-Path -Path $errorLogsDir -ChildPath "TransmissionCleanup_Error.log"

function Write-ErrorToFile {
    param([string]$Message)
    try {
        if (-not (Test-Path -LiteralPath $errorLogsDir)) {
            New-Item -ItemType Directory -Path $errorLogsDir -Force | Out-Null
        }
        Add-Content -Path $errorLogPath -Value "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] $Message" -ErrorAction SilentlyContinue
    } catch {}
}

try {
    Write-ErrorToFile "Script execution started - Host: $($Host.Name)"
    Write-ErrorToFile "Invocation: $($MyInvocation.InvocationName)"
    Write-ErrorToFile "Script Path: $($MyInvocation.MyCommand.Path)"
    
    # Test if we can access basic PowerShell features
    $testPath = $env:TEMP
    if ([string]::IsNullOrEmpty($testPath)) {
        throw "Cannot access environment variables"
    }
    
    Write-ErrorToFile "Basic PowerShell test passed"
}
catch {
    $errorMsg = "PowerShell execution environment issue: $($_.Exception.Message)"
    Write-ErrorToFile "ERROR: $errorMsg"
    
    Write-Host "ERROR: PowerShell execution environment issue detected." -ForegroundColor Red
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host ""
    Write-Host "This usually happens when:" -ForegroundColor Yellow
    Write-Host "1. Running from PowerShell ISE (not supported)" -ForegroundColor Yellow
    Write-Host "2. Execution policy is too restrictive" -ForegroundColor Yellow
    Write-Host "3. Running in a restricted context" -ForegroundColor Yellow
    Write-Host "4. 'Open with PowerShell' execution issue" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "SOLUTIONS:" -ForegroundColor Green
    Write-Host "1. Right-click the script → 'Run with PowerShell'" -ForegroundColor Green
    Write-Host "2. Run from elevated PowerShell: powershell.exe -ExecutionPolicy Bypass -File 'script.ps1'" -ForegroundColor Green
    Write-Host "3. Check error log: $errorLogPath" -ForegroundColor Green
    Write-Host ""
    
    # Force window to stay open
    Write-Host "Press any key to exit..." -ForegroundColor Red
    try {
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    } catch {
        Start-Sleep -Seconds 15
    }
    exit 1
}

# Self-execution wrapper for double-click elevation
if (-not $NoElevation -and -not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-DebugLog "Script started without admin privileges, attempting elevation"
    Write-DebugLog "Execution Policy: $(Get-ExecutionPolicy)"
    Write-DebugLog "PowerShell Version: $($PSVersionTable.PSVersion)"
    Write-DebugLog "Current Location: $(Get-Location)"
    Write-DebugLog "Host Name: $($Host.Name)"
    Write-DebugLog "Invocation Name: $($MyInvocation.InvocationName)"
    Write-DebugLog "Invocation Line: $($MyInvocation.Line)"
    Write-DebugLog "Is Right-Click: $isRightClickExecution"
    Write-DebugLog "Is Open With: $isOpenWithPowerShell"
    
    try {
        # Get the script path
        $scriptPath = $MyInvocation.MyCommand.Path
        Write-DebugLog "MyInvocation.MyCommand.Path: $scriptPath"
        
        if ([string]::IsNullOrEmpty($scriptPath)) {
            $scriptPath = $PSCommandPath
            Write-DebugLog "PSCommandPath: $scriptPath"
        }
        
        if (-not [string]::IsNullOrEmpty($scriptPath)) {
            # Re-launch the script with elevated privileges
            Write-DebugLog "Attempting to relaunch with admin privileges: $scriptPath"
            
            # Build arguments preserving any original parameters
            $argumentList = @()
            $argumentList += "-NoProfile"
            $argumentList += "-ExecutionPolicy", "Bypass"
            # Enforce STA to ensure WinForms dialogs (FolderBrowserDialog) work in all launch contexts (including Open With)
            $argumentList += "-STA"
            
            # Preserve original parameters except NoElevation
            $scriptArgs = @()
            if ($Uninstall) { $scriptArgs += "-Uninstall" }
            if ($RunOnly) { $scriptArgs += "-RunOnly" }
            if ($Reinitialize) { $scriptArgs += "-Reinitialize" }
            if ($WhatIf) { $scriptArgs += "-WhatIf" }
            if ($Verbose) { $scriptArgs += "-Verbose" }
            if ($MaxRetries -ne 3) { $scriptArgs += "-MaxRetries $MaxRetries" }
            if ($RetryDelay -ne 2) { $scriptArgs += "-RetryDelay $RetryDelay" }
            
            # Create the command to run in elevated mode
            $scriptArgsString = $scriptArgs -join " "
            if ($Verbose -or $WhatIf) {
                # Keep window open for verbose/whatif mode so user can see output
                $argumentList += "-Command", "& {& '$scriptPath' $scriptArgsString; Write-Host 'Press any key to exit...' -ForegroundColor Yellow; Read-Host}"
            } else {
                # Always keep window open for GUI-launched execution to see results
                if ($isRightClickExecution -or $isOpenWithPowerShell) {
                    $argumentList += "-Command", "& {try { & '$scriptPath' $scriptArgsString } catch { Write-Host 'Error: ' + `$_.Exception.Message -ForegroundColor Red }; Write-Host ''; Write-Host 'Execution completed. Press any key to close...' -ForegroundColor Yellow; `$null = `$Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown') }"
                } else {
                    # Normal command-line execution
                    $argumentList += "-File", "`"$scriptPath`""
                    if ($scriptArgsString) { $argumentList += $scriptArgsString.Split(' ') }
                }
            }
            
            $arguments = $argumentList -join " "
            Write-DebugLog "Launch arguments: $arguments"
            
            try {
                # Use Start-Process with -Wait to ensure proper elevation
                $processStartInfo = New-Object System.Diagnostics.ProcessStartInfo
                $processStartInfo.FileName = "powershell.exe"
                $processStartInfo.Arguments = $arguments
                $processStartInfo.Verb = "RunAs"
                $processStartInfo.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Normal
                $processStartInfo.UseShellExecute = $true
                $processStartInfo.WorkingDirectory = Split-Path -Path $scriptPath -Parent
                
                $process = [System.Diagnostics.Process]::Start($processStartInfo)
                if ($process) {
                    Write-DebugLog "Elevated process started with PID: $($process.Id)"
                    Write-DebugLog "Relaunch successful, exiting current instance"
                } else {
                    Write-DebugLog "Failed to start elevated process - Start() returned null"
                    throw "Process.Start() returned null"
                }
            }
            catch {
                $errorMsg = "Failed to start elevated process: $($_.Exception.Message)"
                Write-DebugLog $errorMsg
                Write-DebugLog "Error details: $($_.Exception.GetType().FullName)"
                Write-DebugLog "HRESULT: $($_.Exception.HResult)"
                
                # Show error to user
                Write-Host $errorMsg -ForegroundColor Red
                if ($_.Exception.HResult -eq -2147467259) {
                    Write-Host "This usually means the UAC prompt was cancelled or failed." -ForegroundColor Yellow
                    Write-Host "Please try running PowerShell as Administrator and then run the script." -ForegroundColor Yellow
                }
                Write-Host "Press any key to exit..."
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            }
        }
        else {
            $errorMsg = "Could not determine script path for elevation. Please run as administrator."
            Write-DebugLog $errorMsg
            Write-Host $errorMsg -ForegroundColor Red
            Write-Host "Press any key to exit..."
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        }
    }
    catch {
        $errorMsg = "Failed to elevate script: $($_.Exception.Message)"
        Write-DebugLog $errorMsg
        Write-Host $errorMsg -ForegroundColor Red
        Write-Host "Press any key to exit..."
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    }
    
    # Exit the current non-elevated instance without pausing
    Write-DebugLog "Exiting non-elevated instance"
    exit
}
Write-DebugLog "Script running with admin privileges"

#Requires -Version 5.1


# Early helper functions used during config bootstrap


#region CONFIGURATION
function Get-ScriptPath {
    $scriptPath = $null

    if ($null -ne $MyInvocation.MyCommand.Path -and $MyInvocation.MyCommand.Path -ne "") {
        $scriptPath = $MyInvocation.MyCommand.Path
        Write-DebugLog "Script path found using MyInvocation.MyCommand.Path: $scriptPath"
    }
    elseif ($null -ne $PSCommandPath -and $PSCommandPath -ne "") {
        $scriptPath = $PSCommandPath
        Write-DebugLog "Script path found using PSCommandPath: $scriptPath"
    }
    elseif ($null -ne $script:PSCommandPath -and $script:PSCommandPath -ne "") {
        $scriptPath = $script:PSCommandPath
        Write-DebugLog "Script path found using script:PSCommandPath: $scriptPath"
    }
    else {
        $scriptName = Split-Path -Leaf $MyInvocation.MyCommand.Path
        if ([string]::IsNullOrWhiteSpace($scriptName)) { $scriptName = "TransmissionCleanup.ps1" }
        $possiblePath = Join-Path -Path (Get-Location).Path -ChildPath $scriptName
        if (Test-Path $possiblePath) {
            $scriptPath = $possiblePath
            Write-DebugLog "Script path found using current location and script name: $scriptPath"
        }
        else {
            Write-DebugLog "Could not determine script path automatically"
            $scriptPath = $null
        }
    }

    return $scriptPath
}

function Normalize-TransmissionRpcUrl {
    param(
        [string]$Url,
        [string]$DefaultUrl = "http://localhost:9091/transmission/rpc"
    )

    if ([string]::IsNullOrWhiteSpace($Url)) {
        return (Normalize-TransmissionRpcUrl -Url $DefaultUrl)
    }

    $normalized = $Url.Trim()

    if ($normalized -match '/transmission/web/?$') {
        $normalized = $normalized -replace '/transmission/web/?$', '/transmission/rpc'
    }
    elseif ($normalized -match '/transmission/rpc/?$') {
        $normalized = $normalized -replace '/+$', ''
    }
    elseif ($normalized -match '^https?://[^/]+/?$') {
        $normalized = $normalized.TrimEnd('/') + '/transmission/rpc'
    }
    elseif ($normalized -match '^https?://.*/transmission/?$') {
        $normalized = $normalized.TrimEnd('/') + '/rpc'
    }

    return $normalized
}

#-- Log rotation: rotate by size and keep several archives --
function Rotate-Log {
    param(
        [Parameter(Mandatory=$true)]
        [string]$LogFile,
        [long]$MaxSizeBytes = 2MB,
        [int]$MaxArchives = 5
    )

    if ([string]::IsNullOrWhiteSpace($LogFile) -or -not (Test-Path -LiteralPath $LogFile)) {
        return
    }

    $size = (Get-Item -LiteralPath $LogFile).Length
    if ($size -lt $MaxSizeBytes) {
        return
    }

    for ($i = $MaxArchives - 1; $i -ge 1; $i--) {
        $source = "$LogFile.$i"
        $dest = "$LogFile." + ($i + 1)
        if (Test-Path -LiteralPath $source) {
            Move-Item -LiteralPath $source -Destination $dest -Force
        }
    }

    Move-Item -LiteralPath $LogFile -Destination "$LogFile.1" -Force
}

$script:InstallDir     = Join-Path -Path $env:APPDATA -ChildPath "Transmission\AutoCleanup"
$script:LogsDir        = Join-Path -Path $script:InstallDir -ChildPath "Logs"
$script:ScriptPath     = Join-Path -Path $script:InstallDir -ChildPath "TransmissionCleanup.ps1"
$script:CredentialFile = Join-Path -Path $script:InstallDir -ChildPath "TransmissionCredentials.xml"
$script:ConfigFile     = Join-Path -Path $script:InstallDir -ChildPath "TransmissionConfig.xml"
$script:HelpFile       = Join-Path -Path $script:InstallDir -ChildPath "TransmissionCleanupHelp.txt"
$startMenu             = [Environment]::GetFolderPath("Programs")
$script:shortcutFolder = Join-Path -Path $startMenu -ChildPath "Transmission Cleanup"

$script:config = @{
    RpcUrl                = "http://localhost:9091/transmission/rpc"
    DownloadFolder        = Join-Path -Path $env:USERPROFILE -ChildPath "Downloads\Torrents"
    AppsFolder            = Join-Path -Path $env:USERPROFILE -ChildPath "Downloads\Torrents\Apps"
    VideosFolder          = Join-Path -Path $env:USERPROFILE -ChildPath "Downloads\Torrents\Videos"
    MusicFolder           = Join-Path -Path $env:USERPROFILE -ChildPath "Downloads\Torrents\Music"
    ArchiveFolder         = Join-Path -Path $env:USERPROFILE -ChildPath "Downloads\Torrents\Archives"
    OtherFolder           = Join-Path -Path $env:USERPROFILE -ChildPath "Downloads\Torrents\Other"
    LogFile               = Join-Path -Path $script:LogsDir -ChildPath "TransmissionCleanup.log"
    ScheduleTime          = "03:00"
    ScheduleDays          = @()
    ScheduleType          = "Daily"
    AppExtensions         = @(".exe", ".msi", ".dmg", ".pkg", ".app", ".apk", ".iso", ".bat", ".cmd", ".reg", ".dll", ".bin", ".cue", ".mds", ".mdf", ".ccd", ".sub", ".img", ".nrg", ".isz", ".daa", ".dat", ".cab", ".xml", ".jpg", ".jpeg")
    MediaExtensions       = @(".mp4", ".mkv", ".avi", ".mov", ".wmv", ".ts", ".m2ts", ".srt", ".sub", ".idx", ".ass", ".ssa", ".vtt", ".jpg", ".jpeg", ".png", ".gif", ".webp", ".xml")
    MusicExtensions       = @(".mp3", ".flac", ".wav", ".aac", ".ogg", ".m4a", ".wma")
    ArchiveExtensions     = @(".zip", ".rar", ".7z", ".tar", ".gz", ".bz2")
    MaxRpcRetries         = 3
    RpcRetryDelay         = 5
    CompletionCriteria    = "PercentDone"
    DeleteOriginalFolders = $true
    SceneReleaseMode      = $true
}

function Write-Log {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        [ValidateSet("INFO", "WARN", "ERROR", "DEBUG")]
        [string]$Level = "INFO",
        [string]$LogFile = $null,
        [switch]$NoConsole
    )
    try {
        if ([string]::IsNullOrEmpty($LogFile)) {
            $LogFile = $script:config.LogFile
            if ($Uninstall) {
                $LogFile = Join-Path -Path $script:LogsDir -ChildPath "TransmissionCleanupUninstall.log"
            }
        }

        if ([string]::IsNullOrWhiteSpace($LogFile)) {
            $LogFile = Join-Path -Path $script:LogsDir -ChildPath "TransmissionCleanup.log"
        }

        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $logEntry = "[$timestamp][$Level] $Message"

        $logDir = Split-Path -Path $LogFile -Parent
        if (-not [string]::IsNullOrWhiteSpace($logDir) -and -not (Test-Path $logDir)) {
            New-Item -ItemType Directory -Path $logDir -Force | Out-Null
        }

        Rotate-Log -LogFile $LogFile
        Add-Content -Path $LogFile -Value $logEntry -ErrorAction Stop

        if ((-not $NoConsole) -and ($Verbose -or $Level -ne "DEBUG")) {
            switch ($Level) {
                "ERROR" { Write-Host $logEntry -ForegroundColor Red }
                "WARN"  { Write-Host $logEntry -ForegroundColor Yellow }
                "INFO"  { Write-Host $logEntry -ForegroundColor Gray }
                "DEBUG" { if ($Verbose) { Write-Host $logEntry -ForegroundColor Magenta } }
            }
        }
    }
    catch {
        Write-Host "Failed to write to log: $($_.Exception.Message)" -ForegroundColor Red
    }
}

if (Test-Path $script:ConfigFile) {
    try {
        $script:config = Import-Clixml -Path $script:ConfigFile

        if (-not $script:config.LogFile) {
            $script:config.LogFile = Join-Path -Path $script:LogsDir -ChildPath "TransmissionCleanup.log"
        }
        if (-not $script:config.DownloadFolder) {
            $script:config.DownloadFolder = Join-Path -Path $env:USERPROFILE -ChildPath "Downloads\Torrents"
        }

        $baseFolder = $script:config.DownloadFolder
        $script:config.AppsFolder    = Join-Path -Path $baseFolder -ChildPath "Apps"
        $script:config.VideosFolder  = Join-Path -Path $baseFolder -ChildPath "Videos"
        $script:config.MusicFolder   = Join-Path -Path $baseFolder -ChildPath "Music"
        $script:config.ArchiveFolder = Join-Path -Path $baseFolder -ChildPath "Archives"
        $script:config.OtherFolder   = Join-Path -Path $baseFolder -ChildPath "Other"

        if ([string]::IsNullOrWhiteSpace($script:config.RpcUrl)) {
            $script:config.RpcUrl = "http://localhost:9091/transmission/rpc"
        }
        $script:config.RpcUrl = Normalize-TransmissionRpcUrl -Url $script:config.RpcUrl

        if (-not $script:config.AppExtensions -or $script:config.AppExtensions.Count -eq 0) {
            $script:config.AppExtensions = @(".exe", ".msi", ".dmg", ".pkg", ".app", ".apk", ".iso", ".bat", ".cmd", ".reg", ".dll", ".bin", ".cue", ".mds", ".mdf", ".ccd", ".sub", ".img", ".nrg", ".isz", ".daa", ".dat", ".cab", ".xml", ".jpg", ".jpeg")
        }
        if (-not $script:config.MediaExtensions -or $script:config.MediaExtensions.Count -eq 0) {
            $script:config.MediaExtensions = @(".mp4", ".mkv", ".avi", ".mov", ".wmv", ".ts", ".m2ts", ".srt", ".sub", ".idx", ".ass", ".ssa", ".vtt", ".jpg", ".jpeg", ".png", ".gif", ".webp", ".xml")
        }
        if (-not $script:config.MusicExtensions -or $script:config.MusicExtensions.Count -eq 0) {
            $script:config.MusicExtensions = @(".mp3", ".flac", ".wav", ".aac", ".ogg", ".m4a", ".wma")
        }
        if (-not $script:config.ArchiveExtensions -or $script:config.ArchiveExtensions.Count -eq 0) {
            $script:config.ArchiveExtensions = @(".zip", ".rar", ".7z", ".tar", ".gz", ".bz2")
        }
        if ($null -eq $script:config.DeleteOriginalFolders) {
            $script:config.DeleteOriginalFolders = $true
        }
        if ($null -eq $script:config.SceneReleaseMode) {
            $script:config.SceneReleaseMode = $true
        }
    }
    catch {
        Write-Warning "Could not load config file. Using defaults."
        Write-Log "Config load error: $($_.Exception.Message)" -Level WARN
    }
}
#endregion

#-- Add basic log rotation: limit log file to 2MB --
function Test-Admin {
    try {
        $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
        return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        Write-Log "Failed to check admin status: $($_.Exception.Message)" -Level ERROR
        return $false
    }
}

#-- Renamed to conform to PowerShell verb-noun naming convention --
function ConvertTo-SafePath {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Name
    )
    # Get invalid chars, escape them, build regex
    $invalidChars = [IO.Path]::GetInvalidFileNameChars() + [IO.Path]::GetInvalidPathChars() | Select-Object -Unique
    $pattern = ([RegEx]::Escape(($invalidChars -join "")))
    return ($Name -replace "[$pattern]", "_" -replace "\s+$", "")
}

function New-Shortcut {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Path,
        [Parameter(Mandatory=$true)]
        [string]$TargetPath,
        [Parameter(Mandatory=$true)]
        [string]$Arguments,
        [Parameter(Mandatory=$true)]
        [string]$Description,
        [string]$IconLocation = "",
        [ValidateSet("Normal", "Minimized", "Maximized")]
        [string]$WindowStyle = "Normal",
        [bool]$RunAsAdmin = $false
    )
    try {
        # Validate path parameters
        if ([string]::IsNullOrEmpty($Path)) {
            Write-Log "Shortcut Path is null or empty" -Level ERROR
            return $false
        }
        if ([string]::IsNullOrEmpty($TargetPath)) {
            Write-Log "Shortcut TargetPath is null or empty" -Level ERROR
            return $false
        }
        
        # Ensure parent directory exists
        $parentDir = Split-Path -Path $Path -Parent
        if (-not (Test-Path $parentDir)) {
            New-Item -ItemType Directory -Path $parentDir -Force | Out-Null
        }
        
        $WshShell = New-Object -ComObject WScript.Shell
        $Shortcut = $WshShell.CreateShortcut($Path)
        $Shortcut.TargetPath = $TargetPath
        $Shortcut.Arguments = $Arguments
        
        # Validate ScriptPath before using it
        if (-not [string]::IsNullOrEmpty($ScriptPath)) {
            $Shortcut.WorkingDirectory = Split-Path $ScriptPath -Parent
        } else {
            Write-Log "ScriptPath is null or empty, using current directory" -Level WARN
            $Shortcut.WorkingDirectory = (Get-Location).Path
        }
        
        $Shortcut.Description = $Description
        if ($IconLocation) { $Shortcut.IconLocation = $IconLocation }
        # Set window style
        switch ($WindowStyle) {
            "Minimized" { $Shortcut.WindowStyle = 7 }
            "Maximized" { $Shortcut.WindowStyle = 3 }
            default     { $Shortcut.WindowStyle = 1 }
        }
        $Shortcut.Save()
        
        # Set the "Run as Administrator" flag if requested
        if ($RunAsAdmin) {
            # Read the .lnk file as a byte array
            $bytes = [System.IO.File]::ReadAllBytes($Path)
            
            # Set the 21st byte (0-based index 20) to 34 to set the "Run as Administrator" flag
            $bytes[21] = $bytes[21] -bor 0x20
            
            # Write the modified byte array back to the .lnk file
            [System.IO.File]::WriteAllBytes($Path, $bytes)
            
            Write-Log "Set 'Run as Administrator' flag for shortcut: $Path" -Level INFO -NoConsole
        }
        
        Write-Log "Created shortcut: $Path" -Level INFO -NoConsole
        return $true
    }
    catch {
        Write-Log "Failed to create shortcut $Path : $($_.Exception.Message)" -Level ERROR
        return $false
    }
    finally {
        if ($null -ne $WshShell) { 
            [System.Runtime.Interopservices.Marshal]::ReleaseComObject($WshShell) | Out-Null 
        }
    }
}

function Get-FolderSelection {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Prompt, 
        [string]$DefaultPath,
        [switch]$AllowCancel
    )
    try {
        Add-Type -AssemblyName System.Windows.Forms
        $dialog = New-Object System.Windows.Forms.FolderBrowserDialog
        $dialog.Description = $Prompt
        $dialog.SelectedPath = if (Test-Path $DefaultPath) { $DefaultPath } else { [Environment]::GetFolderPath("MyDocuments") }
        $dialog.ShowNewFolderButton = $true
        
        $result = $dialog.ShowDialog()
        if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
            return @{ Path = $dialog.SelectedPath; Cancelled = $false }
        } else {
            if ($AllowCancel) {
                return @{ Path = $null; Cancelled = $true }
            } else {
                return @{ Path = $DefaultPath; Cancelled = $false }
            }
        }
    }
    catch {
        Write-Log "Folder selection failed: $($_.Exception.Message)" -Level WARN
        if ($AllowCancel) {
            return @{ Path = $null; Cancelled = $true }
        } else {
            return @{ Path = $DefaultPath; Cancelled = $false }
        }
    }
}

function Get-TimeInput {
    do {
        $time = Read-Host "Enter run time (HH:MM, 24-hour format)"
        if ([string]::IsNullOrWhiteSpace($time)) {
            Write-Host "Invalid empty input" -ForegroundColor Yellow
            continue
        }
        if ($time -match "^([01]?[0-9]|2[0-3]):([0-5][0-9])$") {
            return $time
        }
        Write-Host "Invalid format. Please use HH:MM (24-hour)" -ForegroundColor Yellow
    } while ($true)
}

function Get-RpcUrlInput {
    param(
        [string]$DefaultUrl = "http://localhost:9091/transmission/rpc"
    )
    
    Write-Host "`nCurrent RPC URL: $DefaultUrl" -ForegroundColor Cyan
    
    $choices = @(
        (New-Object System.Management.Automation.Host.ChoiceDescription -ArgumentList '&Change', 'Change the RPC URL'),
        (New-Object System.Management.Automation.Host.ChoiceDescription -ArgumentList '&Keep', 'Keep the current RPC URL')
    )
    
    $result = $host.UI.PromptForChoice("Transmission RPC URL", "Would you like to change the Transmission RPC URL?", $choices, 1)
    
    if ($result -eq 0) {
        do {
            $newUrl = Read-Host "Enter Transmission URL (web or rpc, e.g., http://localhost:9091/transmission/web/ or http://localhost:9091/transmission/rpc)"
            
            if ([string]::IsNullOrWhiteSpace($newUrl)) {
                Write-Host "Using default URL: $DefaultUrl" -ForegroundColor Yellow
                return (Normalize-TransmissionRpcUrl -Url $DefaultUrl)
            }
            
            $normalizedUrl = Normalize-TransmissionRpcUrl -Url $newUrl
            
            # Basic URL validation
            if ($normalizedUrl -match "^https?://.+/transmission/rpc/?$") {
                Write-Host "Using normalized RPC URL: $normalizedUrl" -ForegroundColor Green
                return $normalizedUrl
            }
            
            Write-Host "Invalid URL format. Please enter a valid Transmission web or RPC URL." -ForegroundColor Red
        } while ($true)
    }
    
    return (Normalize-TransmissionRpcUrl -Url $DefaultUrl)
}

function Get-DeleteOriginalFolderPreference {
    $choices = @(
        (New-Object System.Management.Automation.Host.ChoiceDescription -ArgumentList '&Yes', 'Delete original folders after files are moved'),
        (New-Object System.Management.Automation.Host.ChoiceDescription -ArgumentList '&No', 'Keep original folders after files are moved')
    )
    
    $result = $host.UI.PromptForChoice("Delete Original Folders", "Should the script delete original folders after files are moved?", $choices, 0)
    
    return ($result -eq 0)
}

#-- GUI/CLI hybrid for weekly schedule with improved error handling --
function Get-ScheduleType {
    # Try Out-GridView, else use text selection
    $choices = @(
        (New-Object System.Management.Automation.Host.ChoiceDescription -ArgumentList '&Daily', 'Run the task every day'),
        (New-Object System.Management.Automation.Host.ChoiceDescription -ArgumentList '&Weekly', 'Run the task on specific days each week')
    )
    $result = $host.UI.PromptForChoice("Schedule Type", "How often should the cleanup run?", $choices, 0)
    if ($result -eq 1) {
        $daysOfWeek = @("Monday","Tuesday","Wednesday","Thursday","Friday","Saturday","Sunday")
        try {
            if (Get-Command Out-GridView -ErrorAction SilentlyContinue) {
                $days = $daysOfWeek | Out-GridView -Title "Select days to run (Ctrl+Click to select multiple)" -PassThru
                if ($null -eq $days -or $days.Count -eq 0) {
                    Write-Host "No days selected, defaulting to Monday." -ForegroundColor Yellow
                    $days = @("Monday")
                }
            } else {
                Write-Host "`nOut-GridView not available. Please enter the days as comma-separated list."
                Write-Host "Available days: Monday, Tuesday, Wednesday, Thursday, Friday, Saturday, Sunday"
                $input = Read-Host "Days to run (e.g., Monday,Wednesday,Friday)"
                $days = $input -split "," | ForEach-Object { $_.Trim() } | Where-Object { $daysOfWeek -contains $_ }
                if ($null -eq $days -or $days.Count -eq 0) {
                    Write-Host "No valid days entered, defaulting to Monday." -ForegroundColor Yellow
                    $days = @("Monday")
                }
            }
            return @{
                Type = "Weekly"
                Days = $days
            }
        }
        catch {
            Write-Log "Error in schedule selection: $($_.Exception.Message)" -Level WARN
            Write-Host "Error in schedule selection, defaulting to daily." -ForegroundColor Yellow
            return @{
                Type = "Daily"
                Days = @()
            }
        }
    } else {
        return @{
            Type = "Daily"
            Days = @()
        }
    }
}

function Wait-ForKeyPress {
    param(
        [string]$Message = "Press any key to continue..."
    )
    
    Write-Host "`n$Message" -ForegroundColor Yellow
    try {
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    }
    catch {
        # If ReadKey fails, use a simple timeout
        Start-Sleep -Seconds 5
    }
}

function Get-TransmissionCredential {
    $cred = $null
    
    # Try to load existing credentials
    if (Test-Path $CredentialFile) {
        try {
            $cred = Import-Clixml -Path $CredentialFile
            Write-Log "Credentials loaded successfully" -Level INFO
            return $cred
        }
        catch {
            Write-Log "Failed to load credentials: $($_.Exception.Message)" -Level WARN
        }
    }
    
    # If no credentials or failed to load, prompt for new ones
    Write-Host "`n=== TRANSMISSION CREDENTIALS ===" -ForegroundColor Cyan
    Write-Host "Please enter your Transmission RPC credentials."
    
    # Prompt for RPC URL
    $script:config.RpcUrl = Get-RpcUrlInput -DefaultUrl $script:config.RpcUrl
    Write-Host "Using RPC URL: $($script:config.RpcUrl)" -ForegroundColor Green
    
    # Save updated config with new RPC URL
    try {
        $script:config | Export-Clixml -Path $ConfigFile
    }
    catch {
        Write-Log "Failed to save updated RPC URL: $($_.Exception.Message)" -Level WARN
    }
    
    $username = Read-Host "Username (leave blank for none)"
    if ([string]::IsNullOrWhiteSpace($username)) { $username = "" }
    
    $securePassword = Read-Host "Password (leave blank for none)" -AsSecureString
    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword)
    $password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    
    if ([string]::IsNullOrWhiteSpace($password)) { $password = "" }
    
    $cred = New-Object PSObject -Property @{
        Username = $username
        Password = $password
    }
    
    # Save credentials
    try {
        # Ensure directory exists
        $credDir = Split-Path $CredentialFile -Parent
        if (-not (Test-Path $credDir)) {
            New-Item -ItemType Directory -Path $credDir -Force | Out-Null
        }
        
        $cred | Export-Clixml -Path $CredentialFile
        Write-Host "Credentials saved securely to local file!" -ForegroundColor Green
    }
    catch {
        Write-Log "Failed to save credentials: $($_.Exception.Message)" -Level ERROR
        Write-Host "Failed to save credentials: $($_.Exception.Message)" -ForegroundColor Red
    }

    Prompt-TransmissionConnectionTest -Credential $cred -RpcUrl $script:config.RpcUrl | Out-Null
    
    return $cred
}

function Test-TransmissionConnection {
    param(
        [Parameter(Mandatory=$false)]
        $Credential = $null,

        [Parameter(Mandatory=$false)]
        [string]$RpcUrl = $null
    )

    try {
        if ([string]::IsNullOrWhiteSpace($RpcUrl)) {
            $RpcUrl = $script:config.RpcUrl
        }

        $RpcUrl = Normalize-TransmissionRpcUrl -Url $RpcUrl
        Write-Host "`nTesting Transmission connection..." -ForegroundColor Cyan
        Write-Host "RPC URL: $RpcUrl" -ForegroundColor DarkCyan

        if ($null -eq $Credential -and (Test-Path $CredentialFile)) {
            try {
                $Credential = Import-Clixml -Path $CredentialFile
            }
            catch {
                Write-Log "Failed to load stored credentials for connection test: $($_.Exception.Message)" -Level WARN
            }
        }

        $arguments = @{ fields = @('id') }
        $null = Invoke-TransmissionRPC -Method "torrent-get" -Arguments $arguments -Credential $Credential -ErrorAction Stop

        Write-Host "✓ Connection to Transmission succeeded." -ForegroundColor Green
        Write-Log "Transmission connection test succeeded for URL: $RpcUrl" -Level INFO
        return $true
    }
    catch {
        $message = $_.Exception.Message
        Write-Host "✗ Connection test failed: $message" -ForegroundColor Red
        Write-Log "Transmission connection test failed: $message" -Level ERROR
        return $false
    }
}

function Prompt-TransmissionConnectionTest {
    param(
        [Parameter(Mandatory=$false)]
        $Credential = $null,

        [Parameter(Mandatory=$false)]
        [string]$RpcUrl = $null
    )

    $choices = @(
        (New-Object System.Management.Automation.Host.ChoiceDescription -ArgumentList '&Test Now', 'Test the Transmission connection now'),
        (New-Object System.Management.Automation.Host.ChoiceDescription -ArgumentList '&Skip', 'Skip the connection test for now')
    )

    $result = $host.UI.PromptForChoice("Test Transmission Connection", "Would you like to test the Transmission connection now?", $choices, 0)

    if ($result -eq 0) {
        return (Test-TransmissionConnection -Credential $Credential -RpcUrl $RpcUrl)
    }

    return $false
}

function Reset-TransmissionCredential {
	 # Set title for cleanup
    $host.UI.RawUI.WindowTitle = "Transmission Cleanup - Credential Reset..."
    if (Test-Path $CredentialFile) {
        try {
            Remove-Item -Path $CredentialFile -Force
            Write-Host "Existing credentials removed." -ForegroundColor Green
        }
        catch {
            Write-Log "Failed to remove existing credentials: $($_.Exception.Message)" -Level ERROR
            Write-Host "Failed to remove existing credentials: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    
    $cred = Get-TransmissionCredential
    
    # Ask if user wants to change download folder
    Write-Host "`n=== DOWNLOAD FOLDER CONFIGURATION ===" -ForegroundColor Cyan
    $choices = @(
        (New-Object System.Management.Automation.Host.ChoiceDescription -ArgumentList '&Yes', 'Change the download folder location'),
        (New-Object System.Management.Automation.Host.ChoiceDescription -ArgumentList '&No', 'Keep the current download folder location')
    )
    
    $result = $host.UI.PromptForChoice("Change Download Folder", "Would you like to change the download folder location?", $choices, 1)
    
    if ($result -eq 0) {
        $folderResult = Get-FolderSelection -Prompt "Select Download Folder" -DefaultPath $script:config.DownloadFolder
        if ($folderResult.Path -and $folderResult.Path -ne $script:config.DownloadFolder) {
            $script:config.DownloadFolder = $folderResult.Path
            
            # Update subfolder paths
            $script:config.AppsFolder = Join-Path -Path $folderResult.Path -ChildPath "Apps"
            $script:config.VideosFolder = Join-Path -Path $folderResult.Path -ChildPath "Videos"
            $script:config.MusicFolder = Join-Path -Path $folderResult.Path -ChildPath "Music"
            $script:config.ArchiveFolder = Join-Path -Path $folderResult.Path -ChildPath "Archives"
            $script:config.OtherFolder = Join-Path -Path $folderResult.Path -ChildPath "Other"
            
            # Save updated config
            try {
                $script:config | Export-Clixml -Path $ConfigFile
                Write-Host "Configuration updated with new download folder: $($folderResult.Path)" -ForegroundColor Green
            }
            catch {
                Write-Log "Failed to save updated configuration: $($_.Exception.Message)" -Level ERROR
                Write-Host "Failed to save updated configuration: $($_.Exception.Message)" -ForegroundColor Red
            }
        }
    }

    Prompt-TransmissionConnectionTest -Credential $cred -RpcUrl $script:config.RpcUrl | Out-Null
    
    # Wait for key press before exiting
    Wait-ForKeyPress
    
    return $cred
}

function Invoke-TransmissionRPC {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Method,
        [Parameter(Mandatory=$false)]
        [hashtable]$Arguments = @{},
        [Parameter(Mandatory=$false)]
        [PSObject]$Credential = $null,
        [Parameter(Mandatory=$false)]
        [string]$SessionId = "",
        [Parameter(Mandatory=$false)]
        [int]$MaxRetries = 3
    )
    
    if ($null -eq $Credential) {
        $Credential = Get-TransmissionCredential
    }
    
    $rpcUrl = Normalize-TransmissionRpcUrl -Url $script:config.RpcUrl
    $script:config.RpcUrl = $rpcUrl
    Write-Log "RPC URL: $rpcUrl" -Level DEBUG
    
    $rpcCandidates = @($rpcUrl) | Select-Object -Unique

    $headers = @{
        "X-Transmission-Session-Id" = $SessionId
    }
    
    $body = @{
        method = $Method
        arguments = $Arguments
    } | ConvertTo-Json
    
    Write-Log "Preparing RPC call: $Method" -Level DEBUG
    
    $retryCount = 0
    $maxRetries = [Math]::Max(1, $MaxRetries)
    
    while ($retryCount -lt $maxRetries) {
        $retryCount++
        Write-Log "RPC attempt $retryCount of $maxRetries" -Level DEBUG
        
        try {
            # Add authentication if provided
            $webClient = New-Object System.Net.WebClient
            if (-not [string]::IsNullOrEmpty($Credential.Username)) {
                $webClient.Credentials = New-Object System.Net.NetworkCredential($Credential.Username, $Credential.Password)
            }
            
            # Add headers
            foreach ($key in $headers.Keys) {
                $webClient.Headers.Add($key, $headers[$key])
            }
            
            $response = $null
            $lastRpcError = $null
            foreach ($candidateUrl in $rpcCandidates) {
                try {
                    Write-Log "Trying RPC endpoint: $candidateUrl" -Level DEBUG
                    $response = $webClient.UploadString($candidateUrl, $body)
                    if ($candidateUrl -ne $rpcUrl -and $candidateUrl -match '/transmission/rpc/?$') {
                        $script:config.RpcUrl = $candidateUrl
                    }
                    break
                }
                catch {
                    $lastRpcError = $_.Exception
                    if ($candidateUrl -match '/transmission/web/?$') {
                        $normalizedCandidate = $candidateUrl -replace '/transmission/web/?$', '/transmission/rpc'
                        Write-Log "Web UI URL encountered during RPC call; normalized to: $normalizedCandidate" -Level WARN
                    }
                    Write-Log "RPC endpoint failed: $candidateUrl - $($lastRpcError.Message)" -Level DEBUG
                }
            }
            if ($null -eq $response) {
                if ($null -ne $lastRpcError) { throw $lastRpcError }
                throw "No Transmission RPC endpoint could be reached."
            }
            Write-Log "RPC response received successfully" -Level DEBUG
            
            # Parse and return the response
            $result = $response | ConvertFrom-Json
            return $result
        }
        catch [System.Net.WebException] {
            $ex = $_.Exception
            Write-Log "WebException: $($ex.Message)" -Level DEBUG
            
            # Check for 409 Conflict (need new session ID)
            if ($ex.Response -and $ex.Response.StatusCode -eq 409) {
                $sessionId = $ex.Response.Headers["X-Transmission-Session-Id"]
                Write-Log "Received new session ID: $sessionId, retrying..." -Level INFO
                $headers["X-Transmission-Session-Id"] = $sessionId
                continue
            }
            
            # Other web exception
            if ($retryCount -lt $maxRetries) {
                Write-Log "RPC call failed, retrying in $($script:config.RpcRetryDelay) seconds..." -Level WARN
                Start-Sleep -Seconds $script:config.RpcRetryDelay
                continue
            }
            
            Write-Log "RPC call failed after $maxRetries attempts: $($ex.Message)" -Level ERROR
            throw $ex
        }
        catch {
            # Other exceptions
            Write-Log "Error in RPC call: $($_.Exception.Message)" -Level ERROR
            if ($retryCount -lt $maxRetries) {
                Write-Log "Retrying in $($script:config.RpcRetryDelay) seconds..." -Level WARN
                Start-Sleep -Seconds $script:config.RpcRetryDelay
                continue
            }
            throw
        }
        finally {
            if ($null -ne $webClient) {
                $webClient.Dispose()
            }
        }
    }
}

function Get-TorrentList {
    param(
        [Parameter(Mandatory=$false)]
        [PSObject]$Credential = $null,
        [Parameter(Mandatory=$false)]
        [string]$SessionId = ""
    )
    
    $fields = @(
        "id", "name", "status", "downloadDir", "percentDone", 
        "isFinished", "files", "priorities", "wanted"
    )
    
    $arguments = @{
        fields = $fields
    }
    
    try {
        Write-Log "Retrieving torrent list from Transmission" -Level INFO
        Write-Log "Sending torrent-get request" -Level DEBUG
        
        $result = Invoke-TransmissionRPC -Method "torrent-get" -Arguments $arguments -Credential $Credential -SessionId $SessionId
        
        Write-Log "Response received, processing torrents" -Level DEBUG
        
        if ($result.result -ne "success") {
            Write-Log "Failed to get torrent list: $($result.result)" -Level ERROR
            return $null
        }
        
        $torrents = @($result.arguments.torrents)
        Write-Log "Total torrents: $($torrents.Count)" -Level INFO
        
        # Important: force an array return so 0 torrents is treated as a valid empty result,
        # not as $null / failure by the caller.
        return ,$torrents
    }
    catch {
        Write-Log "Error getting torrent list: $($_.Exception.Message)" -Level ERROR
        return $null
    }
}

function Get-CompletedTorrents {
    param(
        [Parameter(Mandatory=$false)]
        [PSObject]$Credential = $null,
        [Parameter(Mandatory=$false)]
        [string]$SessionId = "",
        [Parameter(Mandatory=$false)]
        [array]$Torrents = $null
    )
    
    if ($null -eq $Torrents) {
        $Torrents = Get-TorrentList -Credential $Credential -SessionId $SessionId
    }
    
    if ($null -eq $Torrents) {
        Write-Log "No torrents found" -Level WARN
        return @()
    }
    
    $completedTorrents = @()
    
    foreach ($torrent in $Torrents) {
        Write-Log "Testing completion for torrent: $($torrent.name) (ID: $($torrent.id))" -Level DEBUG
        
        # Log the completion status
        Write-Log "Percent Done: $($torrent.percentDone), Is Finished: $($torrent.isFinished)" -Level DEBUG
        
        # Log the criteria being used
        Write-Log "Completion Criteria: $($script:config.CompletionCriteria)" -Level DEBUG
        
        # Check completion based on criteria
        $isComplete = $false
        
        # Always use PercentDone criteria
        $isComplete = ($torrent.percentDone -eq 1)
        
        # Log the result
        Write-Log "PercentDone criteria: $isComplete" -Level DEBUG
        
        if ($isComplete) {
            $completedTorrents += $torrent
        }
    }
    
    Write-Log "Completed torrents count: $($completedTorrents.Count)" -Level INFO
    return $completedTorrents
}

function Test-FilePath {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Path
    )
    
    # Try direct path first
    if (Test-Path -LiteralPath $Path) {
        return $true
    }
    
    # Try with normalized path
    $normalizedPath = $Path -replace "\\\\", "\"
    if (Test-Path -LiteralPath $normalizedPath) {
        return $true
    }
    
    # Try with quotes
    $quotedPath = "`"$Path`""
    if (Test-Path -LiteralPath $quotedPath) {
        return $true
    }
    
    # Try with escaped characters
    $escapedPath = [Management.Automation.WildcardPattern]::Escape($Path)
    if (Test-Path -LiteralPath $escapedPath) {
        return $true
    }
    
    return $false
}

function Get-FileCategory {
    param(
        [Parameter(Mandatory=$true)]
        [string]$FilePath
    )
    
    $extension = [System.IO.Path]::GetExtension($FilePath).ToLower()
    $videoExtensions = @('.mp4', '.mkv', '.avi', '.mov', '.wmv', '.flv', '.webm', '.m4v', '.mpg', '.mpeg', '.3gp', '.ts', '.m2ts')
    $releaseSupportExtensions = @('.nfo', '.sfv', '.md5', '.sha1', '.sha256', '.diz', '.txt', '.pdf', '.doc', '.docx', '.rtf', '.ini', '.cfg', '.conf', '.bat', '.cmd', '.reg', '.dll')
    $appSidecarExtensions = @('.dat', '.cab', '.xml', '.jpg', '.jpeg', '.png', '.gif', '.webp', '.bmp', '.ico', '.manifest', '.cat', '.json', '.yaml', '.yml', '.msu', '.msp', '.chm', '.hlp', '.inf', '.drv', '.ocx', '.sys', '.bak', '.log', '.lst', '.sig', '.meta')
    $videoSidecarExtensions = @('.srt', '.sub', '.idx', '.ass', '.ssa', '.vtt', '.nfo', '.txt', '.jpg', '.jpeg', '.png', '.gif', '.webp', '.xml', '.bak', '.log', '.meta')
    $discImageExtensions = @('.iso', '.bin', '.cue', '.mds', '.mdf', '.ccd', '.sub', '.img', '.nrg', '.isz', '.daa')
    $archiveExtensions = @('.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.001', '.002', '.003', '.004', '.005')
    
    if (($script:config.AppExtensions -contains $extension) -or ($discImageExtensions -contains $extension)) {
        return 'App'
    }
    elseif ($script:config.MusicExtensions -contains $extension) {
        return 'Music'
    }
    elseif ($videoExtensions -contains $extension) {
        return 'Video'
    }
    elseif (($script:config.ArchiveExtensions -contains $extension) -or ($archiveExtensions -contains $extension)) {
        return 'Archive'
    }
    elseif ($releaseSupportExtensions -contains $extension) {
        return 'Other'
    }
    else {
        return 'Other'
    }
}

function Get-DestinationFolder {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Category
    )
    
    switch ($Category) {
        "App" { return $script:config.AppsFolder }
        "Video" { return $script:config.VideosFolder }
        "Music" { return $script:config.MusicFolder }
        "Archive" { return $script:config.ArchiveFolder }
        default { return $script:config.OtherFolder }
    }
}

function Test-ShouldKeepFile {
    param(
        [Parameter(Mandatory=$true)]
        [string]$FilePath,
        [Parameter(Mandatory=$true)]
        [string]$Category
    )
    
    $fileName = [System.IO.Path]::GetFileName($FilePath).ToLower()
    $extension = [System.IO.Path]::GetExtension($FilePath).ToLower()
    $videoExtensions = @('.mp4', '.mkv', '.avi', '.mov', '.wmv', '.flv', '.webm', '.m4v', '.mpg', '.mpeg', '.3gp', '.ts', '.m2ts')
    $appSupportingExtensions = @('.txt', '.nfo', '.pdf', '.doc', '.docx', '.rtf', '.ini', '.cfg', '.conf', '.sfv', '.md5', '.sha1', '.sha256', '.diz', '.bat', '.cmd', '.reg', '.dll', '.dat', '.cab', '.xml', '.jpg', '.jpeg', '.png', '.gif', '.webp', '.bmp', '.ico', '.manifest', '.cat', '.json', '.yaml', '.yml', '.msu', '.msp', '.chm', '.hlp', '.inf', '.drv', '.ocx', '.sys', '.bak', '.log', '.lst', '.sig', '.meta')
    $archiveExtensions = @('.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.001', '.002', '.003', '.004', '.005')
    $discImageExtensions = @('.iso', '.bin', '.cue', '.mds', '.mdf', '.ccd', '.sub', '.img', '.nrg', '.isz', '.daa')
    
    if (Test-IsDefinitelyUnwantedFile -FilePath $FilePath) {
        return $false
    }
    
    switch ($Category) {
        'Video' {
            $videoSupportingExtensions = @('.srt', '.sub', '.idx', '.ass', '.ssa', '.vtt', '.nfo', '.txt', '.jpg', '.jpeg', '.png', '.gif', '.webp', '.xml', '.dat', '.mka', '.cue', '.bak', '.log', '.meta')
            if (Test-IsDefinitelyUnwantedFile -FilePath $FilePath) { return $false }
            if (($script:config.AppExtensions -contains $extension) -or ($discImageExtensions -contains $extension) -or ($script:config.MusicExtensions -contains $extension)) { return ($videoExtensions -contains $extension) }
            return ($videoExtensions -contains $extension) -or ($videoSupportingExtensions -contains $extension) -or ($extension -eq '')
        }
        'Music' {
            $unwantedForMusic = @('.srt', '.sub', '.idx', '.nfo', '.url', '.torrent', '.db')
            if ($unwantedForMusic -contains $extension) { return $false }
            return ($script:config.MusicExtensions -contains $extension) -or $extension -eq '.txt' -or $extension -eq '.pdf'
        }
        'App' {
            $unwantedForApps = @('.torrent', '.db', '.url')
            if ($unwantedForApps -contains $extension) { return $false }
            return ($script:config.AppExtensions -contains $extension) -or ($appSupportingExtensions -contains $extension) -or ($archiveExtensions -contains $extension) -or ($discImageExtensions -contains $extension)
        }
        'Archive' {
            return ($script:config.ArchiveExtensions -contains $extension) -or ($archiveExtensions -contains $extension)
        }
        default {
            $unwantedGeneral = @('.url', '.torrent', '.db')
            if ($unwantedGeneral -contains $extension) { return $false }
            return $true
        }
    }
}

function Get-CleanFolderName {
    param(
        [Parameter(Mandatory=$true)]
        [string]$TorrentName
    )
    
    # Remove common torrent naming patterns
    $cleanName = $TorrentName
    
    # Remove resolution patterns (1080p, 720p, etc.)
    $cleanName = $cleanName -replace "\b\d{3,4}p\b", ""
    
    # Remove codec patterns (x264, x265, H264, etc.)
    $cleanName = $cleanName -replace "\b[xhH]\d{3}\b", ""
    $cleanName = $cleanName -replace "\bHEVC\b", ""
    
    # Remove release group patterns (usually in brackets or after dash)
    $cleanName = $cleanName -replace "\[.*?\]", ""
    $cleanName = $cleanName -replace "-\w+$", ""
    
    # Remove year from the end if it's making the name too long
    # But keep it if it's part of the actual title
    
    # Remove extra spaces and clean up
    $cleanName = $cleanName -replace "\s+", " "
    $cleanName = $cleanName.Trim()
    
    # Convert to safe path name
    return ConvertTo-SafePath -Name $cleanName
}

function Remove-FolderForce {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Path
    )
    
    try {
        if (Test-Path -LiteralPath $Path -PathType Container) {
            # Clear read-only attributes recursively to avoid access denied
            Get-ChildItem -LiteralPath $Path -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
                try { $_.Attributes = 'Normal' } catch {}
            }
            try { (Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue).Attributes = 'Normal' } catch {}
            
            # Try normal deletion first
            Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop
            if (-not (Test-Path -LiteralPath $Path)) {
                Write-Log "Successfully deleted folder using standard method: $Path" -Level INFO
                return $true
            }
        }
    }
    catch {
        Write-Log "Standard deletion failed, trying alternative methods: $($_.Exception.Message)" -Level WARN
    }
    
    # Try using robocopy to delete (Windows method)
    try {
        if (Test-Path -LiteralPath $Path -PathType Container) {
            $tempEmptyDir = Join-Path -Path $env:TEMP -ChildPath "EmptyForRobocopy_$(Get-Random)"
            New-Item -ItemType Directory -Path $tempEmptyDir -Force | Out-Null
            
            # Use robocopy to mirror empty folder over the target (effectively wiping it)
            $null = robocopy "$tempEmptyDir" "$Path" /MIR /R:1 /W:1 2>$null
            Remove-Item -LiteralPath $tempEmptyDir -Force -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath $Path -Force -Recurse -ErrorAction SilentlyContinue
            
            if (-not (Test-Path -LiteralPath $Path)) {
                Write-Log "Successfully deleted folder using robocopy method: $Path" -Level INFO
                return $true
            }
        }
    }
    catch {
        Write-Log "Robocopy deletion failed: $($_.Exception.Message)" -Level WARN
    }
    
    # Try using cmd rmdir
    try {
        if (Test-Path -LiteralPath $Path -PathType Container) {
            $null = cmd /c rmdir /s /q "${Path}" 2>$null
            if (-not (Test-Path -LiteralPath $Path)) {
                Write-Log "Successfully deleted folder using cmd rmdir: $Path" -Level INFO
                return $true
            }
        }
    }
    catch {
        Write-Log "CMD rmdir deletion failed: $($_.Exception.Message)" -Level WARN
    }
    
    Write-Log "All deletion methods failed for folder: $Path" -Level ERROR
    return $false
}

function Cut-FileWithRetry {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Source,
        [Parameter(Mandatory=$true)]
        [string]$Destination,
        [int]$MaxRetries = 3,
        [int]$RetryDelay = 2
    )
    
    # Validate parameters
    if ([string]::IsNullOrEmpty($Source)) {
        Write-Log "Source path is null or empty" -Level ERROR
        return $false
    }
    if ([string]::IsNullOrEmpty($Destination)) {
        Write-Log "Destination path is null or empty" -Level ERROR
        return $false
    }
    
    # Check if source file exists
    if (-not (Test-FilePath $Source)) {
        Write-Log "Source file not found: $Source" -Level WARN
        return $false
    }
    
    # Ensure destination directory exists
    $destDir = Split-Path -Path $Destination -Parent
    if (-not (Test-Path $destDir)) {
        try {
            New-Item -ItemType Directory -Path $destDir -Force | Out-Null
            Write-Log "Created destination directory: $destDir" -Level INFO
        }
        catch {
            Write-Log "Failed to create destination directory: $($_.Exception.Message)" -Level ERROR
            return $false
        }
    }
    
    # Try to move the file with retries
    $retryCount = 0
    $success = $false
    
    while (-not $success -and $retryCount -lt $MaxRetries) {
        try {
            Move-Item -LiteralPath $Source -Destination $Destination -Force
            Write-Log "Successfully moved file from $Source to $Destination" -Level INFO
            $success = $true
        }
        catch {
            $retryCount++
            Write-Log "Failed to move file (attempt $retryCount of $MaxRetries): $($_.Exception.Message)" -Level WARN
            
            if ($retryCount -lt $MaxRetries) {
                Start-Sleep -Seconds $RetryDelay
            }
            else {
                Write-Log "Failed to move file after $MaxRetries attempts: $Source" -Level ERROR
                return $false
            }
        }
    }
    
    return $success
}

function Get-ReleaseBundleStem {
    param([Parameter(Mandatory=$true)][string]$RelativePath)
    $name = [System.IO.Path]::GetFileName($RelativePath).ToLower()
    $name = $name -replace '\.(zip|7z|rar)\.\d{3}$', ''
    $name = $name -replace '\.part\d+$', ''
    $name = $name -replace '\.(r|z)\d{2,3}$', ''
    $name = $name -replace '\.\d{3}$', ''
    return [System.IO.Path]::GetFileNameWithoutExtension($name)
}

function Test-IsMultipartArchiveFile {
    param([Parameter(Mandatory=$true)][string]$RelativePath)
    $name = [System.IO.Path]::GetFileName($RelativePath).ToLower()
    return ($name -match '\.part\d+$' -or $name -match '\.(r|z)\d{2,3}$' -or $name -match '\.(zip|7z)\.\d{3}$' -or $name -match '\.\d{3}$')
}


function Test-IsDefinitelyUnwantedFile {
    param([Parameter(Mandatory=$true)][string]$FilePath)
    $fileName = [System.IO.Path]::GetFileName($FilePath).ToLower()
    $extension = [System.IO.Path]::GetExtension($FilePath).ToLower()

    $junkNames = @('thumbs.db', 'desktop.ini')
    $junkExtensions = @('.url', '.torrent', '.db', '.tmp', '.part', '.crdownload')

    if ($junkNames -contains $fileName) { return $true }
    if ($fileName -match 'sample') { return $true }
    if ($fileName -match 'rarbg') { return $true }
    if ($junkExtensions -contains $extension) { return $true }
    return $false
}


function Test-PathIsUnderAnyAnchor {
    param(
        [Parameter(Mandatory=$true)][string]$RelativeDirectory,
        [AllowNull()]
        [AllowEmptyCollection()]
        [System.Collections.Generic.HashSet[string]]$AnchorDirectories = $null
    )

    if ([string]::IsNullOrWhiteSpace($RelativeDirectory)) { $RelativeDirectory = '.' }

    if ($null -eq $AnchorDirectories -or $AnchorDirectories.Count -eq 0) {
        return $false
    }

    $currentDir = $RelativeDirectory

    while ($true) {
        if ($AnchorDirectories.Contains($currentDir)) { return $true }
        if ($currentDir -eq '.' -or $currentDir -eq '\' -or $currentDir -eq '') { break }

        $parentDir = Split-Path -Path $currentDir -Parent
        if ([string]::IsNullOrWhiteSpace($parentDir) -or $parentDir -eq $currentDir) {
            $currentDir = '.'
        }
        else {
            $currentDir = $parentDir
        }
    }

    return $false
}

function Get-TopLevelRelativeFolder {
    param([Parameter(Mandatory=$true)][string]$RelativePath)

    $normalized = ($RelativePath -replace '/', '\').Trim('\')
    if ([string]::IsNullOrWhiteSpace($normalized)) { return '.' }

    $parts = $normalized.Split('\')
    if ($parts.Length -le 1) { return '.' }
    return $parts[0]
}

function Get-RelativeDestinationPath {
    param(
        [Parameter(Mandatory=$true)][string]$TorrentRelativePath,
        [Parameter(Mandatory=$true)][bool]$PreserveNestedStructure,
        [Parameter(Mandatory=$true)][string]$FallbackLeafName
    )

    if ($PreserveNestedStructure) {
        $normalized = ($TorrentRelativePath -replace '/', '\').Trim('\')
        if ([string]::IsNullOrWhiteSpace($normalized)) { return $FallbackLeafName }

        # Transmission often reports files as "Release Folder\file.ext" while this script
        # already creates a cleaned destination folder such as "Videos\Movie Name".
        # Strip the torrent/release root folder from preserved paths so we do not create:
        #   Videos\Movie Name\Movie Name [Release Tags]\file.ext
        $parts = @($normalized -split '\\' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        if ($parts.Count -gt 1) {
            return ($parts[1..($parts.Count - 1)] -join '\')
        }

        return $normalized
    }
    return $FallbackLeafName
}

function Test-FolderHasKeepableContent {
    param(
        [Parameter(Mandatory=$true)][string]$FolderPath
    )

    try {
        if (-not (Test-Path -LiteralPath $FolderPath -PathType Container)) { return $false }

        $remainingFiles = @(Get-ChildItem -LiteralPath $FolderPath -Force -Recurse -File -ErrorAction SilentlyContinue)
        foreach ($remainingFile in $remainingFiles) {
            # Only obvious junk can be auto-discarded. Any non-junk leftover keeps the folder.
            if (-not (Test-IsDefinitelyUnwantedFile -FilePath $remainingFile.FullName)) {
                return $true
            }
        }

        return $false
    }
    catch {
        Write-Log "Could not inspect original folder '$FolderPath' for cleanup: $($_.Exception.Message)" -Level WARN
        return $true
    }
}

function Test-TorrentNameSuggestsAppRelease {
    param([Parameter(Mandatory=$true)][string]$TorrentName)
    return $TorrentName -match '(?i)(setup|install|installer|crack|keygen|patch|portable|x64|x86|exe|msi|app|software|program|tool|office|suite|build|activator|game|repack)'
}

function Organize-Files {
    param(
        [Parameter(Mandatory=$true)]
        [PSObject]$Torrent,
        [Parameter(Mandatory=$false)]
        [switch]$WhatIf
    )
    
    $torrentName = $Torrent.name
    $downloadDir = $Torrent.downloadDir
    
    Write-Log "Organizing files for torrent: $torrentName" -Level INFO
    Write-Log "Download directory: $downloadDir" -Level DEBUG
    
    $cleanTorrentName = Get-CleanFolderName -TorrentName $torrentName
    Write-Log "Clean torrent name: $cleanTorrentName" -Level DEBUG
    
    $organizedFiles = @()
    $failedFiles = @()
    $deletedFiles = @()
    $keptFiles = @()

    $videoExtensions = @('.mp4', '.mkv', '.avi', '.mov', '.wmv', '.flv', '.webm', '.m4v', '.mpg', '.mpeg', '.3gp', '.ts', '.m2ts')
    $archiveExtensions = @('.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.001', '.002', '.003', '.004', '.005')
    $releaseSupportExtensions = @('.nfo', '.sfv', '.md5', '.sha1', '.sha256', '.diz', '.txt', '.pdf', '.doc', '.docx', '.rtf', '.ini', '.cfg', '.conf', '.bat', '.cmd', '.reg', '.dll')
    $appSidecarExtensions = @('.dat', '.cab', '.xml', '.jpg', '.jpeg', '.png', '.gif', '.webp', '.bmp', '.ico', '.manifest', '.cat', '.json', '.yaml', '.yml', '.msu', '.msp', '.chm', '.hlp', '.inf', '.drv', '.ocx', '.sys', '.bak', '.log', '.lst', '.sig', '.meta')
    $videoSidecarExtensions = @('.srt', '.sub', '.idx', '.ass', '.ssa', '.vtt', '.nfo', '.txt', '.jpg', '.jpeg', '.png', '.gif', '.webp', '.xml', '.bak', '.log', '.meta')
    $discImageExtensions = @('.iso', '.bin', '.cue', '.mds', '.mdf', '.ccd', '.sub', '.img', '.nrg', '.isz', '.daa')

    $appFiles = @()
    $videoFiles = @()
    $allFileList = @()
    $discBundleStems = New-Object System.Collections.Generic.HashSet[string]
    $appAnchorDirectories = New-Object System.Collections.Generic.HashSet[string]
    $videoAnchorDirectories = New-Object System.Collections.Generic.HashSet[string]
    $appTopLevelFolders = New-Object System.Collections.Generic.HashSet[string]
    $videoTopLevelFolders = New-Object System.Collections.Generic.HashSet[string]
    
    foreach ($file in $Torrent.files) {
        $relativePath = ($file.name -replace '/', '\')
        $filePath = Join-Path -Path $downloadDir -ChildPath $relativePath
        $extension = [System.IO.Path]::GetExtension($filePath).ToLower()
        $leafName = Split-Path -Path $relativePath -Leaf
        $bundleStem = Get-ReleaseBundleStem -RelativePath $relativePath

        $fileInfo = @{
            File = $file
            RelativePath = $relativePath
            FilePath = $filePath
            FileName = $leafName
            Extension = $extension
            BundleStem = $bundleStem
        }
        $allFileList += $fileInfo
        
        $relativeDir = Split-Path -Path $relativePath -Parent
        if ([string]::IsNullOrEmpty($relativeDir)) { $relativeDir = '.' }

        $topLevelFolder = Get-TopLevelRelativeFolder -RelativePath $relativePath

        if (($script:config.AppExtensions -contains $extension) -or ($discImageExtensions -contains $extension) -or ($archiveExtensions -contains $extension)) {
            $appFiles += $filePath
            $discBundleStems.Add($bundleStem) | Out-Null
            $appAnchorDirectories.Add($relativeDir) | Out-Null
            $appTopLevelFolders.Add($topLevelFolder) | Out-Null
        }
        if ($videoExtensions -contains $extension) {
            $videoFiles += $filePath
            $videoAnchorDirectories.Add($relativeDir) | Out-Null
            $videoTopLevelFolders.Add($topLevelFolder) | Out-Null
        }
    }
    
    $totalFiles = [Math]::Max($allFileList.Count,1)
    $torrentNameSuggestsApp = Test-TorrentNameSuggestsAppRelease -TorrentName $torrentName
    $isVideoTorrent = ($videoFiles.Count -gt 0) -and ($videoFiles.Count -ge ($totalFiles * 0.3))
    $isAppTorrent = ($appFiles.Count -gt 0) -and (($appFiles.Count -ge ($totalFiles * 0.1)) -or $torrentNameSuggestsApp)

    if (-not $isAppTorrent) {
        $releaseSupportCount = @($allFileList | Where-Object { ($releaseSupportExtensions -contains $_.Extension) -or ($archiveExtensions -contains $_.Extension) -or (Test-IsMultipartArchiveFile -RelativePath $_.RelativePath) }).Count
        if ($torrentNameSuggestsApp -and $releaseSupportCount -gt 0) {
            $isAppTorrent = $true
        }
    }
    
    Write-Log "Torrent analysis: $($videoFiles.Count) video files, $($appFiles.Count) app/disc files out of $totalFiles total. IsVideoTorrent: $isVideoTorrent, IsAppTorrent: $isAppTorrent" -Level INFO
    
    $filesByCategory = @{}
    
    foreach ($fileInfo in $allFileList) {
        $filePath = $fileInfo.FilePath
        $extension = $fileInfo.Extension
        $category = Get-FileCategory -FilePath $filePath

        $relativeDir = Split-Path -Path $fileInfo.RelativePath -Parent
        if ([string]::IsNullOrEmpty($relativeDir)) { $relativeDir = '.' }
        $topLevelFolder = Get-TopLevelRelativeFolder -RelativePath $fileInfo.RelativePath
        $underAppAnchor = (Test-PathIsUnderAnyAnchor -RelativeDirectory $relativeDir -AnchorDirectories $appAnchorDirectories) -or $appTopLevelFolders.Contains($topLevelFolder)
        $underVideoAnchor = (Test-PathIsUnderAnyAnchor -RelativeDirectory $relativeDir -AnchorDirectories $videoAnchorDirectories) -or $videoTopLevelFolders.Contains($topLevelFolder)
        $hasNoExtension = [string]::IsNullOrEmpty($extension)

        if ($isAppTorrent) {
            $isKnownNonApp = (($videoExtensions -contains $extension) -or ($script:config.MusicExtensions -contains $extension))
            if (-not (Test-IsDefinitelyUnwantedFile -FilePath $filePath)) {
                if (($category -eq 'Archive') -or ($releaseSupportExtensions -contains $extension) -or ($appSidecarExtensions -contains $extension) -or ($discImageExtensions -contains $extension) -or (Test-IsMultipartArchiveFile -RelativePath $fileInfo.RelativePath) -or ($discBundleStems.Contains($fileInfo.BundleStem)) -or $underAppAnchor -or ($hasNoExtension -and -not $isKnownNonApp) -or (($category -eq 'Other') -and -not $isKnownNonApp)) {
                    $category = 'App'
                }
            }
        }

        if ($isVideoTorrent) {
            $isKnownNonVideo = (($script:config.MusicExtensions -contains $extension) -or ($script:config.AppExtensions -contains $extension) -or ($discImageExtensions -contains $extension))
            if (-not (Test-IsDefinitelyUnwantedFile -FilePath $filePath)) {
                if (($category -eq 'Video') -or ($videoSidecarExtensions -contains $extension) -or $underVideoAnchor -or ($hasNoExtension -and -not $isKnownNonVideo -and -not $isAppTorrent) -or (($category -eq 'Other') -and -not $isKnownNonVideo -and -not $isAppTorrent)) {
                    $category = 'Video'
                }
            }
        }
        
        if (-not $filesByCategory.ContainsKey($category)) {
            $filesByCategory[$category] = @()
        }
        $filesByCategory[$category] += $fileInfo
    }
    
    foreach ($category in $filesByCategory.Keys) {
        $filesInCategory = $filesByCategory[$category]
        Write-Log "Processing $($filesInCategory.Count) files in category: $category" -Level INFO
        
        if ($isVideoTorrent -and $category -ne 'Video' -and -not $isAppTorrent) {
            foreach ($fileInfo in $filesInCategory) {
                $filePath = $fileInfo.FilePath
                $fileName = $fileInfo.FileName
                if ($WhatIf) {
                    Write-Log "WhatIf: Would delete $filePath" -Level INFO
                    $deletedFiles += $fileName
                }
                else {
                    try {
                        if (Test-FilePath $filePath) {
                            Remove-Item -LiteralPath $filePath -Force -ErrorAction Stop
                            Write-Log "Successfully deleted: $fileName" -Level INFO
                            $deletedFiles += $fileName
                        }
                    }
                    catch {
                        Write-Log "Failed to delete file $fileName : $($_.Exception.Message)" -Level WARN
                    }
                }
            }
            continue
        }
        
        $baseCategoryFolder = Get-DestinationFolder -Category $category
        $torrentSpecificFolder = Join-Path -Path $baseCategoryFolder -ChildPath $cleanTorrentName
        
        foreach ($fileInfo in $filesInCategory) {
            $filePath = $fileInfo.FilePath
            $fileName = $fileInfo.FileName
            $shouldKeep = Test-ShouldKeepFile -FilePath $filePath -Category $category
            
            if ($shouldKeep) {
                $preserveNested = (($isAppTorrent -and $category -eq 'App') -or ($isVideoTorrent -and $category -eq 'Video'))
                $relativeDest = Get-RelativeDestinationPath -TorrentRelativePath $fileInfo.RelativePath -PreserveNestedStructure $preserveNested -FallbackLeafName $fileName
                $destPath = Join-Path -Path $torrentSpecificFolder -ChildPath $relativeDest
                
                if ($WhatIf) {
                    Write-Log "WhatIf: Would move $filePath to $destPath" -Level INFO
                    $organizedFiles += $fileName
                }
                else {
                    $success = Cut-FileWithRetry -Source $filePath -Destination $destPath -MaxRetries $MaxRetries -RetryDelay $RetryDelay
                    if ($success) {
                        $organizedFiles += $fileName
                        $keptFiles += $fileName
                    }
                    else {
                        $failedFiles += $fileName
                    }
                }
            }
            else {
                if ($WhatIf) {
                    Write-Log "WhatIf: Would delete $filePath" -Level INFO
                    $deletedFiles += $fileName
                }
                else {
                    try {
                        if (Test-FilePath $filePath) {
                            Remove-Item -LiteralPath $filePath -Force -ErrorAction Stop
                            Write-Log "Successfully deleted: $fileName" -Level INFO
                            $deletedFiles += $fileName
                        }
                    }
                    catch {
                        Write-Log "Failed to delete file $fileName : $($_.Exception.Message)" -Level WARN
                    }
                }
            }
        }
    }
    
    if ($script:config.DeleteOriginalFolders -and -not $WhatIf) {
        Write-Log 'Starting folder cleanup - DeleteOriginalFolders is enabled' -Level INFO
        $possiblePaths = @()
        $directPath = Join-Path -Path $downloadDir -ChildPath $torrentName
        $possiblePaths += $directPath
        foreach ($file in $Torrent.files) {
            $fileDir = Split-Path -Path ($file.name -replace '/', '\') -Parent
            if (-not [string]::IsNullOrEmpty($fileDir)) {
                $pathParts = $fileDir.Split([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar)
                $rootFolderName = $pathParts[0]
                if (-not [string]::IsNullOrEmpty($rootFolderName)) {
                    $rootFolderPath = Join-Path -Path $downloadDir -ChildPath $rootFolderName
                    if ($possiblePaths -notcontains $rootFolderPath) { $possiblePaths += $rootFolderPath }
                }
            }
        }
        foreach ($folderPath in ($possiblePaths | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)) {
            if (Test-Path -LiteralPath $folderPath -PathType Container) {
                try {
                    if (-not (Test-FolderHasKeepableContent -FolderPath $folderPath)) {
                        Write-Log "Original folder has no keepable content remaining; deleting: $folderPath" -Level INFO
                        Remove-Item -LiteralPath $folderPath -Recurse -Force -ErrorAction Stop
                        Write-Log "Successfully deleted original folder: $folderPath" -Level INFO
                    }
                    else {
                        # Remove any empty child folders, but keep the original folder because it still contains non-junk leftovers.
                        $remainingFolders = @(Get-ChildItem -LiteralPath $folderPath -Force -Recurse -Directory -ErrorAction SilentlyContinue)
                        $remainingFolders | Sort-Object FullName -Descending | ForEach-Object {
                            try {
                                $subItems = @(Get-ChildItem -LiteralPath $_.FullName -Force -ErrorAction SilentlyContinue)
                                if ($subItems.Count -eq 0) {
                                    Remove-Item -LiteralPath $_.FullName -Force -ErrorAction Stop
                                }
                            }
                            catch {}
                        }
                        Write-Log "Folder still contains non-junk leftovers, keeping original folder: $folderPath" -Level INFO
                    }
                }
                catch {
                    Write-Log "Error during cleanup of folder $folderPath : $($_.Exception.Message)" -Level WARN
                }
            }
        }
        Write-Log 'Folder cleanup completed' -Level INFO
    }
    else {
        if ($WhatIf) {
            Write-Log 'WhatIf: Would attempt to delete original folders if DeleteOriginalFolders is enabled' -Level INFO
        }
        elseif (-not $script:config.DeleteOriginalFolders) {
            Write-Log 'Folder deletion disabled (DeleteOriginalFolders = false)' -Level INFO
        }
    }
    
    Write-Log "Organization complete. Kept: $($keptFiles.Count), Deleted: $($deletedFiles.Count), Failed: $($failedFiles.Count)" -Level INFO
    return @{ Organized = $organizedFiles; Failed = $failedFiles; Deleted = $deletedFiles; Kept = $keptFiles }
}


function Test-TorrentDataAbsentOrEmpty {
    param(
        [Parameter(Mandatory=$true)]
        [PSObject]$Torrent
    )

    try {
        $downloadDir = $Torrent.downloadDir
        $torrentName = $Torrent.name
        $possiblePaths = New-Object System.Collections.Generic.List[string]

        if (-not [string]::IsNullOrWhiteSpace($downloadDir) -and -not [string]::IsNullOrWhiteSpace($torrentName)) {
            $possiblePaths.Add((Join-Path -Path $downloadDir -ChildPath $torrentName))
        }

        foreach ($file in @($Torrent.files)) {
            $relativePath = ($file.name -replace '/', '\').Trim('\')
            if ([string]::IsNullOrWhiteSpace($relativePath)) { continue }

            if (-not [string]::IsNullOrWhiteSpace($downloadDir)) {
                $possiblePaths.Add((Join-Path -Path $downloadDir -ChildPath $relativePath))
            }

            $rootFolder = ($relativePath -split '[\/]')[0]
            if (-not [string]::IsNullOrWhiteSpace($rootFolder) -and -not [string]::IsNullOrWhiteSpace($downloadDir)) {
                $possiblePaths.Add((Join-Path -Path $downloadDir -ChildPath $rootFolder))
            }
        }

        $candidatePaths = @($possiblePaths | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)
        if ($candidatePaths.Count -eq 0) {
            return $true
        }

        $existingPaths = @($candidatePaths | Where-Object { Test-Path -LiteralPath $_ })
        if ($existingPaths.Count -eq 0) {
            Write-Log "Torrent source paths no longer exist for '$torrentName'; allowing torrent removal." -Level INFO
            return $true
        }

        foreach ($path in $existingPaths) {
            try {
                if (Test-Path -LiteralPath $path -PathType Leaf) {
                    return $false
                }
                if (Test-Path -LiteralPath $path -PathType Container) {
                    $items = @(Get-ChildItem -LiteralPath $path -Force -ErrorAction SilentlyContinue)
                    if ($items.Count -gt 0) {
                        return $false
                    }
                }
            }
            catch {
                Write-Log "Could not inspect path '$path' while checking torrent source emptiness: $($_.Exception.Message)" -Level WARN
                return $false
            }
        }

        Write-Log "Torrent source paths are empty for '$torrentName'; allowing torrent removal." -Level INFO
        return $true
    }
    catch {
        Write-Log "Failed to check whether torrent source data is absent or empty: $($_.Exception.Message)" -Level WARN
        return $false
    }
}

function Remove-Torrent {
    param(
        [Parameter(Mandatory=$true)]
        [int]$TorrentId,
        [Parameter(Mandatory=$true)]
        [string]$TorrentName,
        [Parameter(Mandatory=$false)]
        [PSObject]$Credential = $null,
        [Parameter(Mandatory=$false)]
        [string]$SessionId = "",
        [Parameter(Mandatory=$false)]
        [switch]$DeleteLocalData = $false
    )
    
    try {
        Write-Log "Removing torrent: $TorrentName (ID: $TorrentId)" -Level INFO
        
        $arguments = @{
            ids = @($TorrentId)
            "delete-local-data" = $DeleteLocalData
        }
        
        $result = Invoke-TransmissionRPC -Method "torrent-remove" -Arguments $arguments -Credential $Credential -SessionId $SessionId
        
        if ($result.result -ne "success") {
            Write-Log "Failed to remove torrent: $($result.result)" -Level ERROR
            return $false
        }
        
        Write-Log "Successfully removed torrent: $TorrentName" -Level INFO
        return $true
    }
    catch {
        Write-Log "Failed to remove torrent: $($_.Exception.Message)" -Level ERROR
        return $false
    }
}

function Open-LogsFolder {
    try {
        if (-not (Test-Path -LiteralPath $script:LogsDir)) {
            New-Item -ItemType Directory -Path $script:LogsDir -Force | Out-Null
        }
        Start-Process explorer.exe -ArgumentList "`"$($script:LogsDir)`""
        Write-Log "Opened logs folder: $($script:LogsDir)" -Level INFO -NoConsole
    }
    catch {
        Write-Log "Failed to open logs folder: $($_.Exception.Message)" -Level ERROR
    }
}

function Install-Script {
    $host.UI.RawUI.WindowTitle = "Transmission Cleanup - Installation"
    $currentScript = Get-ScriptPath

    Write-Log "Install-Script | InstallDir = '$InstallDir'" -Level DEBUG -NoConsole
    Write-Log "Install-Script | ScriptPath = '$ScriptPath'" -Level DEBUG -NoConsole
    Write-Log "Install-Script | CurrentScript = '$currentScript'" -Level DEBUG -NoConsole

    try {
        if ([string]::IsNullOrWhiteSpace($InstallDir)) {
            throw "InstallDir is empty."
        }
        if (-not (Test-Path -LiteralPath $InstallDir)) {
            New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
            Write-Log "Created installation directory: $InstallDir" -Level INFO -NoConsole
        }
        if (-not (Test-Path -LiteralPath $script:LogsDir)) {
            New-Item -ItemType Directory -Path $script:LogsDir -Force | Out-Null
            Write-Log "Created logs directory: $($script:LogsDir)" -Level INFO -NoConsole
        }
    }
    catch {
        Write-Log "Failed to prepare installation directory: $($_.Exception.Message)" -Level ERROR
        Write-Host "Failed to prepare installation directory: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }

    try {
        if ([string]::IsNullOrWhiteSpace($currentScript) -or -not (Test-Path -LiteralPath $currentScript)) {
            throw "Could not determine the current script path."
        }

        if ($currentScript -ne $ScriptPath) {
            Copy-Item -LiteralPath $currentScript -Destination $ScriptPath -Force
            Write-Log "Copied script to: $ScriptPath" -Level INFO -NoConsole
        }
        else {
            Write-Log "Script is already running from install path." -Level INFO -NoConsole
        }
    }
    catch {
        Write-Log "Failed to copy script: $($_.Exception.Message)" -Level ERROR
        Write-Host "Failed to copy script: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }

    try {
        $helpLines = @(
            '=== TRANSMISSION CLEANUP HELP ===',
            '',
            'OVERVIEW',
            '--------',
            'Transmission Cleanup automatically organizes completed torrents into category folders.',
            'It can be run manually or on a schedule.',
            '',
            'FEATURES',
            '--------',
            '- Self-install to AppData\Transmission',
            '- Start Menu shortcuts',
            '- Local credential storage',
            '- Category folders: Apps, Videos, Music, Archives, Other',
            '- Scheduled task support',
            '- Cleanup and uninstall options',
            '',
            'NOTES',
            '-----',
            '- Enter your Transmission web URL or RPC URL when prompted.',
            '- /transmission/web/ is normalized to /transmission/rpc automatically.',
            '- Check the log file if something fails.'
        )
        Set-Content -LiteralPath $HelpFile -Value $helpLines -Force
        Write-Log "Created help file: $HelpFile" -Level INFO -NoConsole
    }
    catch {
        Write-Log "Failed to create help file: $($_.Exception.Message)" -Level WARN -NoConsole
    }

    try {
        if (-not (Test-Path -LiteralPath $shortcutFolder)) {
            New-Item -ItemType Directory -Path $shortcutFolder -Force | Out-Null
        }

        $shell32 = "$env:SystemRoot\System32\shell32.dll"
        $imageres = "$env:SystemRoot\System32\imageres.dll"

        New-Shortcut -Path (Join-Path $shortcutFolder 'Run Cleanup.lnk') `
            -TargetPath 'powershell.exe' `
            -Arguments "-NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`" -RunOnly" `
            -Description 'Run Transmission Cleanup' `
            -WindowStyle 'Normal' `
            -IconLocation "$imageres,109" `
            -RunAsAdmin $true

        New-Shortcut -Path (Join-Path $shortcutFolder 'Reset Credentials.lnk') `
            -TargetPath 'powershell.exe' `
            -Arguments "-NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`" -Reinitialize" `
            -Description 'Reset Transmission Credentials' `
            -WindowStyle 'Normal' `
            -IconLocation "$shell32,235" `
            -RunAsAdmin $true

        New-Shortcut -Path (Join-Path $shortcutFolder 'View Log File.lnk') `
            -TargetPath 'notepad.exe' `
            -Arguments "`"$($script:config.LogFile)`"" `
            -Description 'View Transmission Cleanup Log' `
            -WindowStyle 'Normal' `
            -IconLocation "$shell32,70" `
            -RunAsAdmin $false

        New-Shortcut -Path (Join-Path $shortcutFolder 'Open Logs Folder.lnk') `
            -TargetPath 'explorer.exe' `
            -Arguments "`"$($script:LogsDir)`"" `
            -Description 'Open Transmission Cleanup Logs Folder' `
            -WindowStyle 'Normal' `
            -IconLocation "$shell32,4" `
            -RunAsAdmin $false

        New-Shortcut -Path (Join-Path $shortcutFolder 'Help.lnk') `
            -TargetPath 'notepad.exe' `
            -Arguments "`"$HelpFile`"" `
            -Description 'Transmission Cleanup Help' `
            -WindowStyle 'Normal' `
            -IconLocation "$shell32,23" `
            -RunAsAdmin $false

        New-Shortcut -Path (Join-Path $shortcutFolder 'Uninstall.lnk') `
            -TargetPath 'powershell.exe' `
            -Arguments "-NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`" -Uninstall" `
            -Description 'Uninstall Transmission Cleanup' `
            -WindowStyle 'Normal' `
            -IconLocation "$imageres,99" `
            -RunAsAdmin $true

        Write-Log "Created Start Menu shortcuts" -Level INFO -NoConsole
        Write-Host "Created Start Menu shortcuts." -ForegroundColor Green
    }
    catch {
        Write-Log "Failed to create shortcuts: $($_.Exception.Message)" -Level ERROR
        Write-Host "Failed to create shortcuts: $($_.Exception.Message)" -ForegroundColor Red
    }

    try {
        Write-Host "`n=== DOWNLOAD FOLDER CONFIGURATION ===" -ForegroundColor Cyan
        $folderResult = Get-FolderSelection -Prompt "Select the main folder where Transmission downloads torrents" -DefaultPath $script:config.DownloadFolder -AllowCancel
        if ($folderResult.Cancelled) {
            Write-Host "Folder selection was cancelled. Installation aborted." -ForegroundColor Red
            Write-Log "Installation cancelled by user during folder selection." -Level WARN
            Wait-ForKeyPress
            return $false
        }

        if ($folderResult.Path) {
            $script:config.DownloadFolder = $folderResult.Path
            $script:config.AppsFolder = Join-Path $folderResult.Path 'Apps'
            $script:config.VideosFolder = Join-Path $folderResult.Path 'Videos'
            $script:config.MusicFolder = Join-Path $folderResult.Path 'Music'
            $script:config.ArchiveFolder = Join-Path $folderResult.Path 'Archives'
            $script:config.OtherFolder = Join-Path $folderResult.Path 'Other'
        }

        Write-Host "`n=== SCHEDULE CONFIGURATION ===" -ForegroundColor Cyan
        $scheduleTime = Get-TimeInput
        $scheduleConfig = Get-ScheduleType
        $script:config.ScheduleTime = $scheduleTime
        $script:config.ScheduleType = $scheduleConfig.Type
        $script:config.ScheduleDays = $scheduleConfig.Days
        $script:config.DeleteOriginalFolders = Get-DeleteOriginalFolderPreference
        $script:config | Export-Clixml -Path $ConfigFile

        $taskName = 'Transmission Cleanup'
        $taskDescription = 'Automatically organizes completed torrents from Transmission'
        $taskCommand = 'powershell.exe'
        $taskArgs = "-NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`" -RunOnly"

        $existingTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        if ($null -ne $existingTask) {
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        }

        $action = New-ScheduledTaskAction -Execute $taskCommand -Argument $taskArgs
        if ($script:config.ScheduleType -eq 'Weekly' -and $script:config.ScheduleDays.Count -gt 0) {
            $daysOfWeek = $script:config.ScheduleDays | ForEach-Object { [System.DayOfWeek]::$_ }
            $trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek $daysOfWeek -At $script:config.ScheduleTime
        }
        else {
            $trigger = New-ScheduledTaskTrigger -Daily -At $script:config.ScheduleTime
        }

        $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -DontStopOnIdleEnd -AllowStartIfOnBatteries
        $principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType S4U -RunLevel Highest
        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Description $taskDescription -Force | Out-Null

        Write-Log "Created scheduled task: $taskName" -Level INFO -NoConsole
        Write-Host "Scheduled task created successfully." -ForegroundColor Green
    }
    catch {
        Write-Log "Failed to create scheduled task: $($_.Exception.Message)" -Level ERROR
        Write-Host "Failed to create scheduled task: $($_.Exception.Message)" -ForegroundColor Red
    }

    return $true
}

function Uninstall-Script {
	 # Set title for cleanup
    $host.UI.RawUI.WindowTitle = "Transmission Cleanup - Uninstall..."
    Write-Host "`n=== TRANSMISSION CLEANUP UNINSTALLATION ===" -ForegroundColor Cyan
    
    # Redirect logs to desktop during uninstallation
    if (-not (Test-Path -LiteralPath $script:LogsDir)) {
        New-Item -ItemType Directory -Path $script:LogsDir -Force | Out-Null
    }
    $uninstallLogFile = Join-Path -Path $script:LogsDir -ChildPath "TransmissionCleanupUninstall.log"
    
    Write-Log "Starting uninstallation process" -Level INFO -LogFile $uninstallLogFile -NoConsole
    
    # Remove scheduled task
    try {
        $taskName = "Transmission Cleanup"
        
        # Try using PowerShell cmdlet first
        try {
            $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
            if ($null -ne $task) {
                Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
                Write-Log "Removed scheduled task: $taskName" -Level INFO -LogFile $uninstallLogFile -NoConsole
                Write-Host "✓ Removed scheduled task" -ForegroundColor Green
            }
        }
        catch {
            Write-Log "Failed to remove task using PowerShell cmdlet: $($_.Exception.Message)" -Level WARN -LogFile $uninstallLogFile -NoConsole
            
            # Try using schtasks.exe as fallback
            try {
                $null = schtasks.exe /Delete /TN $taskName /F 2>&1
                Write-Log "Removed scheduled task using schtasks.exe: $taskName" -Level INFO -LogFile $uninstallLogFile -NoConsole
                Write-Host "✓ Removed scheduled task" -ForegroundColor Green
            }
            catch {
                Write-Log "Failed to remove task using schtasks.exe: $($_.Exception.Message)" -Level WARN -LogFile $uninstallLogFile -NoConsole
            }
        }
    }
    catch {
        Write-Log "Error during task removal: $($_.Exception.Message)" -Level ERROR -LogFile $uninstallLogFile -NoConsole
    }
    
    # Remove Start Menu shortcuts
    try {
        if (Test-Path $shortcutFolder) {
            Remove-Item -Path $shortcutFolder -Recurse -Force
            Write-Log "Removed Start Menu shortcuts" -Level INFO -LogFile $uninstallLogFile -NoConsole
            Write-Host "✓ Removed Start Menu shortcuts" -ForegroundColor Green
        }
    }
    catch {
        Write-Log "Failed to remove shortcuts: $($_.Exception.Message)" -Level ERROR -LogFile $uninstallLogFile -NoConsole
    }
    
    # Remove the entire Transmission folder in AppData
    try {
        $transmissionFolder = Split-Path -Path $InstallDir -Parent
        
        if (Test-Path $transmissionFolder) {
            # Try standard removal first
            try {
                Remove-Item -Path $transmissionFolder -Recurse -Force
                Write-Log "Removed Transmission folder: $transmissionFolder" -Level INFO -LogFile $uninstallLogFile -NoConsole
                Write-Host "✓ Removed Transmission folder" -ForegroundColor Green
            }
            catch {
                Write-Log "Failed to remove Transmission folder with standard method: $($_.Exception.Message)" -Level WARN -LogFile $uninstallLogFile -NoConsole
                
                # Try alternative removal methods
                try {
                    # Try using cmd.exe rd command
                    $null = cmd.exe /c rd /s /q "$transmissionFolder" 2>&1
                    Write-Log "Removed Transmission folder using cmd.exe: $transmissionFolder" -Level INFO -LogFile $uninstallLogFile -NoConsole
                    Write-Host "✓ Removed Transmission folder" -ForegroundColor Green
                }
                catch {
                    Write-Log "Failed to remove Transmission folder with cmd.exe: $($_.Exception.Message)" -Level ERROR -LogFile $uninstallLogFile -NoConsole
                }
            }
        }
    }
    catch {
        Write-Log "Error during Transmission folder removal: $($_.Exception.Message)" -Level ERROR -LogFile $uninstallLogFile -NoConsole
    }
    
    Write-Host "✓ Uninstallation completed successfully!" -ForegroundColor Green
    Write-Host "Uninstallation log saved to: $uninstallLogFile" -ForegroundColor Cyan
    
    # Wait for key press before exiting
    Wait-ForKeyPress
    
    return $true
}

function Start-Cleanup {
	 # Set title for cleanup
    $host.UI.RawUI.WindowTitle = "Transmission Cleanup - Running..."
    Write-Log "Starting cleanup process" -Level INFO
    
    # Get credentials
    $cred = Get-TransmissionCredential
    if ($null -eq $cred) {
        Write-Log "Failed to get credentials" -Level ERROR
        Write-Host "✗ Failed to get credentials" -ForegroundColor Red
        return
    }
    
    Write-Log "Credentials loaded successfully" -Level INFO
    
    # Get completed torrents
    $torrents = Get-TorrentList -Credential $cred
    if ($null -eq $torrents) {
        Write-Log "Failed to get torrent list" -Level ERROR
        Write-Host "✗ Failed to get torrent list" -ForegroundColor Red
        return
    }
    $torrents = @($torrents)
    
    $completedTorrents = Get-CompletedTorrents -Torrents $torrents -Credential $cred
    if ($completedTorrents.Count -eq 0) {
        Write-Log "No completed torrents found" -Level INFO
        Write-Host "✓ No completed torrents found" -ForegroundColor Green
        return
    }
    
    # Process each completed torrent
    $totalProcessed = 0
    $totalSuccess = 0
    $totalFailed = 0
    $sessionId = ""
    
    foreach ($torrent in $completedTorrents) {
        $torrentName = $torrent.name
        Write-Log "Processing torrent: $torrentName" -Level INFO
        
        # Organize files
        $result = Organize-Files -Torrent $torrent -WhatIf:$WhatIf
        
        Write-Log "Torrent: $torrentName - Kept: $($result.Kept.Count), Deleted: $($result.Deleted.Count), Failed: $($result.Failed.Count)" -Level INFO
        
        $touchedCount = @($result.Organized).Count + @($result.Kept).Count + @($result.Deleted).Count
        $sourceGoneOrEmpty = Test-TorrentDataAbsentOrEmpty -Torrent $torrent
        $canRemoveTorrent = (($sourceGoneOrEmpty) -or (($touchedCount -gt 0) -and @($result.Failed).Count -eq 0))

        if ($canRemoveTorrent) {
            if ($sourceGoneOrEmpty -and $touchedCount -eq 0) {
                Write-Log "Torrent source is missing or empty, so the torrent will still be removed from Transmission." -Level INFO
                if (@($result.Failed).Count -gt 0) {
                    Write-Log "Ignoring source-missing file failures because the torrent source path no longer exists or is empty." -Level WARN
                }
            }
            else {
                Write-Log "Torrent processed successfully. Organized: $($result.Organized.Count), Kept: $($result.Kept.Count), Deleted: $($result.Deleted.Count)" -Level INFO
            }
            
            # Remove torrent from Transmission (keep local data)
            if (-not $WhatIf) {
                $removed = Remove-Torrent -TorrentId $torrent.id -TorrentName $torrentName -Credential $cred -SessionId $sessionId
                if ($removed) {
                    Write-Log "Successfully removed torrent from Transmission" -Level INFO
                    $totalSuccess++
                }
                else {
                    Write-Log "Failed to remove torrent from Transmission" -Level WARN
                    $totalFailed++
                }
            }
            else {
                Write-Log "WhatIf: Would remove torrent from Transmission" -Level INFO
                $totalSuccess++
            }
        }
        else {
            Write-Log "Torrent not removed. Touched: $touchedCount, SourceGoneOrEmpty: $sourceGoneOrEmpty, Failed: $(@($result.Failed).Count)" -Level WARN
            $totalFailed++
        }
        
        $totalProcessed++
    }
    
    # Summary
    Write-Log "Cleanup completed. Processed: $totalProcessed, Success: $totalSuccess, Failed: $totalFailed" -Level INFO
    Write-Host "✓ Cleanup completed. Processed: $totalProcessed, Success: $totalSuccess, Failed: $totalFailed" -ForegroundColor Green
    
    # Wait for key press before exiting
    Wait-ForKeyPress
}

#endregion

#region MAIN EXECUTION


function Get-EmbeddedScriptVersion {
    param(
        [string]$Path
    )

    try {
        if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path)) {
            return $null
        }

        $head = Get-Content -LiteralPath $Path -TotalCount 120 -ErrorAction Stop
        foreach ($line in $head) {
            if ($line -match '^\s*\$ScriptVersion\s*=\s*"([^"]+)"') {
                return $Matches[1]
            }
        }

        foreach ($line in $head) {
            if ($line -match '^\s*Version:\s*([0-9][0-9A-Za-z\.\-_]*)') {
                return $Matches[1]
            }
        }

        return $null
    }
    catch {
        Write-Log "Could not read embedded script version from '$Path': $($_.Exception.Message)" -Level WARN -NoConsole
        return $null
    }
}

function Sync-InstalledScript {
    param(
        [switch]$NoConsole
    )

    try {
        $currentScript = Get-ScriptPath

        if ([string]::IsNullOrWhiteSpace($currentScript) -or -not (Test-Path -LiteralPath $currentScript)) {
            Write-Log "Sync-InstalledScript skipped: current script path could not be determined." -Level WARN -NoConsole:$NoConsole
            return $false
        }

        if ([string]::IsNullOrWhiteSpace($ScriptPath)) {
            Write-Log "Sync-InstalledScript skipped: install ScriptPath is empty." -Level WARN -NoConsole:$NoConsole
            return $false
        }

        if ($currentScript -eq $ScriptPath) {
            Write-Log "Sync-InstalledScript: already running from installed path. Version $ScriptVersion." -Level DEBUG -NoConsole:$NoConsole
            return $true
        }

        if (-not (Test-Path -LiteralPath $InstallDir)) {
            New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
            Write-Log "Created install directory during sync: $InstallDir" -Level INFO -NoConsole:$NoConsole
        }

        $installedExists = Test-Path -LiteralPath $ScriptPath
        $updateRequired = $true
        $reason = "Fresh install copy required"

        if ($installedExists) {
            $sourceVersionText = Get-EmbeddedScriptVersion -Path $currentScript
            $installedVersionText = Get-EmbeddedScriptVersion -Path $ScriptPath
            $sourceVersion = $null
            $installedVersion = $null

            if (-not [string]::IsNullOrWhiteSpace($sourceVersionText)) {
                try { $sourceVersion = [version]$sourceVersionText } catch {}
            }
            if (-not [string]::IsNullOrWhiteSpace($installedVersionText)) {
                try { $installedVersion = [version]$installedVersionText } catch {}
            }

            if ($sourceVersion -and $installedVersion) {
                if ($sourceVersion -gt $installedVersion) {
                    $updateRequired = $true
                    $reason = "Version upgrade $installedVersionText -> $sourceVersionText"
                }
                elseif ($sourceVersion -eq $installedVersion) {
                    $srcTime = (Get-Item -LiteralPath $currentScript).LastWriteTimeUtc
                    $dstTime = (Get-Item -LiteralPath $ScriptPath).LastWriteTimeUtc
                    if ($srcTime -gt $dstTime) {
                        $updateRequired = $true
                        $reason = "Same version $sourceVersionText but newer file date"
                    }
                    else {
                        $updateRequired = $false
                        $reason = "Already up to date (version $sourceVersionText)"
                    }
                }
                else {
                    $updateRequired = $false
                    $reason = "Installed version $installedVersionText is newer than current file version $sourceVersionText"
                }
            }
            else {
                try {
                    $srcItem = Get-Item -LiteralPath $currentScript -ErrorAction Stop
                    $dstItem = Get-Item -LiteralPath $ScriptPath -ErrorAction Stop
                    if ($srcItem.LastWriteTimeUtc -gt $dstItem.LastWriteTimeUtc) {
                        $updateRequired = $true
                        $reason = "Newer source file date detected"
                    }
                    else {
                        $updateRequired = $false
                        $reason = "Already up to date (file date check)"
                    }
                }
                catch {
                    $updateRequired = $true
                    $reason = "Unable to compare dates cleanly; forcing refresh"
                }
            }
        }

        if (-not $updateRequired) {
            Write-Log $reason -Level INFO -NoConsole:$NoConsole
            if (-not $NoConsole) {
                Write-Host "✓ $reason" -ForegroundColor Green
            }
            return $true
        }

        $backupPath = $null
        if ($installedExists) {
            $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
            $backupPath = Join-Path -Path $InstallDir -ChildPath ("TransmissionCleanup_backup_{0}.ps1" -f $stamp)
            Copy-Item -LiteralPath $ScriptPath -Destination $backupPath -Force
            Write-Log "Created backup of installed script: $backupPath" -Level INFO -NoConsole:$NoConsole

            $stableBackup = Join-Path -Path $InstallDir -ChildPath "TransmissionCleanup_previous.ps1"
            Copy-Item -LiteralPath $ScriptPath -Destination $stableBackup -Force
            Write-Log "Updated rollback copy: $stableBackup" -Level DEBUG -NoConsole:$NoConsole
        }

        $tempPath = Join-Path -Path $InstallDir -ChildPath "TransmissionCleanup.update.tmp.ps1"
        Copy-Item -LiteralPath $currentScript -Destination $tempPath -Force

        $srcHash = (Get-FileHash -LiteralPath $currentScript -Algorithm SHA256).Hash
        $tmpHash = (Get-FileHash -LiteralPath $tempPath -Algorithm SHA256).Hash
        if ($srcHash -ne $tmpHash) {
            throw "Temporary updated script failed hash verification."
        }

        Copy-Item -LiteralPath $tempPath -Destination $ScriptPath -Force

        $dstHash = (Get-FileHash -LiteralPath $ScriptPath -Algorithm SHA256).Hash
        if ($srcHash -ne $dstHash) {
            throw "Installed script failed hash verification after copy."
        }

        Remove-Item -LiteralPath $tempPath -Force -ErrorAction SilentlyContinue

        Write-Log "Updated installed script copy: $ScriptPath ($reason)" -Level INFO -NoConsole:$NoConsole
        if (-not $NoConsole) {
            Write-Host "✓ Updated installed script copy." -ForegroundColor Green
        }

        return $true
    }
    catch {
        $syncError = $_.Exception.Message
        Write-Log "Failed to sync installed script copy: $syncError" -Level ERROR -NoConsole:$NoConsole

        try {
            $rollbackCandidate = Get-ChildItem -LiteralPath $InstallDir -Filter 'TransmissionCleanup_backup_*.ps1' -ErrorAction SilentlyContinue |
                Sort-Object LastWriteTime -Descending |
                Select-Object -First 1

            if (-not $rollbackCandidate) {
                $stableRollback = Join-Path -Path $InstallDir -ChildPath 'TransmissionCleanup_previous.ps1'
                if (Test-Path -LiteralPath $stableRollback) {
                    $rollbackCandidate = Get-Item -LiteralPath $stableRollback -ErrorAction Stop
                }
            }

            if ($rollbackCandidate -and (Test-Path -LiteralPath $rollbackCandidate.FullName)) {
                Copy-Item -LiteralPath $rollbackCandidate.FullName -Destination $ScriptPath -Force
                Write-Log "Rolled back installed script using backup: $($rollbackCandidate.FullName)" -Level WARN -NoConsole:$NoConsole
            }
        }
        catch {
            Write-Log "Rollback attempt failed: $($_.Exception.Message)" -Level ERROR -NoConsole:$NoConsole
        }

        try {
            $tempPath = Join-Path -Path $InstallDir -ChildPath "TransmissionCleanup.update.tmp.ps1"
            if (Test-Path -LiteralPath $tempPath) {
                Remove-Item -LiteralPath $tempPath -Force -ErrorAction SilentlyContinue
            }
        }
        catch {}

        if (-not $NoConsole) {
            Write-Host "Failed to update installed script copy: $syncError" -ForegroundColor Yellow
        }
        return $false
    }
}


# Main execution logic
try {
    Write-ErrorToFile "Main execution started - Parameters: Uninstall=$Uninstall, RunOnly=$RunOnly, Reinitialize=$Reinitialize"
    
    if (-not $Uninstall) {
        Sync-InstalledScript -NoConsole:$RunOnly | Out-Null
    }
    
    if ($Uninstall) {
        $success = Uninstall-Script
        if (-not $success) {
            Write-Host "✗ Uninstallation failed. Please check the log for details." -ForegroundColor Red
        }
    }
    elseif ($RunOnly) {
        Start-Cleanup
    }
    elseif ($Reinitialize) {
        $cred = Reset-TransmissionCredential
        if ($null -eq $cred) {
            Write-Host "✗ Failed to reset credentials" -ForegroundColor Red
        }
        else {
            Write-Host "✓ Credentials reset successfully" -ForegroundColor Green
        }
        
        # Wait-ForKeyPress is now called inside Reset-TransmissionCredential
    }
    else {
        $currentScript = Get-ScriptPath
        $isInstalled = (Test-Path -LiteralPath $ScriptPath) -and (Test-Path -LiteralPath $ConfigFile)

        if ($isInstalled -and $currentScript -ne $ScriptPath) {
            Write-Host "=== TRANSMISSION CLEANUP UPDATE ===" -ForegroundColor Cyan
            Write-Host "An existing installed copy was found in AppData." -ForegroundColor White
            Write-Host "This run has refreshed the installed script so scheduled tasks and shortcuts use the updated version." -ForegroundColor White
            Write-Host "" 

            $choices = @(
                (New-Object System.Management.Automation.Host.ChoiceDescription -ArgumentList '&Run Cleanup', 'Run cleanup now using current settings'),
                (New-Object System.Management.Automation.Host.ChoiceDescription -ArgumentList 'Re&configure', 'Open the full install/reconfigure wizard'),
                (New-Object System.Management.Automation.Host.ChoiceDescription -ArgumentList 'Open &Logs Folder', 'Open the Transmission Cleanup logs folder'),
                (New-Object System.Management.Automation.Host.ChoiceDescription -ArgumentList 'E&xit', 'Exit now')
            )

            $result = $host.UI.PromptForChoice("Installed copy updated", "What would you like to do next?", $choices, 0)

            if ($result -eq 0) {
                Start-Cleanup
                Wait-ForKeyPress
                exit 0
            }
            elseif ($result -eq 2) {
                Open-LogsFolder
                Wait-ForKeyPress
                exit 0
            }
            elseif ($result -eq 3) {
                Wait-ForKeyPress
                exit 0
            }
        }

        # Installation confirmation
        Write-Host "=== TRANSMISSION CLEANUP INSTALLATION ===" -ForegroundColor Cyan
        Write-Host "This script will install Transmission Cleanup to organize your torrent downloads." -ForegroundColor White
        Write-Host ""
        Write-Host "What it will do:" -ForegroundColor Yellow
        Write-Host "• Install the script to %AppData%\Transmission\AutoCleanup" -ForegroundColor White
        Write-Host "• Create Start Menu shortcuts" -ForegroundColor White
        Write-Host "• Set up a scheduled task for automatic cleanup" -ForegroundColor White
        Write-Host "• Prompt for download folder configuration" -ForegroundColor White
        Write-Host "• Ask for Transmission RPC credentials" -ForegroundColor White
        Write-Host ""
        
        $choices = @(
            (New-Object System.Management.Automation.Host.ChoiceDescription -ArgumentList '&Yes', 'Continue with installation'),
            (New-Object System.Management.Automation.Host.ChoiceDescription -ArgumentList '&No', 'Cancel and exit')
        )
        
        $result = $host.UI.PromptForChoice("Continue Installation?", "Do you want to proceed with the installation?", $choices, 0)
        
        Write-DebugLog "User choice result: $result" # Debug output
        
        if ($result -ne 0) {
            Write-Host "✗ Installation cancelled by user." -ForegroundColor Yellow
            Write-DebugLog "Installation cancelled - exiting with code 0"
            
            # Don't create any log files if user cancelled
            try {
                Write-Host "Installation was cancelled before any files were created." -ForegroundColor Green
            } catch {}
            
            Wait-ForKeyPress "Press any key to exit..."
            exit 0
        }
        
        Write-Host "✓ Proceeding with installation..." -ForegroundColor Green
        Write-Host ""
        
        # Now ensure log directory exists (only after user confirms installation)
        $logParent = Split-Path -Path $script:config.LogFile -Parent
        if (-not (Test-Path $logParent)) {
            New-Item -ItemType Directory -Path $logParent -Force | Out-Null
        }
        
        $success = Install-Script
        if ($success) {
            Write-Host "✓ Installation completed successfully!" -ForegroundColor Green
            
            # Get credentials if not already set
            if (-not (Test-Path $CredentialFile)) {
                $cred = Get-TransmissionCredential
                if ($null -eq $cred) {
                    Write-Host "✗ Failed to set credentials" -ForegroundColor Red
                }
            }
            
            # Offer a connection test before cleanup / exit
            if (Test-Path $CredentialFile) {
                try {
                    $credToTest = Import-Clixml -Path $CredentialFile
                }
                catch {
                    $credToTest = $null
                }
                Prompt-TransmissionConnectionTest -Credential $credToTest -RpcUrl $script:config.RpcUrl | Out-Null
            }

            # Ask if user wants to run cleanup now
            $choices = @(
                (New-Object System.Management.Automation.Host.ChoiceDescription -ArgumentList '&Yes', 'Run cleanup now'),
                (New-Object System.Management.Automation.Host.ChoiceDescription -ArgumentList 'Open &Logs Folder', 'Open the Transmission Cleanup logs folder'),
                (New-Object System.Management.Automation.Host.ChoiceDescription -ArgumentList '&No', 'Exit without running cleanup')
            )
            
            $result = $host.UI.PromptForChoice("Run Cleanup Now", "Would you like to run the cleanup process now?", $choices, 0)
            
            if ($result -eq 0) {
                Start-Cleanup
                
                # Add an extra pause after cleanup to prevent window from closing immediately
                Wait-ForKeyPress
            }
            elseif ($result -eq 1) {
                Open-LogsFolder
                Wait-ForKeyPress
            }
            else {
                # Wait for key press before exiting
                Wait-ForKeyPress
            }
        }
        else {
            Write-Host "✗ Installation failed. Please check the log for details." -ForegroundColor Red
            
            # Wait for key press before exiting
            Wait-ForKeyPress
        }
    }
}
catch {
    $errorMsg = "Unhandled exception: $($_.Exception.Message)"
    Write-ErrorToFile "MAIN EXECUTION ERROR: $errorMsg"
    Write-ErrorToFile "Stack Trace: $($_.Exception.StackTrace)"
    
    try {
        Write-Log $errorMsg -Level ERROR
    } catch {
        Write-ErrorToFile "Failed to write to main log: $($_.Exception.Message)"
    }
    
    Write-Host "✗ An error occurred: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Error details logged to: $errorLogPath" -ForegroundColor Yellow
    
    # Wait for key press before exiting
    Wait-ForKeyPress
}

#endregion
