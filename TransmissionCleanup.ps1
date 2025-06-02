<#
Copyright (c) [2025] [vampiro2004]
This software is licensed under the MIT License.

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
    [switch]$Verbose
)

# Create a debug log file on the desktop for troubleshooting self-elevation issues
function Write-DebugLog {
    param(
        [string]$Message
    )
    
    # Only write debug logs if $Verbose is specified
    if (-not $Verbose) { return }
    
    try {
        $desktopPath = [Environment]::GetFolderPath("Desktop")
        $debugLogFile = Join-Path -Path $desktopPath -ChildPath "TransmissionCleanupDebug.log"
        
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $logEntry = "[$timestamp] $Message"
        
        Add-Content -Path $debugLogFile -Value $logEntry -ErrorAction Stop
    }
    catch {
        # Silent failure - we don't want to cause more errors while logging
    }
}

# Self-execution wrapper for double-click elevation
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-DebugLog "Script started without admin privileges, attempting elevation"
    
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
            
            # Create a more reliable relaunch command - REMOVED WindowStyle Hidden to ensure window is visible
            $arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`""
            Write-DebugLog "Launch arguments: $arguments"
            
            try {
                # Launch with normal window style to ensure it's visible
                Start-Process powershell.exe -ArgumentList $arguments -Verb RunAs
                Write-DebugLog "Relaunch successful, exiting current instance"
            }
            catch {
                $errorMsg = "Failed to start elevated process: $($_.Exception.Message)"
                Write-DebugLog $errorMsg
                Write-Host $errorMsg -ForegroundColor Red
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

#region CONFIGURATION
# Get the current script path reliably
function Get-ScriptPath {
    # Try multiple methods to get the script path
    $scriptPath = $null
    
    # Method 1: Using $MyInvocation (works in most contexts)
    if ($null -ne $MyInvocation.MyCommand.Path -and $MyInvocation.MyCommand.Path -ne "") {
        $scriptPath = $MyInvocation.MyCommand.Path
        Write-DebugLog "Script path found using MyInvocation.MyCommand.Path: $scriptPath"
    }
    # Method 2: Using $PSCommandPath (works in PS 3.0+)
    elseif ($null -ne $PSCommandPath -and $PSCommandPath -ne "") {
        $scriptPath = $PSCommandPath
        Write-DebugLog "Script path found using PSCommandPath: $scriptPath"
    }
    # Method 3: Using $script:PSCommandPath (another variant)
    elseif ($null -ne $script:PSCommandPath -and $script:PSCommandPath -ne "") {
        $scriptPath = $script:PSCommandPath
        Write-DebugLog "Script path found using script:PSCommandPath: $scriptPath"
    }
    # Method 4: Using current location and script name
    else {
        $scriptName = "fixed_script_final.ps1"
        $possiblePath = Join-Path -Path (Get-Location).Path -ChildPath $scriptName
        if (Test-Path $possiblePath) {
            $scriptPath = $possiblePath
            Write-DebugLog "Script path found using current location and script name: $scriptPath"
        }
        else {
            # Method 5: Fallback to a hardcoded path if all else fails
            Write-Host "[WARN] Could not determine script path automatically" -ForegroundColor Yellow
            Write-Host "[INFO] Using the executing script itself as the source" -ForegroundColor Cyan
            Write-DebugLog "Could not determine script path automatically"
            $scriptPath = $null
        }
    }
    
    return $scriptPath
}

$script:InstallDir    = Join-Path -Path $env:APPDATA -ChildPath "Transmission\AutoCleanup"
$script:ScriptPath     = Join-Path -Path $InstallDir -ChildPath "TransmissionCleanup.ps1"
$script:CredentialFile  = Join-Path -Path $InstallDir -ChildPath "TransmissionCredentials.xml"
$script:ConfigFile      = Join-Path -Path $InstallDir -ChildPath "TransmissionConfig.xml"
$script:HelpFile        = Join-Path -Path $InstallDir -ChildPath "TransmissionCleanupHelp.txt"
# Start Menu configuration
$startMenu = [Environment]::GetFolderPath("Programs")
$shortcutFolder = Join-Path -Path $startMenu -ChildPath "Transmission Cleanup"
# Default configuration
$script:config = @{
    RpcUrl           = "http://localhost:9091/transmission/rpc"
    DownloadFolder    = Join-Path -Path $env:USERPROFILE -ChildPath "Downloads\Torrents"
    AppsFolder        = Join-Path -Path $env:USERPROFILE -ChildPath "Downloads\Torrents\Apps"
    MediaFolder       = Join-Path -Path $env:USERPROFILE -ChildPath "Downloads\Torrents\Media"
    MusicFolder       = Join-Path -Path $env:USERPROFILE -ChildPath "Downloads\Torrents\Music"
    ArchiveFolder     = Join-Path -Path $env:USERPROFILE -ChildPath "Downloads\Torrents\Archives"
    OtherFolder       = Join-Path -Path $env:USERPROFILE -ChildPath "Downloads\Torrents\Other"
    LogFile           = Join-Path -Path $InstallDir -ChildPath "TransmissionCleanup.log"
    ScheduleTime      = "03:00"
    ScheduleDays      = @()
    ScheduleType      = "Daily"
    AppExtensions     = @(".exe", ".msi", ".dmg", ".pkg", ".app", ".apk", ".iso")
    MediaExtensions   = @(".mp4", ".mkv", ".avi", ".mov", ".jpg", ".png", ".gif", ".webp")
    MusicExtensions   = @(".mp3", ".flac", ".wav", ".aac", ".ogg", ".m4a", ".wma")
    ArchiveExtensions = @(".zip", ".rar", ".7z", ".tar", ".gz", ".bz2")
    MaxRpcRetries     = 3
    RpcRetryDelay     = 5
    # Completion criteria - always use PercentDone
    CompletionCriteria = "PercentDone"
    # New setting to delete original folders after files are moved
    DeleteOriginalFolders = $true
}
# Load configuration if it exists
if (Test-Path $ConfigFile) {
    try {
        $script:config = Import-Clixml -Path $ConfigFile
        # Ensure critical paths are set
        if (-not $script:config.LogFile) { 
            $script:config.LogFile = Join-Path -Path $InstallDir -ChildPath "TransmissionCleanup.log" 
        }
        if (-not $script:config.DownloadFolder) { 
            $script:config.DownloadFolder = Join-Path -Path $env:USERPROFILE -ChildPath "Downloads\Torrents" 
        }
        # Update subfolder paths based on download folder
        $baseFolder = $script:config.DownloadFolder
        $script:config.AppsFolder     = Join-Path -Path $baseFolder -ChildPath "Apps"
        $script:config.MediaFolder    = Join-Path -Path $baseFolder -ChildPath "Media"
        $script:config.MusicFolder    = Join-Path -Path $baseFolder -ChildPath "Music"
        $script:config.ArchiveFolder  = Join-Path -Path $baseFolder -ChildPath "Archives"
        $script:config.OtherFolder    = Join-Path -Path $baseFolder -ChildPath "Other"
        
        # Force completion criteria to PercentDone
        $script:config.CompletionCriteria = "PercentDone"
        
        # Ensure the DeleteOriginalFolders setting exists
        if (-not [bool]::TryParse($script:config.DeleteOriginalFolders, [ref]$null)) {
            $script:config.DeleteOriginalFolders = $true
        }
        
        # Ensure RPC URL is set
        if ([string]::IsNullOrEmpty($script:config.RpcUrl)) {
            $script:config.RpcUrl = "http://localhost:9091/transmission/rpc"
        }
        
        # Ensure Music folder and extensions exist (for backward compatibility)
        if (-not $script:config.MusicFolder) {
            $script:config.MusicFolder = Join-Path -Path $baseFolder -ChildPath "Music"
        }
        if (-not $script:config.MusicExtensions -or $script:config.MusicExtensions.Count -eq 0) {
            $script:config.MusicExtensions = @(".mp3", ".flac", ".wav", ".aac", ".ogg", ".m4a", ".wma")
            
            # Remove music extensions from media extensions if they exist there
            if ($script:config.MediaExtensions) {
                $script:config.MediaExtensions = $script:config.MediaExtensions | Where-Object { 
                    $ext = $_
                    -not ($script:config.MusicExtensions -contains $ext)
                }
            }
        }
    }
    catch {
        Write-Host "Warning: Could not load config file. Using defaults." -ForegroundColor Yellow
        Write-Log "Config load error: $($_.Exception.Message)" -Level WARN
    }
}
#endregion

#region HELPER FUNCTIONS

#-- Add basic log rotation: limit log file to 2MB --
function Rotate-Log {
    param(
        [Parameter(Mandatory=$true)]
        [string]$LogFile
    )
    
    if (Test-Path $LogFile) {
        $size = (Get-Item $LogFile).Length
        if ($size -gt 2MB) {
            Move-Item -Path $LogFile -Destination ("$LogFile.old") -Force
        }
    }
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
        # If no log file is specified, use the default from config
        if ([string]::IsNullOrEmpty($LogFile)) {
            $LogFile = $script:config.LogFile
            
            # During uninstallation, redirect logs to desktop
            if ($Uninstall) {
                $desktopPath = [Environment]::GetFolderPath("Desktop")
                $LogFile = Join-Path -Path $desktopPath -ChildPath "TransmissionCleanupUninstall.log"
            }
        }
        
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $logEntry = "[$timestamp][$Level] $Message"
        
        # Ensure log directory exists
        $logDir = Split-Path $LogFile -Parent
        if (-not (Test-Path $logDir)) { 
            New-Item -ItemType Directory -Path $logDir -Force | Out-Null 
        }
        
        Rotate-Log -LogFile $LogFile
        Add-Content -Path $LogFile -Value $logEntry -ErrorAction Stop
        
        # Only write to console if not DEBUG or if $Verbose is set, and NoConsole is not specified
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
        [string]$DefaultPath
    )
    try {
        Add-Type -AssemblyName System.Windows.Forms
        $dialog = New-Object System.Windows.Forms.FolderBrowserDialog
        $dialog.Description = $Prompt
        $dialog.SelectedPath = if (Test-Path $DefaultPath) { $DefaultPath } else { [Environment]::GetFolderPath("MyDocuments") }
        $dialog.ShowNewFolderButton = $true
        if ($dialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            return $dialog.SelectedPath
        } else {
            return $DefaultPath
        }
    }
    catch {
        Write-Log "Folder selection failed: $($_.Exception.Message)" -Level WARN
        return $DefaultPath
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
        [System.Management.Automation.Host.ChoiceDescription]::new("&Change", "Change the RPC URL"),
        [System.Management.Automation.Host.ChoiceDescription]::new("&Keep", "Keep the current RPC URL")
    )
    
    $result = $host.UI.PromptForChoice("Transmission RPC URL", "Would you like to change the Transmission RPC URL?", $choices, 1)
    
    if ($result -eq 0) {
        do {
            $newUrl = Read-Host "Enter Transmission RPC URL (e.g., http://localhost:9091/transmission/rpc)"
            
            if ([string]::IsNullOrWhiteSpace($newUrl)) {
                Write-Host "Using default URL: $DefaultUrl" -ForegroundColor Yellow
                return $DefaultUrl
            }
            
            # Basic URL validation
            if ($newUrl -match "^https?://.*?/.*$") {
                return $newUrl
            }
            
            Write-Host "Invalid URL format. Please enter a valid URL (e.g., http://localhost:9091/transmission/rpc)" -ForegroundColor Red
        } while ($true)
    }
    
    return $DefaultUrl
}

function Get-DeleteOriginalFolderPreference {
    $choices = @(
        [System.Management.Automation.Host.ChoiceDescription]::new("&Yes", "Delete original folders after files are moved"),
        [System.Management.Automation.Host.ChoiceDescription]::new("&No", "Keep original folders after files are moved")
    )
    
    $result = $host.UI.PromptForChoice("Delete Original Folders", "Should the script delete original folders after files are moved?", $choices, 0)
    
    return ($result -eq 0)
}

#-- GUI/CLI hybrid for weekly schedule with improved error handling --
function Get-ScheduleType {
    # Try Out-GridView, else use text selection
    $choices = @(
        [System.Management.Automation.Host.ChoiceDescription]::new("&Daily", "Run the task every day"),
        [System.Management.Automation.Host.ChoiceDescription]::new("&Weekly", "Run the task on specific days each week")
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
    
    return $cred
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
        [System.Management.Automation.Host.ChoiceDescription]::new("&Yes", "Change the download folder location"),
        [System.Management.Automation.Host.ChoiceDescription]::new("&No", "Keep the current download folder location")
    )
    
    $result = $host.UI.PromptForChoice("Change Download Folder", "Would you like to change the download folder location?", $choices, 1)
    
    if ($result -eq 0) {
        $newFolder = Get-FolderSelection -Prompt "Select Download Folder" -DefaultPath $script:config.DownloadFolder
        if ($newFolder -ne $script:config.DownloadFolder) {
            $script:config.DownloadFolder = $newFolder
            
            # Update subfolder paths
            $script:config.AppsFolder = Join-Path -Path $newFolder -ChildPath "Apps"
            $script:config.MediaFolder = Join-Path -Path $newFolder -ChildPath "Media"
            $script:config.MusicFolder = Join-Path -Path $newFolder -ChildPath "Music"
            $script:config.ArchiveFolder = Join-Path -Path $newFolder -ChildPath "Archives"
            $script:config.OtherFolder = Join-Path -Path $newFolder -ChildPath "Other"
            
            # Save updated config
            try {
                $script:config | Export-Clixml -Path $ConfigFile
                Write-Host "Configuration updated with new download folder: $newFolder" -ForegroundColor Green
            }
            catch {
                Write-Log "Failed to save updated configuration: $($_.Exception.Message)" -Level ERROR
                Write-Host "Failed to save updated configuration: $($_.Exception.Message)" -ForegroundColor Red
            }
        }
    }
    
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
    
    $rpcUrl = $script:config.RpcUrl
    Write-Log "RPC URL: $rpcUrl" -Level DEBUG
    
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
            
            # Make the request
            $response = $webClient.UploadString($rpcUrl, $body)
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
        
        $torrents = $result.arguments.torrents
        Write-Log "Total torrents: $($torrents.Count)" -Level INFO
        
        return $torrents
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
    
    if ($script:config.AppExtensions -contains $extension) {
        return "App"
    }
    elseif ($script:config.MusicExtensions -contains $extension) {
        return "Music"
    }
    elseif ($script:config.MediaExtensions -contains $extension) {
        return "Media"
    }
    elseif ($script:config.ArchiveExtensions -contains $extension) {
        return "Archive"
    }
    else {
        return "Other"
    }
}

function Get-DestinationFolder {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Category
    )
    
    switch ($Category) {
        "App" { return $script:config.AppsFolder }
        "Media" { return $script:config.MediaFolder }
        "Music" { return $script:config.MusicFolder }
        "Archive" { return $script:config.ArchiveFolder }
        default { return $script:config.OtherFolder }
    }
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
    
    # Process each file in the torrent
    $organizedFiles = @()
    $failedFiles = @()
    
    foreach ($file in $Torrent.files) {
        $filePath = Join-Path -Path $downloadDir -ChildPath $file.name
        $fileName = Split-Path -Path $file.name -Leaf
        
        Write-Log "Processing file: $fileName" -Level DEBUG
        
        # Determine file category and destination
        $category = Get-FileCategory -FilePath $filePath
        $destFolder = Get-DestinationFolder -Category $category
        $destPath = Join-Path -Path $destFolder -ChildPath $fileName
        
        Write-Log "File category: $category, Destination: $destPath" -Level DEBUG
        
        # Move the file
        if ($WhatIf) {
            Write-Log "WhatIf: Would move $filePath to $destPath" -Level INFO
            $organizedFiles += $file.name
        }
        else {
            $success = Cut-FileWithRetry -Source $filePath -Destination $destPath -MaxRetries $MaxRetries -RetryDelay $RetryDelay
            
            if ($success) {
                $organizedFiles += $file.name
            }
            else {
                $failedFiles += $file.name
            }
        }
    }
    
    # Delete original folder if empty and configured to do so
    if ($script:config.DeleteOriginalFolders -and -not $WhatIf) {
        try {
            # Check if the folder is empty
            $folderPath = Join-Path -Path $downloadDir -ChildPath $torrentName
            if (Test-Path $folderPath) {
                $items = Get-ChildItem -Path $folderPath -Force -ErrorAction SilentlyContinue
                
                if ($null -eq $items -or $items.Count -eq 0) {
                    Write-Log "Deleting empty folder: $folderPath" -Level INFO
                    Remove-Item -Path $folderPath -Force -Recurse -ErrorAction SilentlyContinue
                }
                else {
                    Write-Log "Folder not empty, skipping deletion: $folderPath" -Level INFO
                }
            }
        }
        catch {
            Write-Log "Error checking/deleting folder: $($_.Exception.Message)" -Level WARN
        }
    }
    
    # Return results
    return @{
        Organized = $organizedFiles
        Failed = $failedFiles
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

function Install-Script {
	# Set title for installation
    $host.UI.RawUI.WindowTitle = "Transmission Cleanup - Installation"
    # Get the current script path
    $currentScript = Get-ScriptPath
    Write-Log "Install-Script function | InstallDir = '$InstallDir'" -Level DEBUG -NoConsole
    Write-Log "Current script path | currentScript = '$currentScript'" -Level DEBUG -NoConsole
    Write-Log "Install-Script function | ScriptPath = '$ScriptPath'" -Level DEBUG -NoConsole
    
    # Create installation directory if it doesn't exist
    if (-not (Test-Path $InstallDir)) {
        try {
            New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
            Write-Log "Created installation directory: $InstallDir" -Level INFO -NoConsole
        }
        catch {
            Write-Log "Failed to create installation directory: $($_.Exception.Message)" -Level ERROR
            Write-Host "✗ Failed to create installation directory: $($_.Exception.Message)" -ForegroundColor Red
            return $false
        }
    }
    
    # Copy the script to the installation directory
    try {
        Write-Log "Copying script to installation directory | ScriptPath = '$ScriptPath'" -Level DEBUG -NoConsole
        
        if ($null -ne $currentScript -and (Test-Path $currentScript)) {
            Copy-Item -Path $currentScript -Destination $ScriptPath -Force
            Write-Log "Copied script to: $ScriptPath" -Level INFO -NoConsole
        }
        else {
            # If we can't determine the script path, create it directly
            Write-Log "Creating script directly in destination" -Level WARN -NoConsole
            
            # Get the content of the current script
            $scriptContent = Get-Content -Path $MyInvocation.ScriptName -Raw -ErrorAction SilentlyContinue
            
            if ([string]::IsNullOrEmpty($scriptContent)) {
                # Create a minimal script if we can't get the content
                $scriptContent = @"
<#
.SYNOPSIS
    Transmission Auto-Cleanup with Full Automation
.DESCRIPTION
    This is a placeholder script created during installation.
    Please reinstall the script properly.
#>

Write-Host "This is a placeholder script. Please reinstall Transmission Cleanup properly." -ForegroundColor Red
"@
            }
            
            # Write the content to the destination
            Set-Content -Path $ScriptPath -Value $scriptContent -Force
        }
    }
    catch {
        Write-Log "Failed to copy script: $($_.Exception.Message)" -Level ERROR
        Write-Log "Failed to copy script | Exception = '$($_.Exception.Message)'" -Level DEBUG -NoConsole
        Write-Host "✗ Failed to copy script: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
    
    # Create the help file
    try {
        $helpContent = @"
=== TRANSMISSION CLEANUP HELP ===

OVERVIEW
--------
Transmission Cleanup is a utility that automatically organizes completed torrents from Transmission into category folders.
It can be run manually or scheduled to run automatically at specified times.

FEATURES
--------
- Automatically organizes completed torrents into category folders (Apps, Media, Music, Archives, Other)
- Removes torrents from Transmission after organizing (keeps downloaded files)
- Scheduled task for automatic cleanup
- Secure credential storage for Transmission RPC access

CONFIGURATION
------------
- RPC URL: The URL to connect to Transmission's RPC interface (default: http://localhost:9091/transmission/rpc)
- Download Folder: The main folder where torrents are downloaded
- Category Folders: Subfolders for organizing files by type
- Schedule: When the automatic cleanup should run

SCHEDULED TASK HISTORY
---------------------
Task history may be disabled by default in Windows Task Scheduler. To enable history:

1. Using Task Scheduler GUI:
   a. Open Task Scheduler (taskschd.msc)
   b. Go to Task Scheduler Library
   c. Find the "Transmission Cleanup" task
   d. Right-click and select "Properties"
   e. Go to the "History" tab
   f. Click "Enable All Tasks History" in the right panel

2. Using Command Line:
   Open an elevated Command Prompt and run:
   wevtutil set-log Microsoft-Windows-TaskScheduler/Operational /enabled:true

Enabling history allows you to track when the cleanup task ran and whether it completed successfully.

SHORTCUTS
---------
The following shortcuts are created in the Start Menu:
- Run Cleanup: Manually runs the cleanup process
- Reset Credentials: Resets the stored Transmission credentials
- View Log File: Opens the log file in Notepad
- Help: Opens this help file
- Uninstall: Completely removes Transmission Cleanup

TROUBLESHOOTING
--------------
- Check the log file for detailed error messages
- Verify Transmission is running and accessible
- Ensure your credentials are correct
- Check Task Scheduler for errors if scheduled tasks aren't running
- Make sure the download folder exists and is accessible

For additional help, please contact the script author.
"@
        
        Set-Content -Path $HelpFile -Value $helpContent -Force
        Write-Log "Created help file: $HelpFile" -Level INFO -NoConsole
    }
    catch {
        Write-Log "Failed to create help file: $($_.Exception.Message)" -Level WARN -NoConsole
        # Non-critical error, continue with installation
    }
    
    # Create Start Menu shortcuts
    try {
        # Create the Start Menu folder if it doesn't exist
        if (-not (Test-Path $shortcutFolder)) {
            New-Item -ItemType Directory -Path $shortcutFolder -Force | Out-Null
        }
        
        # Define icon locations
        $shell32 = "$env:SystemRoot\System32\shell32.dll"
        $imageres = "$env:SystemRoot\System32\imageres.dll"
        
        # Create the Run Cleanup shortcut with icon
        $runShortcutPath = Join-Path -Path $shortcutFolder -ChildPath "Run Cleanup.lnk"
        New-Shortcut -Path $runShortcutPath `
                    -TargetPath "powershell.exe" `
                    -Arguments "-NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`" -RunOnly" `
                    -Description "Run Transmission Cleanup" `
                    -WindowStyle "Normal" `
                    -IconLocation "$imageres,109" `
                    -RunAsAdmin $true
        
        # Create the Reset Credentials shortcut with icon
        $resetShortcutPath = Join-Path -Path $shortcutFolder -ChildPath "Reset Credentials.lnk"
        New-Shortcut -Path $resetShortcutPath `
                    -TargetPath "powershell.exe" `
                    -Arguments "-NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`" -Reinitialize" `
                    -Description "Reset Transmission Credentials" `
                    -WindowStyle "Normal" `
                    -IconLocation "$shell32,235" `
                    -RunAsAdmin $true
        
        # Create the View Log shortcut with icon
        $logShortcutPath = Join-Path -Path $shortcutFolder -ChildPath "View Log File.lnk"
        New-Shortcut -Path $logShortcutPath `
                    -TargetPath "notepad.exe" `
                    -Arguments "`"$($script:config.LogFile)`"" `
                    -Description "View Transmission Cleanup Log" `
                    -WindowStyle "Normal" `
                    -IconLocation "$shell32,70" `
                    -RunAsAdmin $false
        
        # Create the Help shortcut with icon
        $helpShortcutPath = Join-Path -Path $shortcutFolder -ChildPath "Help.lnk"
        New-Shortcut -Path $helpShortcutPath `
                    -TargetPath "notepad.exe" `
                    -Arguments "`"$HelpFile`"" `
                    -Description "Transmission Cleanup Help" `
                    -WindowStyle "Normal" `
                    -IconLocation "$shell32,23" `
                    -RunAsAdmin $false
        
        # Create the Uninstall shortcut with icon
        $uninstallShortcutPath = Join-Path -Path $shortcutFolder -ChildPath "Uninstall.lnk"
        New-Shortcut -Path $uninstallShortcutPath `
                    -TargetPath "powershell.exe" `
                    -Arguments "-NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`" -Uninstall" `
                    -Description "Uninstall Transmission Cleanup" `
                    -WindowStyle "Normal" `
                    -IconLocation "$imageres,99" `
                    -RunAsAdmin $true
        
        Write-Log "Created Start Menu shortcuts with icons" -Level INFO -NoConsole
        Write-Host "✓ Created Start Menu shortcuts with icons" -ForegroundColor Green
    }
    catch {
        Write-Log "Failed to create shortcuts: $($_.Exception.Message)" -Level ERROR
        Write-Host "✗ Failed to create shortcuts: $($_.Exception.Message)" -ForegroundColor Red
        # Non-critical error, continue with installation
    }
    
    # Create scheduled task
    try {
        # REMOVED RPC URL prompt from installation
        # $script:config.RpcUrl = Get-RpcUrlInput -DefaultUrl $script:config.RpcUrl
        # Write-Host "Using RPC URL: $($script:config.RpcUrl)" -ForegroundColor Green
        
        Write-Host "`n=== DOWNLOAD FOLDER CONFIGURATION ===" -ForegroundColor Cyan
        # Prompt for download folder during initial installation
        $newFolder = Get-FolderSelection -Prompt "Select the main folder where Transmission downloads torrents" -DefaultPath $script:config.DownloadFolder
        if ($newFolder -ne $script:config.DownloadFolder) {
            $script:config.DownloadFolder = $newFolder
            
            # Update subfolder paths
            $script:config.AppsFolder = Join-Path -Path $newFolder -ChildPath "Apps"
            $script:config.MediaFolder = Join-Path -Path $newFolder -ChildPath "Media"
            $script:config.MusicFolder = Join-Path -Path $newFolder -ChildPath "Music"
            $script:config.ArchiveFolder = Join-Path -Path $newFolder -ChildPath "Archives"
            $script:config.OtherFolder = Join-Path -Path $newFolder -ChildPath "Other"
            
            Write-Host "Download folder set to: $newFolder" -ForegroundColor Green
        }
        
        Write-Host "`n=== SCHEDULE CONFIGURATION ===" -ForegroundColor Cyan
        
        # Get schedule time
        $scheduleTime = Get-TimeInput
        $script:config.ScheduleTime = $scheduleTime
        
        # Get schedule type (daily/weekly)
        $scheduleConfig = Get-ScheduleType
        $script:config.ScheduleType = $scheduleConfig.Type
        $script:config.ScheduleDays = $scheduleConfig.Days
        
        # Get delete original folders preference
        $script:config.DeleteOriginalFolders = Get-DeleteOriginalFolderPreference
        
        # Save configuration
        $script:config | Export-Clixml -Path $ConfigFile
        
        # Create the scheduled task
        $taskName = "Transmission Cleanup"
        $taskDescription = "Automatically organizes completed torrents from Transmission"
        $taskCommand = "powershell.exe"
        $taskArgs = "-NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`" -RunOnly"
        
        # Remove existing task if it exists
        $existingTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        if ($null -ne $existingTask) {
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        }
        
        # Create the task action
        $action = New-ScheduledTaskAction -Execute $taskCommand -Argument $taskArgs
        
        # Create the task trigger based on schedule type
        if ($script:config.ScheduleType -eq "Weekly" -and $script:config.ScheduleDays.Count -gt 0) {
            # Convert day names to DaysOfWeek enum values
            $daysOfWeek = $script:config.ScheduleDays | ForEach-Object {
                [System.DayOfWeek]::$_
            }
            
            $trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek $daysOfWeek -At $script:config.ScheduleTime
        }
        else {
            $trigger = New-ScheduledTaskTrigger -Daily -At $script:config.ScheduleTime
        }
        
        # Create the task settings
        $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -DontStopOnIdleEnd -AllowStartIfOnBatteries
        
        # Create the task principal (run with highest privileges)
        $principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType S4U -RunLevel Highest
        
        # Register the scheduled task
        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Description $taskDescription -Force | Out-Null
        
        Write-Log "Created scheduled task: $taskName" -Level INFO -NoConsole
        Write-Host "✓ Scheduled task created successfully!" -ForegroundColor Green
    }
    catch {
        Write-Log "Failed to create scheduled task: $($_.Exception.Message)" -Level ERROR
        Write-Host "✗ Failed to create scheduled task: $($_.Exception.Message)" -ForegroundColor Red
        # Non-critical error, continue with installation
    }
    
    return $true
}

function Uninstall-Script {
	 # Set title for cleanup
    $host.UI.RawUI.WindowTitle = "Transmission Cleanup - Uninstall..."
    Write-Host "`n=== TRANSMISSION CLEANUP UNINSTALLATION ===" -ForegroundColor Cyan
    
    # Redirect logs to desktop during uninstallation
    $desktopPath = [Environment]::GetFolderPath("Desktop")
    $uninstallLogFile = Join-Path -Path $desktopPath -ChildPath "TransmissionCleanupUninstall.log"
    
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
        
        if ($result.Organized.Count -gt 0) {
            Write-Log "Successfully organized $($result.Organized.Count) files" -Level INFO
            
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
            Write-Log "No files were organized for torrent: $torrentName" -Level WARN
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

# Ensure log directory exists
$logParent = Split-Path -Path $script:config.LogFile -Parent
if (-not (Test-Path $logParent)) {
    New-Item -ItemType Directory -Path $logParent -Force | Out-Null
}

# Main execution logic
try {
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
        # Installation
        Write-Host "=== TRANSMISSION CLEANUP INSTALLATION ===" -ForegroundColor Cyan
        
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
            
            # Ask if user wants to run cleanup now
            $choices = @(
                [System.Management.Automation.Host.ChoiceDescription]::new("&Yes", "Run cleanup now"),
                [System.Management.Automation.Host.ChoiceDescription]::new("&No", "Exit without running cleanup")
            )
            
            $result = $host.UI.PromptForChoice("Run Cleanup Now", "Would you like to run the cleanup process now?", $choices, 0)
            
            if ($result -eq 0) {
                Start-Cleanup
                
                # Add an extra pause after cleanup to prevent window from closing immediately
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
    Write-Log "Unhandled exception: $($_.Exception.Message)" -Level ERROR
    Write-Host "✗ An error occurred: $($_.Exception.Message)" -ForegroundColor Red
    
    # Wait for key press before exiting
    Wait-ForKeyPress
}

#endregion
