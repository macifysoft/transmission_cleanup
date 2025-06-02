# Transmission Cleanup

![Platforms](https://img.shields.io/badge/Platforms-macOS%20%7C%20Windows-lightgrey)
![License](https://img.shields.io/badge/License-MIT-green)

Automatically organize completed Transmission downloads on both macOS and Windows platforms.
Windows 
![Powershell](https://github.com/user-attachments/assets/166bca48-8332-4d33-9e65-8371f9cd3e70)

macOS
![Macos](https://github.com/user-attachments/assets/11c3ae53-8473-4f32-b317-b51e62fabd51)


## Features

### Cross-Platform Core Features
- ✅ **Smart File Organization** - Automatically sorts files into categories (Apps, Media, Music, Archives, Other)
- 🔒 **Secure Credential Storage** - Encrypted storage of Transmission RPC credentials
- ⏰ **Flexible Scheduling** - Set daily or weekly cleanup schedules
- 📝 **Detailed Logging** - Comprehensive logging for troubleshooting
- ♻️ **Torrent Management** - Optional removal of completed torrents from Transmission

### macOS Exclusive Features (v1.5.1)
- 🖥️ Native GUI application
- 🚀 LaunchAgent scheduling integration
- 🔍 Built-in log viewer
- 🎨 Dark/Light mode support
- 🔄 Automatic update checking

### Windows Exclusive Features (v10.2.0)
- ⚡ Self-installing PowerShell script
- 🏁 Start Menu shortcuts
- 🔄 Automatic retry logic
- 🗑️ Complete self-uninstallation
- 🛡️ Self-elevating admin privileges

## Installation

### macOS Installation
1. Download the latest `.dmg` from Releases
2. Open the disk image and drag the app to your Applications folder
3. Launch the application and:
   - Enter your Transmission RPC credentials
   - Configure your download folders
   - Set up your preferred schedule


### Optional: Install via Homebrew (when available)
```bash
brew install --cask transmission-cleanup
```

### Windows Installation
1. Download the TransmissionCleanup.ps1 script
2. Right-click the file and select "Run with PowerShell"
3. Follow the installation prompts to:
   - Set your Transmission RPC URL
   - Configure download folders
   - Set up scheduling preferences

## Configuration

|Setting	| macOS | Windows|
|--------|-------|--------|
|Credentials|GUI Configuration|During first run|
|Folders|Customizable in Settings|Set during installation|
|Schedule |Daily/Weekly In Preferences|Daily/Weekly during setup|
|Log Location|~/Library/Application Support|%APPDATA%\Transmission\Logs

## Requirements

|Componments|macOS|Windows|
|-----------|-----|-------|
|OS Version|macOS 10.15+|Windows 7+|
|Transmission|2.94+|2.94+|
|RPC Access| Enabled|Enabled|
|Runtime|-|PowerShell 5.1+|

## Usage

After installation:

On macOS:

    Use the menu bar icon for quick access
    Run cleanup manually from the main window
    View logs directly in the application
    Scheduled tasks run automatically

On Windows:

    Use Start Menu shortcuts:
        "Run Cleanup Now"
        "Reset Credentials"
        "View Log File"
    Scheduled tasks run automatically

## Troubleshooting

Common issues for both platforms:

    1. Connection Errors:
        Verify Transmission RPC is enabled
        Check your firewall settings
        Confirm correct credentials

    2. File Permission Issues:
        macOS: Grant Full Disk Access in System Preferences
        Windows: Run as Administrator

    3. Scheduling Problems:
        macOS: Check launchctl list | grep transmission
        Windows: Verify task in Task Scheduler

## Uninstalling

macOS: 
Delete the application from your Applications folder Remove config files:

```bash
  rm -rf ~/Library/Application\ Support/Transmission\ Cleanup
```

Windows:
1. Use the Start Menu "Uninstall" shortcut
2 . Or run: 
```bash
  Powershell: .\TransmissionCleanup.ps1 -Uninstall
```
## License

MIT License - See LICENSE for details.