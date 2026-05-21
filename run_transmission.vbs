Option Explicit

Dim shell, fso, launcherFolder, scriptPath, psCommand
Set shell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")

launcherFolder = fso.GetParentFolderName(WScript.ScriptFullName)
scriptPath = fso.BuildPath(launcherFolder, "TransmissionCleanup.ps1")

If Not fso.FileExists(scriptPath) Then
    shell.Popup "Transmission Cleanup script was not found:" & vbCrLf & scriptPath, 10, "Transmission Cleanup", 16
    WScript.Quit 1
End If

shell.Popup "Loading Script, please wait...", 2, "Transmission Cleanup", 64

psCommand = "powershell.exe -ExecutionPolicy Bypass -NoProfile -WindowStyle Minimized -File """ & scriptPath & """"
shell.Run psCommand, 2, False
