# transmission_cleanup
OVERVIEW
--------
Transmission Cleanup is a utility that automatically organizes completed torrents from Transmission into category folders.
It can be run manually or scheduled to run automatically at specified times.

FEATURES
--------
- Automatically organizes completed torrents into category folders (Apps, Media, Archives, Other)
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
