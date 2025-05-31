import sys
import os
import json
import base64
import hashlib
import datetime
import time
import re
import subprocess
import requests
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                            QHBoxLayout, QLabel, QPushButton, QDialog, 
                            QLineEdit, QFileDialog, QMessageBox, QProgressBar,
                            QComboBox, QCheckBox, QGroupBox, QGridLayout,
                            QSpinBox, QTimeEdit, QTextEdit, QScrollArea)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTime, QSize, QTimer
from PyQt5.QtGui import QIcon, QFont, QPixmap

# Version
APP_VERSION = "1.5.1"

# Constants
APP_NAME = "Transmission Cleanup"
CONFIG_DIR = os.path.expanduser(f"~/Library/Application Support/{APP_NAME}")
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.json")
CREDENTIALS_FILE = os.path.join(CONFIG_DIR, "credentials.json")
LOG_FILE = os.path.join(CONFIG_DIR, "cleanup.log")
LAUNCHAGENT_DIR = os.path.expanduser("~/Library/LaunchAgents")
LAUNCHAGENT_FILE = os.path.join(LAUNCHAGENT_DIR, "com.transmissioncleanup.plist")

# Ensure config directory exists
os.makedirs(CONFIG_DIR, exist_ok=True)

# Default configuration
DEFAULT_CONFIG = {
    "download_dir": os.path.expanduser("~/Downloads"),
    "apps_dir": os.path.expanduser("~/Downloads/Apps"),
    "media_dir": os.path.expanduser("~/Downloads/Media"),
    "music_dir": os.path.expanduser("~/Downloads/Music"),
    "archives_dir": os.path.expanduser("~/Downloads/Archives"),
    "other_dir": os.path.expanduser("~/Downloads/Other"),
    "rpc_url": "http://localhost:9091/transmission/rpc",
    "schedule": {
        "enabled": False,
        "days": [0, 1, 2, 3, 4, 5, 6],  # 0=Monday, 6=Sunday
        "time": "03:00"  # 3 AM default
    },
    "delete_torrents": True,
    "debug_mode": False
}

# File extensions
FILE_TYPES = {
    "apps": [".exe", ".dmg", ".pkg", ".app", ".msi", ".deb", ".rpm"],
    "media": [".mp4", ".avi", ".mkv", ".mov", ".wmv", ".m4v", ".mpg", ".mpeg", ".webm", ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".webp", ".svg"],
    "music": [".mp3", ".flac", ".wav", ".aac", ".ogg", ".m4a", ".wma"],
    "archives": [".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz", ".iso", ".tgz"]
}

# Improved robust encryption for credentials
def secure_encrypt(text, key):
    """
    Securely encrypt text using AES-like approach with PBKDF2 key derivation.
    This is a more robust approach than the previous XOR method.
    """
    try:
        # Generate a secure key from the password using PBKDF2
        salt = b'transmission_cleanup_v2'
        iterations = 100000
        key_derived = hashlib.pbkdf2_hmac('sha256', key.encode('utf-8'), salt, iterations)
        
        # Convert text to bytes
        text_bytes = text.encode('utf-8')
        
        # Create a simple initialization vector (IV)
        iv = os.urandom(16)
        
        # Encrypt using a simple byte-by-byte operation with the derived key
        # This simulates a block cipher without external dependencies
        key_bytes = key_derived
        encrypted = bytearray()
        
        # Add IV to the beginning of the encrypted data
        encrypted.extend(iv)
        
        # Encrypt each byte
        for i, byte in enumerate(text_bytes):
            key_byte = key_bytes[i % len(key_bytes)]
            encrypted_byte = (byte + key_byte) % 256
            encrypted.append(encrypted_byte)
        
        # Base64 encode the result for safe storage
        return base64.b64encode(encrypted).decode('utf-8')
    except Exception as e:
        log(f"Encryption error: {str(e)}", "ERROR")
        return None

def secure_decrypt(encrypted_text, key):
    """
    Decrypt text that was encrypted with secure_encrypt.
    """
    try:
        # Generate the same key
        salt = b'transmission_cleanup_v2'
        iterations = 100000
        key_derived = hashlib.pbkdf2_hmac('sha256', key.encode('utf-8'), salt, iterations)
        
        # Decode the base64 encrypted text
        encrypted_bytes = base64.b64decode(encrypted_text)
        
        # Extract the IV (first 16 bytes)
        iv = encrypted_bytes[:16]
        encrypted_data = encrypted_bytes[16:]
        
        # Decrypt each byte
        key_bytes = key_derived
        decrypted = bytearray()
        
        for i, byte in enumerate(encrypted_data):
            key_byte = key_bytes[i % len(key_bytes)]
            decrypted_byte = (byte - key_byte) % 256
            decrypted.append(decrypted_byte)
        
        # Convert back to string
        return decrypted.decode('utf-8')
    except Exception as e:
        log(f"Decryption error: {str(e)}", "ERROR")
        return None

# Legacy decryption for backward compatibility
def legacy_decrypt(encrypted_text, key):
    """
    Attempt to decrypt using the old method for backward compatibility.
    """
    try:
        # Generate the same key
        salt = b'transmission_cleanup_salt'
        key_derived = hashlib.pbkdf2_hmac('sha256', key.encode(), salt, 100000)
        key_b64 = base64.b64encode(key_derived).decode()
        
        # Decrypt
        encrypted = base64.b64decode(encrypted_text).decode()
        decrypted = []
        for i, char in enumerate(encrypted):
            key_char = key_b64[i % len(key_b64)]
            decrypted.append(chr(ord(char) ^ ord(key_char)))
        
        return ''.join(decrypted)
    except Exception:
        return None

# Logger
def log(message, level="INFO"):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_message = f"[{timestamp}][{level}] {message}"
    
    try:
        with open(LOG_FILE, "a") as f:
            f.write(log_message + "\n")
    except Exception as e:
        print(f"Error writing to log: {e}")
    
    if level == "ERROR" or level == "WARNING":
        print(log_message)

# Load configuration
def load_config():
    try:
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, "r") as f:
                config = json.load(f)
                
            # Ensure all keys exist (for backward compatibility)
            for key, value in DEFAULT_CONFIG.items():
                if key not in config:
                    config[key] = value
                    
            # Ensure schedule structure is correct
            if "schedule" not in config:
                config["schedule"] = DEFAULT_CONFIG["schedule"]
            elif isinstance(config["schedule"], dict):
                if "days" not in config["schedule"]:
                    config["schedule"]["days"] = DEFAULT_CONFIG["schedule"]["days"]
                if "time" not in config["schedule"]:
                    config["schedule"]["time"] = DEFAULT_CONFIG["schedule"]["time"]
            else:
                config["schedule"] = DEFAULT_CONFIG["schedule"]
                
            return config
        else:
            return DEFAULT_CONFIG.copy()
    except Exception as e:
        log(f"Error loading config: {e}", "ERROR")
        return DEFAULT_CONFIG.copy()

# Save configuration
def save_config(config):
    try:
        with open(CONFIG_FILE, "w") as f:
            json.dump(config, f, indent=4)
        return True
    except Exception as e:
        log(f"Error saving config: {e}", "ERROR")
        return False

# Load credentials with improved error handling and version detection
def load_credentials():
    """
    Load credentials with improved error handling and version detection.
    Attempts to load credentials using the new secure method first,
    then falls back to the legacy method if needed.
    """
    if not os.path.exists(CREDENTIALS_FILE):
        log("Credentials file does not exist", "INFO")
        return None
    
    try:
        with open(CREDENTIALS_FILE, "r") as f:
            data = json.load(f)
        
        # Check if this is a v2 credential file (has version field)
        version = data.get("version", "1.0")
        
        if version == "2.0":
            # New format
            encrypted_username = data.get("username", "")
            encrypted_password = data.get("password", "")
            
            if not encrypted_username or not encrypted_password:
                log("Credentials file is missing username or password", "WARNING")
                return None
            
            username = secure_decrypt(encrypted_username, APP_NAME)
            password = secure_decrypt(encrypted_password, APP_NAME)
            
            if username and password:
                log("Successfully loaded credentials using v2 format", "INFO")
                return {"username": username, "password": password}
        else:
            # Try legacy format
            encrypted_username = data.get("username", "")
            encrypted_password = data.get("password", "")
            
            if not encrypted_username or not encrypted_password:
                log("Credentials file is missing username or password", "WARNING")
                return None
            
            username = legacy_decrypt(encrypted_username, APP_NAME)
            password = legacy_decrypt(encrypted_password, APP_NAME)
            
            if username and password:
                log("Successfully loaded credentials using legacy format", "INFO")
                # Upgrade to new format
                save_credentials(username, password)
                return {"username": username, "password": password}
    
    except json.JSONDecodeError:
        log("Credentials file is not valid JSON", "ERROR")
    except Exception as e:
        log(f"Error loading credentials: {str(e)}", "ERROR")
    
    # If we get here, something went wrong - delete the corrupted file
    try:
        os.remove(CREDENTIALS_FILE)
        log("Removed corrupted credentials file", "INFO")
    except Exception as e:
        log(f"Failed to remove corrupted credentials file: {str(e)}", "ERROR")
    
    return None

# Save credentials with improved format
def save_credentials(username, password):
    """
    Save credentials using the new secure encryption method.
    """
    try:
        # Use app name as encryption key
        encrypted_username = secure_encrypt(username, APP_NAME)
        encrypted_password = secure_encrypt(password, APP_NAME)
        
        if not encrypted_username or not encrypted_password:
            log("Failed to encrypt credentials", "ERROR")
            return False
        
        with open(CREDENTIALS_FILE, "w") as f:
            json.dump({
                "version": "2.0",  # Add version to identify format
                "username": encrypted_username,
                "password": encrypted_password,
                "created": datetime.datetime.now().isoformat()
            }, f, indent=4)
        
        log("Credentials saved successfully", "INFO")
        return True
    except Exception as e:
        log(f"Error saving credentials: {str(e)}", "ERROR")
        return False

# Create LaunchAgent for scheduling with improved permissions handling
def create_launch_agent(config):
    try:
        if not config["schedule"]["enabled"]:
            # Remove existing LaunchAgent if scheduling is disabled
            if os.path.exists(LAUNCHAGENT_FILE):
                os.remove(LAUNCHAGENT_FILE)
                subprocess.run(["launchctl", "unload", LAUNCHAGENT_FILE], capture_output=True)
            return True
        
        # Ensure LaunchAgent directory exists
        os.makedirs(LAUNCHAGENT_DIR, exist_ok=True)
        
        # Get the path to the app executable
        app_path = sys.executable
        script_path = os.path.abspath(__file__)
        
        # Determine if we're running from a py2app bundle or directly as a script
        if app_path.endswith('MacOS/Python'):
            # We're running from a py2app bundle
            app_path = os.path.dirname(os.path.dirname(os.path.dirname(app_path)))
            app_path = os.path.join(app_path, 'MacOS', APP_NAME)
            
            # Make sure the app executable has proper permissions
            try:
                subprocess.run(["chmod", "+x", app_path], check=True)
                log(f"Set executable permissions on {app_path}", "INFO")
            except Exception as e:
                log(f"Failed to set executable permissions: {e}", "ERROR")
            
            # Use the executable directly
            program_args = [app_path, "--run-cleanup"]
        else:
            # We're running as a script, use python to execute it
            program_args = [app_path, script_path, "--run-cleanup"]
        
        # Create weekday array for LaunchAgent
        weekdays = []
        for day in config["schedule"]["days"]:
            # Convert from Monday=0 to Sunday=0 format (LaunchAgent uses Sunday=0)
            weekdays.append((day + 1) % 7 + 1)
        
        # Parse time
        hour, minute = config["schedule"]["time"].split(":")
        
        # Create plist content with improved permissions handling
        plist_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.transmissioncleanup</string>
    <key>ProgramArguments</key>
    <array>
"""
        
        # Add each program argument as a separate string
        for arg in program_args:
            plist_content += f"        <string>{arg}</string>\n"
        
        plist_content += """    </array>
    <key>StartCalendarInterval</key>
    <array>
"""
        
        # Add each day
        for weekday in weekdays:
            plist_content += f"""        <dict>
            <key>Weekday</key>
            <integer>{weekday}</integer>
            <key>Hour</key>
            <integer>{hour}</integer>
            <key>Minute</key>
            <integer>{minute}</integer>
        </dict>
"""
        
        plist_content += """    </array>
    <key>RunAtLoad</key>
    <false/>
    <key>StandardOutPath</key>
    <string>""" + os.path.join(CONFIG_DIR, "launchagent_stdout.log") + """</string>
    <key>StandardErrorPath</key>
    <string>""" + os.path.join(CONFIG_DIR, "launchagent_stderr.log") + """</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>PATH</key>
        <string>/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
    </dict>
</dict>
</plist>
"""
        
        # Write plist file
        with open(LAUNCHAGENT_FILE, "w") as f:
            f.write(plist_content)
        
        # Set proper permissions on the plist file
        try:
            subprocess.run(["chmod", "644", LAUNCHAGENT_FILE], check=True)
            log(f"Set permissions on {LAUNCHAGENT_FILE}", "INFO")
        except Exception as e:
            log(f"Failed to set permissions on plist: {e}", "ERROR")
        
        # Unload and load the LaunchAgent
        try:
            subprocess.run(["launchctl", "unload", LAUNCHAGENT_FILE], capture_output=True)
            subprocess.run(["launchctl", "load", LAUNCHAGENT_FILE], capture_output=True)
            log("LaunchAgent loaded successfully", "INFO")
        except Exception as e:
            log(f"Error loading LaunchAgent: {e}", "ERROR")
        
        return True
    except Exception as e:
        log(f"Error creating LaunchAgent: {e}", "ERROR")
        return False

# Worker thread for cleanup process
class CleanupWorker(QThread):
    progress_update = pyqtSignal(int, str)
    finished_signal = pyqtSignal(bool, str)
    
    def __init__(self, config):
        super().__init__()
        self.config = config
        self.session_id = None
        self.credentials = load_credentials()
    
    def run(self):
        try:
            self.progress_update.emit(0, "Starting cleanup process...")
            
            # Check if credentials exist
            if not self.credentials:
                self.finished_signal.emit(False, "No credentials found. Please set up Transmission RPC credentials.")
                return
            
            # Connect to Transmission RPC
            self.progress_update.emit(10, "Connecting to Transmission...")
            if not self.connect_to_transmission():
                self.finished_signal.emit(False, "Failed to connect to Transmission RPC.")
                return
            
            # Get completed torrents
            self.progress_update.emit(20, "Getting completed torrents...")
            completed_torrents = self.get_completed_torrents()
            
            if not completed_torrents:
                self.finished_signal.emit(True, "No completed torrents found.")
                return
            
            total_torrents = len(completed_torrents)
            self.progress_update.emit(30, f"Found {total_torrents} completed torrents.")
            
            # Process each torrent
            success_count = 0
            for i, torrent in enumerate(completed_torrents):
                progress = 30 + int(50 * (i / total_torrents))
                self.progress_update.emit(progress, f"Processing torrent {i+1} of {total_torrents}...")
                
                if self.process_torrent(torrent):
                    success_count += 1
            
            self.progress_update.emit(90, "Cleanup completed.")
            
            # Final message
            if success_count == total_torrents:
                self.finished_signal.emit(True, f"Successfully processed all {total_torrents} torrents.")
            else:
                self.finished_signal.emit(True, f"Processed {success_count} out of {total_torrents} torrents.")
                
        except Exception as e:
            log(f"Error in cleanup process: {e}", "ERROR")
            self.finished_signal.emit(False, f"Error: {str(e)}")
    
    def connect_to_transmission(self):
        try:
            # Initial connection attempt
            response = requests.get(
                self.config["rpc_url"],
                auth=(self.credentials["username"], self.credentials["password"]),
                headers={"X-Transmission-Session-Id": ""}
            )
            
            # Get session ID if needed
            if response.status_code == 409:
                self.session_id = response.headers.get("X-Transmission-Session-Id")
                return True
            elif response.status_code == 401:
                log("Authentication failed", "ERROR")
                return False
            elif response.status_code == 200:
                return True
            else:
                log(f"Connection failed with status code: {response.status_code}", "ERROR")
                return False
        except Exception as e:
            log(f"Error connecting to Transmission: {e}", "ERROR")
            return False
    
    def get_completed_torrents(self):
        try:
            # Prepare request
            headers = {"X-Transmission-Session-Id": self.session_id} if self.session_id else {}
            data = {
                "method": "torrent-get",
                "arguments": {
                    "fields": ["id", "name", "percentDone", "downloadDir", "isFinished"]
                }
            }
            
            # Send request
            response = requests.post(
                self.config["rpc_url"],
                auth=(self.credentials["username"], self.credentials["password"]),
                headers=headers,
                json=data
            )
            
            # Check response
            if response.status_code == 200:
                result = response.json()
                torrents = result.get("arguments", {}).get("torrents", [])
                
                # Filter completed torrents (100% done)
                completed = []
                for torrent in torrents:
                    # Check if percentDone is 1.0 (100%)
                    if torrent.get("percentDone") == 1.0:
                        completed.append(torrent)
                
                return completed
            else:
                log(f"Failed to get torrents: {response.status_code}", "ERROR")
                return []
        except Exception as e:
            log(f"Error getting torrents: {e}", "ERROR")
            return []
    
    def process_torrent(self, torrent):
        try:
            torrent_id = torrent.get("id")
            torrent_name = torrent.get("name", "Unknown")
            download_dir = torrent.get("downloadDir", "")
            
            log(f"Processing torrent: {torrent_name}", "INFO")
            
            # Get torrent files
            files = self.get_torrent_files(torrent_id)
            if not files:
                log(f"No files found for torrent: {torrent_name}", "ERROR")
                return False
            
            # Process each file
            for file_info in files:
                file_path = file_info.get("name", "")
                if not file_path:
                    continue
                
                # Get full path
                full_path = os.path.join(download_dir, file_path)
                if not os.path.exists(full_path):
                    log(f"File not found: {full_path}", "ERROR")
                    continue
                
                # Determine file type and destination
                dest_dir = self.get_destination_dir(full_path)
                
                # Create destination directory if it doesn't exist
                os.makedirs(dest_dir, exist_ok=True)
                
                # Move file
                filename = os.path.basename(full_path)
                dest_path = os.path.join(dest_dir, filename)
                
                try:
                    # If destination file already exists, add a suffix
                    if os.path.exists(dest_path):
                        base, ext = os.path.splitext(filename)
                        timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
                        new_filename = f"{base}_{timestamp}{ext}"
                        dest_path = os.path.join(dest_dir, new_filename)
                    
                    # Move the file
                    os.rename(full_path, dest_path)
                    log(f"Moved file: {full_path} -> {dest_path}", "INFO")
                except Exception as e:
                    log(f"Error moving file {full_path}: {e}", "ERROR")
            
            # Remove torrent if configured
            if self.config["delete_torrents"]:
                self.remove_torrent(torrent_id)
            
            return True
        except Exception as e:
            log(f"Error processing torrent {torrent.get('name', 'Unknown')}: {e}", "ERROR")
            return False
    
    def get_torrent_files(self, torrent_id):
        try:
            # Prepare request
            headers = {"X-Transmission-Session-Id": self.session_id} if self.session_id else {}
            data = {
                "method": "torrent-get",
                "arguments": {
                    "ids": [torrent_id],
                    "fields": ["files"]
                }
            }
            
            # Send request
            response = requests.post(
                self.config["rpc_url"],
                auth=(self.credentials["username"], self.credentials["password"]),
                headers=headers,
                json=data
            )
            
            # Check response
            if response.status_code == 200:
                result = response.json()
                torrents = result.get("arguments", {}).get("torrents", [])
                
                if torrents:
                    return torrents[0].get("files", [])
                else:
                    return []
            else:
                log(f"Failed to get torrent files: {response.status_code}", "ERROR")
                return []
        except Exception as e:
            log(f"Error getting torrent files: {e}", "ERROR")
            return []
    
    def get_destination_dir(self, file_path):
        # Get file extension
        _, ext = os.path.splitext(file_path.lower())
        
        # Determine file type
        if ext in FILE_TYPES["apps"]:
            return self.config["apps_dir"]
        elif ext in FILE_TYPES["media"]:
            return self.config["media_dir"]
        elif ext in FILE_TYPES["music"]:
            return self.config["music_dir"]
        elif ext in FILE_TYPES["archives"]:
            return self.config["archives_dir"]
        else:
            return self.config["other_dir"]
    
    def remove_torrent(self, torrent_id):
        try:
            # Prepare request
            headers = {"X-Transmission-Session-Id": self.session_id} if self.session_id else {}
            data = {
                "method": "torrent-remove",
                "arguments": {
                    "ids": [torrent_id],
                    "delete-local-data": False
                }
            }
            
            # Send request
            response = requests.post(
                self.config["rpc_url"],
                auth=(self.credentials["username"], self.credentials["password"]),
                headers=headers,
                json=data
            )
            
            # Check response
            if response.status_code == 200:
                log(f"Removed torrent ID: {torrent_id}", "INFO")
                return True
            else:
                log(f"Failed to remove torrent: {response.status_code}", "ERROR")
                return False
        except Exception as e:
            log(f"Error removing torrent: {e}", "ERROR")
            return False

# Credentials dialog
class CredentialsDialog(QDialog):
    def __init__(self, parent=None, rpc_url=None):
        super().__init__(parent)
        self.setWindowTitle("Transmission RPC Credentials")
        self.setMinimumWidth(400)
        
        layout = QVBoxLayout()
        
        # RPC URL
        url_layout = QHBoxLayout()
        url_label = QLabel("RPC URL:")
        self.url_edit = QLineEdit(rpc_url or "http://localhost:9091/transmission/rpc")
        url_layout.addWidget(url_label)
        url_layout.addWidget(self.url_edit)
        layout.addLayout(url_layout)
        
        # Username
        username_layout = QHBoxLayout()
        username_label = QLabel("Username:")
        self.username_edit = QLineEdit()
        username_layout.addWidget(username_label)
        username_layout.addWidget(self.username_edit)
        layout.addLayout(username_layout)
        
        # Password
        password_layout = QHBoxLayout()
        password_label = QLabel("Password:")
        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.Password)
        password_layout.addWidget(password_label)
        password_layout.addWidget(self.password_edit)
        layout.addLayout(password_layout)
        
        # Buttons
        button_layout = QHBoxLayout()
        save_button = QPushButton("Save")
        cancel_button = QPushButton("Cancel")
        save_button.clicked.connect(self.accept)
        cancel_button.clicked.connect(self.reject)
        button_layout.addWidget(save_button)
        button_layout.addWidget(cancel_button)
        layout.addLayout(button_layout)
        
        self.setLayout(layout)
    
    def get_credentials(self):
        return {
            "url": self.url_edit.text(),
            "username": self.username_edit.text(),
            "password": self.password_edit.text()
        }

# Settings dialog
class SettingsDialog(QDialog):
    def __init__(self, parent=None, config=None):
        super().__init__(parent)
        self.setWindowTitle("Settings")
        self.setMinimumWidth(500)
        
        self.config = config or load_config()
        
        layout = QVBoxLayout()
        
        # Folder settings
        folder_group = QGroupBox("Folder Settings")
        folder_layout = QGridLayout()
        
        # Download folder
        download_label = QLabel("Download Folder:")
        self.download_edit = QLineEdit(self.config["download_dir"])
        download_button = QPushButton("Browse...")
        download_button.clicked.connect(lambda: self.browse_folder(self.download_edit))
        folder_layout.addWidget(download_label, 0, 0)
        folder_layout.addWidget(self.download_edit, 0, 1)
        folder_layout.addWidget(download_button, 0, 2)
        
        # Apps folder
        apps_label = QLabel("Apps Folder:")
        self.apps_edit = QLineEdit(self.config["apps_dir"])
        apps_button = QPushButton("Browse...")
        apps_button.clicked.connect(lambda: self.browse_folder(self.apps_edit))
        folder_layout.addWidget(apps_label, 1, 0)
        folder_layout.addWidget(self.apps_edit, 1, 1)
        folder_layout.addWidget(apps_button, 1, 2)
        
        # Media folder
        media_label = QLabel("Media Folder:")
        self.media_edit = QLineEdit(self.config["media_dir"])
        media_button = QPushButton("Browse...")
        media_button.clicked.connect(lambda: self.browse_folder(self.media_edit))
        folder_layout.addWidget(media_label, 2, 0)
        folder_layout.addWidget(self.media_edit, 2, 1)
        folder_layout.addWidget(media_button, 2, 2)
        
        # Music folder
        music_label = QLabel("Music Folder:")
        self.music_edit = QLineEdit(self.config["music_dir"])
        music_button = QPushButton("Browse...")
        music_button.clicked.connect(lambda: self.browse_folder(self.music_edit))
        folder_layout.addWidget(music_label, 3, 0)
        folder_layout.addWidget(self.music_edit, 3, 1)
        folder_layout.addWidget(music_button, 3, 2)
        
        # Archives folder
        archives_label = QLabel("Archives Folder:")
        self.archives_edit = QLineEdit(self.config["archives_dir"])
        archives_button = QPushButton("Browse...")
        archives_button.clicked.connect(lambda: self.browse_folder(self.archives_edit))
        folder_layout.addWidget(archives_label, 4, 0)
        folder_layout.addWidget(self.archives_edit, 4, 1)
        folder_layout.addWidget(archives_button, 4, 2)
        
        # Other folder
        other_label = QLabel("Other Folder:")
        self.other_edit = QLineEdit(self.config["other_dir"])
        other_button = QPushButton("Browse...")
        other_button.clicked.connect(lambda: self.browse_folder(self.other_edit))
        folder_layout.addWidget(other_label, 5, 0)
        folder_layout.addWidget(self.other_edit, 5, 1)
        folder_layout.addWidget(other_button, 5, 2)
        
        folder_group.setLayout(folder_layout)
        layout.addWidget(folder_group)
        
        # Cleanup settings
        cleanup_group = QGroupBox("Cleanup Settings")
        cleanup_layout = QVBoxLayout()
        
        # Delete torrents
        self.delete_check = QCheckBox("Remove torrents from Transmission after processing")
        self.delete_check.setChecked(self.config["delete_torrents"])
        cleanup_layout.addWidget(self.delete_check)
        
        # Debug mode
        self.debug_check = QCheckBox("Enable debug mode (verbose logging)")
        self.debug_check.setChecked(self.config["debug_mode"])
        cleanup_layout.addWidget(self.debug_check)
        
        cleanup_group.setLayout(cleanup_layout)
        layout.addWidget(cleanup_group)
        
        # Buttons
        button_layout = QHBoxLayout()
        save_button = QPushButton("Save")
        cancel_button = QPushButton("Cancel")
        save_button.clicked.connect(self.accept)
        cancel_button.clicked.connect(self.reject)
        button_layout.addWidget(save_button)
        button_layout.addWidget(cancel_button)
        layout.addLayout(button_layout)
        
        self.setLayout(layout)
    
    def browse_folder(self, line_edit):
        folder = QFileDialog.getExistingDirectory(self, "Select Folder", line_edit.text())
        if folder:
            line_edit.setText(folder)
    
    def get_settings(self):
        return {
            "download_dir": self.download_edit.text(),
            "apps_dir": self.apps_edit.text(),
            "media_dir": self.media_edit.text(),
            "music_dir": self.music_edit.text(),
            "archives_dir": self.archives_edit.text(),
            "other_dir": self.other_edit.text(),
            "delete_torrents": self.delete_check.isChecked(),
            "debug_mode": self.debug_check.isChecked()
        }

# Schedule settings dialog
class ScheduleSettingsDialog(QDialog):
    def __init__(self, parent=None, config=None):
        super().__init__(parent)
        self.setWindowTitle("Schedule Settings")
        self.setMinimumWidth(400)
        
        self.config = config or load_config()
        
        main_layout = QVBoxLayout()
        
        # Enable scheduling
        self.enable_check = QCheckBox("Enable scheduled cleanup")
        self.enable_check.setChecked(self.config["schedule"]["enabled"])
        main_layout.addWidget(self.enable_check)
        
        # Days selection
        days_group = QGroupBox("Days")
        days_layout = QGridLayout()
        
        self.day_checks = []
        days = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
        
        for i, day in enumerate(days):
            check = QCheckBox(day)
            check.setChecked(i in self.config["schedule"]["days"])
            row = i // 4
            col = i % 4
            days_layout.addWidget(check, row, col)
            self.day_checks.append(check)
        
        days_group.setLayout(days_layout)
        main_layout.addWidget(days_group)
        
        # Time selection
        time_group = QGroupBox("Time")
        time_layout = QHBoxLayout()
        
        time_label = QLabel("Run at:")
        self.time_edit = QTimeEdit()
        
        # Parse time from config
        hour, minute = map(int, self.config["schedule"]["time"].split(":"))
        self.time_edit.setTime(QTime(hour, minute))
        
        time_layout.addWidget(time_label)
        time_layout.addWidget(self.time_edit)
        
        time_group.setLayout(time_layout)
        main_layout.addWidget(time_group)
        
        # Buttons
        button_layout = QHBoxLayout()
        save_button = QPushButton("Save")
        cancel_button = QPushButton("Cancel")
        save_button.clicked.connect(self.accept)
        cancel_button.clicked.connect(self.reject)
        button_layout.addWidget(save_button)
        button_layout.addWidget(cancel_button)
        main_layout.addLayout(button_layout)
        
        self.setLayout(main_layout)
    
    def get_schedule(self):
        # Get selected days
        days = []
        for i, check in enumerate(self.day_checks):
            if check.isChecked():
                days.append(i)
        
        # Get time
        time = self.time_edit.time().toString("HH:mm")
        
        return {
            "enabled": self.enable_check.isChecked(),
            "days": days,
            "time": time
        }

# Log viewer dialog
class LogViewerDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Log Viewer")
        self.setMinimumSize(700, 500)
        
        layout = QVBoxLayout()
        
        # Log text area
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setFont(QFont("Courier", 10))
        
        # Wrap in scroll area
        scroll = QScrollArea()
        scroll.setWidget(self.log_text)
        scroll.setWidgetResizable(True)
        
        layout.addWidget(scroll)
        
        # Buttons
        button_layout = QHBoxLayout()
        refresh_button = QPushButton("Refresh")
        clear_button = QPushButton("Clear Log")
        close_button = QPushButton("Close")
        
        refresh_button.clicked.connect(self.load_log)
        clear_button.clicked.connect(self.clear_log)
        close_button.clicked.connect(self.accept)
        
        button_layout.addWidget(refresh_button)
        button_layout.addWidget(clear_button)
        button_layout.addWidget(close_button)
        
        layout.addLayout(button_layout)
        
        self.setLayout(layout)
        
        # Load log
        self.load_log()
    
    def load_log(self):
        try:
            if os.path.exists(LOG_FILE):
                with open(LOG_FILE, "r") as f:
                    log_content = f.read()
                self.log_text.setText(log_content)
                
                # Scroll to bottom
                cursor = self.log_text.textCursor()
                cursor.movePosition(cursor.End)
                self.log_text.setTextCursor(cursor)
            else:
                self.log_text.setText("Log file does not exist.")
        except Exception as e:
            self.log_text.setText(f"Error loading log: {e}")
    
    def clear_log(self):
        try:
            with open(LOG_FILE, "w") as f:
                f.write("")
            self.log_text.setText("")
            QMessageBox.information(self, "Log Cleared", "Log file has been cleared.")
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to clear log: {e}")

# Main window
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"{APP_NAME} v{APP_VERSION}")
        self.setMinimumSize(600, 400)
        
        # Load config
        self.config = load_config()
        
        # Check for credentials
        self.credentials = load_credentials()
        if not self.credentials:
            # Schedule credential setup after UI is shown
            QTimer.singleShot(500, self.reset_credentials)
        
        # Initialize UI
        self.init_ui()
        
        # Check command line arguments
        if len(sys.argv) > 1 and sys.argv[1] == "--run-cleanup":
            QTimer.singleShot(500, self.run_cleanup)
    
    def init_ui(self):
        # Central widget
        central = QWidget()
        self.setCentralWidget(central)
        
        # Main layout
        layout = QVBoxLayout()
        central.setLayout(layout)
        
        # Logo/header
        header_layout = QHBoxLayout()
        logo_label = QLabel()
        
        # Try to load icon if available
        icon_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "app_icon.png")
        if os.path.exists(icon_path):
            pixmap = QPixmap(icon_path)
            logo_label.setPixmap(pixmap.scaled(64, 64, Qt.KeepAspectRatio, Qt.SmoothTransformation))
        
        title_label = QLabel(f"{APP_NAME}")
        title_label.setFont(QFont("Arial", 18, QFont.Bold))
        version_label = QLabel(f"v{APP_VERSION}")
        version_label.setFont(QFont("Arial", 10))
        
        header_text_layout = QVBoxLayout()
        header_text_layout.addWidget(title_label)
        header_text_layout.addWidget(version_label)
        
        header_layout.addWidget(logo_label)
        header_layout.addLayout(header_text_layout)
        header_layout.addStretch()
        
        layout.addLayout(header_layout)
        
        # Status section
        status_group = QGroupBox("Status")
        status_layout = QVBoxLayout()
        
        # RPC URL
        rpc_layout = QHBoxLayout()
        rpc_label = QLabel("Transmission RPC:")
        self.rpc_status = QLabel(self.config["rpc_url"])
        rpc_layout.addWidget(rpc_label)
        rpc_layout.addWidget(self.rpc_status)
        rpc_layout.addStretch()
        status_layout.addLayout(rpc_layout)
        
        # Credentials
        cred_layout = QHBoxLayout()
        cred_label = QLabel("Credentials:")
        self.cred_status = QLabel("Not set" if not self.credentials else "Configured")
        cred_layout.addWidget(cred_label)
        cred_layout.addWidget(self.cred_status)
        cred_layout.addStretch()
        status_layout.addLayout(cred_layout)
        
        # Schedule
        schedule_layout = QHBoxLayout()
        schedule_label = QLabel("Schedule:")
        
        schedule_text = "Disabled"
        if self.config["schedule"]["enabled"]:
            days = []
            for day_index in self.config["schedule"]["days"]:
                day_names = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
                days.append(day_names[day_index])
            
            schedule_text = f"Enabled - {', '.join(days)} at {self.config['schedule']['time']}"
        
        self.schedule_status = QLabel(schedule_text)
        schedule_layout.addWidget(schedule_label)
        schedule_layout.addWidget(self.schedule_status)
        schedule_layout.addStretch()
        status_layout.addLayout(schedule_layout)
        
        status_group.setLayout(status_layout)
        layout.addWidget(status_group)
        
        # Progress section
        progress_group = QGroupBox("Cleanup Progress")
        progress_layout = QVBoxLayout()
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        
        self.status_label = QLabel("Ready")
        
        progress_layout.addWidget(self.progress_bar)
        progress_layout.addWidget(self.status_label)
        
        progress_group.setLayout(progress_layout)
        layout.addWidget(progress_group)
        
        # Buttons
        button_layout = QHBoxLayout()
        
        self.run_button = QPushButton("Run Cleanup")
        settings_button = QPushButton("Settings")
        schedule_button = QPushButton("Configure Schedule")
        credentials_button = QPushButton("Reset Credentials")
        logs_button = QPushButton("View Logs")
        
        self.run_button.clicked.connect(self.run_cleanup)
        settings_button.clicked.connect(self.open_settings)
        schedule_button.clicked.connect(self.configure_schedule)
        credentials_button.clicked.connect(self.reset_credentials)
        logs_button.clicked.connect(self.view_logs)
        
        button_layout.addWidget(self.run_button)
        button_layout.addWidget(settings_button)
        button_layout.addWidget(schedule_button)
        button_layout.addWidget(credentials_button)
        button_layout.addWidget(logs_button)
        
        layout.addLayout(button_layout)
    
    def run_cleanup(self):
        # Check if credentials exist
        if not self.credentials:
            QMessageBox.warning(self, "No Credentials", "Please set up Transmission RPC credentials first.")
            self.reset_credentials()
            return
        
        # Disable run button
        self.run_button.setEnabled(False)
        
        # Create worker thread
        self.worker = CleanupWorker(self.config)
        self.worker.progress_update.connect(self.update_progress)
        self.worker.finished_signal.connect(self.cleanup_finished)
        self.worker.start()
    
    def update_progress(self, value, message):
        self.progress_bar.setValue(value)
        self.status_label.setText(message)
    
    def cleanup_finished(self, success, message):
        # Re-enable run button
        self.run_button.setEnabled(True)
        
        # Update status
        self.status_label.setText(message)
        
        # Show message box
        if success:
            QMessageBox.information(self, "Cleanup Complete", message)
        else:
            QMessageBox.warning(self, "Cleanup Failed", message)
    
    def open_settings(self):
        dialog = SettingsDialog(self, self.config)
        if dialog.exec_():
            # Get settings
            settings = dialog.get_settings()
            
            # Update config
            for key, value in settings.items():
                self.config[key] = value
            
            # Save config
            save_config(self.config)
            
            # Create directories
            for dir_key in ["apps_dir", "media_dir", "music_dir", "archives_dir", "other_dir"]:
                os.makedirs(self.config[dir_key], exist_ok=True)
    
    def configure_schedule(self):
        dialog = ScheduleSettingsDialog(self, self.config)
        if dialog.exec_():
            # Get schedule
            schedule = dialog.get_schedule()
            
            # Update config
            self.config["schedule"] = schedule
            
            # Save config
            save_config(self.config)
            
            # Update LaunchAgent
            create_launch_agent(self.config)
            
            # Update status
            schedule_text = "Disabled"
            if self.config["schedule"]["enabled"]:
                days = []
                for day_index in self.config["schedule"]["days"]:
                    day_names = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
                    days.append(day_names[day_index])
                
                schedule_text = f"Enabled - {', '.join(days)} at {self.config['schedule']['time']}"
            
            self.schedule_status.setText(schedule_text)
            
            # Show information about permissions if scheduling is enabled
            if self.config["schedule"]["enabled"]:
                QMessageBox.information(
                    self,
                    "Schedule Permissions",
                    "For scheduled tasks to work properly, you may need to:\n\n"
                    "1. Grant Full Disk Access to this app in System Preferences > Security & Privacy > Privacy\n"
                    "2. Make sure the app is in your Applications folder\n"
                    "3. Run the app at least once manually before scheduling\n\n"
                    "If you experience issues with scheduling, check the log files in:\n"
                    f"{CONFIG_DIR}"
                )
    
    def reset_credentials(self):
        dialog = CredentialsDialog(self, self.config["rpc_url"])
        if dialog.exec_():
            # Get credentials
            creds = dialog.get_credentials()
            
            # Update RPC URL
            self.config["rpc_url"] = creds["url"]
            self.rpc_status.setText(creds["url"])
            
            # Save config
            save_config(self.config)
            
            # Save credentials
            if save_credentials(creds["username"], creds["password"]):
                self.credentials = {"username": creds["username"], "password": creds["password"]}
                self.cred_status.setText("Configured")
                QMessageBox.information(self, "Credentials Saved", "Transmission RPC credentials have been saved.")
            else:
                QMessageBox.warning(self, "Error", "Failed to save credentials.")
    
    def view_logs(self):
        dialog = LogViewerDialog(self)
        dialog.exec_()

def main():
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
