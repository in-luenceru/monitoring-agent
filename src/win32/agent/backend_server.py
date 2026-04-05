"""
RiskNoX Security Agent - Backend API Server
Provides secure endpoints for antivirus, web blocking, and patch management
"""
import os
import sys

# Set encoding hint for Python (doesn't modify streams)
if 'PYTHONIOENCODING' not in os.environ:
    os.environ['PYTHONIOENCODING'] = 'utf-8:replace'

import json
import subprocess
import threading
import time
import hashlib
import secrets
import schedule
from datetime import datetime, timedelta
from pathlib import Path
import win32com.client
import pythoncom
import winreg
import subprocess

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import psutil

# Initialize Flask app
app = Flask(__name__)
CORS(app)

# Configuration
CONFIG_DIR = Path(__file__).parent / "config"
VENDOR_DIR = Path(__file__).parent / "vendor"
LOGS_DIR = Path(__file__).parent / "logs"
WEB_DIR = Path(__file__).parent / "web"

# Create directories if they don't exist
LOGS_DIR.mkdir(exist_ok=True)
CONFIG_DIR.mkdir(exist_ok=True)

# Security configuration
ADMIN_TOKENS = {}  # In production, use database
SCAN_SESSIONS = {}  # Active scan sessions
SCHEDULED_SCANS = {}  # Scheduled scan configurations

# Global state for process monitors
ACTIVE_MONITORS = {}
MONITOR_LOCK = threading.Lock()

# Debug settings
DEBUG_MODE = True

# ============================================================================
# SAFE encoding helper - NO system stream modification
# ============================================================================
def safe_print(message, level="INFO"):
    """Safely print messages, handling encoding issues without touching system streams"""
    try:
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        log_msg = f"[{timestamp}] [{level}] {message}"
        print(log_msg)
    except UnicodeEncodeError:
        # Fallback: convert to ASCII-safe string
        try:
            timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
            safe_msg = str(message).encode('ascii', errors='replace').decode('ascii')
            print(f"[{timestamp}] [{level}] {safe_msg}")
        except:
            # Ultimate fallback: just print without timestamp
            try:
                print(str(message).encode('ascii', errors='ignore').decode('ascii'))
            except:
                pass  # Give up silently if all else fails

def safe_str(value):
    """Convert any value to ASCII-safe string"""
    try:
        return str(value).encode('ascii', errors='replace').decode('ascii')
    except:
        return str(value)

def debug_log(message, level="INFO"):
    """Print debug messages with timestamp - encoding safe"""
    if DEBUG_MODE:
        safe_print(message, level)


class SecurityAgent:
        
    def __init__(self):
        self.clamav_path = VENDOR_DIR / "clamscan.exe"
        self.clamd_path = VENDOR_DIR / "clamd.exe"
        self.freshclam_path = VENDOR_DIR / "freshclam.exe"
        self.hosts_file = Path("C:/Windows/System32/drivers/etc/hosts")
        self.blocked_urls_file = CONFIG_DIR / "blocked_urls.json"
        self.blocked_apps_file = CONFIG_DIR / "blocked_apps.json"

        
        # Application discovery cache
        self._app_cache = None
        self._app_cache_time = None
        self._app_cache_duration = 300  # 5 minutes cache
    
    def _check_clamav_databases(self):
        """Check if ClamAV databases are available"""
        db_path = VENDOR_DIR / "database"
        main_cvd = db_path / "main.cvd"
        main_cld = db_path / "main.cld"
        daily_cvd = db_path / "daily.cvd"
        daily_cld = db_path / "daily.cld"
        
        # Check if either .cvd or .cld format exists (ClamAV uses both)
        has_main = (main_cvd.exists() and main_cvd.stat().st_size > 1000) or \
                   (main_cld.exists() and main_cld.stat().st_size > 1000)
        has_daily = (daily_cvd.exists() and daily_cvd.stat().st_size > 1000) or \
                    (daily_cld.exists() and daily_cld.stat().st_size > 1000)
        
        return has_main and has_daily
    
    def _add_scan_log(self, session_id, message):
        """Add a log message to the scan session"""
        if session_id in SCAN_SESSIONS:
            timestamp = datetime.now().strftime("%H:%M:%S")
            log_entry = f"[{timestamp}] {message}"
            SCAN_SESSIONS[session_id]['scan_log'].append(log_entry)
            
            if len(SCAN_SESSIONS[session_id]['scan_log']) > 100:
                SCAN_SESSIONS[session_id]['scan_log'] = SCAN_SESSIONS[session_id]['scan_log'][-100:]
    
    def _update_virus_database(self):
        """Update ClamAV virus database using freshclam"""
        try:
            db_dir = VENDOR_DIR / "database"
            db_dir.mkdir(exist_ok=True)
            
            print("Updating ClamAV virus database...")
            
            result = subprocess.run([
                str(self.freshclam_path),
                f'--datadir={db_dir}',
                '--quiet',
                '--no-warnings'
            ], capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                print("Virus database updated successfully")
                return True
            else:
                print(f"Database update warning: {result.stderr}")
                return (db_dir / "main.cvd").exists() or (db_dir / "main.cld").exists()
                
        except subprocess.TimeoutExpired:
            print("Database update timed out")
            return False
        except Exception as e:
            print(f"Error updating database: {e}")
            return False
    
    def setup_database_updates(self):
        """Schedule daily virus database updates"""
        def update_job():
            print("Running scheduled virus database update...")
            self._update_virus_database()
        
        schedule.every().day.at("02:00").do(update_job)
        print("Scheduled daily virus database updates at 02:00")
    
    def generate_admin_token(self, username, password):
        """Generate admin authentication token"""
        if username == "admin" and password == "RiskNoX@2024":
            token = secrets.token_hex(32)
            ADMIN_TOKENS[token] = {
                'username': username,
                'created_at': datetime.now(),
                'expires_at': datetime.now() + timedelta(hours=8)
            }
            return token
        return None
    
    def verify_admin_token(self, token):
        """Verify admin token"""
        if token in ADMIN_TOKENS:
            if datetime.now() < ADMIN_TOKENS[token]['expires_at']:
                return True
            else:
                del ADMIN_TOKENS[token]
        return False
    
    def scan_directory(self, scan_path, session_id, is_scheduled=False):
        """Perform ACTUAL antivirus scan using ClamAV"""
        try:
            log_file = LOGS_DIR / f"scan_{session_id}.log"
            
            if not Path(scan_path).exists():
                raise Exception(f"Scan path does not exist: {scan_path}")
            
            SCAN_SESSIONS[session_id] = {
                'status': 'initializing',
                'path': scan_path,
                'started_at': datetime.now(),
                'log_file': str(log_file),
                'files_scanned': 0,
                'threats_found': 0,
                'total_files': 0,
                'is_scheduled': is_scheduled,
                'progress_percent': 0,
                'scan_log': [],
                'threats': [],
                'errors': [],
                'last_update': datetime.now() 
            }
            
            self._add_scan_log(session_id, "Initializing ClamAV scan engine...")
            
            if not self.clamav_path.exists():
                raise Exception("ClamAV executable not found. Please install ClamAV.")
            
            db_dir = VENDOR_DIR / "database"
            if not self._check_clamav_databases():
                self._add_scan_log(session_id, "Virus database not found. Updating...")
                if not self._update_virus_database():
                    raise Exception("Failed to download virus database")
            
            self._add_scan_log(session_id, f"Starting scan of: {scan_path}")
            SCAN_SESSIONS[session_id]['status'] = 'scanning'
            
            clamscan_cmd = [
                str(self.clamav_path),
                '--recursive',
                '--infected',
                '--bell',
                f'--database={db_dir}',
                f'--log={log_file}',
                '--verbose',
                scan_path
            ]
            
            process = subprocess.Popen(
                clamscan_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )
            
            threats = []
            files_scanned = 0
            last_progress_update = time.time()
            
            for line in process.stdout:
                line = line.strip()
    
                if session_id not in SCAN_SESSIONS:
                    process.terminate()
                    return
    
                if line.startswith('Scanning '):
                    files_scanned += 1
                    SCAN_SESSIONS[session_id]['files_scanned'] = files_scanned
                    SCAN_SESSIONS[session_id]['last_update'] = datetime.now()
        
                    # Update progress percent periodically
                    current_time = time.time()
                    if current_time - last_progress_update >= 2:  # Update every 2 seconds
                        # Estimate progress based on files scanned
                        if files_scanned < 100:
                            progress = min(files_scanned, 50)
                        elif files_scanned < 500:
                            progress = 50 + (files_scanned - 100) // 10
                        else:
                            progress = min(70 + (files_scanned - 500) // 50, 90)
            
                        SCAN_SESSIONS[session_id]['progress_percent'] = progress
                        last_progress_update = current_time
        
                    if files_scanned % 10 == 0:
                        self._add_scan_log(session_id, f"Scanned {files_scanned} files...")
            
                elif 'FOUND' in line:
                    if ': ' in line and 'FOUND' in line:
                        last_colon_index = line.rfind(': ')
                        file_path = line[:last_colon_index].strip()
                        threat_part = line[last_colon_index + 2:].strip()
                        threat_name = threat_part.replace('FOUND', '').strip()

                        threats.append({
                            'file': file_path,
                            'threat': threat_name,
                            'timestamp': datetime.now().isoformat()
                        })

                        self._add_scan_log(session_id, f"THREAT DETECTED: {threat_name}")
                        self._add_scan_log(session_id, f"  Location: {file_path}")

                        SCAN_SESSIONS[session_id]['threats_found'] = len(threats)

            return_code = process.wait()
            stderr_output = process.stderr.read()
            
            SCAN_SESSIONS[session_id].update({
                'status': 'completed',
                'completed_at': datetime.now(),
                'files_scanned': files_scanned,
                'threats_found': len(threats),
                'threats': threats,
                'return_code': return_code,
                'progress_percent': 100
            })
            
            duration = (datetime.now() - SCAN_SESSIONS[session_id]['started_at']).total_seconds()
            self._add_scan_log(session_id, f"Scan completed in {duration:.1f} seconds")
            self._add_scan_log(session_id, f"Files scanned: {files_scanned}")
            self._add_scan_log(session_id, f"Threats found: {len(threats)}")
            
            if len(threats) == 0:
                self._add_scan_log(session_id, "System is clean - no threats detected")
            
            return True
            
        except Exception as e:
            error_msg = f'Scan error: {str(e)}'
            self._add_scan_log(session_id, f"ERROR: {error_msg}")
            SCAN_SESSIONS[session_id].update({
                'status': 'error',
                'error': error_msg,
                'progress_percent': 0
            })
            return False

    def scan_full_system(self, session_id):
        """Perform comprehensive full system scan with enhanced reliability"""
        import psutil
        import threading
        
        # Initialize session with enhanced tracking
        SCAN_SESSIONS[session_id] = {
            'session_id': session_id,
            'status': 'initializing',
            'started_at': datetime.now(),
            'path': 'Full System Scan',
            'files_scanned': 0,
            'threats_found': 0,
            'progress_percent': 0,
            'scan_log': [],
            'threats': [],
            'last_update': datetime.now(),
            'total_files': 0,
            'current_file': '',
            'scan_speed': 0,
            'errors': []
        }
        
        self._add_scan_log(session_id, " Initializing full system scan...")
        self._add_scan_log(session_id, " Preparing to scan all drives and critical directories")
        
        try:
            # Get all available drives with better error handling
            drives = []
            self._add_scan_log(session_id, " Detecting system drives...")
            
            for partition in psutil.disk_partitions():
                try:
                    usage = psutil.disk_usage(partition.mountpoint)
                    if usage and usage.total > 0:
                        drives.append(partition.mountpoint)
                        self._add_scan_log(session_id, f" Available drive: {partition.mountpoint} ({usage.total // (1024**3):.1f} GB)")
                except (PermissionError, OSError) as e:
                    self._add_scan_log(session_id, f" Cannot access drive {partition.mountpoint}: Permission denied")
                    continue
                except Exception as e:
                    self._add_scan_log(session_id, f" Error checking drive {partition.mountpoint}: {str(e)}")
                    continue
            
            # Add critical system directories (priority scan areas)
            critical_dirs = [
                ("C:\\Users", "User profiles and data"),
                ("C:\\Program Files", "Installed applications"),
                ("C:\\Program Files (x86)", "32-bit applications"),
                ("C:\\ProgramData", "Application data"),
                ("C:\\Windows\\System32", "System files"),
                ("C:\\Windows\\Temp", "Temporary files"),
                ("C:\\Temp", "System temp")
            ]
            
            # Filter existing paths and build scan list
            scan_targets = []
            
            # Add drives first
            for drive in drives:
                if Path(drive).exists():
                    scan_targets.append((drive, f"Full drive scan"))
            
            # Add critical directories that exist and aren't already covered by drive scans
            for dir_path, description in critical_dirs:
                if Path(dir_path).exists():
                    # Only add if not already covered by a drive scan
                    covered = any(dir_path.startswith(drive) for drive, _ in scan_targets)
                    if not covered:
                        scan_targets.append((dir_path, description))
            
            total_targets = len(scan_targets)
            self._add_scan_log(session_id, f" Will scan {total_targets} locations")
            SCAN_SESSIONS[session_id]['status'] = 'scanning'
            
            # Process each scan target
            for i, (scan_path, description) in enumerate(scan_targets):
                try:
                    # Check if scan was cancelled
                    if session_id not in SCAN_SESSIONS:
                        self._add_scan_log(session_id, " Scan cancelled by user")
                        return
        
                    # Update overall progress
                    overall_progress = int((i / total_targets) * 100)
                    SCAN_SESSIONS[session_id]['progress_percent'] = overall_progress
                    SCAN_SESSIONS[session_id]['last_update'] = datetime.now()
        
                    self._add_scan_log(session_id, f"[{i+1}/{total_targets}] Scanning: {scan_path}")
                    self._add_scan_log(session_id, f"  {description}")
        
                    # Create unique temporary session for sub-scan
                    temp_session = f"{session_id}_sys_{i}"
        
                    try:
                        # Run directory scan for this location
                        result = self.scan_directory(scan_path, temp_session, is_scheduled=False)
            
                        # Merge results if scan completed successfully
                        if temp_session in SCAN_SESSIONS:
                            temp_results = SCAN_SESSIONS[temp_session]
                
                            # Accumulate results
                            SCAN_SESSIONS[session_id]['files_scanned'] += temp_results.get('files_scanned', 0)
                            SCAN_SESSIONS[session_id]['threats_found'] += temp_results.get('threats_found', 0)
                            SCAN_SESSIONS[session_id]['total_files'] += temp_results.get('total_files', 0)
                            SCAN_SESSIONS[session_id]['last_update'] = datetime.now()
                
                            # Merge threats
                            if temp_results.get('threats'):
                                SCAN_SESSIONS[session_id]['threats'].extend(temp_results['threats'])
                
                            # Merge errors
                            if temp_results.get('errors'):
                                SCAN_SESSIONS[session_id]['errors'].extend(temp_results['errors'])
                
                            # Log sub-scan results
                            sub_files = temp_results.get('files_scanned', 0)
                            sub_threats = temp_results.get('threats_found', 0)
                            self._add_scan_log(session_id, f"    Completed: {sub_files} files, {sub_threats} threats")
                
                            # Clean up temp session
                            del SCAN_SESSIONS[temp_session]
                        else:
                            self._add_scan_log(session_id, f"    Sub-scan session lost for: {scan_path}")
                
                    except Exception as subscan_error:
                        self._add_scan_log(session_id, f"    Error scanning {scan_path}: {str(subscan_error)}")
                        SCAN_SESSIONS[session_id]['errors'].append(f"Scan error in {scan_path}: {str(subscan_error)}")
                        continue
            
                except Exception as path_error:
                    self._add_scan_log(session_id, f" Cannot access {scan_path}: {str(path_error)}")
                    SCAN_SESSIONS[session_id]['errors'].append(f"Access error: {scan_path} - {str(path_error)}")
                    continue
            
            # Finalize full system scan
            end_time = datetime.now()
            duration = end_time - SCAN_SESSIONS[session_id]['started_at']
            
            SCAN_SESSIONS[session_id].update({
                'progress_percent': 100,
                'status': 'completed',
                'completed_at': end_time,
                'scan_duration': duration.total_seconds()
            })
            
            files_scanned = SCAN_SESSIONS[session_id]['files_scanned']
            threats_found = SCAN_SESSIONS[session_id]['threats_found']
            total_files = SCAN_SESSIONS[session_id]['total_files']
            
            # Comprehensive completion logging
            self._add_scan_log(session_id, " Full system scan completed!")
            self._add_scan_log(session_id, f" COMPREHENSIVE SCAN SUMMARY:")
            self._add_scan_log(session_id, f"    Total files analyzed: {total_files}")
            self._add_scan_log(session_id, f"    Files scanned: {files_scanned}")
            self._add_scan_log(session_id, f"    Threats detected: {threats_found}")
            self._add_scan_log(session_id, f"    Total scan time: {duration.total_seconds():.1f} seconds")
            
            if SCAN_SESSIONS[session_id]['errors']:
                error_count = len(SCAN_SESSIONS[session_id]['errors'])
                self._add_scan_log(session_id, f"    Errors encountered: {error_count}")
                
            if threats_found > 0:
                self._add_scan_log(session_id, f" SECURITY ALERT: {threats_found} threats found across system!")
                self._add_scan_log(session_id, f" ACTION REQUIRED: Review detected threats immediately")
            else:
                self._add_scan_log(session_id, f" SYSTEM SECURE: No threats detected in full scan")
                self._add_scan_log(session_id, f" Your system appears to be clean!")
            
        except Exception as e:
            error_msg = f'System scan error: {str(e)}'
            self._add_scan_log(session_id, f" {error_msg}")
            SCAN_SESSIONS[session_id].update({
                'status': 'error',
                'error': error_msg,
                'progress_percent': 0
            })
            return False

    def scan_quick_system(self, session_id):
        """Perform enhanced quick system scan with better reliability"""
        import os
        
        # Initialize session with enhanced tracking
        SCAN_SESSIONS[session_id] = {
            'session_id': session_id,
            'status': 'initializing',
            'started_at': datetime.now(),
            'path': 'Quick System Scan',
            'files_scanned': 0,
            'threats_found': 0,
            'progress_percent': 0,
            'scan_log': [],
            'threats': [],
            'last_update': datetime.now(),
            'total_files': 0,
            'current_file': '',
            'scan_speed': 0,
            'errors': []
        }
        
        self._add_scan_log(session_id, " Initializing quick system scan...")
        self._add_scan_log(session_id, " Targeting high-risk areas for rapid threat detection")
        
        try:
            # Quick scan targets - prioritized threat locations
            quick_targets = [
                (os.path.expanduser("~\\Downloads"), "User downloads (high risk)"),
                (os.path.expanduser("~\\Desktop"), "Desktop files"),
                (os.path.expanduser("~\\Documents"), "User documents"),
                ("C:\\Windows\\Temp", "Windows temporary files"),
                ("C:\\Temp", "System temporary files"),
                ("C:\\ProgramData", "Application data"),
                ("C:\\Users\\Public", "Public user area"),
                ("C:\\Program Files\\Common Files", "Common program files")
            ]
            
            # Filter existing paths and validate access
            accessible_targets = []
            self._add_scan_log(session_id, " Checking target locations...")
            
            for path, description in quick_targets:
                try:
                    if Path(path).exists() and Path(path).is_dir():
                        # Test if we can access the directory
                        list(Path(path).iterdir())  # This will raise an exception if no access
                        accessible_targets.append((path, description))
                        self._add_scan_log(session_id, f"    {description}: {path}")
                    else:
                        self._add_scan_log(session_id, f"    Not found: {path}")
                except PermissionError:
                    self._add_scan_log(session_id, f"    Access denied: {path}")
                    SCAN_SESSIONS[session_id]['errors'].append(f"Access denied: {path}")
                except Exception as e:
                    self._add_scan_log(session_id, f"    Error accessing {path}: {str(e)}")
                    SCAN_SESSIONS[session_id]['errors'].append(f"Error accessing {path}: {str(e)}")
            
            total_targets = len(accessible_targets)
            
            if total_targets == 0:
                self._add_scan_log(session_id, " No accessible scan targets found")
                SCAN_SESSIONS[session_id].update({
                    'status': 'completed',
                    'progress_percent': 100,
                    'completed_at': datetime.now()
                })
                return False
            
            self._add_scan_log(session_id, f" Quick scanning {total_targets} critical locations")
            SCAN_SESSIONS[session_id]['status'] = 'scanning'
            
            # Process each target location
            for i, (scan_path, description) in enumerate(accessible_targets):
                try:
                    # Check if scan was cancelled
                    if session_id not in SCAN_SESSIONS:
                        self._add_scan_log(session_id, " Quick scan cancelled")
                        return
        
                    # Update progress
                    progress = int((i / total_targets) * 90)  # Leave 10% for finalization
                    SCAN_SESSIONS[session_id]['progress_percent'] = progress
                    SCAN_SESSIONS[session_id]['last_update'] = datetime.now()
        
                    self._add_scan_log(session_id, f" [{i+1}/{total_targets}] {description}")
                    self._add_scan_log(session_id, f"    Location: {scan_path}")
        
                    # Create temporary session for sub-scan
                    temp_session = f"{session_id}_quick_{i}"
        
                    try:
                        # Run focused directory scan
                        result = self.scan_directory(scan_path, temp_session, is_scheduled=False)
            
                        # Merge results if sub-scan completed
                        if temp_session in SCAN_SESSIONS:
                            temp_results = SCAN_SESSIONS[temp_session]
                
                            # Accumulate results
                            SCAN_SESSIONS[session_id]['files_scanned'] += temp_results.get('files_scanned', 0)
                            SCAN_SESSIONS[session_id]['threats_found'] += temp_results.get('threats_found', 0)
                            SCAN_SESSIONS[session_id]['total_files'] += temp_results.get('total_files', 0)
                            SCAN_SESSIONS[session_id]['last_update'] = datetime.now()
                
                            # Merge threats
                            if temp_results.get('threats'):
                                SCAN_SESSIONS[session_id]['threats'].extend(temp_results['threats'])
                
                            # Merge errors
                            if temp_results.get('errors'):
                                SCAN_SESSIONS[session_id]['errors'].extend(temp_results['errors'])
                
                            # Log sub-scan results
                            sub_files = temp_results.get('files_scanned', 0)
                            sub_threats = temp_results.get('threats_found', 0)
                            self._add_scan_log(session_id, f"   Scanned: {sub_files} files, found: {sub_threats} threats")
                
                            # Clean up temp session
                            del SCAN_SESSIONS[temp_session]
                        else:
                            self._add_scan_log(session_id, f"    Sub-scan session lost for: {scan_path}")
                
                    except Exception as subscan_error:
                        self._add_scan_log(session_id, f"    Error in quick scan: {str(subscan_error)}")
                        SCAN_SESSIONS[session_id]['errors'].append(f"Quick scan error in {scan_path}: {str(subscan_error)}")
            
                except Exception as path_error:
                    self._add_scan_log(session_id, f" Cannot process {scan_path}: {str(path_error)}")
                    SCAN_SESSIONS[session_id]['errors'].append(f"Path processing error: {scan_path} - {str(path_error)}")
                    continue
            
            # Finalize quick scan
            end_time = datetime.now()
            duration = end_time - SCAN_SESSIONS[session_id]['started_at']
            
            SCAN_SESSIONS[session_id].update({
                'progress_percent': 100,
                'status': 'completed',
                'completed_at': end_time,
                'scan_duration': duration.total_seconds()
            })
            
            files_scanned = SCAN_SESSIONS[session_id]['files_scanned']
            threats_found = SCAN_SESSIONS[session_id]['threats_found']
            total_files = SCAN_SESSIONS[session_id]['total_files']
            
            # Comprehensive quick scan summary
            self._add_scan_log(session_id, " Quick system scan completed!")
            self._add_scan_log(session_id, f" QUICK SCAN SUMMARY:")
            self._add_scan_log(session_id, f"    Total files analyzed: {total_files}")
            self._add_scan_log(session_id, f"   Files scanned: {files_scanned}")
            self._add_scan_log(session_id, f"    Threats detected: {threats_found}")
            self._add_scan_log(session_id, f"    Scan time: {duration.total_seconds():.1f} seconds")
            
            if SCAN_SESSIONS[session_id]['errors']:
                error_count = len(SCAN_SESSIONS[session_id]['errors'])
                self._add_scan_log(session_id, f"    Areas with access issues: {error_count}")
                
            if threats_found > 0:
                self._add_scan_log(session_id, f" THREATS FOUND: {threats_found} items require attention!")
                self._add_scan_log(session_id, f" Recommendation: Run full system scan for complete analysis")
            else:
                self._add_scan_log(session_id, f" QUICK SCAN CLEAR: No immediate threats in critical areas")
                self._add_scan_log(session_id, f" Tip: Quick scans check high-risk areas only")
            
            
        except Exception as e:
            error_msg = f'Quick scan error: {str(e)}'
            self._add_scan_log(session_id, f" {error_msg}")
            SCAN_SESSIONS[session_id].update({
                'status': 'error',
                'error': error_msg,
                'progress_percent': 0
            })
            return False
    
    def create_scheduled_scan(self, name, scan_path, scan_type='directory', schedule_type='daily', schedule_time=None, enabled=True, **kwargs):
        """Create a scheduled scan configuration"""
        scan_id = hashlib.md5(f"{name}_{scan_path}_{scan_type}_{datetime.now()}".encode()).hexdigest()
        
        SCHEDULED_SCANS[scan_id] = {
            'id': scan_id,
            'name': name,
            'path': scan_path,
            'scan_type': scan_type,           # 'directory', 'system', 'quick_system'
            'schedule_type': schedule_type,   # 'interval', 'daily', 'weekly', 'monthly'
            'schedule_time': schedule_time,   # HH:MM format or None for intervals
            'enabled': enabled,
            'created_at': datetime.now().isoformat(),
            'last_run': None,
            'next_run': self._calculate_next_run(schedule_type, schedule_time, **kwargs),
            'total_runs': 0,
            # Additional parameters for different schedule types
            'interval_value': kwargs.get('interval_value'),
            'interval_unit': kwargs.get('interval_unit'),
            'weekly_day': kwargs.get('weekly_day'),
            'monthly_day': kwargs.get('monthly_day')
        }
        
        # Register with scheduler
        if enabled:
            self._register_scheduled_scan(scan_id)
        
        return scan_id

    def get_database_info(self):
        """Get virus database information and last update time"""
        try:
            db_dir = VENDOR_DIR / "database"
        
            if not db_dir.exists():
                return {
                    'status': 'not_found',
                    'message': 'Database directory does not exist'
                }
        
            database_info = {
                'status': 'available',
                'databases': [],
                'total_size_mb': 0,
                'last_update': None
            }
        
            # Check for database files
            db_files = ['main.cvd', 'main.cld', 'daily.cvd', 'daily.cld', 'bytecode.cvd', 'bytecode.cld']
        
            latest_time = None
            for db_file in db_files:
                file_path = db_dir / db_file
                if file_path.exists():
                    stat_info = file_path.stat()
                    size_mb = stat_info.st_size / (1024 * 1024)
                    modified_time = datetime.fromtimestamp(stat_info.st_mtime)
                
                    database_info['databases'].append({
                        'name': db_file,
                        'size_mb': round(size_mb, 2),
                        'last_modified': modified_time.isoformat()
                    })
                
                    database_info['total_size_mb'] += size_mb
                
                    # Track latest modification time
                    if latest_time is None or modified_time > latest_time:
                        latest_time = modified_time
        
            database_info['total_size_mb'] = round(database_info['total_size_mb'], 2)
            database_info['last_update'] = latest_time.isoformat() if latest_time else None
            database_info['database_count'] = len(database_info['databases'])
        
            # Get ClamAV version
            try:
                result = subprocess.run([
                    str(self.clamav_path),
                    '--version'
                ], capture_output=True, text=True, timeout=5)
            
                if result.returncode == 0:
                    database_info['clamav_version'] = result.stdout.strip()
            except:
                database_info['clamav_version'] = 'Unknown'
        
            return database_info
        
        except Exception as e:
            return {
                'status': 'error',
                'message': str(e)
           }

    def get_last_database_update_log(self):
        """Get the last database update log from file"""
        try:
            log_file = LOGS_DIR / "database_updates.log"
        
            if not log_file.exists():
                return None
        
            # Read last 20 lines
            with open(log_file, 'r', encoding='utf-8') as f:
                lines = f.readlines()
                return ''.join(lines[-20:]) if lines else None
            
        except Exception as e:
            return None

    def _update_virus_database(self):
        """Update ClamAV virus database using freshclam - with logging"""
        try:
            db_dir = VENDOR_DIR / "database"
            db_dir.mkdir(exist_ok=True)
        
            print("Updating ClamAV virus database...")
        
            # Create log file
            log_file = LOGS_DIR / "database_updates.log"
        
            # Log update attempt
            with open(log_file, 'a', encoding='utf-8') as f:
                f.write(f"\n{'='*50}\n")
                f.write(f"Database Update Attempt\n")
                f.write(f"Time: {datetime.now().isoformat()}\n")
                f.write(f"{'='*50}\n")
        
            result = subprocess.run([
                str(self.freshclam_path),
                f'--datadir={db_dir}',
                '--quiet',
                '--no-warnings'
            ], capture_output=True, text=True, timeout=300)
        
            # Log result
            with open(log_file, 'a', encoding='utf-8') as f:
                if result.returncode == 0:
                    f.write("Status: SUCCESS\n")
                    print("Virus database updated successfully")
                else:
                    f.write(f"Status: WARNING (return code: {result.returncode})\n")
                    f.write(f"Error output: {result.stderr}\n")
                    print(f"Database update warning: {result.stderr}")
            
                if result.stdout:
                    f.write(f"Output: {result.stdout}\n")
        
            if result.returncode == 0:
                return True
            else:
                return (db_dir / "main.cvd").exists() or (db_dir / "main.cld").exists()
            
        except subprocess.TimeoutExpired:
            print("Database update timed out")
            with open(log_file, 'a', encoding='utf-8') as f:
                f.write("Status: TIMEOUT\n")
            return False
        except Exception as e:
            print(f"Error updating database: {e}")
            with open(log_file, 'a', encoding='utf-8') as f:
                f.write(f"Status: ERROR - {str(e)}\n")
            return False

    def _calculate_next_run(self, schedule_type, schedule_time, **kwargs):
        """Calculate next run time for scheduled scan"""
        try:
            now = datetime.now()
            
            if schedule_type == 'interval':
                # For interval-based scheduling
                interval_value = kwargs.get('interval_value', 30)
                interval_unit = kwargs.get('interval_unit', 'minutes')
                
                if interval_unit == 'minutes':
                    next_run = now + timedelta(minutes=interval_value)
                else:  # hours
                    next_run = now + timedelta(hours=interval_value)
                    
            elif schedule_type == 'daily':
                hour, minute = map(int, schedule_time.split(':'))
                next_run = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
                if next_run <= now:
                    next_run += timedelta(days=1)
                    
            elif schedule_type == 'weekly':
                hour, minute = map(int, schedule_time.split(':'))
                weekly_day = kwargs.get('weekly_day', 'monday')
                
                # Convert day name to number (Monday=0, Sunday=6)
                day_map = {'monday': 0, 'tuesday': 1, 'wednesday': 2, 'thursday': 3, 
                          'friday': 4, 'saturday': 5, 'sunday': 6}
                target_day = day_map.get(weekly_day, 0)
                
                next_run = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
                days_ahead = target_day - now.weekday()
                if days_ahead <= 0 or (days_ahead == 0 and next_run <= now):
                    days_ahead += 7
                next_run += timedelta(days=days_ahead)
                
            elif schedule_type == 'monthly':
                hour, minute = map(int, schedule_time.split(':'))
                monthly_day = int(kwargs.get('monthly_day', 1))
                
                if monthly_day == -1:  # Last day of month
                    # Get last day of current month
                    next_month = now.month + 1 if now.month < 12 else 1
                    next_year = now.year if now.month < 12 else now.year + 1
                    last_day = (datetime(next_year, next_month, 1) - timedelta(days=1)).day
                    
                    try:
                        next_run = now.replace(day=last_day, hour=hour, minute=minute, second=0, microsecond=0)
                        if next_run <= now:
                            # Go to last day of next month
                            next_month = now.month + 1 if now.month < 12 else 1
                            next_year = now.year if now.month < 12 else now.year + 1
                            if next_month == 12:
                                next_next_month = 1
                                next_next_year = next_year + 1
                            else:
                                next_next_month = next_month + 1
                                next_next_year = next_year
                            last_day_next = (datetime(next_next_year, next_next_month, 1) - timedelta(days=1)).day
                            next_run = datetime(next_year, next_month, last_day_next, hour, minute)
                    except ValueError:
                        # Fallback to 28th if calculation fails
                        next_run = now.replace(day=28, hour=hour, minute=minute, second=0, microsecond=0)
                        if next_run <= now:
                            next_run = next_run.replace(month=next_run.month + 1 if next_run.month < 12 else 1)
                else:
                    # Specific day of month
                    try:
                        next_run = now.replace(day=monthly_day, hour=hour, minute=minute, second=0, microsecond=0)
                        if next_run <= now:
                            # Go to next month
                            next_month = now.month + 1 if now.month < 12 else 1
                            next_year = now.year if now.month < 12 else now.year + 1
                            next_run = datetime(next_year, next_month, monthly_day, hour, minute)
                    except ValueError:
                        # Day doesn't exist in current month, use last valid day
                        next_run = now + timedelta(days=30)
            else:
                next_run = now + timedelta(days=1)
            
            return next_run.isoformat()
        except Exception as e:
            print(f"Error calculating next run: {e}")
            return (datetime.now() + timedelta(hours=1)).isoformat()
    
    def _register_scheduled_scan(self, scan_id):
        """Register scheduled scan with the scheduler with enhanced error handling"""
        try:
            if scan_id not in SCHEDULED_SCANS:
                print(f"Error: Cannot register scan {scan_id} - not found in SCHEDULED_SCANS")
                return
            
            scan_config = SCHEDULED_SCANS[scan_id]
            print(f"Registering scheduled scan: {scan_config.get('name', 'Unknown')} (ID: {scan_id})")
            
            # Clear any existing jobs for this scan
            schedule.clear(f'scan_{scan_id}')
            
            schedule_type = scan_config.get('schedule_type', 'daily')
            
            try:
                if schedule_type == 'interval':
                    interval_value = scan_config.get('interval_value', 30)
                    interval_unit = scan_config.get('interval_unit', 'minutes')
                    
                    if interval_unit == 'minutes':
                        job = schedule.every(interval_value).minutes.do(
                            self._execute_scheduled_scan, scan_id
                        )
                        job.tag = f'scan_{scan_id}'
                        print(f"  Registered for every {interval_value} minutes")
                    else:  # hours
                        job = schedule.every(interval_value).hours.do(
                            self._execute_scheduled_scan, scan_id
                        )
                        job.tag = f'scan_{scan_id}'
                        print(f"  Registered for every {interval_value} hours")
                        
                elif schedule_type == 'daily':
                    schedule_time = scan_config.get('schedule_time', '00:00')
                    job = schedule.every().day.at(schedule_time).do(
                        self._execute_scheduled_scan, scan_id
                    )
                    job.tag = f'scan_{scan_id}'
                    print(f"  Registered for daily at {schedule_time}")
                    
                elif schedule_type == 'weekly':
                    weekly_day = scan_config.get('weekly_day', 'monday').lower()
                    schedule_time = scan_config.get('schedule_time', '00:00')
                    
                    # Validate weekly day
                    valid_days = ['monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday']
                    if weekly_day not in valid_days:
                        weekly_day = 'monday'
                    
                    schedule_obj = getattr(schedule.every(), weekly_day)
                    job = schedule_obj.at(schedule_time).do(
                        self._execute_scheduled_scan, scan_id
                    )
                    job.tag = f'scan_{scan_id}'
                    print(f"  Registered for weekly on {weekly_day} at {schedule_time}")
                    
                elif schedule_type == 'monthly':
                    schedule_time = scan_config.get('schedule_time', '00:00')
                    # For monthly, we'll check daily and run if it's the right day
                    job = schedule.every().day.at(schedule_time).do(
                        self._check_monthly_scan, scan_id
                    )
                    job.tag = f'scan_{scan_id}'
                    print(f"  Registered for monthly check at {schedule_time}")
                    
                else:
                    print(f"  Warning: Unknown schedule type '{schedule_type}', defaulting to daily")
                    job = schedule.every().day.at('00:00').do(
                        self._execute_scheduled_scan, scan_id
                    )
                    job.tag = f'scan_{scan_id}'
                
                # Update scan config with successful registration
                SCHEDULED_SCANS[scan_id]['registered'] = True
                SCHEDULED_SCANS[scan_id]['registration_error'] = None
                
                # Calculate and update next run time
                next_run = self._calculate_next_run(schedule_type, scan_config.get('schedule_time'))
                if next_run:
                    SCHEDULED_SCANS[scan_id]['next_run'] = next_run.isoformat()
                    print(f"  Next run scheduled for: {next_run}")
                    
            except Exception as schedule_error:
                print(f"Error setting up schedule for scan {scan_id}: {str(schedule_error)}")
                SCHEDULED_SCANS[scan_id].update({
                    'registered': False,
                    'registration_error': str(schedule_error)
                })
                
        except Exception as e:
            print(f"Critical error registering scheduled scan {scan_id}: {str(e)}")
            if scan_id in SCHEDULED_SCANS:
                SCHEDULED_SCANS[scan_id].update({
                    'registered': False,
                    'registration_error': f"Registration error: {str(e)}"
                })
    
    def _execute_scheduled_scan(self, scan_id):
        """Execute a scheduled scan with enhanced reliability and error handling"""
        try:
            if scan_id not in SCHEDULED_SCANS:
                print(f"Warning: Scheduled scan {scan_id} not found in SCHEDULED_SCANS")
                return
            
            scan_config = SCHEDULED_SCANS[scan_id]
            
            # Check if scan is enabled
            if not scan_config.get('enabled', False):
                print(f"Scheduled scan {scan_id} is disabled, skipping execution")
                return
            
            # Check if scan path exists (for directory scans)
            scan_type = scan_config.get('scan_type', 'directory')
            if scan_type == 'directory' and not Path(scan_config.get('path', '')).exists():
                print(f"Warning: Scheduled scan path does not exist: {scan_config.get('path')}")
                SCHEDULED_SCANS[scan_id]['last_error'] = f"Path not found: {scan_config.get('path')}"
                SCHEDULED_SCANS[scan_id]['error_count'] = scan_config.get('error_count', 0) + 1
                return
            
            # Generate unique session ID for this scheduled scan
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            session_id = hashlib.md5(f"scheduled_{scan_id}_{timestamp}".encode()).hexdigest()
            
            print(f"Executing scheduled scan: {scan_config['name']} (ID: {scan_id}, Session: {session_id})")
            
            # Calculate next run time before starting scan
            next_run = self._calculate_next_run(scan_config['schedule_type'], scan_config['schedule_time'])
            
            # Update scheduled scan info
            current_time = datetime.now()
            SCHEDULED_SCANS[scan_id].update({
                'last_run': current_time.isoformat(),
                'total_runs': scan_config.get('total_runs', 0) + 1,
                'next_run': next_run.isoformat() if next_run else None,
                'current_session': session_id,
                'last_error': None,  # Clear previous errors on successful start
                'status': 'running'
            })
            
            # Create scan wrapper function for better error handling
            def scan_wrapper():
                try:
                    if scan_type == 'system':
                        result = self.scan_full_system(session_id)
                    elif scan_type == 'quick_system':
                        result = self.scan_quick_system(session_id)
                    else:  # directory scan
                        result = self.scan_directory(scan_config['path'], session_id, is_scheduled=True)
                    
                    # Update scan status on completion
                    if scan_id in SCHEDULED_SCANS:
                        SCHEDULED_SCANS[scan_id].update({
                            'status': 'completed',
                            'current_session': None
                        })
                        print(f"Scheduled scan {scan_id} completed successfully")
                    
                except Exception as scan_error:
                    print(f"Error in scheduled scan {scan_id}: {str(scan_error)}")
                    if scan_id in SCHEDULED_SCANS:
                        SCHEDULED_SCANS[scan_id].update({
                            'status': 'error',
                            'last_error': str(scan_error),
                            'error_count': scan_config.get('error_count', 0) + 1,
                            'current_session': None
                        })
            
            # Start scan in background thread
            scan_thread = threading.Thread(target=scan_wrapper, name=f"ScheduledScan-{scan_id}")
            scan_thread.daemon = True
            scan_thread.start()
            
            print(f"Scheduled scan thread started for {scan_config['name']}")
            
        except Exception as e:
            print(f"Critical error executing scheduled scan {scan_id}: {str(e)}")
            if scan_id in SCHEDULED_SCANS:
                SCHEDULED_SCANS[scan_id].update({
                    'status': 'error',
                    'last_error': f"Execution error: {str(e)}",
                    'error_count': SCHEDULED_SCANS[scan_id].get('error_count', 0) + 1,
                    'current_session': None
                })
    
    def _check_monthly_scan(self, scan_id):
        """Check if monthly scan should run today"""
        if datetime.now().day == 1:
            self._execute_scheduled_scan(scan_id)
    
    def get_scheduled_scans(self):
        """Get all scheduled scan configurations"""
        return list(SCHEDULED_SCANS.values())
    
    def update_scheduled_scan(self, scan_id, enabled=None):
        """Update scheduled scan configuration"""
        if scan_id not in SCHEDULED_SCANS:
            return False
        
        if enabled is not None:
            SCHEDULED_SCANS[scan_id]['enabled'] = enabled
            
            if enabled:
                self._register_scheduled_scan(scan_id)
            else:
                # Remove from scheduler - would need more complex logic
                pass
        
        return True
    
    def delete_scheduled_scan(self, scan_id):
        """Delete a scheduled scan"""
        if scan_id in SCHEDULED_SCANS:
            del SCHEDULED_SCANS[scan_id]
            return True
        return False

    def cancel_scan(self, session_id):
        """Cancel an active scan"""
        try:
            if session_id not in SCAN_SESSIONS:
                return {
                    'success': False,
                    'message': 'Scan session not found'
                }
        
            session = SCAN_SESSIONS[session_id]
        
            if session['status'] not in ['initializing', 'scanning']:
                return {
                    'success': False,
                    'message': f'Cannot cancel scan with status: {session["status"]}'
                }
        
            # Log cancellation
            self._add_scan_log(session_id, "Scan cancellation requested by user")
        
            # Update session status
            SCAN_SESSIONS[session_id].update({
                'status': 'cancelled',
                'cancelled_at': datetime.now(),
                'progress_percent': session.get('progress_percent', 0)
            })
        
            self._add_scan_log(session_id, "Scan has been cancelled")
        
            # Delete the session after a short delay to allow frontend to read final status
            def cleanup_session():
                time.sleep(2)
                if session_id in SCAN_SESSIONS:
                    del SCAN_SESSIONS[session_id]
        
            cleanup_thread = threading.Thread(target=cleanup_session, daemon=True)
            cleanup_thread.start()
        
            return {
                'success': True,
                'message': 'Scan cancelled successfully'
            }
        
        except Exception as e:
            return {
                'success': False,
                'message': str(e)
            }
    
    def block_url(self, url):
        """Enhanced URL blocking using multiple methods"""
        try:
            # Load current blocked URLs
            blocked_urls = self.load_blocked_urls()
            
            # Clean and normalize URL
            clean_url = url.replace('http://', '').replace('https://', '').strip()
            
            # Check if already blocked
            if any(u.get('url') == clean_url for u in blocked_urls):
                print(f"URL {clean_url} is already blocked")
                return True
            
            # Add new URL
            blocked_urls.append({
                'url': clean_url,
                'blocked_at': datetime.now().isoformat(),
                'status': 'active',
                'method': 'hosts_file'
            })
            
            # Save to config
            self.save_blocked_urls(blocked_urls)
            
            # Update hosts file with enhanced blocking
            hosts_success = self.update_hosts_file()
            
            # Additional blocking methods for better coverage
            self._create_local_blocking_page(clean_url)
            
            print(f"URL {clean_url} blocked successfully using multiple methods")
            return hosts_success
            
        except Exception as e:
            print(f"Error blocking URL: {e}")
            return False
    
    def _create_local_blocking_page(self, url):
        """Create a local blocking page to serve when users try to access blocked sites"""
        try:
            # Create a simple blocking page
            blocking_page_content = f'''
<!DOCTYPE html>
<html>
<head>
    <title>Website Blocked - RiskNoX Security</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            text-align: center;
            padding: 50px;
            margin: 0;
        }}
        .container {{
            background: rgba(255,255,255,0.1);
            border-radius: 15px;
            padding: 40px;
            max-width: 600px;
            margin: 0 auto;
            backdrop-filter: blur(10px);
        }}
        .icon {{
            font-size: 4em;
            margin-bottom: 20px;
        }}
        h1 {{
            color: #ff6b6b;
            margin-bottom: 20px;
        }}
        .url {{
            background: rgba(255,255,255,0.2);
            padding: 10px;
            border-radius: 5px;
            margin: 20px 0;
            word-break: break-all;
        }}
        .info {{
            margin-top: 30px;
            font-size: 0.9em;
            opacity: 0.8;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="icon">icon</div>
        <h1>Website Blocked</h1>
        <p>Access to this website has been restricted by RiskNoX Security Agent.</p>
        <div class="url">{url}</div>
        <p>This website is blocked according to your security policy.</p>
        <div class="info">
            <p>If you believe this is an error, please contact your system administrator.</p>
            <p>Blocked at: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        </div>
    </div>
</body>
</html>
            '''
            
            # Save the blocking page
            blocking_page_file = WEB_DIR / f"blocked_{url.replace('.', '_')}.html"
            with open(blocking_page_file, 'w', encoding='utf-8') as f:
                f.write(blocking_page_content)
                
            print(f"Created local blocking page for {url}")
            
        except Exception as e:
            print(f"Error creating blocking page: {e}")
    
    def unblock_url(self, url):
        """Enhanced URL unblocking with comprehensive cleanup"""
        try:
            blocked_urls = self.load_blocked_urls()
            
            # Clean and normalize URL
            clean_url = url.replace('http://', '').replace('https://', '').strip()
            
            # Remove from blocked list
            original_count = len(blocked_urls)
            blocked_urls = [u for u in blocked_urls if u.get('url') != clean_url]
            
            if len(blocked_urls) == original_count:
                print(f"URL {clean_url} was not in blocked list")
                return True  # Not an error if it wasn't blocked
            
            # Save updated list
            self.save_blocked_urls(blocked_urls)
            
            # Update hosts file
            hosts_success = self.update_hosts_file()
            
            # Clean up local blocking page
            self._remove_local_blocking_page(clean_url)
            
            print(f"URL {clean_url} unblocked successfully")
            return hosts_success
            
        except Exception as e:
            print(f"Error unblocking URL: {e}")
            return False
    
    def _remove_local_blocking_page(self, url):
        """Remove local blocking page for unblocked URL"""
        try:
            blocking_page_file = WEB_DIR / f"blocked_{url.replace('.', '_')}.html"
            if blocking_page_file.exists():
                blocking_page_file.unlink()
                print(f"Removed local blocking page for {url}")
        except Exception as e:
            print(f"Error removing blocking page: {e}")
    
    def load_blocked_urls(self):
        """Load blocked URLs from config"""
        try:
            if self.blocked_urls_file.exists():
                with open(self.blocked_urls_file, 'r') as f:
                    return json.load(f)
        except:
            pass
        return []
    
    def save_blocked_urls(self, urls):
        """Save blocked URLs to config"""
        CONFIG_DIR.mkdir(exist_ok=True)
        with open(self.blocked_urls_file, 'w') as f:
            json.dump(urls, f, indent=2)
    
    def update_hosts_file(self):
        """Update Windows hosts file with blocked URLs using enhanced blocking"""
        try:
            print("=== Starting enhanced hosts file update ===")
            blocked_urls = self.load_blocked_urls()
            print(f"Blocked URLs to add: {len(blocked_urls)}")
        
            # Read existing hosts file
            try:
                with open(self.hosts_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                print(f"Read existing hosts file: {len(content)} bytes")
            except Exception as e:
                print(f"Error reading hosts file: {e}")
                content = ""
        
            # Remove existing RiskNoX blocks
            lines = content.split('\n')
            cleaned_lines = [line for line in lines if not line.strip().endswith('# RiskNoX Block')]
            print(f"Cleaned {len(lines) - len(cleaned_lines)} existing RiskNoX entries")
            
            # Add RiskNoX header if not present
            if not any('# RiskNoX Security Agent - Blocked URLs' in line for line in cleaned_lines):
                cleaned_lines.append('')
                cleaned_lines.append('# RiskNoX Security Agent - Blocked URLs')
        
            # Add comprehensive blocks for each URL
            for url_data in blocked_urls:
                if url_data.get('status') == 'active':
                    url = url_data['url'].replace('http://', '').replace('https://', '').strip()
                    
                    # Add multiple variations to ensure comprehensive blocking
                    variations = [
                        url,
                        f"www.{url}",
                        f"m.{url}",  # Mobile version
                        f"mobile.{url}",  # Mobile version
                        f"*.{url}",  # Wildcard (for some parsers)
                    ]
                    
                    # Add IPv4 blocks
                    for variation in variations:
                        cleaned_lines.append(f"127.0.0.1 {variation} # RiskNoX Block")
                    
                    # Add IPv6 blocks for better coverage
                    for variation in variations:
                        cleaned_lines.append(f"::1 {variation} # RiskNoX Block")
                    
                    print(f"Added comprehensive block for: {url}")
        
            # Write back to hosts file with enhanced error handling
            new_content = '\n'.join(cleaned_lines)
        
            try: 
                # Try direct write first (requires admin privileges)
                with open(self.hosts_file, 'w', encoding='utf-8') as f:
                    f.write(new_content)
                print("Successfully wrote to hosts file directly")
                
                # Flush DNS cache to ensure changes take effect immediately
                self._flush_dns_cache()
                
                return True
                
            except PermissionError:
                print("Direct write failed, trying elevated PowerShell method...")
                
                # Create a temporary file with the content
                temp_hosts_file = CONFIG_DIR / "temp_hosts.txt"
                with open(temp_hosts_file, 'w', encoding='utf-8') as f:
                    f.write(new_content)
                
                # Use PowerShell with elevated privileges to copy the file
                ps_cmd = f'''
                    Start-Process powershell -ArgumentList "-Command","Copy-Item '{temp_hosts_file}' 'C:\\Windows\\System32\\drivers\\etc\\hosts' -Force" -Verb RunAs -Wait
                '''
                
                try:
                    result = subprocess.run(
                        ["powershell", "-Command", ps_cmd],
                        capture_output=True,
                        text=True,
                        timeout=30
                    )
                    
                    # Clean up temp file
                    if temp_hosts_file.exists():
                        temp_hosts_file.unlink()
                    
                    if result.returncode == 0:
                        print("Elevated PowerShell write succeeded")
                        self._flush_dns_cache()
                        return True
                    else:
                        print(f"Elevated PowerShell write failed: {result.stderr}")
                        return False
                        
                except subprocess.TimeoutExpired:
                    print("PowerShell command timed out - user may have cancelled UAC prompt")
                    return False
                except Exception as ps_error:
                    print(f"PowerShell execution error: {ps_error}")
                    return False
                
        except Exception as e:
            print(f"Error updating hosts file: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def _flush_dns_cache(self):
        """Flush DNS cache to ensure hosts file changes take effect"""
        try:
            print("Flushing DNS cache...")
            
            # Flush Windows DNS cache
            result = subprocess.run(
                ["ipconfig", "/flushdns"],
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                print("DNS cache flushed successfully")
            else:
                print(f"DNS flush failed: {result.stderr}")
                
            # Also try to restart DNS Client service (requires admin)
            try:
                dns_restart_cmd = '''
                    Stop-Service -Name "Dnscache" -Force -ErrorAction SilentlyContinue
                    Start-Service -Name "Dnscache" -ErrorAction SilentlyContinue
                '''
                subprocess.run(
                    ["powershell", "-Command", dns_restart_cmd],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                print("DNS Client service restart attempted")
            except:
                pass  # Don't fail if we can't restart the service
                
        except Exception as e:
            print(f"Error flushing DNS cache: {e}")

    # ---------------- JSON handling ----------------
    def get_blocked_applications(self):
        try:
            if self.blocked_apps_file.exists():
                with open(self.blocked_apps_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            return []
        except Exception as e:
            safe_print(f"Error loading blocked apps: {safe_str(e)}")
            return []

    def save_blocked_applications(self, blocked_apps):
        try:
            CONFIG_DIR.mkdir(exist_ok=True)
        
            # Sanitize all string values in blocked_apps before saving
            sanitized_apps = []
            for app in blocked_apps:
                sanitized_app = {}
                for key, value in app.items():
                    if isinstance(value, str):
                        sanitized_app[key] = safe_str(value)
                    else:
                        sanitized_app[key] = value
                sanitized_apps.append(sanitized_app)
        
            with open(self.blocked_apps_file, 'w', encoding='utf-8') as f:
                json.dump(sanitized_apps, f, indent=2, ensure_ascii=True)  # ensure_ascii=True is safer
            return True
        except Exception as e:
            safe_print(f"Error saving blocked apps: {safe_str(e)}")
            return False

    # ---------------- Explorer Restart ----------------
    def _restart_explorer(self):
        """Restart Windows Explorer to apply registry changes"""
        try:
            subprocess.run(["taskkill", "/f", "/im", "explorer.exe"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(1)
            subprocess.Popen(["explorer.exe"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            safe_print("Explorer restarted successfully")
        except Exception as e:
            safe_print(f"Failed to restart Explorer: {safe_str(e)}")

    # ---------------- BLOCK APP ----------------
    def block_application(self, app_name, executable):
        try:
            # Sanitize inputs immediately - this is the key fix
            app_name = safe_str(app_name)
            executable = safe_str(executable)
        
            safe_print(f"Blocking {app_name} ({executable})")
            blocked_apps = self.get_blocked_applications()

            # Prevent duplicates
            if any(safe_str(b.get('executable', '')).lower() == executable.lower() for b in blocked_apps):
                return {'success': True, 'message': 'Already blocked', 'already_blocked': True}

            # Kill running instances first
            killed_count = self._terminate_all_instances(executable)

            # --- Registry Blocking ---
            registry_success = False
            try:
                explorer_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
                disallow_path = explorer_path + r"\DisallowRun"

                # Ensure DisallowRun is enabled
                key_explorer = winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, explorer_path, 0, winreg.KEY_ALL_ACCESS)
                winreg.SetValueEx(key_explorer, "DisallowRun", 0, winreg.REG_DWORD, 1)
                winreg.CloseKey(key_explorer)

                key_disallow = winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, disallow_path, 0, winreg.KEY_ALL_ACCESS)

                # Find next available numeric key (skip duplicates)
                idx = 1
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key_disallow, idx - 1)
                        if safe_str(value).lower() == executable.lower():
                            safe_print(f"Registry entry already exists for {executable}")
                            registry_success = True
                            break
                        idx += 1
                    except OSError:
                        break

                if not registry_success:
                    winreg.SetValueEx(key_disallow, str(idx), 0, winreg.REG_SZ, executable)
                    safe_print(f"Added registry block for {executable}")

                winreg.CloseKey(key_disallow)
                registry_success = True
                self._restart_explorer()
            
            except Exception as e:
                safe_print(f"Registry block failed: {safe_str(e)}")

            # Fallback to process monitor if registry fails
            if not registry_success:
                self._start_process_monitor(executable)
                safe_print(f"Using process monitor fallback for {executable}")

            # Save blocked app record with sanitized data
            blocked_apps.append({
                'name': app_name,  # Already sanitized
                'executable': executable,  # Already sanitized
                'blocked_at': datetime.now().isoformat(),
                'status': 'active',
                'method': 'registry' if registry_success else 'process_monitor',
                'kills_count': killed_count
            })
            self.save_blocked_applications(blocked_apps)

            return {
                'success': True,
                'details': {
                    'executable': executable,
                    'method': 'registry' if registry_success else 'process_monitor',
                    'initial_kills': killed_count,
                    'monitor_active': not registry_success
                }
            }

        except Exception as e:
            error_msg = safe_str(e)
            safe_print(f"Error in block_application: {error_msg}")
            return {'success': False, 'message': error_msg}

    # ---------------- UNBLOCK APP ----------------
    def unblock_application(self, executable):
        try:
            print(f"\n{'='*80}\nUNBLOCKING APPLICATION: {executable}\n{'='*80}")

            blocked_apps = self.get_blocked_applications()
            app_to_remove = next((b for b in blocked_apps if b.get('executable', '').lower() == executable.lower()), None)

            if not app_to_remove:
                print(f" Application {executable} not found in blocked list")
                return {'success': True, 'message': 'Application not blocked', 'was_blocked': False}

            # --- Registry Unblock Logic ---
            try:
                key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_ALL_ACCESS)

                values_to_delete = []
                idx = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, idx)
                        if value.lower() == executable.lower():
                            values_to_delete.append(name)
                        idx += 1
                    except OSError:
                        break

                for name in values_to_delete:
                    try:
                        winreg.DeleteValue(key, name)
                        print(f" Deleted registry value {name} ({executable})")
                    except Exception as e:
                        print(f" Could not delete registry value {name}: {e}")

                winreg.CloseKey(key)

                if values_to_delete:
                    print(f" {len(values_to_delete)} registry entries removed for {executable}")
                else:
                    print("No matching registry entries found")

                self._restart_explorer()
            except FileNotFoundError:
                print("Registry path not found — skipping registry cleanup")

            # --- Stop process monitor ---
            self._stop_process_monitor(executable)
            print(f" Process monitor stopped for {executable}")

            # --- Remove from JSON list ---
            blocked_apps = [b for b in blocked_apps if b.get('executable', '').lower() != executable.lower()]
            self.save_blocked_applications(blocked_apps)

            print(f"{'='*80}\n APPLICATION UNBLOCKED SUCCESSFULLY\n{'='*80}\n")
            return {
                'success': True,
                'message': f'{executable} unblocked successfully',
                'details': {'executable': executable, 'registry_removed': True}
            }

        except Exception as e:
            print(f" ERROR unblocking application: {e}")
            return {'success': False, 'message': str(e)}

    # ---------------- PROCESS MONITOR ----------------
    def _terminate_all_instances(self, executable):
        killed = 0
        exe_lower = safe_str(executable).lower()
        exe_no_ext = exe_lower.replace(".exe", "")
        for proc in psutil.process_iter(['name', 'pid']):
            try:
                pname = safe_str(proc.info['name']).lower()
                if pname == exe_lower or pname == exe_no_ext:
                    proc.kill()
                    proc.wait(timeout=2)
                    killed += 1
            except Exception:
                pass
        return killed

    def _start_process_monitor(self, executable):
        exe_lower = executable.lower()
        with MONITOR_LOCK:
            if exe_lower in ACTIVE_MONITORS:
                return
        def loop():
            while True:
                blocked = self.get_blocked_applications()
                if not any(b.get('executable', '').lower() == exe_lower for b in blocked):
                    break
                for proc in psutil.process_iter(['name', 'pid']):
                    try:
                        pname = proc.info['name'].lower()
                        if pname == exe_lower or pname == exe_lower.replace('.exe', ''):
                            proc.kill()
                    except Exception:
                        pass
                time.sleep(1)
            with MONITOR_LOCK:
                ACTIVE_MONITORS.pop(exe_lower, None)
        t = threading.Thread(target=loop, daemon=True)
        with MONITOR_LOCK:
            ACTIVE_MONITORS[exe_lower] = t
        t.start()

    def _stop_process_monitor(self, executable):
        exe_lower = executable.lower()
        with MONITOR_LOCK:
            if exe_lower in ACTIVE_MONITORS:
                del ACTIVE_MONITORS[exe_lower]
                return True
        return False

    def get_monitor_status(self):
        with MONITOR_LOCK:
            return {exe: {'alive': t.is_alive()} for exe, t in ACTIVE_MONITORS.items()}
    

    def get_patch_info(self):
        """Get Windows patch information using Windows Update API"""
        try:
            pythoncom.CoInitialize()
        
            update_session = win32com.client.Dispatch("Microsoft.Update.Session")
            update_searcher = update_session.CreateUpdateSearcher()
        
            # Get installed updates
            installed_result = update_searcher.Search("IsInstalled=1")
            installed_list = []
        
            for update in installed_result.Updates:
                # Skip driver updates
                is_driver = any(cat.Name == "Drivers" for cat in update.Categories)
                if is_driver:
                    continue
            
                kb_numbers = ", ".join([f"KB{kb}" for kb in update.KBArticleIDs]) if update.KBArticleIDs and update.KBArticleIDs.Count > 0 else "N/A"
                category_names = ", ".join([cat.Name for cat in update.Categories])
            
                try:
                    install_date = str(update.LastDeploymentChangeTime)
                except:
                    install_date = "Unknown"
            
                installed_list.append({
                    "title": update.Title,
                    "kb": kb_numbers,
                    "update_id": update.Identity.UpdateID,
                    "type": "Software",
                    "category": category_names,
                    "date_installed": install_date
                })
        
            installed_list.sort(key=lambda x: x['date_installed'], reverse=True)
        
            # Get pending updates
            pending_result = update_searcher.Search("IsInstalled=0")
            pending_list = []
        
            for update in pending_result.Updates:
                is_driver = any(cat.Name == "Drivers" for cat in update.Categories)
                if is_driver:
                    continue
            
                kb_numbers = ", ".join([f"KB{kb}" for kb in update.KBArticleIDs]) if update.KBArticleIDs and update.KBArticleIDs.Count > 0 else "N/A"
                file_size_mb = int(update.MaxDownloadSize) / (1024 * 1024) if hasattr(update, "MaxDownloadSize") else 0
                category_names = ", ".join([cat.Name for cat in update.Categories])
            
                pending_list.append({
                    "title": update.Title,
                    "kb": kb_numbers,
                    "update_id": update.Identity.UpdateID,
                    "size_mb": round(file_size_mb, 2),
                    "severity": update.MsrcSeverity if hasattr(update, "MsrcSeverity") else "Unknown",
                    "category": category_names,
                    "type": "Software",
                    "description": getattr(update, "Description", "")
                })
        
            return {
                "status": "success",
                "updates": pending_list,
                "count": len(pending_list),
                "installed_updates": installed_list,
                "last_check": datetime.now().isoformat()
            }
        
        except Exception as e:
            return {"status": "error", "message": str(e)}

    def install_updates(self, update_ids):
        """Downloads and installs selected updates by Update ID"""
        try:
            pythoncom.CoInitialize()
        
            update_session = win32com.client.Dispatch("Microsoft.Update.Session")
            update_searcher = update_session.CreateUpdateSearcher()
        
            search_result = update_searcher.Search("IsInstalled=0")
        
            to_install = win32com.client.Dispatch("Microsoft.Update.UpdateColl")
            found_updates = []
        
            for update in search_result.Updates:
                is_driver = any(cat.Name == "Drivers" for cat in update.Categories)
                if is_driver:
                    continue
            
                if update.Identity.UpdateID in update_ids:
                    to_install.Add(update)
                    found_updates.append(update.Identity.UpdateID)
        
            if to_install.Count == 0:
                try:
                    installed_search = update_searcher.Search("IsInstalled=1")
                    already_installed = []
                    for update in installed_search.Updates:
                        is_driver = any(cat.Name == "Drivers" for cat in update.Categories)
                        if is_driver:
                            continue
                    
                        if update.Identity.UpdateID in update_ids:
                            already_installed.append(update.Identity.UpdateID)
                
                    if already_installed:
                        return {"status": "info", "message": f"Updates already installed: {len(already_installed)} update(s)"}
                    else:
                        return {"status": "error", "message": "No matching updates found - they may be invalid or no longer available"}
                except:
                    return {"status": "error", "message": "No matching updates found"}
        
            downloader = update_session.CreateUpdateDownloader()
            downloader.Updates = to_install
            download_result = downloader.Download()
        
            if download_result.ResultCode != 2:
                return {"status": "error", "message": f"Download failed with code: {download_result.ResultCode}"}
        
            installer = update_session.CreateUpdateInstaller()
            installer.Updates = to_install
            install_result = installer.Install()
        
            return {
                "status": "success",
                "installed": to_install.Count,
                "reboot_required": install_result.RebootRequired,
                "result_code": install_result.ResultCode
            }
        
        except Exception as e:
            return {"status": "error", "message": str(e)}

# Initialize security agent
security_agent = SecurityAgent()

# API Routes

@app.route('/')
def index():
    """Serve the main web interface"""
    return send_from_directory(WEB_DIR, 'index.html')

@app.route('/health')
def test_root():
    return jsonify({'status': 'Backend is running', 'message': 'API endpoints available'})

@app.route('/<path:filename>')
def serve_static(filename):
    """Serve static files"""
    return send_from_directory(WEB_DIR, filename)

@app.route('/api/auth/login', methods=['POST'])
def login():
    """Admin authentication"""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    token = security_agent.generate_admin_token(username, password)
    if token:
        return jsonify({
            'success': True,
            'token': token,
            'message': 'Authentication successful'
        })
    else:
        return jsonify({
            'success': False,
            'message': 'Invalid credentials'
        }), 401

@app.route('/api/antivirus/scan', methods=['POST'])
def start_scan():
    """Start antivirus scan"""
    data = request.get_json()
    scan_path = data.get('path', '')
    scan_type = data.get('scan_type', 'directory')
    
    # Handle different scan types
    if scan_type == 'system':
        if scan_path != 'SYSTEM_SCAN':
            return jsonify({
                'success': False,
                'message': 'Invalid system scan request'
            }), 400
        actual_path = None  # Will be handled by system scan function
    elif scan_type == 'quick_system':
        if scan_path != 'QUICK_SYSTEM_SCAN':
            return jsonify({
                'success': False,
                'message': 'Invalid quick system scan request'
            }), 400
        actual_path = None  # Will be handled by quick system scan function
    else:
        # Directory scan - validate path exists
        if not scan_path or not Path(scan_path).exists():
            return jsonify({
                'success': False,
                'message': 'Invalid scan path'
            }), 400
        actual_path = scan_path
    
    # Generate session ID
    session_id = hashlib.md5(f"{scan_path}{scan_type}{time.time()}".encode()).hexdigest()
    
    # Start appropriate scan in background thread
    if scan_type == 'system':
        thread = threading.Thread(
            target=security_agent.scan_full_system,
            args=(session_id,)
        )
    elif scan_type == 'quick_system':
        thread = threading.Thread(
            target=security_agent.scan_quick_system,
            args=(session_id,)
        )
    else:
        thread = threading.Thread(
            target=security_agent.scan_directory,
            args=(actual_path, session_id)
        )
    
    thread.start()
    
    return jsonify({
        'success': True,
        'session_id': session_id,
        'message': f'{scan_type.replace("_", " ").title()} scan started'
    })

@app.route('/api/antivirus/database-info')
def get_database_info():
    """Get virus database information"""
    try:
        info = security_agent.get_database_info()
        update_log = security_agent.get_last_database_update_log()
        
        return jsonify({
            'success': True,
            'database_info': info,
            'last_update_log': update_log
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500

@app.route('/api/antivirus/update-database', methods=['POST'])
def trigger_database_update():
    """Manually trigger database update"""
    try:
        success = security_agent._update_virus_database()
        
        if success:
            return jsonify({
                'success': True,
                'message': 'Database updated successfully'
            })
        else:
            return jsonify({
                'success': False,
                'message': 'Database update failed or partially completed'
            }), 500
    except Exception as e:
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500

@app.route('/api/antivirus/cancel/<session_id>', methods=['POST'])
def cancel_scan(session_id):
    """Cancel an active scan"""
    try:
        result = security_agent.cancel_scan(session_id)
        
        if result['success']:
            return jsonify(result)
        else:
            return jsonify(result), 400
            
    except Exception as e:
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500

@app.route('/api/web-blocking/urls', methods=['GET'])
def get_blocked_urls():
    """Get list of blocked URLs"""
    urls = security_agent.load_blocked_urls()
    return jsonify({
        'success': True,
        'urls': urls
    })

@app.route('/api/web-blocking/block', methods=['POST'])
def block_url():
    """Block a URL"""
    data = request.get_json()
    url = data.get('url', '').strip()
    
    if not url:
        return jsonify({
            'success': False,
            'message': 'URL is required'
        }), 400
    
    success = security_agent.block_url(url)
    if success:
        return jsonify({
            'success': True,
            'message': f'URL {url} blocked successfully'
        })
    else:
        return jsonify({
            'success': False,
            'message': 'Failed to block URL'
        }), 500

@app.route('/api/web-blocking/unblock', methods=['POST'])
def unblock_url():
    """Unblock a URL"""
    data = request.get_json()
    url = data.get('url', '').strip()
    
    if not url:
        return jsonify({
            'success': False,
            'message': 'URL is required'
        }), 400
    
    success = security_agent.unblock_url(url)
    if success:
        return jsonify({
            'success': True,
            'message': f'URL {url} unblocked successfully'
        })
    else:
        return jsonify({
            'success': False,
            'message': 'Failed to unblock URL'
        }), 500

@app.route('/api/web-blocking/verify', methods=['POST'])
def verify_url_blocked():
    """Check if a specific URL is blocked"""
    data = request.get_json()
    url = data.get('url', '').strip()
    
    if not url:
        return jsonify({
            'success': False,
            'message': 'URL is required'
        }), 400
    
    blocked_urls = security_agent.load_blocked_urls()
    clean_url = url.replace('http://', '').replace('https://', '').strip()
    
    blocked_entry = next(
        (u for u in blocked_urls if u.get('url') == clean_url), 
        None
    )
    
    return jsonify({
        'success': True,
        'is_blocked': bool(blocked_entry),
        'details': blocked_entry
    })
    
@app.route('/api/patch-management/info')
def patch_info():
    """Get patch management information"""
    info = security_agent.get_patch_info()
    return jsonify({
        'success': True,
        'data': info
    })

@app.route('/api/patch-management/install', methods=['POST'])
def install_patches():
    """Install patches (admin only)"""
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    
    if not security_agent.verify_admin_token(token):
        return jsonify({
            'success': False,
            'message': 'Admin authentication required'
        }), 401
    
    data = request.get_json()
    update_ids = data.get('update_ids', []) 
    
    result = security_agent.install_updates(update_ids)  
    return jsonify(result)

@app.route('/api/system/status')
def system_status():
    """Get system status"""
    try:
        # System information
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        # Process information
        processes = len(psutil.pids())
        
        # ClamAV status
        clamav_status = "Available" if security_agent.clamav_path.exists() else "Not Found"
        
        return jsonify({
            'success': True,
            'system': {
                'cpu_percent': cpu_percent,
                'memory_percent': memory.percent,
                'disk_percent': disk.percent,
                'processes': processes,
                'clamav_status': clamav_status,
                'uptime': time.time() - psutil.boot_time(),
                'timestamp': datetime.now().isoformat()
            }
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500

# Application Blocking API Endpoints
@app.route('/api/app-blocking/applications', methods=['GET'])
def get_applications():
    """Get list of all installed applications"""
    try:
        applications = security_agent.get_installed_applications()
        return jsonify({
            'success': True,
            'applications': applications,
            'count': len(applications)
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500

@app.route('/api/app-blocking/block', methods=['POST'])
def block_app():
    try:
        data = request.get_json()
        app_name = safe_str(data.get('name', ''))
        executable = safe_str(data.get('executable', ''))
        
        result = security_agent.block_application(app_name, executable)
        return jsonify(result)
        
    except Exception as e:
        error_msg = safe_str(e)
        return jsonify({
            'success': False,
            'message': error_msg,
            'type': 'block_application',
            'error': error_msg
        }), 500

@app.route('/api/app-blocking/unblock', methods=['POST'])
def unblock_app():
    data = request.get_json()
    return jsonify(security_agent.unblock_application(data.get('executable')))

@app.route('/api/app-blocking/blocked', methods=['GET'])
def blocked():
    apps = security_agent.get_blocked_applications()
    return jsonify({'success': True, 'count': len(apps), 'apps': apps})

@app.route('/api/app-blocking/unblock-all', methods=['POST'])
def unblock_all():
    apps = security_agent.get_blocked_applications()
    for b in apps:
        security_agent.unblock_application(b['executable'])
    return jsonify({'success': True})

@app.route('/api/app-blocking/verify/<exe>', methods=['GET'])
def verify(exe):
    apps = security_agent.get_blocked_applications()
    app = next((b for b in apps if b['executable'].lower() == exe.lower()), None)
    return jsonify({'success': True, 'is_blocked': bool(app), 'details': app})

# Scheduled Scanning API Endpoints
@app.route('/api/antivirus/scheduled', methods=['GET'])
def get_scheduled_scans():
    """Get all scheduled scans"""
    try:
        scans = security_agent.get_scheduled_scans()
        return jsonify({
            'success': True,
            'scheduled_scans': scans
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500

@app.route('/api/antivirus/scheduled', methods=['POST'])
def create_scheduled_scan():
    """Create a new scheduled scan"""
    try:
        data = request.get_json()
        
        # Required fields
        if not data.get('name') or not data.get('path') or not data.get('schedule_type'):
            return jsonify({
                'success': False,
                'message': 'Missing required fields: name, path, schedule_type'
            }), 400
        
        # Get scan type (default to directory for backward compatibility)
        scan_type = data.get('scan_type', 'directory')
        
        # Validate scan type
        if scan_type not in ['directory', 'system', 'quick_system']:
            return jsonify({
                'success': False,
                'message': 'Invalid scan_type. Must be directory, system, or quick_system'
            }), 400
        
        schedule_type = data['schedule_type']
        
        # Validate schedule type
        if schedule_type not in ['interval', 'daily', 'weekly', 'monthly']:
            return jsonify({
                'success': False,
                'message': 'Invalid schedule_type. Must be interval, daily, weekly, or monthly'
            }), 400
        
        # Validate based on schedule type
        if schedule_type == 'interval':
            # For interval scheduling, we need interval_value and interval_unit
            if not data.get('interval_value') or not data.get('interval_unit'):
                return jsonify({
                    'success': False,
                    'message': 'Interval scheduling requires interval_value and interval_unit'
                }), 400
            
            if data['interval_unit'] not in ['minutes', 'hours']:
                return jsonify({
                    'success': False,
                    'message': 'interval_unit must be minutes or hours'
                }), 400
                
            try:
                interval_value = int(data['interval_value'])
                if interval_value <= 0:
                    raise ValueError()
            except ValueError:
                return jsonify({
                    'success': False,
                    'message': 'interval_value must be a positive integer'
                }), 400
        else:
            # For time-based scheduling, we need schedule_time
            if not data.get('schedule_time'):
                return jsonify({
                    'success': False,
                    'message': f'{schedule_type} scheduling requires schedule_time'
                }), 400
            
            # Validate schedule time format (HH:MM)
            try:
                time_parts = data['schedule_time'].split(':')
                if len(time_parts) != 2:
                    raise ValueError()
                hour, minute = int(time_parts[0]), int(time_parts[1])
                if not (0 <= hour <= 23 and 0 <= minute <= 59):
                    raise ValueError()
            except ValueError:
                return jsonify({
                    'success': False,
                    'message': 'Invalid schedule_time format. Must be HH:MM (24-hour format)'
                }), 400
        
        # Validate path exists (except for system scans)
        if scan_type == 'directory' and not Path(data['path']).exists():
            return jsonify({
                'success': False,
                'message': f'Scan path does not exist: {data["path"]}'
            }), 400
        
        scan_id = security_agent.create_scheduled_scan(
            name=data['name'],
            scan_path=data['path'],
            scan_type=scan_type,
            schedule_type=data['schedule_type'],
            schedule_time=data.get('schedule_time'),
            enabled=data.get('enabled', True),
            interval_value=data.get('interval_value'),
            interval_unit=data.get('interval_unit'),
            weekly_day=data.get('weekly_day'),
            monthly_day=data.get('monthly_day')
        )
        
        # Get the created schedule details
        schedule_details = SCHEDULED_SCANS.get(scan_id)
        
        return jsonify({
            'success': True,
            'message': 'Scheduled scan created successfully',
            'id': scan_id,
            'name': schedule_details.get('name'),
            'schedule_type': schedule_details.get('schedule_type'),
            'interval_value': schedule_details.get('interval_value'),
            'interval_unit': schedule_details.get('interval_unit'),
            'next_run': schedule_details.get('next_run'),
            'enabled': schedule_details.get('enabled')
        }), 201
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500

@app.route('/api/antivirus/scheduled/<scan_id>', methods=['PUT'])
def update_scheduled_scan(scan_id):
    """Update a scheduled scan"""
    try:
        data = request.get_json()
        
        success = security_agent.update_scheduled_scan(
            scan_id=scan_id,
            enabled=data.get('enabled')
        )
        
        if success:
            return jsonify({
                'success': True,
                'message': 'Scheduled scan updated successfully'
            })
        else:
            return jsonify({
                'success': False,
                'message': 'Scheduled scan not found'
            }), 404
            
    except Exception as e:
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500

@app.route('/api/antivirus/scheduled/<scan_id>', methods=['DELETE'])
def delete_scheduled_scan(scan_id):
    """Delete a scheduled scan"""
    try:
        success = security_agent.delete_scheduled_scan(scan_id)
        
        if success:
            return jsonify({
                'success': True,
                'message': 'Scheduled scan deleted successfully'
            })
        else:
            return jsonify({
                'success': False,
                'message': 'Scheduled scan not found'
            }), 404
            
    except Exception as e:
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500

@app.route('/api/antivirus/status/<session_id>')
def scan_status(session_id):
    """Get scan status - WITH CHILD SESSION AGGREGATION"""
    debug_log(f"API: /api/antivirus/status/{session_id[:8]}...", "INFO")
    
    if session_id in SCAN_SESSIONS:
        session = SCAN_SESSIONS[session_id]
        
        # Get base values
        progress_percent = session.get('progress_percent', 0)
        files_scanned = session.get('files_scanned', 0)
        threats_found = session.get('threats_found', 0)
        threats_list = session.get('threats', [])
        
        # Check for child sessions (system/quick scans)
        scan_path = session.get('path', '')
        child_sessions = []
        
        if scan_path in ['Quick System Scan', 'Full System Scan']:
            # Aggregate from child sessions
            child_progress_sum = 0
            
            for child_id, child_session in SCAN_SESSIONS.items():
                if child_id.startswith(f"{session_id}_quick_") or child_id.startswith(f"{session_id}_sys_"):
                    child_sessions.append(child_session)
                    
                    # Aggregate data
                    files_scanned += child_session.get('files_scanned', 0)
                    threats_found += child_session.get('threats_found', 0)
                    child_progress_sum += child_session.get('progress_percent', 0)
                    
                    # Merge threats
                    if child_session.get('threats'):
                        threats_list.extend(child_session['threats'])
            
            if child_sessions:
                # Calculate combined progress
                avg_child_progress = child_progress_sum / len(child_sessions)
                estimated_dirs = 8 if scan_path == 'Quick System Scan' else 15
                combined_progress = progress_percent + int(avg_child_progress / estimated_dirs)
                progress_percent = min(combined_progress, 100)
                
                debug_log(f"[STATUS AGGREGATION] {len(child_sessions)} child sessions, {files_scanned} total files, {progress_percent}% progress", "INFO")
        
        response_data = {
            'success': True,
            'session': {
                'session_id': session_id,
                'status': session['status'],
                'path': session['path'],
                'started_at': session['started_at'].isoformat(),
                'files_scanned': files_scanned,  # AGGREGATED
                'threats_found': threats_found,  # AGGREGATED
                'progress_percent': progress_percent,
                'scan_log': session.get('scan_log', []),
                'threats': threats_list,  # AGGREGATED
                'last_update': session['last_update'].isoformat(),
                'completed_at': session.get('completed_at').isoformat() if session.get('completed_at') else None,
                'has_child_sessions': len(child_sessions)
            }
        }
        
        debug_log(f"Status response: {session['status']}, {files_scanned} files (aggregated), {progress_percent}%", "INFO")
        return jsonify(response_data), 200
    else:
        debug_log(f"Session not found: {session_id[:8]}...", "WARNING")
        return jsonify({
            'success': False,
            'message': 'Session not found'
        }), 404

@app.route('/api/antivirus/scan-progress/<session_id>')
def get_scan_progress(session_id):
    """Get real-time scan progress with debug info - WITH CHILD SESSION AGGREGATION"""
    debug_log(f"API: /api/antivirus/scan-progress/{session_id[:8]}...", "INFO")
    
    if session_id in SCAN_SESSIONS:
        session = SCAN_SESSIONS[session_id]
        
        # Get base progress from parent session
        progress_percent = session.get('progress_percent', 0)
        files_scanned = session.get('files_scanned', 0)
        threats_found = session.get('threats_found', 0)
        
        # Check if this is a parent session with active child scans
        # (quick_system and system scans create child sessions)
        scan_path = session.get('path', '')
        child_sessions = []
        
        if scan_path in ['Quick System Scan', 'Full System Scan']:
            # Aggregate progress from ALL child sessions
            for child_id, child_session in SCAN_SESSIONS.items():
                if child_id.startswith(f"{session_id}_quick_") or child_id.startswith(f"{session_id}_sys_"):
                    child_sessions.append(child_session)
            
            if child_sessions:
                # Add progress from active child scans
                child_progress_sum = 0
                
                for child in child_sessions:
                    child_files = child.get('files_scanned', 0)
                    child_threats = child.get('threats_found', 0)
                    child_progress = child.get('progress_percent', 0)
                    
                    # Aggregate files and threats
                    files_scanned += child_files
                    threats_found += child_threats
                    child_progress_sum += child_progress
                
                # Calculate combined progress
                # Parent progress = which directory (0%, 12%, 25%...)
                # Child progress = within current directory (1%, 6%, 50%...)
                # Total = parent + (average_child / estimated_total_dirs)
                
                if len(child_sessions) > 0:
                    avg_child_progress = child_progress_sum / len(child_sessions)
                    # Estimate 8 directories for quick scan, more for full scan
                    estimated_dirs = 8 if scan_path == 'Quick System Scan' else 15
                    
                    # Add proportional child progress to parent
                    combined_progress = progress_percent + int(avg_child_progress / estimated_dirs)
                    progress_percent = min(combined_progress, 100)
                
                debug_log(f"[AGGREGATION] Found {len(child_sessions)} active child sessions", "INFO")
                debug_log(f"[AGGREGATION] Total files: {files_scanned}, Threats: {threats_found}", "INFO")
                debug_log(f"[AGGREGATION] Combined progress: {progress_percent}% (parent: {session.get('progress_percent', 0)}%, child avg: {child_progress_sum/len(child_sessions) if child_sessions else 0:.1f}%)", "INFO")
        
        progress_data = {
            'success': True,
            'progress': {
                'session_id': session_id,
                'status': session['status'],
                'progress_percent': progress_percent,
                'files_scanned': files_scanned,  # AGGREGATED from children
                'total_files': session.get('total_files', 0),
                'threats_found': threats_found,  # AGGREGATED from children
                'scan_log': session.get('scan_log', [])[-10:],
                'last_update': session['last_update'].isoformat(),
                # Debug info
                'debug': {
                    'recent_clamav_output': session.get('clamav_output', [])[-5:],
                    'total_lines_read': len(session.get('clamav_output', [])),
                    'has_child_sessions': len(child_sessions)
                }
            }
        }
        
        debug_log(
            f"Progress: {progress_data['progress']['progress_percent']}%, "
            f"Files: {progress_data['progress']['files_scanned']} (aggregated), "
            f"Status: {progress_data['progress']['status']}", 
            "INFO"
        )
        
        return jsonify(progress_data), 200
    else:
        debug_log(f"Session not found: {session_id[:8]}...", "WARNING")
        return jsonify({
            'success': False,
            'message': 'Session not found'
        }), 404


# Initialize scheduler thread
def run_scheduler():
    """Run the scheduled task scheduler with enhanced reliability"""
    print("Scheduler thread started - monitoring scheduled scans...")
    last_status_report = time.time()
    
    while True:
        try:
            # Run pending scheduled tasks
            schedule.run_pending()
            
            # Report scheduler status every 5 minutes
            current_time = time.time()
            if current_time - last_status_report > 300:  # 5 minutes
                job_count = len(schedule.jobs)
                active_scans = len([s for s in SCHEDULED_SCANS.values() if s.get('status') == 'running'])
                print(f"Scheduler status: {job_count} jobs registered, {active_scans} active scans")
                last_status_report = current_time
            
            # Sleep for 1 second
            time.sleep(1)
            
        except Exception as e:
            print(f"Error in scheduler thread: {str(e)}")
            # Continue running even if there's an error
            time.sleep(5)  # Wait a bit longer after an error

if __name__ == '__main__':
    print("Starting RiskNoX Security Agent Backend...")
    print(f"Config Directory: {CONFIG_DIR}")
    print(f"Vendor Directory: {VENDOR_DIR}")
    print(f"Logs Directory: {LOGS_DIR}")
    
    WEB_DIR.mkdir(exist_ok=True)
    
    # Setup and verify ClamAV
    print("Checking ClamAV virus database...")
    if not security_agent._check_clamav_databases():
        print("Downloading initial virus database (this may take several minutes)...")
        if not security_agent._update_virus_database():
            print("WARNING: Failed to download virus database. Scans may not work.")
    else:
        print("Virus database found and ready")
    
    # Setup daily database updates
    security_agent.setup_database_updates()
    
    # Start scheduler thread
    scheduler_thread = threading.Thread(target=run_scheduler, daemon=True)
    scheduler_thread.start()
    print("Scheduler thread started for automatic scans and database updates")
    
    app.run(host='0.0.0.0', port=5000, debug=False)