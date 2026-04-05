"""
RiskNoX Windows Supervisor Service
Production-ready process supervisor for managing multiple security agents
Designed to run as a Windows service via NSSM
"""

import os
import sys
import time
import signal
import subprocess
import threading
import json
import yaml
import logging
import logging.handlers
import psutil
import socket
import hashlib
import secrets
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from enum import Enum
from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.parse

# Constants
SUPERVISOR_VERSION = "1.0.0"

# Fix working directory for PyInstaller bundle and NSSM service
if getattr(sys, 'frozen', False):
    # Running as compiled executable via NSSM service
    # NSSM sets AppDirectory, so use current working directory
    BASE_DIR = Path.cwd()
    
    # Verify we're in the right place (config folder should exist)
    config_check = BASE_DIR / "config"
    if not config_check.exists():
        # Fallback: try executable's parent directory
        BASE_DIR = Path(sys.executable).parent
        if not (BASE_DIR / "config").exists():
            # Last resort: try one level up from executable
            BASE_DIR = Path(sys.executable).parent.parent
else:
    # Running as script
    BASE_DIR = Path(__file__).parent.parent

CONFIG_FILE = BASE_DIR / "config" / "services.yml"
LOGS_DIR = BASE_DIR / "logs"
STATE_DIR = BASE_DIR / "state"

# Ensure directories exist
LOGS_DIR.mkdir(exist_ok=True)
STATE_DIR.mkdir(exist_ok=True)


class RestartPolicy(Enum):
    """Process restart policies"""
    ALWAYS = "always"
    ON_FAILURE = "on-failure"
    NEVER = "never"


class ProcessState(Enum):
    """Process lifecycle states"""
    STOPPED = "stopped"
    STARTING = "starting"
    RUNNING = "running"
    STOPPING = "stopping"
    FAILED = "failed"
    BACKOFF = "backoff"


@dataclass
class ServiceConfig:
    """Configuration for a managed service"""
    name: str
    enabled: bool
    description: str
    cmd: List[str]
    cwd: str
    env: Dict[str, str]
    restart_policy: str
    max_restarts: int
    restart_delay: int
    backoff_multiplier: float
    max_restart_delay: int
    start_delay: int
    stop_timeout: int
    stop_signal: str
    healthcheck: Dict[str, Any]
    dependencies: List[str]
    run_as_user: bool = False  # Run as interactive user instead of SYSTEM


@dataclass
class ProcessInfo:
    """Runtime information for a managed process"""
    config: ServiceConfig
    process: Optional[subprocess.Popen] = None
    pid: Optional[int] = None
    state: ProcessState = ProcessState.STOPPED
    restart_count: int = 0
    last_start_time: Optional[datetime] = None
    last_stop_time: Optional[datetime] = None
    last_exit_code: Optional[int] = None
    current_restart_delay: int = 0
    backoff_until: Optional[datetime] = None
    health_check_failures: int = 0
    
    def reset_restart_count(self):
        """Reset restart counter after successful run"""
        self.restart_count = 0
        self.current_restart_delay = self.config.restart_delay
        
    def increment_restart_delay(self):
        """Apply exponential backoff to restart delay"""
        self.current_restart_delay = min(
            int(self.current_restart_delay * self.config.backoff_multiplier),
            self.config.max_restart_delay
        )


class SupervisorService:
    """Main supervisor service for managing child processes"""
    
    def __init__(self, config_path: Path):
        self.config_path = config_path
        self.processes: Dict[str, ProcessInfo] = {}
        self.running = False
        self.logger = self._setup_logging()
        self.control_api_thread = None
        self.config = None
        self.network_interface = None
        
        # Load configuration
        self._load_config()
        
        # Setup signal handlers
        signal.signal(signal.SIGTERM, self._handle_shutdown)
        signal.signal(signal.SIGINT, self._handle_shutdown)
        
    def _setup_logging(self) -> logging.Logger:
        """Configure logging with rotation"""
        logger = logging.getLogger('supervisor')
        logger.setLevel(logging.INFO)
        
        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)
        console_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        console_handler.setFormatter(console_formatter)
        logger.addHandler(console_handler)
        
        # File handler with rotation
        log_file = LOGS_DIR / "supervisor.log"
        file_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=10 * 1024 * 1024,  # 10 MB
            backupCount=5
        )
        file_handler.setLevel(logging.INFO)
        file_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)
        
        return logger
        
    def _load_config(self):
        """Load service configuration from YAML"""
        try:
            with open(self.config_path, 'r') as f:
                self.config = yaml.safe_load(f)
                
            self.logger.info(f"Loaded configuration from {self.config_path}")
            
            # Detect network interface for Suricata
            if self.config.get('supervisor', {}).get('network_interface_detection', {}).get('enabled', False):
                self.network_interface = self._detect_network_interface()
                
            # Parse service configurations
            for service_data in self.config.get('services', []):
                if not service_data.get('enabled', True):
                    self.logger.info(f"Service {service_data['name']} is disabled, skipping")
                    continue
                    
                service_config = ServiceConfig(
                    name=service_data['name'],
                    enabled=service_data.get('enabled', True),
                    description=service_data.get('description', ''),
                    cmd=service_data['cmd'],
                    cwd=service_data.get('cwd', '.'),
                    env=service_data.get('env', {}),
                    restart_policy=service_data.get('restart_policy', 'always'),
                    max_restarts=service_data.get('max_restarts', 5),
                    restart_delay=service_data.get('restart_delay', 5),
                    backoff_multiplier=service_data.get('backoff_multiplier', 2.0),
                    max_restart_delay=service_data.get('max_restart_delay', 300),
                    start_delay=service_data.get('start_delay', 0),
                    stop_timeout=service_data.get('stop_timeout', 30),
                    stop_signal=service_data.get('stop_signal', 'SIGTERM'),
                    healthcheck=service_data.get('healthcheck', {}),
                    dependencies=service_data.get('dependencies', []),
                    run_as_user=service_data.get('run_as_user', False)  # NEW: Read run_as_user flag
                )
                
                # Substitute network interface placeholder
                if self.network_interface:
                    service_config.cmd = [
                        arg.replace('{NETWORK_INTERFACE}', self.network_interface)
                        for arg in service_config.cmd
                    ]
                
                process_info = ProcessInfo(config=service_config)
                process_info.current_restart_delay = service_config.restart_delay
                self.processes[service_config.name] = process_info
                
                self.logger.info(f"Registered service: {service_config.name}")
                
        except Exception as e:
            self.logger.error(f"Failed to load configuration: {e}")
            raise
            
    def _detect_network_interface(self) -> str:
        """Detect best network interface for packet capture"""
        try:
            import psutil
            interfaces = psutil.net_if_stats()
            active_interfaces = [name for name, stats in interfaces.items() if stats.isup]
            
            # Preference order: Wi-Fi, Ethernet, Others
            for iface in active_interfaces:
                if 'wi-fi' in iface.lower() or 'wireless' in iface.lower():
                    self.logger.info(f"Detected Wi-Fi interface: {iface}")
                    return iface
                    
            for iface in active_interfaces:
                if 'ethernet' in iface.lower() and 'virtual' not in iface.lower():
                    self.logger.info(f"Detected Ethernet interface: {iface}")
                    return iface
                    
            if active_interfaces:
                self.logger.info(f"Using first available interface: {active_interfaces[0]}")
                return active_interfaces[0]
                
            self.logger.warning("No active network interfaces found, using 'any'")
            return "any"
            
        except Exception as e:
            self.logger.error(f"Failed to detect network interface: {e}")
            return "any"
            
    def _find_process_by_script(self, script_name: str, user: str = None, max_age: int = None) -> Optional[int]:
        """
        Find a process running a specific Python script
        
        Args:
            script_name: Name of the Python script (e.g., 'backend_server.py')
            user: Username to match (optional)
            max_age: Maximum age in seconds for process creation time (optional)
            
        Returns:
            PID of the matching process or None if not found
        """
        script_name_lower = script_name.lower()
        
        for proc in psutil.process_iter(['pid', 'name', 'create_time', 'cmdline', 'username']):
            try:
                proc_name_lower = proc.info['name'].lower()
                
                # Only check Python processes
                if proc_name_lower in ['python.exe', 'pythonw.exe']:
                    # Check user if specified
                    if user and proc.info['username']:
                        proc_user = proc.info['username'].split('\\')[-1]
                        if proc_user.lower() != user.lower():
                            continue
                    
                    # Check age if specified
                    if max_age and (time.time() - proc.info['create_time']) > max_age:
                        continue
                    
                    # Check command line for our script
                    if proc.info['cmdline']:
                        for arg in proc.info['cmdline']:
                            if arg.lower().endswith(script_name_lower):
                                self.logger.debug(f"Found process {proc.info['pid']} running {script_name}")
                                return proc.info['pid']
                                
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
                
        return None

    def _handle_shutdown(self, signum, frame):
        """Handle graceful shutdown"""
        self.logger.info(f"Received shutdown signal {signum}")
        self.stop()
        
    def _resolve_dependencies(self) -> List[str]:
        """Resolve service start order based on dependencies"""
        sorted_services = []
        visited = set()
        
        def visit(service_name: str):
            if service_name in visited:
                return
            visited.add(service_name)
            
            if service_name not in self.processes:
                self.logger.warning(f"Dependency {service_name} not found")
                return
                
            # Visit dependencies first
            for dep in self.processes[service_name].config.dependencies:
                visit(dep)
                
            sorted_services.append(service_name)
            
        # Visit all services
        for service_name in self.processes.keys():
            visit(service_name)
            
        return sorted_services
        
    def _start_process(self, name: str) -> bool:
        """Start a single process"""
        process_info = self.processes.get(name)
        if not process_info:
            self.logger.error(f"Process {name} not found")
            return False
            
        if process_info.state == ProcessState.RUNNING:
            self.logger.warning(f"Process {name} is already running")
            return True
            
        # Check if in backoff period
        if process_info.backoff_until and datetime.now() < process_info.backoff_until:
            remaining = (process_info.backoff_until - datetime.now()).total_seconds()
            self.logger.info(f"Process {name} in backoff, waiting {remaining:.1f}s")
            return False
            
        try:
            process_info.state = ProcessState.STARTING
            config = process_info.config
            
            # Resolve working directory
            cwd = BASE_DIR / config.cwd if config.cwd != '.' else BASE_DIR
            
            # Build environment
            env = os.environ.copy()
            env.update(config.env)
            
            # Resolve command paths relative to base directory
            cmd = []
            for arg in config.cmd:
                if arg.endswith('.exe') or arg.endswith('.py'):
                    arg_path = BASE_DIR / arg
                    if arg_path.exists():
                        cmd.append(str(arg_path))
                    else:
                        # Path doesn't exist, try as-is (might be absolute or in PATH)
                        cmd.append(arg)
                else:
                    cmd.append(arg)
            
            # Validate that the executable exists
            exe_path = Path(cmd[0])
            if not exe_path.exists() and not exe_path.is_absolute():
                # Try to find it in PATH
                import shutil
                found_exe = shutil.which(cmd[0])
                if found_exe:
                    cmd[0] = found_exe
                    self.logger.info(f"Resolved {config.cmd[0]} to {found_exe}")
                else:
                    self.logger.error(f"Executable not found: {cmd[0]}")
                    self.logger.error(f"Make sure the virtual environment is set up correctly")
                    process_info.state = ProcessState.FAILED
                    return False
            elif not exe_path.exists():
                self.logger.error(f"Executable not found: {cmd[0]}")
                process_info.state = ProcessState.FAILED
                return False
            
            self.logger.info(f"Starting process {name}: {' '.join(cmd)}")
            self.logger.debug(f"Working directory: {cwd}")
            
            # Check if process should run as interactive user
            if config.run_as_user:
                self.logger.info(f"Process {name} configured to run as interactive user with hidden console")
                success = self._start_process_as_user(name, cmd, cwd, env, process_info)
                return success
            
            # Start process normally (as SYSTEM)
            process = subprocess.Popen(
                cmd,
                cwd=str(cwd),
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP
            )
            
            process_info.process = process
            process_info.pid = process.pid
            process_info.state = ProcessState.RUNNING
            process_info.last_start_time = datetime.now()
            process_info.health_check_failures = 0
            
            # Save PID file if configured
            pid_file = STATE_DIR / f"{name}.pid"
            with open(pid_file, 'w') as f:
                f.write(str(process.pid))
            
            self.logger.info(f"Process {name} started with PID {process.pid}")
            
            # Log stdout/stderr in background
            self._start_log_capture(name, process)
            
            # Reset restart count after successful start
            if (datetime.now() - process_info.last_start_time).total_seconds() > 60:
                process_info.reset_restart_count()
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to start process {name}: {e}")
            process_info.state = ProcessState.FAILED
            return False
    
    def _start_process_as_user(self, name: str, cmd: List[str], cwd: Path, env: Dict[str, str], process_info: ProcessInfo) -> bool:
        """
        Start a process as the interactive user WITH ADMIN PRIVILEGES
        Launches process in the active user session with elevated rights
        """
        try:
            # Method 1: Use scheduled task to run as user with highest privileges
            # This is the most reliable method for running as logged-in user with admin rights
            
            self.logger.info(f"Launching {name} as interactive user with admin privileges")
            
            # Get the current logged-in user
            current_user = None
            use_s4u_logon = False  # Track if we should use S4U logon type
            
            # Get Windows version for compatibility (early detection)
            import platform
            win_version = platform.version()
            is_win10 = '10.' in win_version
            self.logger.info(f"Windows version: {win_version} (Win10: {is_win10})")
            
            try:
                import win32ts
                import win32security
                
                session_id = win32ts.WTSGetActiveConsoleSessionId()
                
                if session_id == 0xFFFFFFFF:  # -1 means no active session
                    self.logger.warning(f"No active console session found. Will use S4U logon type for {name}.")
                    use_s4u_logon = True  # Force S4U when no active session
                    # Don't fail here - try to get username anyway
                else:
                    self.logger.info(f"Active console session ID: {session_id}")
                
                # Get the username for the active session
                for proc in psutil.process_iter(['pid', 'name', 'username']):
                    try:
                        if proc.info['username'] and not proc.info['username'].endswith('SYSTEM'):
                            # Found a user process
                            username_parts = proc.info['username'].split('\\')
                            if len(username_parts) == 2:
                                user_part = username_parts[1]
                                # Skip system users (UMFD-*, DWM-*, etc.)
                                if not user_part.startswith(('UMFD-', 'DWM-', 'SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE')):
                                    current_user = user_part
                                    break
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                
                if not current_user:
                    # Fallback: try to get from explorer.exe (most reliable way to get logged-in user)
                    for proc in psutil.process_iter(['pid', 'name']):
                        try:
                            if proc.name().lower() == 'explorer.exe':
                                proc_obj = psutil.Process(proc.pid)
                                username = proc_obj.username()
                                if username and '\\' in username:
                                    user_part = username.split('\\')[1]
                                    # Skip system users (UMFD-*, DWM-*, etc.)
                                    if not user_part.startswith(('UMFD-', 'DWM-', 'SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE')):
                                        current_user = user_part
                                        break
                        except:
                            continue
                
                if not current_user:
                    self.logger.warning(f"Could not determine logged-in username from active processes")
                    # Don't fail here - will try other methods
                    
                self.logger.info(f"Target user: {current_user if current_user else 'not detected yet'}")
                
            except ImportError:
                self.logger.warning("pywin32 not available, using alternative user detection methods")
                use_s4u_logon = True  # Force S4U when pywin32 not available
                # Don't set current_user here, let fallback method handle it
            except Exception as e:
                self.logger.warning(f"Error detecting active session: {e}")
                use_s4u_logon = True  # Force S4U on any session detection error
            
            # Fallback method: Get username from explorer.exe or any user process
            if not current_user:
                self.logger.info("Attempting fallback user detection from explorer.exe...")
                # Try to get username from explorer.exe (most reliable fallback)
                for proc in psutil.process_iter(['pid', 'name']):
                    try:
                        if proc.name().lower() == 'explorer.exe':
                            proc_obj = psutil.Process(proc.pid)
                            username = proc_obj.username()
                            if username and '\\' in username:
                                user_part = username.split('\\')[1]
                                # Skip system users
                                if not user_part.startswith(('UMFD-', 'DWM-', 'SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE')):
                                    current_user = user_part
                                    self.logger.info(f"Detected user from explorer.exe: {current_user}")
                                    break
                    except Exception as e:
                        continue
                
            # Last resort: Get from Windows environment variables
            if not current_user:
                self.logger.info("Attempting to get user from environment variables...")
                try:
                    # Try to get from WMI
                    import wmi
                    w = wmi.WMI()
                    for u in w.Win32_ComputerSystem():
                        if u.UserName and '\\' in u.UserName:
                            current_user = u.UserName.split('\\')[1]
                            self.logger.info(f"Detected user from WMI: {current_user}")
                            break
                except:
                    pass
            
            # Ultimate fallback: Check registry for last logged on user
            if not current_user:
                self.logger.info("Attempting to get user from registry...")
                try:
                    import winreg
                    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                                        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI")
                    current_user, _ = winreg.QueryValueEx(key, "LastLoggedOnUser")
                    winreg.CloseKey(key)
                    if '\\' in current_user:
                        current_user = current_user.split('\\')[1]
                    self.logger.info(f"Detected user from registry: {current_user}")
                except Exception as e:
                    self.logger.error(f"Failed to get user from registry: {e}")
            
            # If still no user found, fail
            if not current_user:
                self.logger.error("Could not determine target user through any method")
                self.logger.error("Tried: pywin32, explorer.exe, WMI, registry")
                process_info.state = ProcessState.FAILED
                return False
            
            # Build command line with proper escaping
            # Use pythonw.exe instead of python.exe to hide console window
            # Backend processes have file logging configured internally for output capture
            final_cmd = cmd.copy()
            
            # Replace python.exe with pythonw.exe to hide console windows
            if final_cmd[0].endswith('python.exe'):
                pythonw_path = final_cmd[0].replace('python.exe', 'pythonw.exe')
                if Path(pythonw_path).exists():
                    final_cmd[0] = pythonw_path
                    self.logger.info(f"Using pythonw.exe to hide console window: {pythonw_path}")
                else:
                    self.logger.warning(f"pythonw.exe not found, using python.exe (console will be visible)")
            
            self.logger.info(f"Command: {' '.join(final_cmd)}")
            
            # Escape command and arguments for XML and command line safety
            # XML requires escaping of: & < > " '
            def xml_escape(text):
                """Escape special XML characters"""
                return (text.replace('&', '&amp;')
                           .replace('<', '&lt;')
                           .replace('>', '&gt;')
                           .replace('"', '&quot;')
                           .replace("'", '&apos;'))
            
            # Escape the command path for XML
            cmd_path = xml_escape(str(final_cmd[0]))
            
            # Build arguments with proper quoting and XML escaping
            if len(final_cmd) > 1:
                # Quote arguments that contain spaces or special characters
                quoted_args = []
                for arg in final_cmd[1:]:
                    if ' ' in arg or '&' in arg or '<' in arg or '>' in arg:
                        quoted_args.append(f'"{xml_escape(arg)}"')
                    else:
                        quoted_args.append(xml_escape(arg))
                cmd_args = ' '.join(quoted_args)
            else:
                cmd_args = ''
            
            # Create a scheduled task that runs as the user with highest privileges
            task_name = f"RiskNoX_{name}_{int(time.time())}"
            
            # Determine LogonType based on Windows version and session availability
            # LogonType options:
            #   - S4U: Service-For-User, allows running as user from SYSTEM context (Win10+)
            #          Works WITHOUT active session, but user must have logged in at least once
            #   - InteractiveToken: Requires active interactive session (best for Win11 with active session)
            # 
            # Decision logic:
            #   - Use S4U if: Windows 10, OR no active session, OR pywin32 not available
            #   - Use InteractiveToken if: Windows 11 AND active session detected
            if use_s4u_logon or is_win10:
                logon_type = "S4U"
            else:
                logon_type = "InteractiveToken"
            
            self.logger.info(f"Selected LogonType: {logon_type} (use_s4u_logon={use_s4u_logon}, is_win10={is_win10})")
            
            # Build XML for scheduled task with highest privileges
            # Hidden=true prevents the task from showing in Task Scheduler UI
            # WindowStyle and ShowWindowCommand control console window visibility
            task_xml = f'''<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>RiskNoX {name} running as user with admin privileges</Description>
  </RegistrationInfo>
  <Principals>
    <Principal id="Author">
      <UserId>{current_user}</UserId>
      <LogonType>{logon_type}</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>false</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>true</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>4</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{cmd_path}</Command>
      <Arguments>{cmd_args}</Arguments>
      <WorkingDirectory>{xml_escape(str(cwd))}</WorkingDirectory>
    </Exec>
  </Actions>
</Task>'''
            
            # Save task XML to temp file
            task_xml_file = STATE_DIR / f"{task_name}.xml"
            with open(task_xml_file, 'w', encoding='utf-16') as f:
                f.write(task_xml)
            
            self.logger.info(f"Creating scheduled task: {task_name} (LogonType: {logon_type})")
            self.logger.debug(f"Task XML saved to: {task_xml_file}")
            
            # Register the scheduled task
            result = subprocess.run(
                ['schtasks', '/Create', '/TN', task_name, '/XML', str(task_xml_file), '/F'],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            # Log both stdout and stderr for debugging
            if result.stdout:
                self.logger.info(f"schtasks create output: {result.stdout.strip()}")
            if result.stderr:
                self.logger.warning(f"schtasks create stderr: {result.stderr.strip()}")
            
            if result.returncode != 0:
                self.logger.error(f"Failed to create scheduled task: {result.stderr}")
                self.logger.error(f"Command was: schtasks /Create /TN {task_name} /XML {task_xml_file} /F")
                
                # Try fallback: create task without XML using command line (Windows 10 fallback)
                self.logger.info("Attempting fallback method: direct schtasks command...")
                fallback_result = subprocess.run(
                    [
                        'schtasks', '/Create', '/TN', task_name,
                        '/TR', f'"{final_cmd[0]}" {cmd_args}',
                        '/SC', 'ONCE',
                        '/ST', '00:00',
                        '/RU', current_user,
                        '/RL', 'HIGHEST',
                        '/F'
                    ],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                
                if fallback_result.returncode != 0:
                    self.logger.error(f"Fallback method also failed: {fallback_result.stderr}")
                    process_info.state = ProcessState.FAILED
                    try:
                        task_xml_file.unlink()
                    except:
                        pass
                    return False
                else:
                    self.logger.info("Fallback method succeeded!")
            
            self.logger.info(f"Scheduled task created successfully")
            
            # Run the scheduled task
            self.logger.info(f"Running scheduled task to launch {name} with admin privileges...")
            result = subprocess.run(
                ['schtasks', '/Run', '/TN', task_name],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            # Log output
            if result.stdout:
                self.logger.info(f"schtasks run output: {result.stdout.strip()}")
            if result.stderr:
                self.logger.warning(f"schtasks run stderr: {result.stderr.strip()}")
            
            if result.returncode != 0:
                self.logger.error(f"Failed to run scheduled task: {result.stderr}")
                self.logger.error(f"This may indicate UAC issues or user permissions problems on Windows 10")
                
                # Try to get more info about why it failed
                query_result = subprocess.run(
                    ['schtasks', '/Query', '/TN', task_name, '/V', '/FO', 'LIST'],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                if query_result.returncode == 0:
                    self.logger.info(f"Task details:\n{query_result.stdout}")
                
                # Clean up task
                subprocess.run(['schtasks', '/Delete', '/TN', task_name, '/F'], 
                             capture_output=True, timeout=10)
                process_info.state = ProcessState.FAILED
                try:
                    task_xml_file.unlink()
                except:
                    pass
                return False
            
            # Wait a moment for process to start (longer wait for Windows 10)
            initial_wait = 3 if is_win10 else 2
            time.sleep(initial_wait)
            
            # Find the PID of the started process using the new helper function
            pid = None
            
            # Extract the script name from the original command for matching
            script_name = None
            for arg in cmd:
                if arg.endswith('.py'):
                    script_name = Path(arg).name
                    break
            
            if script_name:
                self.logger.info(f"Looking for process running script: {script_name}, user: {current_user}")
                
                # Try multiple times with increasing wait (Windows 10 may be slower)
                max_attempts = 5
                for attempt in range(max_attempts):
                    if attempt > 0:
                        self.logger.info(f"Process detection attempt {attempt + 1}/{max_attempts}...")
                        time.sleep(1)
                    
                    # Use helper function to find the process
                    max_age = 15 if is_win10 else 12  # Allow more time on Windows 10
                    pid = self._find_process_by_script(script_name, current_user, max_age)
                    
                    if pid:
                        self.logger.info(f"Found process: PID={pid} running {script_name}")
                        break
            else:
                self.logger.warning(f"Could not determine script name from command: {cmd}")
            
            # Clean up scheduled task (we don't need it anymore)
            subprocess.run(['schtasks', '/Delete', '/TN', task_name, '/F'], 
                         capture_output=True, timeout=10)
            
            # Clean up XML file
            try:
                task_xml_file.unlink()
            except:
                pass
            
            if not pid:
                self.logger.error(f"Could not find PID of launched process {name}")
                
                # Check if task is actually running
                query_result = subprocess.run(
                    ['schtasks', '/Query', '/TN', task_name, '/FO', 'LIST'],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                
                if query_result.returncode == 0 and 'Running' in query_result.stdout:
                    self.logger.warning(f"Task is running but PID detection failed (common on Windows 10)")
                    self.logger.info(f"Task output: {query_result.stdout[:200]}")
                    # Mark as running even without PID - health checks will verify
                    process_info.process = None
                    process_info.pid = None
                    process_info.state = ProcessState.RUNNING
                    process_info.last_start_time = datetime.now()
                    return True
                else:
                    self.logger.error(f"Task is not running. Process {name} failed to start.")
                    if query_result.stdout:
                        self.logger.error(f"Task status: {query_result.stdout}")
                    # Check system event log for errors
                    self.logger.error(f"Check Event Viewer > Windows Logs > Application for errors from 'Task Scheduler'")
                    process_info.state = ProcessState.FAILED
                    return False
            
            self.logger.info(f"Process {name} launched as user {current_user} with admin privileges (PID {pid})")
            
            # Store process info
            process_info.process = None  # No subprocess handle
            process_info.pid = pid
            process_info.state = ProcessState.RUNNING
            process_info.last_start_time = datetime.now()
            process_info.health_check_failures = 0
            
            # Save PID file
            pid_file = STATE_DIR / f"{name}.pid"
            with open(pid_file, 'w') as f:
                f.write(str(pid))
            
            self.logger.info(f"Process {name} started successfully as elevated user")
            
            return True
                
        except Exception as e:
            self.logger.error(f"Failed to start process {name} as elevated user: {e}", exc_info=True)
            process_info.state = ProcessState.FAILED
            return False
            
    def _start_log_capture(self, name: str, process: subprocess.Popen):
        """Capture stdout/stderr to log files"""
        stdout_log = LOGS_DIR / f"{name}_stdout.log"
        stderr_log = LOGS_DIR / f"{name}_stderr.log"
        
        def capture_stdout():
            try:
                with open(stdout_log, 'a') as f:
                    for line in iter(process.stdout.readline, b''):
                        if line:
                            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                            f.write(f"[{timestamp}] {line.decode('utf-8', errors='ignore')}")
                            f.flush()
            except:
                pass
                
        def capture_stderr():
            try:
                with open(stderr_log, 'a') as f:
                    for line in iter(process.stderr.readline, b''):
                        if line:
                            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                            f.write(f"[{timestamp}] {line.decode('utf-8', errors='ignore')}")
                            f.flush()
            except:
                pass
        
        threading.Thread(target=capture_stdout, daemon=True).start()
        threading.Thread(target=capture_stderr, daemon=True).start()
        
    def _stop_process(self, name: str, timeout: Optional[int] = None) -> bool:
        """Stop a single process gracefully"""
        process_info = self.processes.get(name)
        if not process_info:
            self.logger.error(f"Process {name} not found")
            return False
            
        if process_info.state != ProcessState.RUNNING:
            self.logger.warning(f"Process {name} is not running")
            return True
            
        try:
            process_info.state = ProcessState.STOPPING
            process = process_info.process
            pid = process_info.pid
            timeout = timeout or process_info.config.stop_timeout
            
            self.logger.info(f"Stopping process {name} (PID {pid})")
            
            if process:
                # Process started normally with subprocess.Popen
                try:
                    process.terminate()
                    process.wait(timeout=min(timeout, 10))
                    self.logger.info(f"Process {name} terminated gracefully")
                except subprocess.TimeoutExpired:
                    self.logger.warning(f"Process {name} did not terminate, killing")
                    process.kill()
                    process.wait(timeout=5)
                    self.logger.info(f"Process {name} killed")
                
                process_info.last_exit_code = process.returncode
            else:
                # Process started as user (no process handle), use psutil to terminate by PID
                try:
                    if pid and psutil.pid_exists(pid):
                        proc = psutil.Process(pid)
                        self.logger.info(f"Terminating user process {name} (PID {pid})")
                        proc.terminate()
                        
                        # Wait for termination
                        try:
                            proc.wait(timeout=min(timeout, 10))
                            self.logger.info(f"Process {name} terminated gracefully")
                        except psutil.TimeoutExpired:
                            self.logger.warning(f"Process {name} did not terminate, killing")
                            proc.kill()
                            proc.wait(timeout=5)
                            self.logger.info(f"Process {name} killed")
                        
                        process_info.last_exit_code = proc.returncode
                    else:
                        self.logger.warning(f"Process {name} PID {pid} not found, assuming already stopped")
                except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                    self.logger.warning(f"Could not stop process {name}: {e}")
                
            process_info.state = ProcessState.STOPPED
            process_info.last_stop_time = datetime.now()
            
            # Remove PID file
            pid_file = STATE_DIR / f"{name}.pid"
            if pid_file.exists():
                pid_file.unlink()
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to stop process {name}: {e}")
            process_info.state = ProcessState.FAILED
            return False
            
    def _monitor_processes(self):
        """Monitor running processes and restart if needed"""
        monitor_interval = 3  # Check every 3 seconds for faster crash recovery
        health_check_counter = 0
        
        while self.running:
            try:
                for name, process_info in self.processes.items():
                    if not self.running:
                        break
                        
                    # Skip if in backoff period
                    if process_info.backoff_until and datetime.now() < process_info.backoff_until:
                        continue
                        
                    # Check if process is still running
                    if process_info.state == ProcessState.RUNNING:
                        process = process_info.process
                        
                        # Check if process handle is still valid and process is alive
                        is_alive = False
                        if process:
                            # Process started normally with subprocess.Popen
                            poll_result = process.poll()
                            if poll_result is None:
                                # Process handle says it's running, verify with PID
                                try:
                                    if process_info.pid and psutil.pid_exists(process_info.pid):
                                        proc = psutil.Process(process_info.pid)
                                        if proc.is_running() and proc.status() != psutil.STATUS_ZOMBIE:
                                            is_alive = True
                                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                                    is_alive = False
                            else:
                                # Process has definitely exited
                                is_alive = False
                        else:
                            # Process started as user (no process handle), use robust verification
                            try:
                                if process_info.pid and psutil.pid_exists(process_info.pid):
                                    proc = psutil.Process(process_info.pid)
                                    if proc.is_running() and proc.status() != psutil.STATUS_ZOMBIE:
                                        # Additional verification: check if it's still our process
                                        # by verifying command line contains our script name
                                        script_name = None
                                        for arg in process_info.config.cmd:
                                            if arg.endswith('.py'):
                                                script_name = Path(arg).name
                                                break
                                        
                                        if script_name:
                                            # Use helper function to verify the process is still ours
                                            found_pid = self._find_process_by_script(script_name)
                                            if found_pid == process_info.pid:
                                                is_alive = True
                                            else:
                                                self.logger.warning(f"Process {name} PID {process_info.pid} exists but no longer running our script {script_name}")
                                                is_alive = False
                                        else:
                                            # Fallback: if we can't determine script name, assume it's alive if PID exists
                                            is_alive = True
                                    else:
                                        is_alive = False
                                else:
                                    is_alive = False
                            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                                is_alive = False
                        
                        if not is_alive:
                            # Process has crashed or exited
                            exit_code = process.returncode if process else -1
                            process_info.last_exit_code = exit_code
                            process_info.state = ProcessState.STOPPED
                            
                            self.logger.error(f"CRASH DETECTED: Process {name} is no longer running (exit code: {exit_code})")
                            
                            # Determine if we should restart
                            should_restart = False
                            restart_policy = RestartPolicy(process_info.config.restart_policy)
                            
                            if restart_policy == RestartPolicy.ALWAYS:
                                should_restart = True
                                self.logger.info(f"Restart policy ALWAYS enabled for {name}")
                            elif restart_policy == RestartPolicy.ON_FAILURE and exit_code != 0:
                                should_restart = True
                                self.logger.info(f"Restart policy ON_FAILURE enabled for {name} (non-zero exit)")
                                
                            if should_restart:
                                # Check restart limits
                                if process_info.restart_count >= process_info.config.max_restarts:
                                    self.logger.error(
                                        f"Process {name} exceeded max restarts ({process_info.config.max_restarts}), "
                                        f"resetting counter and continuing restart attempts"
                                    )
                                    # Reset counter instead of giving up - critical processes must stay running
                                    process_info.restart_count = 0
                                    process_info.current_restart_delay = process_info.config.restart_delay
                                
                                # Apply backoff
                                process_info.restart_count += 1
                                process_info.increment_restart_delay()
                                process_info.backoff_until = datetime.now() + timedelta(
                                    seconds=process_info.current_restart_delay
                                )
                                process_info.state = ProcessState.BACKOFF
                                
                                self.logger.warning(
                                    f"RECOVERY: Will restart {name} in {process_info.current_restart_delay}s "
                                    f"(attempt {process_info.restart_count}/{process_info.config.max_restarts})"
                                )
                            else:
                                self.logger.info(f"Process {name} will not be restarted (policy: {restart_policy.value})")
                                    
                    # Attempt to start processes in backoff that are ready
                    elif process_info.state == ProcessState.BACKOFF:
                        if not process_info.backoff_until or datetime.now() >= process_info.backoff_until:
                            self.logger.info(f"RECOVERY: Attempting to restart {name} after backoff period")
                            self._start_process(name)
                    
                    # Auto-start stopped processes with restart policy ALWAYS
                    elif process_info.state == ProcessState.STOPPED:
                        restart_policy = RestartPolicy(process_info.config.restart_policy)
                        if restart_policy == RestartPolicy.ALWAYS:
                            self.logger.warning(f"Process {name} is STOPPED but policy is ALWAYS, scheduling restart")
                            process_info.state = ProcessState.BACKOFF
                            process_info.backoff_until = datetime.now() + timedelta(seconds=5)
                            
                    # Perform health checks (every 10 monitor cycles = 30 seconds)
                    if process_info.state == ProcessState.RUNNING and health_check_counter % 10 == 0:
                        self._perform_health_check(name, process_info)
                
                health_check_counter += 1
                time.sleep(monitor_interval)
                
            except Exception as e:
                self.logger.error(f"Error in monitor loop: {e}", exc_info=True)
                time.sleep(monitor_interval)
                
    def _perform_health_check(self, name: str, process_info: ProcessInfo):
        """Perform health check on a running process"""
        healthcheck = process_info.config.healthcheck
        if not healthcheck.get('enabled', False):
            return
            
        try:
            check_type = healthcheck.get('type', 'process')
            
            if check_type == 'http':
                # HTTP health check with fallback to process check
                import urllib.request
                url = healthcheck.get('url')
                timeout = healthcheck.get('timeout', 10)
                
                try:
                    with urllib.request.urlopen(url, timeout=timeout) as response:
                        if response.status == 200:
                            process_info.health_check_failures = 0
                            return
                except Exception as e:
                    self.logger.warning(f"HTTP health check failed for {name}: {e}")
                    
                    # Fallback: if HTTP check fails, verify process is still running
                    # This prevents false positives when service is running but HTTP endpoint is temporarily unavailable
                    if process_info.pid:
                        script_name = None
                        for arg in process_info.config.cmd:
                            if arg.endswith('.py'):
                                script_name = Path(arg).name
                                break
                        
                        if script_name:
                            found_pid = self._find_process_by_script(script_name)
                            if found_pid == process_info.pid:
                                self.logger.info(f"HTTP health check failed for {name} but process is still running, giving it more time")
                                # Don't increment failure count if process is running - HTTP might be starting up
                                return
                    
                process_info.health_check_failures += 1
                max_failures = healthcheck.get('retries', 3)
                
                if process_info.health_check_failures >= max_failures:
                    self.logger.error(f"Health check failed {max_failures} times for {name}, forcing restart")
                    self._stop_process(name)
                    process_info.state = ProcessState.BACKOFF
                    process_info.backoff_until = datetime.now() + timedelta(seconds=5)
                    
            elif check_type == 'process':
                # Enhanced process existence check using psutil
                if process_info.process and process_info.pid:
                    try:
                        # Verify PID exists and process is running
                        if psutil.pid_exists(process_info.pid):
                            proc = psutil.Process(process_info.pid)
                            if proc.is_running() and proc.status() != psutil.STATUS_ZOMBIE:
                                process_info.health_check_failures = 0
                                return
                        
                        self.logger.warning(f"Process health check failed for {name}: PID {process_info.pid} not found or zombie")
                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
                        self.logger.warning(f"Process health check failed for {name}: {e}")
                    
                    process_info.health_check_failures += 1
                    max_failures = healthcheck.get('retries', 3)
                    
                    if process_info.health_check_failures >= max_failures:
                        self.logger.error(f"Process health check failed {max_failures} times for {name}, forcing restart")
                        self._stop_process(name)
                        process_info.state = ProcessState.BACKOFF
                        process_info.backoff_until = datetime.now() + timedelta(seconds=5)
                else:
                    process_info.health_check_failures += 1
                    
            elif check_type == 'pidfile':
                # Check PID file
                pidfile = BASE_DIR / healthcheck.get('pidfile', '')
                if pidfile.exists():
                    try:
                        pid = int(pidfile.read_text().strip())
                        if psutil.pid_exists(pid):
                            proc = psutil.Process(pid)
                            if proc.is_running() and proc.status() != psutil.STATUS_ZOMBIE:
                                process_info.health_check_failures = 0
                                return
                    except Exception as e:
                        self.logger.warning(f"PID file health check failed for {name}: {e}")
                        
                process_info.health_check_failures += 1
                max_failures = healthcheck.get('retries', 3)
                
                if process_info.health_check_failures >= max_failures:
                    self.logger.error(f"PID file health check failed {max_failures} times for {name}, forcing restart")
                    self._stop_process(name)
                    process_info.state = ProcessState.BACKOFF
                    process_info.backoff_until = datetime.now() + timedelta(seconds=5)
                
        except Exception as e:
            self.logger.error(f"Health check error for {name}: {e}", exc_info=True)
            
    def start(self):
        """Start all managed processes"""
        self.logger.info(f"Starting RiskNoX Supervisor v{SUPERVISOR_VERSION}")
        self.running = True
        
        # Write supervisor PID
        supervisor_config = self.config.get('supervisor', {})
        pid_file = BASE_DIR / supervisor_config.get('pid_file', 'state/supervisor.pid')
        pid_file.parent.mkdir(exist_ok=True)
        with open(pid_file, 'w') as f:
            f.write(str(os.getpid()))
        
        # Start control API
        if supervisor_config.get('control_api', {}).get('enabled', False):
            self._start_control_api()
        
        # Resolve start order
        start_order = self._resolve_dependencies()
        self.logger.info(f"Service start order: {', '.join(start_order)}")
        
        # Start processes in order with delays
        for name in start_order:
            process_info = self.processes[name]
            
            # Apply start delay
            if process_info.config.start_delay > 0:
                self.logger.info(f"Waiting {process_info.config.start_delay}s before starting {name}")
                time.sleep(process_info.config.start_delay)
            
            self._start_process(name)
        
        # Start monitoring thread
        monitor_thread = threading.Thread(target=self._monitor_processes, daemon=True)
        monitor_thread.start()
        
        self.logger.info("Supervisor started successfully")
        
        # Keep running
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.logger.info("Keyboard interrupt received")
            self.stop()
            
    def stop(self):
        """Stop all managed processes gracefully"""
        self.logger.info("Stopping supervisor and all managed processes")
        self.running = False
        
        # Stop processes in reverse dependency order
        stop_order = list(reversed(self._resolve_dependencies()))
        
        for name in stop_order:
            process_info = self.processes.get(name)
            if process_info and process_info.state == ProcessState.RUNNING:
                self._stop_process(name)
        
        # Stop control API
        if self.control_api_thread:
            self.control_api_thread.join(timeout=5)
        
        self.logger.info("Supervisor stopped")
        
    def restart_process(self, name: str) -> bool:
        """Restart a specific process"""
        self.logger.info(f"Restarting process {name}")
        if self._stop_process(name):
            time.sleep(2)
            return self._start_process(name)
        return False
        
    def reload_config(self):
        """Reload configuration and restart services"""
        self.logger.info("Reloading configuration")
        try:
            # Stop all services
            self.stop()
            
            # Reload config
            self._load_config()
            
            # Restart
            self.start()
            
            self.logger.info("Configuration reloaded successfully")
            return True
        except Exception as e:
            self.logger.error(f"Failed to reload configuration: {e}")
            return False
            
    def get_status(self) -> Dict[str, Any]:
        """Get status of all processes"""
        status = {
            'supervisor': {
                'version': SUPERVISOR_VERSION,
                'pid': os.getpid(),
                'uptime': time.time(),
                'running': self.running
            },
            'processes': []
        }
        
        for name, process_info in self.processes.items():
            # Get detailed process info
            process_status = {
                'name': name,
                'state': process_info.state.value,
                'pid': process_info.pid,
                'restart_count': process_info.restart_count,
                'last_start_time': process_info.last_start_time.isoformat() if process_info.last_start_time else None,
                'last_exit_code': process_info.last_exit_code,
                'health_check_failures': process_info.health_check_failures
            }
            
            # Add uptime if running
            if process_info.state == ProcessState.RUNNING and process_info.last_start_time:
                uptime_seconds = (datetime.now() - process_info.last_start_time).total_seconds()
                process_status['uptime_seconds'] = int(uptime_seconds)
            
            # Add backoff info if in backoff state
            if process_info.state == ProcessState.BACKOFF and process_info.backoff_until:
                remaining_seconds = (process_info.backoff_until - datetime.now()).total_seconds()
                process_status['backoff_remaining_seconds'] = max(0, int(remaining_seconds))
            
            # Verify process is actually running using psutil
            if process_info.pid:
                try:
                    if psutil.pid_exists(process_info.pid):
                        proc = psutil.Process(process_info.pid)
                        process_status['verified_running'] = proc.is_running() and proc.status() != psutil.STATUS_ZOMBIE
                        process_status['cpu_percent'] = proc.cpu_percent(interval=0.1)
                        process_status['memory_mb'] = proc.memory_info().rss / 1024 / 1024
                    else:
                        process_status['verified_running'] = False
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    process_status['verified_running'] = False
            
            status['processes'].append(process_status)
            
        return status
        
    def _start_control_api(self):
        """Start HTTP control API"""
        api_config = self.config.get('supervisor', {}).get('control_api', {})
        host = api_config.get('host', '127.0.0.1')
        port = api_config.get('port', 8765)
        
        # Generate or load auth token
        token_file = BASE_DIR / api_config.get('auth_token_file', 'config/supervisor_token.txt')
        token_file.parent.mkdir(exist_ok=True)
        
        if token_file.exists():
            auth_token = token_file.read_text().strip()
        else:
            auth_token = secrets.token_hex(32)
            token_file.write_text(auth_token)
            self.logger.info(f"Generated new auth token: {auth_token}")
        
        class ControlAPIHandler(BaseHTTPRequestHandler):
            supervisor = self
            token = auth_token
            
            def log_message(self, format, *args):
                pass  # Suppress default logging
                
            def do_GET(self):
                # Check auth
                auth_header = self.headers.get('Authorization', '')
                if not auth_header.startswith('Bearer ') or auth_header[7:] != self.token:
                    self.send_error(401, "Unauthorized")
                    return
                
                if self.path == '/status' or self.path == '/api/status':
                    status = self.supervisor.get_status()
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/json')
                    self.end_headers()
                    self.wfile.write(json.dumps(status, indent=2).encode())
                else:
                    self.send_error(404)
                    
            def do_POST(self):
                # Check auth
                auth_header = self.headers.get('Authorization', '')
                if not auth_header.startswith('Bearer ') or auth_header[7:] != self.token:
                    self.send_error(401, "Unauthorized")
                    return
                
                if self.path == '/reload':
                    success = self.supervisor.reload_config()
                    self.send_response(200 if success else 500)
                    self.send_header('Content-Type', 'application/json')
                    self.end_headers()
                    self.wfile.write(json.dumps({'success': success}).encode())
                    
                elif self.path.startswith('/restart/'):
                    process_name = self.path.split('/')[-1]
                    success = self.supervisor.restart_process(process_name)
                    self.send_response(200 if success else 500)
                    self.send_header('Content-Type', 'application/json')
                    self.end_headers()
                    self.wfile.write(json.dumps({'success': success}).encode())
                else:
                    self.send_error(404)
        
        def run_server():
            server = HTTPServer((host, port), ControlAPIHandler)
            self.logger.info(f"Control API listening on {host}:{port}")
            self.logger.info(f"Auth token: {auth_token}")
            server.serve_forever()
        
        self.control_api_thread = threading.Thread(target=run_server, daemon=True)
        self.control_api_thread.start()


def main():
    """Main entry point"""
    print(f"RiskNoX Supervisor v{SUPERVISOR_VERSION}")
    print(f"Config: {CONFIG_FILE}")
    print(f"Base Directory: {BASE_DIR}")
    
    if not CONFIG_FILE.exists():
        print(f"ERROR: Configuration file not found: {CONFIG_FILE}")
        sys.exit(1)
    
    try:
        supervisor = SupervisorService(CONFIG_FILE)
        supervisor.start()
    except KeyboardInterrupt:
        print("\nShutdown requested")
    except Exception as e:
        print(f"FATAL ERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
