"""
RiskNoX Service Control Backend
Simple Flask server to control the RiskNoXSupervisor service via web interface
Runs on port 5001 (separate from main agent on port 5000)
"""

import subprocess
import json
from datetime import datetime
from pathlib import Path
from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# Configuration
SERVICE_NAME = "RiskNoXSupervisor"
REPO_ROOT = Path(__file__).parent
CONTROL_SCRIPT = REPO_ROOT / "RiskNoXServiceControl.ps1"

class ServiceController:
    """Handle Windows service operations"""
    
    def __init__(self):
        """Initialize the service controller and find PowerShell"""
        self.pwsh_exe = self._find_powershell()
    
    def _find_powershell(self):
        """Find available PowerShell executable"""
        # Try PowerShell 7 first (preferred)
        pwsh_paths = [
            "pwsh",
            r"C:\Program Files\PowerShell\7\pwsh.exe",
            r"C:\Program Files (x86)\PowerShell\7\pwsh.exe"
        ]
        
        for pwsh_path in pwsh_paths:
            try:
                result = subprocess.run(
                    [pwsh_path, "-Command", "echo OK"],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if result.returncode == 0:
                    return pwsh_path
            except FileNotFoundError:
                continue
        
        # Fallback to Windows PowerShell (always available)
        return "powershell"
    
    def get_service_status(self):
        """Get current service status and details"""
        try:
            # Get service status using PowerShell
            cmd = f'Get-Service -Name "{SERVICE_NAME}" -ErrorAction SilentlyContinue | ConvertTo-Json'
            result = subprocess.run(
                [self.pwsh_exe, "-Command", cmd],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0 and result.stdout.strip():
                service_info = json.loads(result.stdout)
                
                # Get additional process information
                processes = self._get_managed_processes()
                
                # Convert numeric status codes to readable strings
                status_map = {
                    1: 'Stopped',
                    2: 'StartPending', 
                    3: 'StopPending',
                    4: 'Running',
                    5: 'ContinuePending',
                    6: 'PausePending',
                    7: 'Paused'
                }
                
                start_type_map = {
                    0: 'Boot',
                    1: 'System',
                    2: 'Automatic',
                    3: 'Manual',
                    4: 'Disabled'
                }
                
                raw_status = service_info.get('Status', 'Unknown')
                raw_start_type = service_info.get('StartType', 'Unknown')
                
                # Convert to string if numeric
                status = status_map.get(raw_status, str(raw_status)) if isinstance(raw_status, int) else raw_status
                start_type = start_type_map.get(raw_start_type, str(raw_start_type)) if isinstance(raw_start_type, int) else raw_start_type
                
                return {
                    'success': True,
                    'service_exists': True,
                    'service_name': service_info.get('Name', SERVICE_NAME),
                    'display_name': service_info.get('DisplayName', ''),
                    'status': status,
                    'start_type': start_type,
                    'can_stop': service_info.get('CanStop', False),
                    'processes': processes,
                    'timestamp': datetime.now().isoformat()
                }
            else:
                return {
                    'success': True,
                    'service_exists': False,
                    'message': 'Service not installed',
                    'timestamp': datetime.now().isoformat()
                }
                
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'error': 'Command timeout - system may be overloaded'
            }
        except Exception as e:
            return {
                'success': False,
                'error': f'Failed to get service status: {str(e)}'
            }
    
    def _get_managed_processes(self):
        """Get status of managed processes from supervisor Control API"""
        processes = {
            'backend_server': {'running': False, 'pid': None},
            'service_control_backend': {'running': False, 'pid': None},
            'monitoring_agent': {'running': False, 'pid': None},
            'suricata_ids': {'running': False, 'pid': None}
        }
        
        try:
            # Try to query supervisor Control API for accurate process status
            token_file = REPO_ROOT / "config" / "supervisor_token.txt"
            if token_file.exists():
                token = token_file.read_text().strip()
                import urllib.request
                
                req = urllib.request.Request(
                    "http://127.0.0.1:8765/api/status",
                    headers={"Authorization": f"Bearer {token}"}
                )
                
                with urllib.request.urlopen(req, timeout=5) as response:
                    data = json.loads(response.read().decode())
                    
                    if data.get('processes'):
                        for proc in data['processes']:
                            proc_name = proc.get('name')
                            if proc_name in processes:
                                processes[proc_name] = {
                                    'running': proc.get('state') == 'running',
                                    'pid': proc.get('pid'),
                                    'name': proc_name,
                                    'state': proc.get('state'),
                                    'uptime': proc.get('uptime')
                                }
                        return processes
            
            # Fallback: Check individual processes using PowerShell
            # Check backend_server (python process running backend_server.py)
            cmd = '''Get-CimInstance Win32_Process -Filter "Name = 'python.exe'" | Where-Object { $_.CommandLine -like "*backend_server.py*" } | Select-Object ProcessId, Name | ConvertTo-Json'''
            result = subprocess.run(
                [self.pwsh_exe, "-Command", cmd],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0 and result.stdout.strip():
                try:
                    proc_info = json.loads(result.stdout)
                    if isinstance(proc_info, list) and len(proc_info) > 0:
                        proc_info = proc_info[0]
                    if isinstance(proc_info, dict):
                        processes['backend_server'] = {
                            'running': True,
                            'pid': proc_info.get('ProcessId'),
                            'name': 'backend_server'
                        }
                except json.JSONDecodeError:
                    pass
            
            # Check service_control_backend (python process running service_control_backend.py)
            cmd = '''Get-CimInstance Win32_Process -Filter "Name = 'python.exe'" | Where-Object { $_.CommandLine -like "*service_control_backend.py*" } | Select-Object ProcessId, Name | ConvertTo-Json'''
            result = subprocess.run(
                [self.pwsh_exe, "-Command", cmd],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0 and result.stdout.strip():
                try:
                    proc_info = json.loads(result.stdout)
                    if isinstance(proc_info, list) and len(proc_info) > 0:
                        proc_info = proc_info[0]
                    if isinstance(proc_info, dict):
                        processes['service_control_backend'] = {
                            'running': True,
                            'pid': proc_info.get('ProcessId'),
                            'name': 'service_control_backend'
                        }
                except json.JSONDecodeError:
                    pass
            
            # Check monitoring-agent
            cmd = '''Get-Process -Name "monitoring-agent" -ErrorAction SilentlyContinue | Select-Object Id, ProcessName | ConvertTo-Json'''
            result = subprocess.run(
                [self.pwsh_exe, "-Command", cmd],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0 and result.stdout.strip():
                try:
                    proc_info = json.loads(result.stdout)
                    if isinstance(proc_info, list) and len(proc_info) > 0:
                        proc_info = proc_info[0]
                    if isinstance(proc_info, dict):
                        processes['monitoring_agent'] = {
                            'running': True,
                            'pid': proc_info.get('Id'),
                            'name': proc_info.get('ProcessName')
                        }
                except json.JSONDecodeError:
                    pass
            
            # Check suricata
            cmd = '''Get-Process -Name "suricata" -ErrorAction SilentlyContinue | Select-Object Id, ProcessName | ConvertTo-Json'''
            result = subprocess.run(
                [self.pwsh_exe, "-Command", cmd],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0 and result.stdout.strip():
                try:
                    proc_info = json.loads(result.stdout)
                    if isinstance(proc_info, list) and len(proc_info) > 0:
                        proc_info = proc_info[0]
                    if isinstance(proc_info, dict):
                        processes['suricata_ids'] = {
                            'running': True,
                            'pid': proc_info.get('Id'),
                            'name': proc_info.get('ProcessName')
                        }
                except json.JSONDecodeError:
                    pass
                    
        except Exception as e:
            print(f"Error getting process info: {e}")
        
        return processes
    
    def start_service(self, password):
        """Start the RiskNoXSupervisor service"""
        try:
            # Validate password is provided
            if not password:
                return {
                    'success': False,
                    'error': 'Password is required to start the service',
                    'needs_password': True
                }
            
            # Use the RiskNoXServiceControl.ps1 script
            if not CONTROL_SCRIPT.exists():
                return {
                    'success': False,
                    'error': f'Control script not found: {CONTROL_SCRIPT}'
                }
            
            # Escape password for PowerShell
            escaped_password = password.replace("'", "''")
            cmd = f'& "{CONTROL_SCRIPT}" start -Password \'{escaped_password}\''
            
            result = subprocess.run(
                [self.pwsh_exe, "-ExecutionPolicy", "Bypass", "-Command", cmd],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode == 0:
                return {
                    'success': True,
                    'message': 'Service start command issued successfully',
                    'output': result.stdout
                }
            else:
                # Check if it's a password error
                error_output = result.stderr or result.stdout
                if 'Incorrect password' in error_output or 'Password is required' in error_output:
                    return {
                        'success': False,
                        'error': 'Incorrect password',
                        'needs_password': True
                    }
                return {
                    'success': False,
                    'error': 'Failed to start service',
                    'details': error_output
                }
                
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'error': 'Start command timeout - service may be starting'
            }
        except Exception as e:
            return {
                'success': False,
                'error': f'Failed to start service: {str(e)}'
            }
    
    def stop_service(self, password):
        """Stop the RiskNoXSupervisor service"""
        try:
            # Validate password is provided
            if not password:
                return {
                    'success': False,
                    'error': 'Password is required to stop the service',
                    'needs_password': True
                }
            
            # Check if running as administrator
            is_admin_cmd = '([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)'
            admin_check = subprocess.run(
                [self.pwsh_exe, "-Command", is_admin_cmd],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if admin_check.stdout.strip().lower() != 'true':
                return {
                    'success': False,
                    'error': 'Administrator privileges required to stop service',
                    'needs_admin': True
                }
            
            # Use the RiskNoXServiceControl.ps1 script
            if not CONTROL_SCRIPT.exists():
                return {
                    'success': False,
                    'error': f'Control script not found: {CONTROL_SCRIPT}'
                }
            
            # Escape password for PowerShell
            escaped_password = password.replace("'", "''")
            cmd = f'& "{CONTROL_SCRIPT}" stop -Password \'{escaped_password}\''
            
            result = subprocess.run(
                [self.pwsh_exe, "-ExecutionPolicy", "Bypass", "-Command", cmd],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode == 0:
                return {
                    'success': True,
                    'message': 'Service stop command issued successfully',
                    'output': result.stdout
                }
            else:
                # Check if it's a password error
                error_output = result.stderr or result.stdout
                if 'Incorrect password' in error_output or 'Password is required' in error_output:
                    return {
                        'success': False,
                        'error': 'Incorrect password',
                        'needs_password': True
                    }
                return {
                    'success': False,
                    'error': 'Failed to stop service',
                    'details': error_output
                }
                
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'error': 'Stop command timeout - service may be stopping'
            }
        except Exception as e:
            return {
                'success': False,
                'error': f'Failed to stop service: {str(e)}'
            }
    
    def restart_service(self, password):
        """Restart the RiskNoXSupervisor service"""
        try:
            # Validate password is provided
            if not password:
                return {
                    'success': False,
                    'error': 'Password is required to restart the service',
                    'needs_password': True
                }
            
            # Check admin privileges
            is_admin_cmd = '([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)'
            admin_check = subprocess.run(
                [self.pwsh_exe, "-Command", is_admin_cmd],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if admin_check.stdout.strip().lower() != 'true':
                return {
                    'success': False,
                    'error': 'Administrator privileges required to restart service',
                    'needs_admin': True
                }
            
            # Use the RiskNoXServiceControl.ps1 script
            if not CONTROL_SCRIPT.exists():
                return {
                    'success': False,
                    'error': f'Control script not found: {CONTROL_SCRIPT}'
                }
            
            # Escape password for PowerShell
            escaped_password = password.replace("'", "''")
            cmd = f'& "{CONTROL_SCRIPT}" restart -Password \'{escaped_password}\''
            
            result = subprocess.run(
                [self.pwsh_exe, "-ExecutionPolicy", "Bypass", "-Command", cmd],
                capture_output=True,
                text=True,
                timeout=90
            )
            
            if result.returncode == 0:
                return {
                    'success': True,
                    'message': 'Service restart command issued successfully',
                    'output': result.stdout
                }
            else:
                # Check if it's a password error
                error_output = result.stderr or result.stdout
                if 'Incorrect password' in error_output or 'Password is required' in error_output:
                    return {
                        'success': False,
                        'error': 'Incorrect password',
                        'needs_password': True
                    }
                return {
                    'success': False,
                    'error': 'Failed to restart service',
                    'details': error_output
                }
                
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'error': 'Restart command timeout - service may be restarting'
            }
        except Exception as e:
            return {
                'success': False,
                'error': f'Failed to restart service: {str(e)}'
            }

# Initialize controller
controller = ServiceController()

# API Routes
@app.route('/')
def index():
    """Serve the service control web interface"""
    return send_from_directory(Path(__file__).parent / 'web', 'service_control.html')

@app.route('/health')
def health():
    """Health check endpoint"""
    return jsonify({
        'status': 'running',
        'service': 'RiskNoX Service Control Backend',
        'port': 5001,
        'timestamp': datetime.now().isoformat()
    })

@app.route('/api/service/status', methods=['GET'])
def get_status():
    """Get service status"""
    return jsonify(controller.get_service_status())

@app.route('/api/service/start', methods=['POST'])
def start_service():
    """Start the service"""
    data = request.get_json(force=True) or {}  # ✅ Add force=True
    password = data.get('password', '')
    return jsonify(controller.start_service(password))

@app.route('/api/service/stop', methods=['POST'])
def stop_service():
    """Stop the service"""
    data = request.get_json(force=True) or {}  # ✅ Add force=True
    password = data.get('password', '')
    return jsonify(controller.stop_service(password))

@app.route('/api/service/restart', methods=['POST'])
def restart_service():
    """Restart the service"""
    data = request.get_json(force=True) or {}  # ✅ Add force=True
    password = data.get('password', '')
    return jsonify(controller.restart_service(password))

if __name__ == '__main__':
    print("=" * 60)
    print("RiskNoX Service Control Backend")
    print("=" * 60)
    print(f"Service: {SERVICE_NAME}")
    print(f"Control Script: {CONTROL_SCRIPT}")
    print(f"Starting server on http://0.0.0.0:5001")
    print("=" * 60)
    
    app.run(host='0.0.0.0', port=5001, debug=False)
