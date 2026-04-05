
import os
import sys

# ============================================================================
# SAFE ENCODING - Add right after imports, before anything else
# ============================================================================
def safe_print(*args, **kwargs):
    """Safely print messages, handling encoding issues"""
    try:
        # Convert all args to safe strings
        safe_args = []
        for arg in args:
            try:
                # Try to encode to ASCII, replacing problematic characters
                safe_arg = str(arg).encode('ascii', errors='replace').decode('ascii')
                safe_args.append(safe_arg)
            except:
                safe_args.append(str(arg))
        print(*safe_args, **kwargs)
        sys.stdout.flush()
    except:
        pass  # Silently fail if print fails

def safe_str(value, fallback=''):
    """Convert any value to ASCII-safe string"""
    try:
        if value is None:
            return fallback
        s = str(value)
        return s.encode('ascii', errors='replace').decode('ascii')
    except:
        return fallback

# Replace built-in print
print = safe_print


import requests
import time
import socket
import uuid
import json
import platform
from pathlib import Path
import threading

# Configuration
MANAGER_URL = "https://testingmanagerapi-production.up.railway.app"
AGENT_API_KEY = "agent-secure-key-xyz123"
LOCAL_BACKEND_URL = "http://localhost:5000"
LOCAL_SERVICE_CONTROL_URL = "http://localhost:5001"

CONFIG_FILE = Path("config/agent_config.json")
POLL_INTERVAL = 5

class RiskNoXAgent:
    def __init__(self):
        self.agent_id = self.get_or_create_agent_id()
        self.hostname = socket.gethostname()
        self.ip_address = self.get_ip_address()
        self.os_info = platform.platform()
        self.headers = {
            'X-Agent-Key': AGENT_API_KEY,
            'Content-Type': 'application/json'
        }
        self.active_scans = {}
        self.scan_monitor_running = False
        
    def get_or_create_agent_id(self):
        CONFIG_FILE.parent.mkdir(exist_ok=True)
        
        if CONFIG_FILE.exists():
            with open(CONFIG_FILE, 'r') as f:
                return json.load(f)['agent_id']
        else:
            agent_id = str(uuid.uuid4())
            with open(CONFIG_FILE, 'w') as f:
                json.dump({
                    'agent_id': agent_id,
                    'hostname': socket.gethostname(),
                    'created_at': time.strftime('%Y-%m-%d %H:%M:%S')
                }, f, indent=2)
            return agent_id
    
    def get_ip_address(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return '127.0.0.1'
    
    def register(self):
        try:
            response = requests.post(
                f"{MANAGER_URL}/api/agents/register",
                json={
                    'agent_id': self.agent_id,
                    'hostname': self.hostname,
                    'ip_address': self.ip_address,
                    'os_info': self.os_info
                },
                headers=self.headers,
                timeout=10
            )
            if response.status_code == 200:
                print(f"Registered - Agent ID: {self.agent_id}")
                return True
            else:
                print(f"Registration failed - Status: {response.status_code}")
                return False
        except Exception as e:
            print(f"Registration error: {e}")
            return False
    
    def send_heartbeat(self):
        try:
            requests.post(
                f"{MANAGER_URL}/api/agents/heartbeat",
                json={'agent_id': self.agent_id},
                headers=self.headers,
                timeout=10
            )
            print(f"[HEARTBEAT] Heartbeat sent")
        except Exception as e:
            print(f" Heartbeat failed: {e}")
    
    def monitor_active_scans(self):
        """Background thread to monitor active scans and report completion"""
        print(" Scan monitor thread started")
    
        while self.scan_monitor_running:
            try:
                # Clean up scans that no longer exist or are completed
                scans_to_remove = []
            
                for session_id, command_id in list(self.active_scans.items()):
                    try:
                        # Use scan-progress endpoint for real-time data
                        progress_response = requests.get(
                            f"{LOCAL_BACKEND_URL}/api/antivirus/scan-progress/{session_id}",
                            timeout=10
                       )
                    
                        if progress_response.status_code == 404:
                            print(f" Scan session not found: {session_id[:8]}... (removing)")
                            print(f"[DEBUG] Adding to scans_to_remove list")
                            scans_to_remove.append(session_id)
                            print(f"[DEBUG] scans_to_remove now has {len(scans_to_remove)} items")
                            continue
                    
                        if progress_response.status_code == 200:
                            result_data = progress_response.json()
                            progress_info = result_data.get('progress', {})
                        
                            status = progress_info.get('status', 'unknown')
                            progress_percent = progress_info.get('progress_percent', 0)
                            files_scanned = progress_info.get('files_scanned', 0)
                            threats_found = progress_info.get('threats_found', 0)
                        
                            # Check if scan is completed, cancelled, or errored
                            if status in ['completed', 'cancelled', 'error']:
                                print(f" Scan {status}: {session_id[:8]}...")
                                print(f"   Files: {files_scanned}, Threats: {threats_found}")
                            
                                # Get full status for reporting
                                status_response = requests.get(
                                    f"{LOCAL_BACKEND_URL}/api/antivirus/status/{session_id}",
                                    timeout=10
                               )
                            
                                if status_response.status_code == 200:
                                    full_result = status_response.json()
                                    self.report_result(command_id, 'completed', full_result.get('session', {}))
                            
                                scans_to_remove.append(session_id)
                        
                            else:
                                # Scan is still running - show progress
                                print(f"Scan {session_id[:8]}... progress: {progress_percent}% status: {status} files: {files_scanned}")
                
                    except requests.exceptions.ConnectionError:
                        print(f"Cannot connect to backend for scan {session_id[:8]}...")
                    except requests.exceptions.Timeout:
                        print(f"Timeout checking scan {session_id[:8]}...")
                    except Exception as e:
                        print(f" Error checking scan {session_id[:8]}...: {e}")
            
                # Remove completed/cancelled scans
                print(f"[DEBUG] Processing cleanup for {len(scans_to_remove)} scans")
                for session_id in scans_to_remove:
                    if session_id in self.active_scans:
                        command_id = self.active_scans[session_id]
                        del self.active_scans[session_id]
                        print(f"Removed scan from monitoring: {session_id[:8]}... (command: {command_id})")
                    else:
                        print(f"[DEBUG] Session {session_id[:8]}... already removed")

                # Report active scans count
                print(f"[DEBUG] Remaining active scans: {len(self.active_scans)}")
                if self.active_scans:
                    print(f"Active scans being monitored: {list(self.active_scans.keys())}")
            
                time.sleep(5)  # Check every 5 seconds
            
            except Exception as e:
                print(f" Error in scan monitor: {e}")
                time.sleep(5)
    
        print("Scan monitor thread stopped")
    
    def poll_commands(self):
        try:
            response = requests.get(
                f"{MANAGER_URL}/api/commands/poll/{self.agent_id}",
                headers=self.headers,
                timeout=10
            )
            
            if response.status_code != 200:
                return
            
            commands = response.json().get('commands', [])
            
            if commands:
                print(f"\nReceived {len(commands)} command(s)")
                
            for cmd in commands:
                print(f"  Executing: {cmd['type']}")
                self.execute_command(cmd)
                
        except Exception as e:
            print(f" Poll error: {e}")
    
    def execute_command(self, cmd):
        command_id = cmd['command_id']
        command_type = cmd['type']
        parameters = cmd.get('parameters', {})
    
        try:
            # Route to appropriate handler
            if command_type == 'scan':
                result = self.execute_scan(parameters, command_id)
            elif command_type == 'get_scan_status':
                result = self.execute_get_scan_status(parameters)
            elif command_type == 'cancel_scan':
                result = self.execute_cancel_scan(parameters)
            elif command_type == 'patch':
                result = self.execute_patch(parameters)
            elif command_type == 'install_patches': 
                result = self.execute_install_patches(parameters)
            elif command_type == 'web_blocking':
                result = self.execute_web_blocking(parameters)
            elif command_type == 'unblock_url':
                result = self.execute_unblock_url(parameters)
            elif command_type == 'verify_url_blocked':
                result = self.execute_verify_url_blocked(parameters)
            elif command_type == 'get_blocked_urls':
                result = self.execute_get_blocked_urls(parameters)
            elif command_type == 'system_status':
                result = self.execute_system_status(parameters)
            elif command_type == 'get_scan_progress':
                result = self.execute_get_scan_progress(parameters)
            
            # ============ APP BLOCKING COMMANDS ============
            elif command_type == 'block_application':
                result = self.execute_block_application(parameters)
            elif command_type == 'unblock_application':
                result = self.execute_unblock_application(parameters)
            elif command_type == 'get_blocked_applications':
                result = self.execute_get_blocked_applications(parameters)
            elif command_type == 'verify_app_blocking':
                result = self.execute_verify_app_blocking(parameters)
            elif command_type == 'unblock_all_applications':
                result = self.execute_unblock_all_applications(parameters)
            # ==============================================
            
            elif command_type == 'get_applications':
                result = self.execute_get_applications(parameters)
            elif command_type == 'create_scheduled_scan':
                result = self.execute_create_scheduled_scan(parameters)
            elif command_type == 'update_scheduled_scan':
                result = self.execute_update_scheduled_scan(parameters)
            elif command_type == 'delete_scheduled_scan':
                result = self.execute_delete_scheduled_scan(parameters)
            elif command_type == 'get_scheduled_scans':
                result = self.execute_get_scheduled_scans(parameters)
            elif command_type == 'get_database_info':
                result = self.execute_get_database_info(parameters)
            elif command_type == 'update_database':
                result = self.execute_update_database(parameters)
            elif command_type == 'service_control':
                result = self.execute_service_control(parameters)
            else:
                result = {'error': f'Unknown command: {command_type}'}
                self.report_result(command_id, 'failed', result)
                return
        
            # Don't report scan commands immediately (they're monitored)
            if command_type != 'scan':
                self.report_result(command_id, 'completed', result)
                print(f" Completed: {command_type}")
        
        except Exception as e:
            print(f" Execution error: {e}")
            import traceback
            traceback.print_exc()
            self.report_result(command_id, 'failed', {'error': str(e)})
    
    # ============================================================================
    # APP BLOCKING COMMAND HANDLERS
    # ============================================================================
    
    def execute_block_application(self, params):
        """Block an application"""
        try:
            app_name = params.get('name')
            executable = params.get('executable')
        
            if not app_name or not executable:
                return {
                    'type': 'block_application',
                    'error': 'Both name and executable are required',
                    'success': False
                }
        
            # Sanitize inputs
            app_name = safe_str(app_name, 'Unknown')
            executable = safe_str(executable, 'unknown.exe')
        
            print(f"[BLOCK] Blocking application: {app_name} ({executable})")
        
            response = requests.post(
                f"{LOCAL_BACKEND_URL}/api/app-blocking/block",
                json={
                    'name': app_name,
                    'executable': executable
                },
                timeout=30
            )
        
            if response.status_code == 200:
                result_data = response.json()
                print(f"[SUCCESS] Application blocked successfully")
            
                return {
                    'type': 'block_application',
                    'success': result_data.get('success', True),
                    'app_name': app_name,
                    'executable': executable,
                    'details': result_data.get('details', {}),
                    'message': result_data.get('message', 'Application blocked'),
                    'response': result_data
                }
            else:
                error_msg = f'HTTP {response.status_code}'
                try:
                    error_data = response.json()
                    error_msg = error_data.get('message', error_msg)
                except:
                    pass
            
                return {
                    'type': 'block_application',
                    'error': error_msg,
                    'success': False
                }
            
        except requests.exceptions.ConnectionError:
            return {
                'type': 'block_application',
                'error': 'Cannot connect to backend API. Make sure backend_server.py is running on port 5000.',
                'success': False
            }
        except Exception as e:
            return {
                'type': 'block_application',
                'error': safe_str(e, 'Unknown error'),
                'success': False
            }
    
    def execute_unblock_application(self, params):
        """Unblock an application"""
        try:
            executable = params.get('executable')
            
            if not executable:
                return {
                    'type': 'unblock_application',
                    'error': 'Executable name is required',
                    'success': False
                }
            
            print(f" Unblocking application: {executable}")
            
            response = requests.post(
                f"{LOCAL_BACKEND_URL}/api/app-blocking/unblock",
                json={'executable': executable},
                timeout=30
            )
            
            if response.status_code == 200:
                result_data = response.json()
                print(f" Application unblocked successfully")
                
                return {
                    'type': 'unblock_application',
                    'success': result_data.get('success', True),
                    'executable': executable,
                    'details': result_data.get('details', {}),
                    'message': result_data.get('message', 'Application unblocked'),
                    'was_blocked': result_data.get('was_blocked', True),
                    'response': result_data
                }
            else:
                error_msg = f'HTTP {response.status_code}'
                try:
                    error_data = response.json()
                    error_msg = error_data.get('message', error_msg)
                except:
                    pass
                
                return {
                    'type': 'unblock_application',
                    'error': error_msg,
                    'success': False
                }
                
        except requests.exceptions.ConnectionError:
            return {
                'type': 'unblock_application',
                'error': 'Cannot connect to backend API',
                'success': False
            }
        except Exception as e:
            return {
                'type': 'unblock_application',
                'error': str(e),
                'success': False
            }
    
    def execute_get_blocked_applications(self, params):
        """Get list of all currently blocked applications"""
        try:
            print(f" Getting blocked applications list...")
            
            response = requests.get(
                f"{LOCAL_BACKEND_URL}/api/app-blocking/blocked",
                timeout=10
            )
            
            if response.status_code == 200:
                result_data = response.json()
                blocked_apps = result_data.get('apps', result_data.get('blocked_applications', []))
                count = result_data.get('count', len(blocked_apps))
                
                print(f" Found {count} blocked application(s)")
                
                return {
                    'type': 'get_blocked_applications',
                    'success': True,
                    'blocked_applications': blocked_apps,
                    'count': count
                }
            else:
                return {
                    'type': 'get_blocked_applications',
                    'error': f'HTTP {response.status_code}',
                    'success': False
                }
                
        except requests.exceptions.ConnectionError:
            return {
                'type': 'get_blocked_applications',
                'error': 'Cannot connect to backend API',
                'success': False
            }
        except Exception as e:
            return {
                'type': 'get_blocked_applications',
                'error': str(e),
                'success': False
            }
    
    def execute_verify_app_blocking(self, params):
        """Verify if a specific application is currently blocked"""
        try:
            executable = params.get('executable')
            
            if not executable:
                return {
                    'type': 'verify_app_blocking',
                    'error': 'Executable name is required',
                    'success': False
                }
            
            print(f" Verifying blocking status for: {executable}")
            
            response = requests.get(
                f"{LOCAL_BACKEND_URL}/api/app-blocking/verify/{executable}",
                timeout=10
            )
            
            if response.status_code == 200:
                result_data = response.json()
                is_blocked = result_data.get('is_blocked', False)
                
                status_text = "BLOCKED" if is_blocked else "NOT BLOCKED"
                print(f" Status: {status_text}")
                
                return {
                    'type': 'verify_app_blocking',
                    'success': True,
                    'executable': executable,
                    'is_blocked': is_blocked,
                    'details': result_data.get('details')
                }
            else:
                return {
                    'type': 'verify_app_blocking',
                    'error': f'HTTP {response.status_code}',
                    'success': False
                }
                
        except requests.exceptions.ConnectionError:
            return {
                'type': 'verify_app_blocking',
                'error': 'Cannot connect to backend API',
                'success': False
            }
        except Exception as e:
            return {
                'type': 'verify_app_blocking',
                'error': str(e),
                'success': False
            }
    
    def execute_unblock_all_applications(self, params):
        """Unblock all currently blocked applications"""
        try:
            print(f" Unblocking all applications...")
            
            response = requests.post(
                f"{LOCAL_BACKEND_URL}/api/app-blocking/unblock-all",
                timeout=60
            )
            
            if response.status_code == 200:
                result_data = response.json()
                print(f" All applications unblocked")
                
                return {
                    'type': 'unblock_all_applications',
                    'success': True,
                    'message': 'All applications unblocked successfully',
                    'response': result_data
                }
            else:
                return {
                    'type': 'unblock_all_applications',
                    'error': f'HTTP {response.status_code}',
                    'success': False
                }
                
        except requests.exceptions.ConnectionError:
            return {
                'type': 'unblock_all_applications',
                'error': 'Cannot connect to backend API',
                'success': False
            }
        except Exception as e:
            return {
                'type': 'unblock_all_applications',
                'error': str(e),
                'success': False
            }
    
    # ============================================================================
    # EXISTING COMMAND HANDLERS
    # ============================================================================
    
    def execute_scan(self, params, command_id):
        """Start scan and register for monitoring"""
        try:
            scan_path = params.get('path', 'C:\\')
            scan_type = params.get('scan_type', 'directory')
            
            if scan_type == 'system':
                scan_path = 'SYSTEM_SCAN'
            elif scan_type == 'quick_system':
                scan_path = 'QUICK_SYSTEM_SCAN'
            
            response = requests.post(
                f"{LOCAL_BACKEND_URL}/api/antivirus/scan",
                json={
                    'path': scan_path,
                    'scan_type': scan_type
                },
                timeout=10
            )
            
            if response.status_code == 200:
                scan_data = response.json()
                session_id = scan_data.get('session_id')
                
                self.active_scans[session_id] = command_id
                print(f" Scan started and registered for monitoring: {session_id[:8]}...")
                
                result = {
                    'type': 'scan',
                    'status': 'started',
                    'session_id': session_id,
                    'scan_type': scan_type,
                    'path': scan_path,
                    'message': f'{scan_type} scan started successfully',
                    'success': True
                }
                
                self.report_result(command_id, 'completed', result)
                return result
            else:
                return {
                    'type': 'scan',
                    'error': f'Failed to start scan: {response.status_code}',
                    'success': False
                }
                
        except Exception as e:
            return {
                'type': 'scan',
                'error': str(e),
                'success': False
            }
    
    def execute_get_scan_status(self, params):
        """Get status of running or completed scan"""
        try:
            session_id = params.get('session_id')
            
            if not session_id:
                return {
                    'type': 'get_scan_status',
                    'error': 'session_id is required',
                    'success': False
                }
            
            status_response = requests.get(
                f"{LOCAL_BACKEND_URL}/api/antivirus/status/{session_id}",
                timeout=10
            )
            
            if status_response.status_code == 200:
                status_data = status_response.json()
                session = status_data.get('session', {})
                
                return {
                    'type': 'get_scan_status',
                    'session_id': session_id,
                    'status': session.get('status'),
                    'progress_percent': session.get('progress_percent', 0),
                    'files_scanned': session.get('files_scanned', 0),
                    'total_files': session.get('total_files', 0),
                    'threats_found': session.get('threats_found', 0),
                    'threats': session.get('threats', []),
                    'scan_log': session.get('scan_log', []),
                    'completed': session.get('status') in ['completed', 'error', 'cancelled'],
                    'success': True
                }
            else:
                return {
                    'type': 'get_scan_status',
                    'error': f'Failed to get scan status: {status_response.status_code}',
                    'success': False
                }
                
        except Exception as e:
            return {
                'type': 'get_scan_status',
                'error': str(e),
                'success': False
            }
    
    def execute_cancel_scan(self, params):
        """Cancel an active scan"""
        try:
            session_id = params.get('session_id')
            
            if not session_id:
                return {
                    'type': 'cancel_scan',
                    'error': 'session_id is required',
                    'success': False
                }
            
            response = requests.post(
                f"{LOCAL_BACKEND_URL}/api/antivirus/cancel/{session_id}",
                timeout=10
            )
            
            if response.status_code == 200:
                if session_id in self.active_scans:
                    del self.active_scans[session_id]
                
                return {
                    'type': 'cancel_scan',
                    'session_id': session_id,
                    'success': True,
                    'message': 'Scan cancelled successfully'
                }
            else:
                return {
                    'type': 'cancel_scan',
                    'error': f'Failed to cancel scan: {response.status_code}',
                    'success': False
                }
                
        except Exception as e:
            return {
                'type': 'cancel_scan',
                'error': str(e),
                'success': False
            }
    
    def execute_patch(self, params):
        """Get patch information"""
        try:
            response = requests.get(
                f"{LOCAL_BACKEND_URL}/api/patch-management/info",
                timeout=60
            )
            
            if response.status_code == 200:
                patch_data = response.json()
                return {
                    'type': 'patch',
                    'data': patch_data,
                    'success': patch_data.get('success', True)
                }
            else:
                return {
                    'type': 'patch',
                    'error': f'Failed to get patch info: {response.status_code}',
                    'success': False
                }
                
        except Exception as e:
            return {
                'type': 'patch',
                'error': str(e),
                'success': False
            }
    
    def execute_install_patches(self, params):
        """Install Windows updates"""
        try:
            patch_ids = params.get('patch_ids', [])
            install_all = params.get('install_all', False)
            
            response = requests.post(
                f"{LOCAL_BACKEND_URL}/api/patch-management/install",
                json={
                    'update_ids': patch_ids,
                    'install_all': install_all
                },
                timeout=3600
            )
            
            if response.status_code == 200:
                result_data = response.json()
                return {
                    'type': 'install_patches',
                    'success': result_data.get('success', True),
                    'data': result_data
                }
            else:
                return {
                    'type': 'install_patches',
                    'error': f'Installation failed: {response.status_code}',
                    'success': False
                }
                
        except Exception as e:
            return {
                'type': 'install_patches',
                'error': str(e),
                'success': False
            }
    
    def execute_web_blocking(self, params):
        """Block URLs"""
        try:
            urls = params.get('urls', [])
            results = []
            
            for url in urls:
                response = requests.post(
                    f"{LOCAL_BACKEND_URL}/api/web-blocking/block",
                    json={'url': url},
                    timeout=10
                )
                
                results.append({
                    'url': url,
                    'success': response.status_code == 200,
                    'response': response.json() if response.status_code == 200 else None
                })
            
            return {
                'type': 'web_blocking',
                'blocked_count': sum(1 for r in results if r['success']),
                'results': results,
                'success': True
            }
            
        except Exception as e:
            return {
                'type': 'web_blocking',
                'error': str(e),
                'success': False
            }
    
    def execute_unblock_url(self, params):
        """Unblock URL"""
        try:
            url = params.get('url')
            
            if not url:
                return {'type': 'unblock_url', 'error': 'No URL provided', 'success': False}
            
            response = requests.post(
                f"{LOCAL_BACKEND_URL}/api/web-blocking/unblock",
                json={'url': url},
                timeout=10
            )
            
            return {
                'type': 'unblock_url',
                'url': url,
                'success': response.status_code == 200,
                'response': response.json() if response.status_code == 200 else None
            }
                
        except Exception as e:
            return {
                'type': 'unblock_url',
                'error': str(e),
                'success': False
            }
    
    def execute_get_applications(self, params):
        """Get installed applications"""
        try:
            response = requests.get(
                f"{LOCAL_BACKEND_URL}/api/app-blocking/applications",
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                return {
                    'type': 'get_applications',
                    'success': True,
                    'applications': data.get('applications', []),
                    'count': data.get('count', 0)
                }
            else:
                return {
                    'type': 'get_applications',
                    'error': f'Failed: {response.status_code}',
                    'success': False
                }
        except Exception as e:
            return {
                'type': 'get_applications',
                'error': str(e),
                'success': False
            }
    
    def execute_get_database_info(self, params):
        """Get virus database information"""
        try:
            response = requests.get(
                f"{LOCAL_BACKEND_URL}/api/antivirus/database-info",
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                return {
                    'type': 'get_database_info',
                    'success': True,
                    'database_info': data.get('database_info'),
                    'last_update_log': data.get('last_update_log')
                }
            else:
                return {
                    'type': 'get_database_info',
                    'error': f'Failed: {response.status_code}',
                    'success': False
                }
        except Exception as e:
            return {
                'type': 'get_database_info',
                'error': str(e),
                'success': False
            }
    
    def execute_update_database(self, params):
        """Manually trigger virus database update"""
        try:
            response = requests.post(
                f"{LOCAL_BACKEND_URL}/api/antivirus/update-database",
                timeout=600
            )
            
            if response.status_code == 200:
                return {
                    'type': 'update_database',
                    'success': True,
                    'message': 'Database updated successfully'
                }
            else:
                return {
                    'type': 'update_database',
                    'error': f'Update failed: {response.status_code}',
                    'success': False
                }
        except Exception as e:
            return {
                'type': 'update_database',
                'error': str(e),
                'success': False
            }
    
    def execute_create_scheduled_scan(self, params):
        """Create scheduled scan"""
        try:
            response = requests.post(
                f"{LOCAL_BACKEND_URL}/api/antivirus/scheduled",
                json=params,
                timeout=10
            )
            
            if response.status_code in [200, 201]:
                return {
                    'type': 'create_scheduled_scan',
                    'success': True,
                    'response': response.json()
                }
            else:
                return {
                    'type': 'create_scheduled_scan',
                    'error': f'Failed: {response.status_code}',
                    'success': False
                }
        except Exception as e:
            return {
                'type': 'create_scheduled_scan',
                'error': str(e),
                'success': False
            }
    
    def execute_update_scheduled_scan(self, params):
        """Update scheduled scan"""
        try:
            scan_id = params.get('scan_id')
            response = requests.put(
                f"{LOCAL_BACKEND_URL}/api/antivirus/scheduled/{scan_id}",
                json=params,
                timeout=10
            )
            
            if response.status_code == 200:
                return {
                    'type': 'update_scheduled_scan',
                    'success': True,
                    'response': response.json()
                }
            else:
                return {
                    'type': 'update_scheduled_scan',
                    'error': f'Failed: {response.status_code}',
                    'success': False
                }
        except Exception as e:
            return {
                'type': 'update_scheduled_scan',
                'error': str(e),
                'success': False
            }
    
    def execute_delete_scheduled_scan(self, params):
        """Delete scheduled scan"""
        try:
            scan_id = params.get('scan_id')
            response = requests.delete(
                f"{LOCAL_BACKEND_URL}/api/antivirus/scheduled/{scan_id}",
                timeout=10
            )
            
            if response.status_code == 200:
                return {
                    'type': 'delete_scheduled_scan',
                    'success': True,
                    'response': response.json()
                }
            else:
                return {
                    'type': 'delete_scheduled_scan',
                    'error': f'Failed: {response.status_code}',
                    'success': False
                }
        except Exception as e:
            return {
                'type': 'delete_scheduled_scan',
                'error': str(e),
                'success': False
            }
    
    def execute_get_scheduled_scans(self, params):
        """Get scheduled scans"""
        try:
            response = requests.get(
                f"{LOCAL_BACKEND_URL}/api/antivirus/scheduled",
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                return {
                    'type': 'get_scheduled_scans',
                    'success': True,
                    'scheduled_scans': data.get('scheduled_scans', [])
                }
            else:
                return {
                    'type': 'get_scheduled_scans',
                    'error': f'Failed: {response.status_code}',
                    'success': False
                }
        except Exception as e:
            return {
                'type': 'get_scheduled_scans',
                'error': str(e),
                'success': False
            }

    def execute_verify_url_blocked(self, params):
        """Verify if a specific URL is blocked"""
        try:
            url = params.get('url', '').strip()
        
            if not url:
                return {
                    'type': 'verify_url_blocked',
                    'error': 'URL is required',
                    'success': False
                }
        
            response = requests.post(
                f"{LOCAL_BACKEND_URL}/api/web-blocking/verify",
                json={'url': url},
                timeout=10
            )
        
            if response.status_code == 200:
                result_data = response.json()
                return {
                    'type': 'verify_url_blocked',
                    'success': True,
                    'url': url,
                    'is_blocked': result_data.get('is_blocked', False),
                    'details': result_data.get('details')
                }
            else:
                return {
                    'type': 'verify_url_blocked',
                    'error': f'HTTP {response.status_code}',
                    'success': False
                }
        except Exception as e:
            return {
                'type': 'verify_url_blocked',
                'error': str(e),
                'success': False
            }

    def execute_get_blocked_urls(self, params):
        """Get list of all blocked URLs"""
        try:
            response = requests.get(
                f"{LOCAL_BACKEND_URL}/api/web-blocking/urls",
                timeout=10
            )
        
            if response.status_code == 200:
                result_data = response.json()
                return {
                    'type': 'get_blocked_urls',
                    'success': True,
                    'urls': result_data.get('urls', []),
                    'count': len(result_data.get('urls', []))
                }
            else:
                return {
                    'type': 'get_blocked_urls',
                    'error': f'HTTP {response.status_code}',
                    'success': False
                }
        except Exception as e:
            return {
                'type': 'get_blocked_urls',
                'error': str(e),
                'success': False
            }

    def execute_system_status(self, params):
        """Get system status"""
        try:
            response = requests.get(
                f"{LOCAL_BACKEND_URL}/api/system/status",
                timeout=10
            )
        
            if response.status_code == 200:
                result_data = response.json()
                return {
                    'type': 'system_status',
                    'success': True,
                    'system': result_data.get('system', {})
                }
            else:
                return {
                    'type': 'system_status',
                    'error': f'HTTP {response.status_code}',
                    'success': False
               }
        except Exception as e:
            return {
                'type': 'system_status',
                'error': str(e),
                'success': False
            }

    def execute_get_scan_progress(self, params):
        """Get real-time scan progress"""
        try:
            session_id = params.get('session_id')
        
            if not session_id:
                return {
                    'type': 'get_scan_progress',
                    'error': 'session_id is required',
                    'success': False
                }
        
            response = requests.get(
                f"{LOCAL_BACKEND_URL}/api/antivirus/scan-progress/{session_id}",
                timeout=10
            )
        
            if response.status_code == 200:
                result_data = response.json()
                return {
                    'type': 'get_scan_progress',
                    'success': True,
                    'progress': result_data.get('progress', {})
               }
            else:
                return {
                    'type': 'get_scan_progress',
                    'error': f'HTTP {response.status_code}',
                    'success': False
                }
        except Exception as e:
            return {
                'type': 'get_scan_progress',
                'error': str(e),
                'success': False
            }

    def execute_service_control(self, params):
        """Execute service control via local Flask API on port 5001"""
        try:
            action = params.get('action')  
            password = params.get('password')
        
            # Validate action
            valid_actions = ['start', 'stop', 'restart', 'status']
            if action not in valid_actions:
                return {
                    'type': 'service_control',
                    'error': f'Invalid action. Must be one of: {", ".join(valid_actions)}',
                    'success': False
                }
        
            # Check if password is required for this action
            actions_requiring_password = ['start', 'stop', 'restart']
            if action in actions_requiring_password and not password:
                return {
                    'type': 'service_control',
                    'error': f'Password is required for {action} action',
                    'success': False,
                    'needs_password': True
                }
        
            # Call local Flask API
            endpoint_map = {
                'status': ('GET', f'{LOCAL_SERVICE_CONTROL_URL}/api/service/status'),
                'start': ('POST', f'{LOCAL_SERVICE_CONTROL_URL}/api/service/start'),
                'stop': ('POST', f'{LOCAL_SERVICE_CONTROL_URL}/api/service/stop'),
                'restart': ('POST', f'{LOCAL_SERVICE_CONTROL_URL}/api/service/restart')
            }
        
            method, url = endpoint_map[action]
        
            print(f"Calling service control API: {action}")
        
            if method == 'GET':
                response = requests.get(url, timeout=90)
            else:
                # POST requests need password in JSON body
                print(f"DEBUG: Sending POST to {url}")
                print(f"DEBUG: Password value: {password}")
                print(f"DEBUG: Password type: {type(password)}")
                print(f"DEBUG: JSON payload: {{'password': password}}")
    
                response = requests.post(
                    url, 
                    json={'password': password},
                    timeout=90
                )
    
                print(f"DEBUG: Response status: {response.status_code}")
                print(f"DEBUG: Response text: {response.text}")
        
            if response.status_code == 200:
                result_data = response.json()
                return {
                    'type': 'service_control',
                    'action': action,
                    'success': result_data.get('success', True),
                    'data': result_data,
                    'message': result_data.get('message', f'{action} command executed')
                }
            else:
                return {
                    'type': 'service_control',
                    'action': action,
                    'error': f'HTTP {response.status_code}: {response.text}',
                    'success': False
                }
        
        except requests.exceptions.ConnectionError:
            return {
                'type': 'service_control',
                'error': 'Cannot connect to service control API on port 5001. Make sure the Flask app is running.',
                'success': False
            }
        except requests.exceptions.Timeout:
            return {
                'type': 'service_control',
                'error': 'Service control API timeout (90 seconds)',
                'success': False
            }
        except Exception as e:
            return {
                'type': 'service_control',
                'error': str(e),
                'success': False
            }
    
    def report_result(self, command_id, status, result):
        try:
            requests.post(
                f"{MANAGER_URL}/api/commands/result",
                json={
                    'command_id': command_id,
                    'status': status,
                    'result': result
                },
                headers=self.headers,
                timeout=10
            )
            print(f" Result reported: {status}")
        except Exception as e:
            print(f" Report failed: {e}")
    
    def run(self):
        print("=" * 60)
        print("RiskNoX Security Agent - Polling Service")
        print("=" * 60)
        print(f"Agent ID: {self.agent_id}")
        print(f"Hostname: {self.hostname}")
        print(f"Manager: {MANAGER_URL}")
        print(f"Local Backend: {LOCAL_BACKEND_URL}")
        print("=" * 60)
        
        if not self.register():
            print("Registration failed. Retrying in 30s...")
            time.sleep(30)
            return self.run()
        
        self.scan_monitor_running = True
        monitor_thread = threading.Thread(target=self.monitor_active_scans, daemon=True)
        monitor_thread.start()
        
        counter = 0
        print("\nPolling for commands...\n")
        
        while True:
            try:
                if counter % 5 == 0:
                    self.send_heartbeat()
                
                self.poll_commands()
                
                counter += 1
                time.sleep(POLL_INTERVAL)
                
            except KeyboardInterrupt:
                print("\n\nStopping agent...")
                self.scan_monitor_running = False
                monitor_thread.join(timeout=5)
                print("Agent stopped by user")
                break
            except Exception as e:
                print(f"Error: {e}")
                time.sleep(POLL_INTERVAL)

if __name__ == '__main__':
    agent = RiskNoXAgent()
    agent.run()

