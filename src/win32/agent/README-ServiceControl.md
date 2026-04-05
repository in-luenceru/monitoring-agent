# RiskNoX Service Control Web Interface

A simple web-based interface to control the RiskNoXSupervisor Windows service.

## Overview

This service control backend runs on **port 5001** (separate from the main agent backend on port 5000) and provides a clean web interface to:

- **Start** the RiskNoXSupervisor service
- **Stop** the service (requires administrator privileges)
- **Restart** the service
- **View real-time status** of the service and managed processes
- **Monitor** backend_server, monitoring_agent, and suricata processes

## Quick Start

### Method 1: Using PowerShell Script (Recommended)

```powershell
# Start the service control backend
.\start_service_control.ps1
```

Then open your browser to: **http://localhost:5001**

### Method 2: Direct Python Execution

```powershell
# Make sure you're in the monitoring-agent-windows directory
cd c:\Users\ANANDHU\Downloads\monitoring-agent-windows

# Install dependencies (if not already installed)
pip install flask flask-cors

# Start the backend
python service_control_backend.py
```

Then open your browser to: **http://localhost:5001**

## Features

### 🎯 Service Control
- **Start Service**: Launch the RiskNoXSupervisor service
- **Stop Service**: Gracefully stop the service (admin required)
- **Restart Service**: Quick restart of the service (admin required)
- **Auto-refresh**: Status updates every 10 seconds

### 📊 Real-time Monitoring
- Service status (Running/Stopped)
- Service configuration (Name, Type, Display Name)
- Process status for:
  - Backend Server (Python Flask API)
  - Monitoring Agent (Wazuh agent)
  - Suricata IDS

### 🔒 Security
- Administrator privileges required for stop/restart operations
- Uses the official RiskNoXServiceControl.ps1 script
- Secure service protection handling

## API Endpoints

The backend exposes the following REST API endpoints:

### Health Check
```
GET /health
```
Returns server status and basic information.

### Get Service Status
```
GET /api/service/status
```
Returns current service status and managed process information.

### Start Service
```
POST /api/service/start
```
Issues a start command to the RiskNoXSupervisor service.

### Stop Service
```
POST /api/service/stop
```
Stops the RiskNoXSupervisor service (requires admin privileges).

### Restart Service
```
POST /api/service/restart
```
Restarts the RiskNoXSupervisor service (requires admin privileges).

## Architecture

```
┌─────────────────────────────────────────┐
│   Web Browser (localhost:5001)         │
│   - Service Control Interface           │
│   - Real-time Status Display            │
└────────────────┬────────────────────────┘
                 │
                 │ HTTP/REST API
                 │
┌────────────────▼────────────────────────┐
│   Service Control Backend (Port 5001)  │
│   - Flask API Server                    │
│   - PowerShell Integration              │
│   - Service Management                  │
└────────────────┬────────────────────────┘
                 │
                 │ Invokes
                 │
┌────────────────▼────────────────────────┐
│   RiskNoXServiceControl.ps1             │
│   - Official service control script     │
│   - Handles SDDL protection             │
│   - Service operations                  │
└────────────────┬────────────────────────┘
                 │
                 │ Manages
                 │
┌────────────────▼────────────────────────┐
│   RiskNoXSupervisor (Windows Service)  │
│   - Supervises all processes            │
│   - Backend Server (port 5000)          │
│   - Monitoring Agent                    │
│   - Suricata IDS                        │
└─────────────────────────────────────────┘
```

## Important Notes

### Administrator Privileges
- **Starting** the service does NOT require admin privileges
- **Stopping** or **restarting** requires administrator privileges
- If you try to stop/restart without admin, you'll get a warning message

### Service Protection
The RiskNoXSupervisor service has protection enabled by default:
- Runs as LocalSystem (highest privileges)
- Protected by SDDL to prevent normal administrator stops
- This control interface uses the official script to bypass protection

### Port Configuration
- **Port 5001**: Service Control Backend (this application)
- **Port 5000**: Main Agent Backend (RiskNoX API)
- **Port 8765**: Supervisor Control API

Make sure port 5001 is not blocked by your firewall.

## Troubleshooting

### Backend Won't Start
```powershell
# Check if Python is installed
python --version

# Check if port 5001 is already in use
netstat -ano | findstr :5001

# Install dependencies
pip install flask flask-cors
```

### Service Control Not Working
```powershell
# Verify the control script exists
Test-Path .\RiskNoXServiceControl.ps1

# Check service status manually
.\RiskNoXServiceControl.ps1 status

# Run as administrator for stop/restart
Start-Process powershell -Verb RunAs -ArgumentList "-File `"$PWD\start_service_control.ps1`""
```

### Cannot Stop Service
This is expected behavior due to service protection. Solutions:
1. Use this web interface (it uses the official control script)
2. Run PowerShell as administrator
3. Use: `.\RiskNoXServiceControl.ps1 stop`

## Integration Options

### Option 1: Standalone Service Control (Current)
Run this service control backend separately on port 5001.
- **Pros**: Clean separation, dedicated control interface
- **Cons**: Two separate backends to manage

### Option 2: Integrate into Main Backend (Alternative)
You can integrate these endpoints into the main `backend_server.py` on port 5000:

1. Add the `ServiceController` class to `backend_server.py`
2. Add the service control routes to the main Flask app
3. Add a service control section to the main web interface

**Note**: The main backend doesn't need to run for service control to work, making the standalone approach cleaner.

## Running Both Backends

To run both the main agent backend and service control:

```powershell
# Terminal 1: Start main agent backend (if needed)
.\start_backend.ps1

# Terminal 2: Start service control backend
.\start_service_control.ps1
```

Or start the service control only:
```powershell
.\start_service_control.ps1
```

The service control backend works independently and doesn't require the main agent to be running.

## Files

- `service_control_backend.py` - Flask backend server (port 5001)
- `web/service_control.html` - Web interface
- `start_service_control.ps1` - Startup script
- `README-ServiceControl.md` - This documentation

## Support

For issues or questions:
1. Check the service status: `.\RiskNoXServiceControl.ps1 status`
2. View logs: `logs\service-control.log`
3. Verify service exists: `Get-Service RiskNoXSupervisor`

## License

Part of the RiskNoX Monitoring Agent project.
