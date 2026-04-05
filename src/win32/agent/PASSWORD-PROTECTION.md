# RiskNoX Service Control - Password Protection

## Overview

The RiskNoX Service Control system now includes password protection for critical operations (start, stop, restart). This ensures only authorized users can control the monitoring service.

## Default Password

**Default Password:** `RiskNoX@2024`

⚠️ **IMPORTANT:** Change the default password after installation!

## Password Storage

- Passwords are stored as SHA-256 hashes in `config/.service_password`
- The password file is automatically created on first use with the default password
- Passwords are never stored in plain text

## Using Password Protection

### Command Line (PowerShell)

#### Start Service with Password
```powershell
.\RiskNoXServiceControl.ps1 start -Password "YourPassword"
```

#### Stop Service with Password
```powershell
.\RiskNoXServiceControl.ps1 stop -Password "YourPassword"
```

#### Restart Service with Password
```powershell
.\RiskNoXServiceControl.ps1 restart -Password "YourPassword"
```

### Web Interface

1. Open the web interface at `http://localhost:5001`
2. Click **Start**, **Stop**, or **Restart** button
3. Enter password when prompted
4. The default password is shown in the prompt: `RiskNoX@2024`

## Changing the Password

### Method 1: Manual File Edit

1. Generate SHA-256 hash of your new password:
   ```powershell
   $newPassword = "YourNewPassword"
   $hash = Get-FileHash -InputStream ([System.IO.MemoryStream]::new([System.Text.Encoding]::UTF8.GetBytes($newPassword))) -Algorithm SHA256
   $hash.Hash
   ```

2. Save the hash to `config\.service_password`:
   ```powershell
   Set-Content -Path "config\.service_password" -Value $hash.Hash
   ```

### Method 2: Using PowerShell Function (Future Enhancement)

A password change command will be added in future versions:
```powershell
.\RiskNoXServiceControl.ps1 change-password -CurrentPassword "OldPassword" -NewPassword "NewPassword"
```

## Security Features

### Password Requirements

- Minimum length: 8 characters
- Recommended: Use strong passwords with mixed case, numbers, and symbols

### Hash Algorithm

- SHA-256 hashing ensures passwords cannot be recovered from the hash
- Each password attempt is hashed and compared against the stored hash

### Protected Operations

The following operations require password authentication:

- ✅ **Start Service** - Requires password
- ✅ **Stop Service** - Requires password AND admin privileges
- ✅ **Restart Service** - Requires password AND admin privileges
- ❌ **Status Check** - No password required (read-only)
- ❌ **Install** - No password required (first-time setup)
- ❌ **Configure** - No password required (agent enrollment)

## Error Messages

### "Password is required"
You must provide a password to start/stop/restart the service.

### "Incorrect password"
The password you entered doesn't match the stored password hash.

### "Administrator privileges required"
Stop and restart operations require running as Administrator, in addition to the password.

## API Integration

### Backend API Endpoints

All control endpoints now accept password in request body:

```javascript
// Start Service
POST /api/service/start
Content-Type: application/json
{
  "password": "YourPassword"
}

// Stop Service
POST /api/service/stop
Content-Type: application/json
{
  "password": "YourPassword"
}

// Restart Service
POST /api/service/restart
Content-Type: application/json
{
  "password": "YourPassword"
}
```

### Response Codes

Success response:
```json
{
  "success": true,
  "message": "Service start command issued successfully"
}
```

Password error:
```json
{
  "success": false,
  "error": "Incorrect password",
  "needs_password": true
}
```

## Best Practices

1. **Change Default Password Immediately**
   - Never use the default password in production
   - Change password right after installation

2. **Use Strong Passwords**
   - Minimum 12 characters recommended
   - Mix uppercase, lowercase, numbers, and symbols
   - Avoid dictionary words

3. **Secure Password Storage**
   - Don't write passwords in scripts
   - Don't commit passwords to version control
   - Use secure password managers

4. **Regular Password Rotation**
   - Change password periodically
   - Change immediately if compromised

5. **Access Control**
   - Limit who has access to the password
   - Use different passwords for different environments

## Troubleshooting

### Problem: Forgot Password

**Solution:** Reset the password file
```powershell
Remove-Item "config\.service_password" -Force
# The default password will be recreated on next use
```

### Problem: Password File Missing

**Solution:** It will be automatically recreated with default password on next start/stop attempt.

### Problem: Web Interface Not Prompting for Password

**Solution:** 
1. Clear browser cache
2. Refresh the page (Ctrl+F5)
3. Ensure backend is running on port 5001

### Problem: Password Works in PowerShell but Not in Web Interface

**Solution:**
1. Check backend logs: `logs\backend_error.log`
2. Ensure backend_server.py is updated and running
3. Verify API is accessible: `http://localhost:5001/health`

## Implementation Details

### Files Modified

1. **RiskNoXServiceControl.ps1**
   - Added `$Password` parameter
   - Added password validation functions
   - Updated `Invoke-Start` and `Invoke-Stop` functions

2. **service_control_backend.py**
   - Updated `start_service()` to accept password
   - Updated `stop_service()` to accept password
   - Updated `restart_service()` to accept password
   - Modified API endpoints to read password from request body

3. **web/service_control.html**
   - Added password prompts for start/stop/restart buttons
   - Updated API calls to include password in request body
   - Enhanced error handling for password errors

### Password Hash Storage

Location: `config/.service_password`

Format:
```
<SHA256_HASH_OF_PASSWORD>
```

Example:
```
5E884898DA28047151D0E56F8DC6292773603D0D6AABBDD62A11EF721D1542D8
```

## Support

For issues or questions:
1. Check logs in `logs/service-control.log`
2. Verify password file exists in `config/.service_password`
3. Test with default password after resetting

## Version History

- **v1.0** - Initial password protection implementation
  - SHA-256 password hashing
  - Default password: RiskNoX@2024
  - Web interface integration
  - PowerShell command-line support
