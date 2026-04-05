"""
Remote Control Authentication Module for Protected RiskNoX Supervisor Service

This module provides cryptographic validation for remote control commands
when the service is running with LocalSystem privileges and SDDL protection.

Usage:
    from remote_control_auth import RemoteControlAuth
    
    auth = RemoteControlAuth()
    
    if auth.validate_command(command, signature, source_ip):
        # Execute authorized command
        execute_service_control(command)
    else:
        # Log and reject
        log_unauthorized_attempt(source_ip)
"""

import os
import hmac
import hashlib
import time
import json
import logging
from pathlib import Path
from typing import Optional, Dict, Tuple
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


class RemoteControlAuth:
    """
    Handles authentication and validation of remote control commands
    for the protected RiskNoX Supervisor service.
    """
    
    def __init__(self, config_dir: Optional[Path] = None, 
                 max_age_seconds: int = 300,
                 rate_limit_window: int = 60,
                 max_requests_per_window: int = 10):
        """
        Initialize remote control authentication.
        
        Args:
            config_dir: Directory containing supervisor_token.txt
            max_age_seconds: Maximum age of command timestamp (default 5 minutes)
            rate_limit_window: Rate limit window in seconds (default 60s)
            max_requests_per_window: Max requests per window (default 10)
        """
        if config_dir is None:
            # Default to config directory relative to this script
            base_dir = Path(__file__).parent.parent
            config_dir = base_dir / "config"
        
        self.config_dir = Path(config_dir)
        self.token_file = self.config_dir / "supervisor_token.txt"
        self.max_age_seconds = max_age_seconds
        
        # Rate limiting
        self.rate_limit_window = rate_limit_window
        self.max_requests_per_window = max_requests_per_window
        self.request_history: Dict[str, list] = {}
        
        # Load token
        self._token = self._load_token()
        
        # Audit log
        self.audit_log = self.config_dir.parent / "logs" / "remote_control_audit.log"
        self._setup_audit_logging()
    
    def _load_token(self) -> Optional[bytes]:
        """Load the authentication token from file."""
        try:
            if not self.token_file.exists():
                logger.error(f"Token file not found: {self.token_file}")
                logger.error("Run: .\\tools\\protect_service.ps1 -AllowRemoteControl")
                return None
            
            with open(self.token_file, 'r') as f:
                token_str = f.read().strip()
            
            # Token should be base64 encoded
            import base64
            token_bytes = base64.b64decode(token_str)
            
            logger.info("Remote control token loaded successfully")
            return token_bytes
        
        except Exception as e:
            logger.error(f"Failed to load token: {e}")
            return None
    
    def _setup_audit_logging(self):
        """Setup audit logging for remote control attempts."""
        try:
            self.audit_log.parent.mkdir(parents=True, exist_ok=True)
            
            # Create separate audit logger
            audit_logger = logging.getLogger('remote_control_audit')
            audit_logger.setLevel(logging.INFO)
            
            # File handler for audit log
            handler = logging.FileHandler(self.audit_log)
            handler.setFormatter(logging.Formatter(
                '%(asctime)s - %(levelname)s - %(message)s'
            ))
            audit_logger.addHandler(handler)
            
        except Exception as e:
            logger.warning(f"Could not setup audit logging: {e}")
    
    def _log_audit(self, event_type: str, details: Dict):
        """Log audit event."""
        try:
            audit_logger = logging.getLogger('remote_control_audit')
            audit_entry = {
                'timestamp': datetime.utcnow().isoformat(),
                'event': event_type,
                **details
            }
            audit_logger.info(json.dumps(audit_entry))
        except Exception as e:
            logger.warning(f"Could not write audit log: {e}")
    
    def _check_rate_limit(self, source_ip: str) -> bool:
        """
        Check if source IP is within rate limits.
        
        Args:
            source_ip: Source IP address
            
        Returns:
            True if within limits, False if rate limited
        """
        now = time.time()
        
        # Clean old entries
        if source_ip in self.request_history:
            self.request_history[source_ip] = [
                ts for ts in self.request_history[source_ip]
                if now - ts < self.rate_limit_window
            ]
        else:
            self.request_history[source_ip] = []
        
        # Check limit
        if len(self.request_history[source_ip]) >= self.max_requests_per_window:
            return False
        
        # Record this request
        self.request_history[source_ip].append(now)
        return True
    
    def validate_command(self, command: str, signature: str, 
                        source_ip: str = "unknown",
                        timestamp: Optional[int] = None,
                        allowed_ips: Optional[list] = None) -> bool:
        """
        Validate a remote control command.
        
        Args:
            command: The command to execute (e.g., "stop", "restart", "status")
            signature: HMAC-SHA256 signature of the command
            source_ip: Source IP address
            timestamp: Unix timestamp of when command was issued
            allowed_ips: List of allowed source IPs (optional whitelist)
            
        Returns:
            True if command is valid and authorized, False otherwise
        """
        
        # Check if token is loaded
        if self._token is None:
            self._log_audit("DENIED", {
                "reason": "No token configured",
                "source_ip": source_ip,
                "command": command
            })
            return False
        
        # Check IP whitelist if provided
        if allowed_ips is not None and source_ip not in allowed_ips:
            self._log_audit("DENIED", {
                "reason": "IP not whitelisted",
                "source_ip": source_ip,
                "command": command
            })
            return False
        
        # Check rate limit
        if not self._check_rate_limit(source_ip):
            self._log_audit("DENIED", {
                "reason": "Rate limit exceeded",
                "source_ip": source_ip,
                "command": command
            })
            return False
        
        # Check timestamp if provided (replay attack prevention)
        if timestamp is not None:
            now = int(time.time())
            age = abs(now - timestamp)
            
            if age > self.max_age_seconds:
                self._log_audit("DENIED", {
                    "reason": f"Timestamp too old ({age}s)",
                    "source_ip": source_ip,
                    "command": command,
                    "timestamp": timestamp
                })
                return False
        
        # Verify HMAC signature
        try:
            # Decode signature from hex
            signature_bytes = bytes.fromhex(signature)
            
            # Compute expected signature
            message = command.encode('utf-8')
            if timestamp is not None:
                message = f"{command}:{timestamp}".encode('utf-8')
            
            expected_sig = hmac.new(
                self._token,
                message,
                hashlib.sha256
            ).digest()
            
            # Constant-time comparison to prevent timing attacks
            if not hmac.compare_digest(signature_bytes, expected_sig):
                self._log_audit("DENIED", {
                    "reason": "Invalid signature",
                    "source_ip": source_ip,
                    "command": command
                })
                return False
            
            # All checks passed
            self._log_audit("ALLOWED", {
                "source_ip": source_ip,
                "command": command,
                "timestamp": timestamp
            })
            return True
        
        except Exception as e:
            logger.error(f"Signature validation error: {e}")
            self._log_audit("ERROR", {
                "reason": f"Validation error: {str(e)}",
                "source_ip": source_ip,
                "command": command
            })
            return False
    
    def generate_signature(self, command: str, 
                          timestamp: Optional[int] = None) -> str:
        """
        Generate a signature for a command (for testing/client use).
        
        Args:
            command: The command to sign
            timestamp: Unix timestamp (will use current time if not provided)
            
        Returns:
            Hex-encoded HMAC-SHA256 signature
        """
        if self._token is None:
            raise ValueError("Token not loaded")
        
        if timestamp is None:
            timestamp = int(time.time())
        
        message = f"{command}:{timestamp}".encode('utf-8')
        signature = hmac.new(self._token, message, hashlib.sha256).digest()
        
        return signature.hex()
    
    def is_configured(self) -> bool:
        """Check if remote control is properly configured."""
        return self._token is not None


# Example usage and testing
if __name__ == "__main__":
    # Setup logging for testing
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    print("RiskNoX Remote Control Authentication Test")
    print("=" * 60)
    
    # Initialize auth
    auth = RemoteControlAuth()
    
    if not auth.is_configured():
        print("\n❌ Remote control not configured!")
        print("Run: .\\tools\\protect_service.ps1 -AllowRemoteControl")
        exit(1)
    
    print("\n✅ Remote control token loaded successfully")
    
    # Test command signing and validation
    print("\n--- Test 1: Valid Command ---")
    command = "stop"
    timestamp = int(time.time())
    signature = auth.generate_signature(command, timestamp)
    
    print(f"Command: {command}")
    print(f"Timestamp: {timestamp}")
    print(f"Signature: {signature}")
    
    is_valid = auth.validate_command(
        command=command,
        signature=signature,
        source_ip="127.0.0.1",
        timestamp=timestamp
    )
    
    print(f"Validation Result: {'✅ VALID' if is_valid else '❌ INVALID'}")
    
    # Test invalid signature
    print("\n--- Test 2: Invalid Signature ---")
    invalid_sig = "0" * 64  # Wrong signature
    
    is_valid = auth.validate_command(
        command=command,
        signature=invalid_sig,
        source_ip="127.0.0.1",
        timestamp=timestamp
    )
    
    print(f"Validation Result: {'✅ VALID' if is_valid else '❌ INVALID (Expected)'}")
    
    # Test old timestamp
    print("\n--- Test 3: Old Timestamp (Replay Attack) ---")
    old_timestamp = int(time.time()) - 400  # 400 seconds ago (> max_age)
    old_signature = auth.generate_signature(command, old_timestamp)
    
    is_valid = auth.validate_command(
        command=command,
        signature=old_signature,
        source_ip="127.0.0.1",
        timestamp=old_timestamp
    )
    
    print(f"Validation Result: {'✅ VALID' if is_valid else '❌ INVALID (Expected)'}")
    
    # Test rate limiting
    print("\n--- Test 4: Rate Limiting ---")
    source_ip = "192.168.1.100"
    
    for i in range(12):
        timestamp = int(time.time())
        signature = auth.generate_signature("status", timestamp)
        
        is_valid = auth.validate_command(
            command="status",
            signature=signature,
            source_ip=source_ip,
            timestamp=timestamp
        )
        
        print(f"Request {i+1}: {'✅' if is_valid else '❌ Rate Limited'}")
    
    print("\n--- Test 5: IP Whitelist ---")
    allowed_ips = ["127.0.0.1", "192.168.1.50"]
    
    timestamp = int(time.time())
    signature = auth.generate_signature("restart", timestamp)
    
    # From allowed IP
    is_valid = auth.validate_command(
        command="restart",
        signature=signature,
        source_ip="127.0.0.1",
        timestamp=timestamp,
        allowed_ips=allowed_ips
    )
    print(f"From allowed IP (127.0.0.1): {'✅ VALID' if is_valid else '❌ INVALID'}")
    
    # From disallowed IP
    is_valid = auth.validate_command(
        command="restart",
        signature=signature,
        source_ip="10.0.0.1",
        timestamp=timestamp,
        allowed_ips=allowed_ips
    )
    print(f"From blocked IP (10.0.0.1): {'✅ VALID' if is_valid else '❌ INVALID (Expected)'}")
    
    print("\n" + "=" * 60)
    print("✅ All tests completed!")
    print(f"Check audit log: {auth.audit_log}")
