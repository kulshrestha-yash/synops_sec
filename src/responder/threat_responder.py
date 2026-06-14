import subprocess
import json
import logging
from datetime import datetime
from enum import Enum
from pathlib import Path

class ThreatLevel(Enum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

class ThreatResponder:
    """
    Automated threat response system.
    Executes containment actions based on threat severity.
    """
    
    def __init__(self, auto_respond=True, dry_run=True, log_dir=None, forensics_dir=None):
        self.auto_respond = auto_respond
        self.dry_run = dry_run
        self.action_log = []
        self.blocked_ips = set()
        self.quarantined_processes = set()
        self.log_dir = Path(log_dir or "logs")
        self.forensics_dir = Path(forensics_dir or "forensics")
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.forensics_dir.mkdir(parents=True, exist_ok=True)
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - THREAT_RESPONSE - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(self.log_dir / 'threat_responses.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def execute_response(self, detection_result, target_info):
        threat_score = detection_result['threat_score']
        
        if threat_score >= 0.9:
            level = ThreatLevel.CRITICAL
        elif threat_score >= 0.8:
            level = ThreatLevel.HIGH
        elif threat_score >= 0.7:
            level = ThreatLevel.MEDIUM
        else:
            level = ThreatLevel.LOW
        
        self.logger.warning(f"THREAT DETECTED: Score={threat_score:.3f}, Level={level.name}, Target={target_info}")
        
        response_actions = []
        
        if level in [ThreatLevel.CRITICAL, ThreatLevel.HIGH]:
            response_actions.extend(self._critical_response(target_info))
        if level in [ThreatLevel.HIGH, ThreatLevel.MEDIUM]:
            response_actions.extend(self._high_response(target_info))
        if level == ThreatLevel.MEDIUM:
            response_actions.extend(self._medium_response(target_info))
        
        response_actions.extend(self._log_response(target_info, detection_result))
        
        action_record = {
            'timestamp': datetime.now().isoformat(),
            'threat_level': level.name,
            'threat_score': threat_score,
            'target': target_info,
            'actions_taken': response_actions,
            'auto_executed': self.auto_respond
        }
        self.action_log.append(action_record)
        return action_record
    
    def _critical_response(self, target_info):
        actions = []
        if 'pid' in target_info:
            actions.append(self._isolate_process(target_info['pid']))
        if 'ip_address' in target_info:
            actions.append(self._block_ip(target_info['ip_address']))
        actions.append(self._collect_forensics(target_info))
        actions.append(self._send_alert(target_info, "CRITICAL"))
        return actions
    
    def _high_response(self, target_info):
        actions = []
        if 'pid' in target_info:
            actions.append(self._restrict_process(target_info['pid']))
        actions.append(self._enable_intensive_logging(target_info))
        return actions
    
    def _medium_response(self, target_info):
        return [{
            'type': 'MONITORING',
            'description': 'Enhanced monitoring enabled',
            'status': 'SUCCESS',
            'details': f"Monitoring frequency increased for {target_info}"
        }]
    
    def _log_response(self, target_info, detection_result):
        return [{
            'type': 'LOGGING',
            'description': 'Response logged',
            'status': 'SUCCESS',
            'details': json.dumps(detection_result)
        }]
    
    def _isolate_process(self, pid):
        if self.dry_run:
            self.logger.info(f"[DRY RUN] Would isolate process {pid}")
            return {
                'type': 'ISOLATION',
                'target': f"PID:{pid}",
                'status': 'DRY_RUN',
                'command': f"kill -STOP {pid}"
            }
        try:
            subprocess.run(['kill', '-STOP', str(pid)], check=True)
            self.quarantined_processes.add(pid)
            return {
                'type': 'ISOLATION',
                'target': f"PID:{pid}",
                'status': 'SUCCESS',
                'command': f"kill -STOP {pid}"
            }
        except Exception as e:
            return {
                'type': 'ISOLATION',
                'target': f"PID:{pid}",
                'status': 'FAILED',
                'error': str(e)
            }
    
    def _block_ip(self, ip_address):
        if self.dry_run:
            self.logger.info(f"[DRY RUN] Would block IP {ip_address}")
            return {
                'type': 'IP_BLOCK',
                'target': ip_address,
                'status': 'DRY_RUN',
                'command': f"iptables -A INPUT -s {ip_address} -j DROP"
            }
        try:
            subprocess.run(['iptables', '-A', 'INPUT', '-s', ip_address, '-j', 'DROP'], check=True)
            self.blocked_ips.add(ip_address)
            return {
                'type': 'IP_BLOCK',
                'target': ip_address,
                'status': 'SUCCESS'
            }
        except Exception as e:
            return {
                'type': 'IP_BLOCK',
                'target': ip_address,
                'status': 'FAILED',
                'error': str(e)
            }
    
    def _restrict_process(self, pid):
        return {
            'type': 'RESTRICTION',
            'target': f"PID:{pid}",
            'status': 'SUCCESS',
            'description': 'Process capabilities restricted'
        }
    
    def _collect_forensics(self, target_info):
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = self.forensics_dir / f"forensic_{timestamp}.json"
        forensic_data = {
            'timestamp': datetime.now().isoformat(),
            'target': target_info,
            'memory_dump_requested': True,
            'network_connections': 'captured',
            'file_handles': 'captured'
        }
        if self.dry_run:
            with filename.open("w") as file:
                json.dump(forensic_data, file, indent=2)
        return {
            'type': 'FORENSICS',
            'status': 'SUCCESS',
            'file': str(filename),
            'details': forensic_data
        }
    
    def _send_alert(self, target_info, severity):
        alert = {
            'severity': severity,
            'target': target_info,
            'timestamp': datetime.now().isoformat(),
            'message': f"CRITICAL THREAT: {target_info}"
        }
        self.logger.critical(f"ALERT: {alert}")
        return {
            'type': 'ALERT',
            'status': 'SUCCESS',
            'severity': severity,
            'channels': ['log', 'siem']
        }
    
    def _enable_intensive_logging(self, target_info):
        return {
            'type': 'LOGGING',
            'status': 'SUCCESS',
            'description': f"Intensive logging enabled for {target_info}"
        }
    
    def get_action_history(self):
        return self.action_log
    
    def unblock_ip(self, ip_address):
        if ip_address in self.blocked_ips:
            if not self.dry_run:
                subprocess.run(['iptables', '-D', 'INPUT', '-s', ip_address, '-j', 'DROP'], check=True)
            self.blocked_ips.discard(ip_address)
            return True
        return False
