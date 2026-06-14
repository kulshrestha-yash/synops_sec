import psutil
import time
import threading
from collections import deque
from datetime import datetime

class RealTimeSystemMonitor:
    """
    Real-time system behavior monitoring.
    Collects process events, network activity, and file system operations.
    """
    
    def __init__(self, buffer_size=1000):
        self.buffer_size = buffer_size
        self.event_buffer = deque(maxlen=buffer_size)
        self.network_buffer = deque(maxlen=buffer_size)
        self.is_running = False
        self.monitor_thread = None
        self.callbacks = []
        
        # Process tracking
        self.known_processes = {}
        self.suspicious_patterns = [
            'crypt', 'encrypt', ' ransom', 'inject', 'hook',
            'keylog', 'screenshot', 'exfil'
        ]
    
    def start_monitoring(self, interval=1.0):
        """Start real-time monitoring in background thread"""
        self.is_running = True
        self.monitor_thread = threading.Thread(target=self._monitoring_loop, args=(interval,))
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        print(f"🔍 Real-time monitoring started (interval: {interval}s)")
    
    def stop_monitoring(self):
        """Stop monitoring"""
        self.is_running = False
        if self.monitor_thread:
            self.monitor_thread.join()
        print("⏹️  Monitoring stopped")
    
    def _monitoring_loop(self, interval):
        """Main monitoring loop"""
        while self.is_running:
            try:
                self._collect_process_events()
                self._collect_network_events()
                self._detect_new_processes()
                time.sleep(interval)
            except Exception as e:
                # Only print error once per minute to avoid spam
                if not hasattr(self, '_last_error_time') or time.time() - self._last_error_time > 60:
                    print(f"Monitoring error: {e}")
                    self._last_error_time = time.time()
    
    def _collect_process_events(self):
        """Collect process behavior events"""
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
            try:
                pinfo = proc.info
                event = {
                    'timestamp': datetime.now().isoformat(),
                    'type': 'PROCESS',
                    'pid': pinfo['pid'],
                    'name': pinfo['name'],
                    'cpu_percent': pinfo['cpu_percent'],
                    'memory_percent': pinfo['memory_percent'],
                    'event_type': self._classify_process_event(pinfo)
                }
                self.event_buffer.append(event)
                for callback in self.callbacks:
                    callback(event)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    
    def _collect_network_events(self):
        """Collect network activity"""
        try:
            connections = psutil.net_connections()
            for conn in connections:
                if conn.status == 'ESTABLISHED':
                    event = {
                        'timestamp': datetime.now().isoformat(),
                        'type': 'NETWORK',
                        'local_addr': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                        'remote_addr': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                        'status': conn.status,
                        'pid': conn.pid
                    }
                    self.network_buffer.append(event)
        except Exception:
            pass
    
    def _detect_new_processes(self):
        """Detect newly spawned processes"""
        current_processes = {p.pid: p.info for p in psutil.process_iter(['pid', 'name', 'create_time'])}
        for pid, info in current_processes.items():
            if pid not in self.known_processes:
                self.known_processes[pid] = info
                proc_name = info['name'].lower()
                is_suspicious = any(pattern in proc_name for pattern in self.suspicious_patterns)
                if is_suspicious:
                    event = {
                        'timestamp': datetime.now().isoformat(),
                        'type': 'SUSPICIOUS_PROCESS',
                        'pid': pid,
                        'name': info['name'],
                        'severity': 'HIGH'
                    }
                    self.event_buffer.append(event)
    
    def _classify_process_event(self, pinfo):
        """Classify process behavior into event types"""
        name = pinfo['name'].lower()
        if any(x in name for x in ['chrome', 'firefox', 'safari']):
            return 'BROWSER'
        elif any(x in name for x in ['ssh', 'telnet', 'ftp']):
            return 'NETWORK_TOOL'
        elif any(x in name for x in ['python', 'node', 'java']):
            return 'RUNTIME'
        elif any(x in name for x in ['bash', 'sh', 'zsh', 'cmd', 'powershell']):
            return 'SHELL'
        else:
            return 'GENERIC'
    
    def register_callback(self, callback):
        """Register callback for real-time event processing"""
        self.callbacks.append(callback)
    
    def get_recent_events(self, n=100):
        """Get recent events from buffer"""
        return list(self.event_buffer)[-n:]
    
    def get_event_stream(self):
        """Generator for real-time event streaming"""
        last_index = 0
        while self.is_running:
            current_length = len(self.event_buffer)
            if current_length > last_index:
                new_events = list(self.event_buffer)[last_index:current_length]
                for event in new_events:
                    yield event
                last_index = current_length
            time.sleep(0.1)