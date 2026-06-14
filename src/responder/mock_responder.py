"""Mock security responder for dry-run threat response simulation."""

from datetime import datetime
from typing import Any


class MockResponder:
    """Simulates security response actions without executing real system commands.
    
    All methods return structured action records with DRY_RUN status showing
    what command would be executed. Useful for validating detection-to-response
    pipeline without affecting live systems.
    """

    def isolate_process(self, process_id: int | str, reason: str) -> dict[str, Any]:
        """Simulate immediate process isolation."""
        return {
            "status": "DRY_RUN",
            "action": "ISOLATE",
            "command": f"kill -STOP {process_id}",
            "reason": reason,
            "timestamp": datetime.now().isoformat(),
        }

    def suspend_and_analyze(self, process_id: int | str, reason: str) -> dict[str, Any]:
        """Simulate process suspension for forensic analysis."""
        return {
            "status": "DRY_RUN",
            "action": "SUSPEND",
            "command": f"docker pause container_{process_id}",
            "reason": reason,
            "timestamp": datetime.now().isoformat(),
        }

    def enhanced_monitoring(self, process_id: int | str, reason: str) -> dict[str, Any]:
        """Simulate enhanced monitoring activation."""
        return {
            "status": "DRY_RUN",
            "action": "MONITOR",
            "command": f"strace -p {process_id} -o /var/log/trace_{process_id}.log",
            "reason": reason,
            "timestamp": datetime.now().isoformat(),
        }

    def continue_monitoring(self, process_id: int | str) -> dict[str, Any]:
        """Simulate continuation of baseline monitoring."""
        return {
            "status": "DRY_RUN",
            "action": "CONTINUE",
            "command": "no action required",
            "reason": "Threat score below threshold",
            "timestamp": datetime.now().isoformat(),
        }

    def execute_action(
        self,
        action_type: str,
        process_id: int | str,
        reason: str = "Automated threat response",
    ) -> dict[str, Any]:
        """Route to appropriate response method based on action type."""
        action_map = {
            "IMMEDIATE_ISOLATION": self.isolate_process,
            "ISOLATE": self.isolate_process,
            "SUSPEND_AND_ANALYZE": self.suspend_and_analyze,
            "SUSPEND": self.suspend_and_analyze,
            "ENHANCED_MONITORING": self.enhanced_monitoring,
            "MONITOR": self.enhanced_monitoring,
            "CONTINUE_MONITORING": self.continue_monitoring,
            "CONTINUE": self.continue_monitoring,
        }
        
        handler = action_map.get(action_type, self.continue_monitoring)
        
        if action_type in ["CONTINUE_MONITORING", "CONTINUE"]:
            return handler(process_id)
        return handler(process_id, reason)
