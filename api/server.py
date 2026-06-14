from __future__ import annotations

import asyncio
import random
import sys
import time
import webbrowser
from datetime import datetime
from pathlib import Path
from typing import Any

import uvicorn
from fastapi import BackgroundTasks, FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = PROJECT_ROOT / "src"
DASHBOARD_DIR = PROJECT_ROOT / "dashboard"
LOG_DIR = PROJECT_ROOT / "api" / "logs"
FORENSICS_DIR = PROJECT_ROOT / "forensics"

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

try:
    from integration_helper import create_detector_from_model, load_production_model
    from responder.threat_responder import ThreatResponder

    ML_MODULES_AVAILABLE = True
    ML_IMPORT_ERROR = None
except Exception as exc:  # pragma: no cover - startup reports this in health
    ThreatResponder = None
    ML_MODULES_AVAILABLE = False
    ML_IMPORT_ERROR = str(exc)


app = FastAPI(title="SynOps API", version="1.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

if DASHBOARD_DIR.exists():
    app.mount("/dashboard", StaticFiles(directory=DASHBOARD_DIR, html=True), name="dashboard")


@app.middleware("http")
async def log_requests(request, call_next):
    start = time.time()
    response = await call_next(request)
    duration = time.time() - start
    print(f"{request.method} {request.url.path} - {response.status_code} - {duration:.3f}s")
    return response


engine = None
detector = None
responder = None
runtime_mode = "mock"
startup_errors: list[str] = []
active_connections: list[WebSocket] = []

mock_stats = {
    "total_analyzed": 0,
    "total_scanned": 0,
    "threats_detected": 0,
    "false_positives": 0,
    "adaptations_made": 0,
}
mock_threshold = 0.75
recent_threats: list[dict[str, Any]] = []
recent_analyses: list[dict[str, Any]] = []

SUSPICIOUS_KEYWORDS = {
    "encrypt",
    "unlink",
    "connect",
    "execve",
    "inject",
    "hook",
    "exfil",
    "mprotect",
    "mmap",
    "pack",
    "obfuscate",
}


class SequenceRequest(BaseModel):
    sequence: list[str]
    context: dict[str, Any] | None = None


class BatchSequenceRequest(BaseModel):
    sequences: list[list[str]]
    context: dict[str, Any] | None = None


class ThreatResponse(BaseModel):
    timestamp: str
    threat_score: float
    is_threat: bool
    recommended_action: dict[str, Any]
    confidence: float
    severity: str
    anomaly_score: float | None = None


def _priority_for_score(score: float) -> str:
    if score >= 0.85:
        return "CRITICAL"
    if score >= 0.72:
        return "HIGH"
    if score >= 0.6:
        return "MEDIUM"
    return "LOW"


def _action_for_score(score: float) -> str:
    if score >= 0.85:
        return "IMMEDIATE_ISOLATION"
    if score >= 0.72:
        return "SUSPEND_AND_ANALYZE"
    if score >= 0.6:
        return "ENHANCED_MONITORING"
    return "CONTINUE_MONITORING"


def _normalize_context(context: dict[str, Any] | None) -> dict[str, Any]:
    normalized = dict(context or {})
    if normalized.get("is_privileged") and "privileged_process" not in normalized:
        normalized["privileged_process"] = True
    return normalized


def _action_payload(action: str, score: float, description: str) -> dict[str, Any]:
    return {
        "action": action,
        "priority": _priority_for_score(score),
        "description": description,
    }


def _normalize_detection_result(result: dict[str, Any], sequence: list[str]) -> dict[str, Any]:
    score = float(result.get("threat_score", 0.0))
    severity = result.get("severity") or _priority_for_score(score)
    action = result.get("recommended_action") or _action_for_score(score)

    if isinstance(action, str):
        action = _action_payload(
            action,
            score,
            "Adaptive temporal detector recommendation",
        )
    else:
        action = {
            "action": action.get("action", _action_for_score(score)),
            "priority": action.get("priority", severity),
            "description": action.get("description", "Threat-response recommendation"),
        }

    return {
        "timestamp": result.get("timestamp", datetime.now().isoformat()),
        "threat_score": score,
        "is_threat": bool(result.get("is_threat", score >= mock_threshold)),
        "recommended_action": action,
        "confidence": float(result.get("lstm_confidence", result.get("confidence", score))),
        "severity": severity,
        "anomaly_score": result.get("anomaly_score"),
        "sequence": sequence,
    }


def _mock_analyze(sequence: list[str], context: dict[str, Any] | None = None) -> dict[str, Any]:
    mock_stats["total_analyzed"] += 1
    mock_stats["total_scanned"] += 1

    seq_str = " ".join(sequence).lower()
    suspicious_count = sum(1 for keyword in SUSPICIOUS_KEYWORDS if keyword in seq_str)
    repeated_risk = max(0, len(sequence) - len(set(sequence))) / max(len(sequence), 1)
    base_score = 0.12 + suspicious_count * 0.11 + repeated_risk * 0.18

    normalized_context = _normalize_context(context)
    if normalized_context.get("privileged_process"):
        base_score *= 1.2
    if normalized_context.get("external_connection"):
        base_score *= 1.15
    if normalized_context.get("known_good"):
        base_score *= 0.5

    threat_score = max(0.0, min(base_score + random.uniform(-0.03, 0.03), 0.99))
    is_threat = threat_score >= mock_threshold
    if is_threat:
        mock_stats["threats_detected"] += 1

    result = {
        "timestamp": datetime.now().isoformat(),
        "threat_score": threat_score,
        "is_threat": is_threat,
        "recommended_action": _action_payload(
            _action_for_score(threat_score),
            threat_score,
            "Heuristic fallback result; trained temporal model unavailable",
        ),
        "lstm_confidence": min(0.99, 0.55 + threat_score * 0.4),
        "anomaly_score": min(1.0, suspicious_count / max(len(SUSPICIOUS_KEYWORDS), 1) + repeated_risk),
        "severity": _priority_for_score(threat_score),
    }
    return _normalize_detection_result(result, sequence)


def _record_analysis(result: dict[str, Any]) -> None:
    recent_analyses.append(result)
    del recent_analyses[:-100]

    if result["is_threat"]:
        recent_threats.append(result)
        del recent_threats[:-100]


@app.on_event("startup")
async def startup():
    global engine, detector, responder, runtime_mode

    try:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        FORENSICS_DIR.mkdir(parents=True, exist_ok=True)
    except Exception as exc:
        error_msg = f"Failed to create directories: {type(exc).__name__}: {exc}"
        startup_errors.append(error_msg)
        print(f"\nERROR: {error_msg}\n")

    try:
        if ThreatResponder is not None:
            responder = ThreatResponder(dry_run=True, log_dir=LOG_DIR, forensics_dir=FORENSICS_DIR)
        else:
            startup_errors.append(f"Responder unavailable: {ML_IMPORT_ERROR}")
    except Exception as exc:
        error_msg = f"Responder initialization failed: {type(exc).__name__}: {exc}"
        startup_errors.append(error_msg)
        print(f"\nWARNING: {error_msg}\n")

    if not ML_MODULES_AVAILABLE:
        runtime_mode = "mock"
        startup_errors.append(f"WARNING: ML modules unavailable: {ML_IMPORT_ERROR}")
        print(f"\nWARNING: Running in mock mode due to missing ML dependencies.")
        print("   Install TensorFlow to enable real-time ML threat detection.\n")
        return

    model_path = PROJECT_ROOT / "models" / "temporal_engine.h5"
    encoder_path = PROJECT_ROOT / "models" / "label_encoder.pkl"
    baseline_path = PROJECT_ROOT / "models" / "detector_baseline.json"

    try:
        if not model_path.exists():
            raise FileNotFoundError(f"Model file not found: {model_path}")
        if not encoder_path.exists():
            raise FileNotFoundError(f"Label encoder not found: {encoder_path}")
        if not baseline_path.exists():
            raise FileNotFoundError(f"Baseline config not found: {baseline_path}")

        print(f"Loading temporal engine from {model_path}...")
        engine = load_production_model(model_path, encoder_path)
        print(f"[OK] Temporal engine loaded successfully")

        print(f"Creating detector from baseline {baseline_path}...")
        detector = create_detector_from_model(engine, baseline_path)
        print(f"[OK] Detector initialized successfully")

        runtime_mode = "ml"
        print(f"\n[OK] SynOps running in ML MODE with trained models\n")
    except FileNotFoundError as exc:
        detector = None
        runtime_mode = "mock"
        error_msg = f"Model files missing: {exc}"
        startup_errors.append(error_msg)
        print(f"\nWARNING: {error_msg}")
        print("   Ensure model files exist in /models directory.\n")
    except ImportError as exc:
        detector = None
        runtime_mode = "mock"
        error_msg = f"TensorFlow not available: {exc}"
        startup_errors.append(error_msg)
        print(f"\nWARNING: {error_msg}")
        print("   Install TensorFlow: pip install tensorflow>=2.15.0\n")
    except Exception as exc:
        detector = None
        runtime_mode = "mock"
        error_msg = f"ML initialization failed: {type(exc).__name__}: {exc}"
        startup_errors.append(error_msg)
        print(f"\nWARNING: {error_msg}")
        print("   Using heuristic-based mock detection.\n")


def _generate_demo_data():
    """Demo data generation removed - start with clean UI."""
    pass


@app.get("/")
async def root():
    return {
        "name": "SynOps API",
        "version": "1.1.0",
        "status": "operational",
        "mode": runtime_mode,
        "dashboard": "/dashboard/",
        "features": [
            "temporal_pattern_analysis",
            "behavioral_detection",
            "automated_response",
            "self_learning",
        ],
    }


@app.get("/health")
async def health_check():
    ml_status = "operational" if runtime_mode == "ml" and detector else "fallback"
    overall_status = "healthy" if responder or detector else "degraded"

    return {
        "status": overall_status,
        "timestamp": datetime.now().isoformat(),
        "version": "1.1.0",
        "mode": runtime_mode,
        "ml_enabled": runtime_mode == "ml",
        "model_loaded": detector is not None,
        "ml_mode_active": runtime_mode == "ml",
        "components": {
            "detector": {
                "status": "ready" if detector else "mock",
                "mode": runtime_mode,
                "description": "ML-based temporal threat detection" if detector else "Heuristic fallback detection",
            },
            "responder": {
                "status": "ready" if responder else "down",
                "description": "Automated threat response system" if responder else "Response module unavailable",
            },
            "dashboard": {
                "status": "mounted" if DASHBOARD_DIR.exists() else "missing",
                "path": "/dashboard/" if DASHBOARD_DIR.exists() else None,
            },
        },
        "startup_errors": startup_errors if startup_errors else [],
        "message": "All systems operational" if not startup_errors else "Running with fallback components",
    }


@app.post("/analyze", response_model=ThreatResponse)
async def analyze_sequence(request: SequenceRequest):
    try:
        if not request.sequence:
            raise HTTPException(status_code=400, detail="Sequence cannot be empty")

        normalized_context = _normalize_context(request.context)
        if runtime_mode == "ml" and detector is not None:
            raw_result = detector.analyze_sequence(request.sequence, normalized_context)
            result = _normalize_detection_result(raw_result, request.sequence)
        else:
            result = _mock_analyze(request.sequence, normalized_context)

        _record_analysis(result)
        return ThreatResponse(**result)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Analysis failed: {type(exc).__name__}: {str(exc)}",
        )


@app.post("/analyze/batch")
async def analyze_batch(request: BatchSequenceRequest | list[list[str]]):
    try:
        if isinstance(request, list):
            sequences = request
            context = None
        else:
            sequences = request.sequences
            context = request.context

        if not sequences:
            raise HTTPException(status_code=400, detail="Sequences list cannot be empty")

        results = []
        for sequence in sequences:
            try:
                results.append(await analyze_sequence(SequenceRequest(sequence=sequence, context=context)))
            except HTTPException as exc:
                if exc.status_code == 400:
                    raise
                raise HTTPException(
                    status_code=500,
                    detail=f"Failed to analyze sequence: {exc.detail}",
                )

        return {"results": [result.model_dump() for result in results], "total": len(results)}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Batch analysis failed: {type(exc).__name__}: {str(exc)}",
        )


@app.get("/status")
async def get_status():
    if runtime_mode == "ml" and detector is not None:
        stats = detector.get_stats()
        stats["total_scanned"] = stats.get("total_analyzed", 0)
        stats["adaptations_made"] = detector.detection_stats["adaptations_made"]
        return {
            "status": "operational",
            "mode": "ml",
            "statistics": stats,
            "threshold": detector.confidence_threshold,
            "adaptations": detector.detection_stats["adaptations_made"],
            "recent_count": len(getattr(detector, "recent_results", [])),
        }

    return {
        "status": "operational",
        "mode": "mock",
        "statistics": mock_stats,
        "threshold": mock_threshold,
        "adaptations": mock_stats["adaptations_made"],
        "recent_count": len(recent_analyses),
    }


@app.get("/threats")
async def get_threats(limit: int = 50):
    if runtime_mode == "ml" and detector is not None:
        ml_results = list(getattr(detector, "recent_results", []))
        threats = [
            _normalize_detection_result(result, result.get("sequence", []))
            for result in ml_results
            if result.get("is_threat")
        ]
        return threats[-limit:]

    return recent_threats[-limit:]


@app.get("/events")
async def get_events(limit: int = 100):
    return recent_analyses[-limit:]


@app.post("/feedback/false_positive")
async def report_false_positive(sequence: list[str]):
    global mock_threshold

    if runtime_mode == "ml" and detector is not None:
        detector.report_false_positive(sequence)
        return {"status": "feedback_recorded", "new_threshold": detector.confidence_threshold}

    mock_stats["false_positives"] += 1
    if mock_stats["false_positives"] > 5:
        mock_threshold = min(0.9, mock_threshold + 0.02)
        mock_stats["adaptations_made"] += 1
    return {"status": "feedback_recorded", "new_threshold": mock_threshold}


@app.post("/respond")
async def manual_response(threat_info: dict[str, Any], background_tasks: BackgroundTasks):
    if responder:
        result = responder.execute_response(threat_info, threat_info.get("target", {}))
        return result
    raise HTTPException(status_code=503, detail="Responder not available")


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    active_connections.append(websocket)
    try:
        while True:
            try:
                status = await get_status()
                await websocket.send_json(
                    {
                        "type": "status_update",
                        "data": status,
                        "threats": await get_threats(limit=10),
                        "events": await get_events(limit=20),
                    }
                )
            except Exception as exc:
                try:
                    await websocket.send_json(
                        {
                            "type": "error",
                            "error": f"Status update failed: {type(exc).__name__}",
                            "message": str(exc),
                        }
                    )
                except Exception:
                    break
            await asyncio.sleep(2)
    except WebSocketDisconnect:
        pass
    except Exception as exc:
        try:
            await websocket.send_json(
                {
                    "type": "error",
                    "error": "WebSocket connection error",
                    "message": f"{type(exc).__name__}: {str(exc)}",
                }
            )
        except Exception:
            pass
    finally:
        if websocket in active_connections:
            active_connections.remove(websocket)


if __name__ == "__main__":
    import threading
    
    def open_browser():
        time.sleep(2)
        webbrowser.open("http://127.0.0.1:8000/dashboard/")
    
    threading.Thread(target=open_browser, daemon=True).start()
    uvicorn.run(app, host="127.0.0.1", port=8000)
