"""
Mock API server for frontend development.
Use this when the real model isn't trained yet.
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Dict, Optional
import random
from datetime import datetime

app = FastAPI(title="NeuroShield API (MOCK)", version="mock-1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

class SequenceRequest(BaseModel):
    sequence: List[str]
    context: Optional[Dict] = None

# Mock state
mock_stats = {
    'total_scanned': 0,
    'threats_detected': 0,
    'false_positives': 0,
    'adaptations_made': 0
}
mock_threshold = 0.75
recent_threats = []

suspicious_keywords = ['encrypt', 'unlink', 'connect', 'execve', 'inject', 'hook', 'exfil']

@app.get("/")
async def root():
    return {
        "name": "NeuroShield API (MOCK)",
        "status": "operational",
        "features": ["temporal_pattern_analysis", "behavioral_detection", "automated_response", "self_learning"]
    }

@app.post("/analyze")
async def analyze_sequence(request: SequenceRequest):
    """Mock analysis - returns realistic threat scores"""
    global mock_stats
    mock_stats['total_scanned'] += 1
    
    # Simple heuristic for demo
    seq_str = ' '.join(request.sequence).lower()
    suspicious_count = sum(1 for kw in suspicious_keywords if kw in seq_str)
    
    base_score = 0.1
    base_score += suspicious_count * 0.15
    
    # Context boost
    if request.context:
        if request.context.get('is_privileged'):
            base_score *= 1.2
        if request.context.get('external_connection'):
            base_score *= 1.15
    
    threat_score = min(base_score + random.uniform(-0.05, 0.05), 0.99)
    is_threat = threat_score > mock_threshold
    
    if is_threat:
        mock_stats['threats_detected'] += 1
        threat_record = {
            'timestamp': datetime.now().isoformat(),
            'threat_score': threat_score,
            'is_threat': True,
            'recommended_action': {
                'action': 'IMMEDIATE_ISOLATION' if threat_score > 0.9 else 'SUSPEND_AND_ANALYZE' if threat_score > 0.8 else 'ENHANCED_MONITORING',
                'priority': 'CRITICAL' if threat_score > 0.9 else 'HIGH' if threat_score > 0.8 else 'MEDIUM'
            },
            'lstm_confidence': random.uniform(0.8, 0.99),
            'anomaly_score': random.uniform(0.3, 0.9)
        }
        recent_threats.append(threat_record)
    
    return {
        'timestamp': datetime.now().isoformat(),
        'threat_score': threat_score,
        'is_threat': is_threat,
        'recommended_action': {
            'action': 'IMMEDIATE_ISOLATION' if threat_score > 0.9 else 'SUSPEND_AND_ANALYZE' if threat_score > 0.8 else 'ENHANCED_MONITORING' if threat_score > 0.7 else 'CONTINUE_MONITORING',
            'priority': 'CRITICAL' if threat_score > 0.9 else 'HIGH' if threat_score > 0.8 else 'MEDIUM' if threat_score > 0.7 else 'LOW',
            'description': 'Mock detection result'
        },
        'lstm_confidence': random.uniform(0.7, 0.99),
        'anomaly_score': random.uniform(0.1, 0.8)
    }

@app.post("/analyze/batch")
async def analyze_batch(sequences: List[List[str]]):
    results = []
    for seq in sequences:
        result = await analyze_sequence(SequenceRequest(sequence=seq))
        results.append(result)
    return {"results": results, "total": len(results)}

@app.get("/status")
async def get_status():
    return {
        "status": "operational",
        "statistics": mock_stats,
        "threshold": mock_threshold,
        "adaptations": mock_stats['adaptations_made']
    }

@app.get("/threats")
async def get_threats(limit: int = 50):
    return recent_threats[-limit:]

@app.post("/feedback/false_positive")
async def report_false_positive(sequence: List[str]):
    mock_stats['false_positives'] += 1
    global mock_threshold
    if mock_stats['false_positives'] > 5:
        mock_threshold = min(0.85, mock_threshold + 0.02)
    return {"status": "feedback_recorded", "new_threshold": mock_threshold}

@app.post("/respond")
async def manual_response(threat_info: Dict):
    return {
        "timestamp": datetime.now().isoformat(),
        "actions_taken": [{"type": "MOCK_RESPONSE", "status": "SUCCESS"}],
        "dry_run": True
    }

if __name__ == "__main__":
    import uvicorn
    print("🧪 Starting MOCK API server for frontend development")
    print("   This server simulates AI responses without requiring TensorFlow")
    uvicorn.run(app, host="0.0.0.0", port=8000)