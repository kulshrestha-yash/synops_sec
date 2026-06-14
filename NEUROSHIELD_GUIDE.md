# NeuroShield - AI-Powered Threat Detection & Response

## 🛡️ Overview

NeuroShield is an intelligent threat-response framework that autonomously prioritizes and mitigates cyber threats in real time using neuromorphic computing for temporal pattern recognition.

### Key Features

- **Self-Learning Malware Detection**: Adapts to evolving attack patterns without predefined signatures
- **Temporal Pattern Recognition**: Uses LSTM neural networks to detect behavioral anomalies
- **Automated Response**: Prioritizes threats and recommends appropriate mitigation actions
- **Real-Time Monitoring**: Live dashboard with WebSocket updates
- **Threat Intelligence**: Tracks and learns from attack patterns

## 🚀 Quick Start

### 1. Start the API Server

```bash
python api/server.py
```

The server will start on `http://127.0.0.1:8000`

### 2. Open the Dashboard

Navigate to: **http://127.0.0.1:8000/dashboard/**

### 3. Test Threat Detection

Use the built-in analyzer with sample sequences:
- **Ransomware Sample**: Tests encryption and file deletion patterns
- **Reverse Shell Sample**: Tests remote code execution patterns
- **Normal Activity Sample**: Tests baseline system behavior

## 📊 Dashboard Features

### System Overview
- **Total Analyzed**: Number of sequences processed
- **Threats Detected**: High-risk patterns identified
- **Detection Threshold**: Self-adjusting sensitivity (adapts based on feedback)
- **AI Adaptations**: Number of learning updates applied

### Threat Analyzer
- Input custom system call sequences
- Set context flags (privileged process, external connection, known safe)
- Get instant threat scores with recommended actions
- Visual threat bar showing severity

### Threat Timeline
- Real-time chart showing threat scores over time
- Automatically updated via WebSocket

### Recent Threats Table
- Prioritized queue of detected threats
- Shows timestamp, score, severity, and recommended action
- Sequence preview for quick analysis

### Response Playbook

#### 🔴 CRITICAL (Score ≥ 0.85)
- Immediate isolation
- Block all external IPs
- Collect forensic evidence
- Alert SIEM and security team

#### 🟠 HIGH (Score ≥ 0.72)
- Suspend suspicious process
- Analyze behavior patterns
- Enable intensive logging
- Prepare response plan

#### 🔵 MEDIUM (Score ≥ 0.60)
- Increase monitoring frequency
- Track associated processes
- Watch for threshold changes
- Log all network activity

#### 🟢 LOW (Score < 0.60)
- Maintain baseline monitoring
- Log standard events
- Update threat intelligence
- No immediate action required

## 🔧 Recent Improvements

### Bug Fixes
✅ Fixed detector return type consistency - `_determine_action` now returns proper dict structure
✅ Improved error handling in API server
✅ Fixed WebSocket connection stability

### Dashboard Redesign
✅ Modern, clean interface with intuitive navigation
✅ Color-coded threat levels for instant recognition
✅ Beginner-friendly explanations and contextual help
✅ Clear visual hierarchy with card-based layout
✅ Responsive design for mobile and desktop
✅ Comprehensive "How It Works" section
✅ Detailed response playbook documentation

### User Experience
✅ Sample sequences for quick testing
✅ Context flags with helpful descriptions
✅ Real-time result updates with visual feedback
✅ Threat bar visualization
✅ Live WebSocket streaming with fallback polling
✅ Status indicators for connection and mode

## 🧠 How It Works

### 1. Pattern Detection
Uses temporal neural networks (LSTM) to recognize malware behavior patterns without requiring predefined signatures. The system learns what malicious behavior looks like over time.

### 2. Self-Learning
Adapts detection thresholds based on:
- Prediction distribution drift
- False positive feedback
- Historical pattern evolution

### 3. Real-Time Response
Automatically prioritizes threats and recommends actions based on:
- **Ensemble scoring** (50% LSTM + 30% behavioral + 20% anomaly)
- **Context multipliers** (privilege level, network activity, known signatures)
- **Threat intelligence** (tracked attack patterns)

### 4. Threat Intelligence
Tracks attack signatures with:
- Frequency and trend analysis
- Related sequence mapping
- Confidence scoring
- Recommended response history

## 🎯 Detection Pipeline

```
System Calls → Feature Extraction → Temporal Analysis → Ensemble Scoring → 
Context Adjustment → Severity Classification → Automated Response
```

## 📋 API Endpoints

- `GET /` - API information
- `GET /health` - System health check
- `POST /analyze` - Analyze single sequence
- `POST /analyze/batch` - Analyze multiple sequences
- `GET /status` - Detection statistics
- `GET /threats` - Recent threat list
- `GET /events` - All analysis events
- `POST /feedback/false_positive` - Report false positive
- `WS /ws` - WebSocket live updates

## 🛠️ Technical Details

### ML Mode
When trained models are available in `/models` directory:
- `temporal_engine.h5` - LSTM model for pattern recognition
- `label_encoder.pkl` - System call encoder
- `detector_baseline.json` - Behavioral baseline

### Mock Mode
When ML models are unavailable, uses heuristic-based detection with:
- Keyword matching for suspicious calls
- Repetition scoring
- Context-based risk adjustment

## 📈 Performance

- **Real-time analysis**: < 50ms per sequence
- **Adaptive learning**: Adjusts every 100 predictions
- **Memory efficient**: Ring buffer with 1000-item history
- **Scalable**: Batch processing support

## 🔒 Security

- All responses are recommendations (dry-run mode by default)
- Threat intelligence tracking for pattern analysis
- False positive feedback loop for continuous improvement
- Forensic data collection for incident response

## 📝 Testing

Run verification tests:

```bash
python test_fixes.py
```

## 💡 Tips for Beginners

1. **Start with samples**: Use the built-in sample buttons to understand threat patterns
2. **Experiment with context**: Toggle context flags to see how they affect threat scores
3. **Watch the timeline**: Observe how threat scores change over time
4. **Check the playbook**: Understand what actions are recommended for each severity level
5. **Review recent threats**: Learn from detected patterns in the threats table

## 🎨 Color Scheme

- **Green (#10b981)**: Low severity - Safe
- **Blue (#3b82f6)**: Medium severity - Monitor
- **Orange (#f59e0b)**: High severity - Investigate
- **Red (#dc2626)**: Critical severity - Act immediately

## 📞 Support

For issues or questions, check:
- API health endpoint: `/health`
- Server logs for detailed diagnostics
- Dashboard connection status indicator

---

**NeuroShield v1.1.0** - Neuromorphic Threat Detection Framework
