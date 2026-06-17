<p align="center">
  <img src="https://img.shields.io/badge/Status-Active-success?style=for-the-badge" alt="Status" />
  <img src="https://img.shields.io/badge/Python-3.11+-blue?style=for-the-badge&logo=python" alt="Python" />
  <img src="https://img.shields.io/badge/TensorFlow-2.15+-orange?style=for-the-badge&logo=tensorflow" alt="TF" />
  <img src="https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge" alt="License" />
</p>

# 🛡️ Synops_Sec — NeuroShield

**AI-Powered Threat Detection & Autonomous Response Framework**

NeuroShield is an intelligent cybersecurity framework that leverages **neuromorphic computing** and **BiLSTM neural networks** for real-time threat detection, behavioral anomaly recognition, and automated incident response. It combines temporal pattern analysis with ensemble scoring to identify malware and suspicious activity without relying on predefined signatures.

---

## 🧠 Architecture

```
synops_sec/
├── api/                  # FastAPI backend + WebSocket server
│   ├── server.py         # Main API server (port 8000)
│   └── logs/             # Threat response logs
├── dashboard/            # Real-time monitoring dashboard
├── src/
│   ├── collectors/       # Data & telemetry collectors
│   ├── detector/         # Adaptive threat detection engine
│   ├── features/         # Behavioral feature extraction
│   ├── models/           # Trained BiLSTM models
│   ├── neuromorphic/     # Neuromorphic computing components
│   ├── responder/        # Automated threat response module
│   ├── main.py           # Integration demo pipeline
│   ├── train_model.py    # Model training script
│   ├── validate_model.py # Model validation & reporting
│   └── optimize_model.py # Quantization & pruning
├── forensics/            # Post-incident analysis tools
├── data/                 # Training & test datasets
├── models/               # Saved model artifacts
└── tests/                # Unit & property-based tests (Hypothesis)
```

---

## ✨ Key Features

| Feature | Description |
|---------|-------------|
| 🧬 **Self-Learning Detection** | Adapts to evolving attack patterns without signature updates |
| ⏳ **Temporal Pattern Recognition** | BiLSTM neural networks detect behavioral anomalies over time |
| ⚡ **Automated Response** | Prioritizes threats and triggers appropriate mitigation actions |
| 📊 **Real-Time Dashboard** | Live monitoring with WebSocket updates |
| 🧪 **Neuromorphic Computing** | Brain-inspired architectures for pattern matching |
| 📈 **Adaptive Thresholding** | Ensemble scoring with dynamic risk calibration |
| 🕵️ **Threat Intelligence** | Tracks, correlates, and learns from attack patterns |

---

## 🚀 Quick Start

### Prerequisites
- Python 3.11+
- Windows / Linux / macOS

### 1. Clone & Install
```bash
git clone https://github.com/kulshrestha-yash/synops_sec.git
cd synops_sec
pip install -r requirements.txt
```

### 2. Train the Model
```bash
cd src
python train_model.py
```
Trains the BiLSTM model on synthetic dataset (500 normal + 100 malware sequences) for 30 epochs. Saves to `models/temporal_engine.h5`.

### 3. Start the API Server
```bash
python api/server.py
```
Server starts at `http://127.0.0.1:8000`

### 4. Open the Dashboard
Navigate to: `http://127.0.0.1:8000/dashboard/`

### 5. Run Tests
```bash
pytest tests/ -v
```

### 6. Run Full Pipeline (Demo)
```bash
python src/main.py
```
Demonstrates: Load model → Analyze sequences → Trigger responder → Export threat intel.

---

## 🔧 Optional: Model Optimization
```bash
python src/validate_model.py   # Generate performance report
python src/optimize_model.py   # Quantization + pruning benchmarks
```

---

## 🛠️ Tech Stack

| Layer | Technology |
|-------|-----------|
| **ML Framework** | TensorFlow 2.15+, scikit-learn |
| **API Server** | FastAPI, Uvicorn, WebSockets |
| **Data** | NumPy, Pandas, scikit-learn |
| **System Monitoring** | psutil |
| **Testing** | pytest, Hypothesis (property-based) |
| **Dashboard** | HTML5, WebSocket live updates |

---

## 📄 Documentation

- [NeuroShield Guide](NEUROSHIELD_GUIDE.md) — Full feature walkthrough
- [Implementation Summary](IMPLEMENTATION_SUMMARY.md) — Architecture decisions
- [Backend Fixes](BACKEND_FIXES_SUMMARY.md) — Known issues & resolutions
- [Troubleshooting](TROUBLESHOOTING.md) — Common problems & fixes

---

## 👥 Contributors

| Name | GitHub | Email | Role |
|------|--------|-------|------|
| **Yash Kulshrestha** | [kulshrestha-yash](https://github.com/kulshrestha-yash) | yashkulshrestha76@gmail.com | Project Lead |
| **Yatharth Saini** | [Yatharth0143](https://github.com/Yatharth0143) | yatharthsaini52@gmail.com | Developer |
| **Rohit Kumar Jha** | [rohitpay1008-dot](https://github.com/rohitpay1008-dot) | rohitpay1008@gmail.com | Developer |
| **Roshan Kumar Jha** | [roshanjha1007-ctrl](https://github.com/roshanjha1007-ctrl) | roshanjha1007@gmail.com | Developer |

---

## 📝 License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

---

<p align="center">
  <sub>Built with ❤️ by the Synops_Sec Team</sub>
</p>
