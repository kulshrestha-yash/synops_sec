// NeuroShield Cyber Dashboard

const API_BASE = localStorage.getItem("neuroshieldApiBase") || 
  (location.protocol.startsWith("http") ? location.origin : "http://127.0.0.1:8000");

// System calls library - expanded
const SYSCALLS = [
  // File Operations
  "open", "read", "write", "close", "stat", "fstat", "lstat", "lseek",
  "pread", "pwrite", "truncate", "ftruncate", "unlink", "rename",
  // Directory Operations
  "mkdir", "rmdir", "chdir", "getcwd", "opendir", "readdir", "closedir",
  // Process Operations
  "fork", "clone", "execve", "execvp", "exit", "wait", "waitpid", "kill",
  "getpid", "getppid", "setuid", "setgid",
  // Memory Operations
  "mmap", "munmap", "mprotect", "mlock", "munlock", "brk", "sbrk",
  // Network Operations
  "socket", "bind", "listen", "accept", "connect", "send", "recv",
  "sendto", "recvfrom", "shutdown", "setsockopt", "getsockopt",
  // IPC Operations
  "pipe", "dup", "dup2", "dup3", "select", "poll", "epoll_create",
  // File Descriptors
  "fcntl", "ioctl", "chmod", "chown", "fchmod", "fchown",
  // Crypto/Security
  "encrypt", "decrypt", "hash", "sign", "verify",
  // System Info
  "uname", "sysinfo", "getuid", "geteuid",
];

const PRESETS = {
  ransomware: ["open", "read", "encrypt", "write", "unlink", "open", "read", "encrypt", "write", "unlink"],
  shell: ["socket", "connect", "send", "recv", "execve", "dup2", "dup2", "fork"],
  normal: ["open", "read", "write", "close", "stat", "fstat"],
};

// State
const state = {
  sequence: [],
  threatHistory: [],
  chart: null,
};

// Audio
const sounds = {
  scan: document.getElementById("scanSound"),
  click: document.getElementById("clickSound"),
};

function playSound(sound) {
  try {
    if (sounds[sound]) {
      sounds[sound].volume = 1.0;
      sounds[sound].currentTime = 0;
      sounds[sound].play().catch(err => console.log('Audio play failed:', err));
    }
  } catch (e) {
    console.log('Sound error:', e);
  }
}

// Elements
const els = {
  connectionState: document.getElementById("connectionState"),
  connectionText: document.getElementById("connectionText"),
  modeValue: document.getElementById("modeValue"),
  totalAnalyzed: document.getElementById("totalAnalyzed"),
  threatsDetected: document.getElementById("threatsDetected"),
  threshold: document.getElementById("threshold"),
  adaptations: document.getElementById("adaptations"),
  tagLibrary: document.getElementById("tagLibrary"),
  tagContainer: document.getElementById("tagContainer"),
  clearBtn: document.getElementById("clearBtn"),
  privilegedInput: document.getElementById("privilegedInput"),
  externalInput: document.getElementById("externalInput"),
  knownGoodInput: document.getElementById("knownGoodInput"),
  analyzeBtn: document.getElementById("analyzeBtn"),
  resultsDisplay: document.getElementById("resultsDisplay"),
  scoreValue: document.getElementById("scoreValue"),
  threatFill: document.getElementById("threatFill"),
  severityBadge: document.getElementById("severityBadge"),
  actionText: document.getElementById("actionText"),
  threatTableBody: document.getElementById("threatTableBody"),
  threatChart: document.getElementById("threatChart"),
};

// Initialize tag library
function initTagLibrary() {
  els.tagLibrary.innerHTML = SYSCALLS.map(syscall => 
    `<button class="syscall-tag" data-syscall="${syscall}">${syscall}</button>`
  ).join('');
  
  els.tagLibrary.querySelectorAll('.syscall-tag').forEach(tag => {
    tag.addEventListener('click', () => {
      playSound('click');
      addToSequence(tag.dataset.syscall);
    });
  });
}

// Sequence management
function addToSequence(syscall) {
  state.sequence.push(syscall);
  renderSequence();
}

function removeFromSequence(index) {
  playSound('click');
  state.sequence.splice(index, 1);
  renderSequence();
}

function clearSequence() {
  playSound('click');
  state.sequence = [];
  renderSequence();
}

function renderSequence() {
  if (state.sequence.length === 0) {
    els.tagContainer.innerHTML = '<span class="placeholder-text">Click tags above to build sequence...</span>';
    return;
  }
  
  els.tagContainer.innerHTML = state.sequence.map((syscall, i) =>
    `<span class="sequence-tag">${syscall}<span class="remove" onclick="removeFromSequence(${i})">×</span></span>`
  ).join('');
}

// Make removeFromSequence global
window.removeFromSequence = removeFromSequence;

// Connection status
function setConnectionStatus(isOnline, text) {
  els.connectionState.classList.remove("online", "offline");
  els.connectionState.classList.add(isOnline ? "online" : "offline");
  els.connectionText.textContent = text;
}

// API calls
async function apiCall(endpoint, options = {}) {
  try {
    const response = await fetch(`${API_BASE}${endpoint}`, {
      headers: { "Content-Type": "application/json" },
      ...options,
    });
    if (!response.ok) throw new Error(`API Error: ${response.status}`);
    return await response.json();
  } catch (error) {
    console.error("API call failed:", error);
    setConnectionStatus(false, "OFFLINE");
    throw error;
  }
}

// Update statistics
function updateStats(data) {
  const stats = data.statistics || {};
  els.totalAnalyzed.textContent = stats.total_analyzed || stats.total_scanned || 0;
  els.threatsDetected.textContent = stats.threats_detected || 0;
  els.threshold.textContent = (data.threshold || 0.75).toFixed(3);
  els.adaptations.textContent = data.adaptations || stats.adaptations_made || 0;
  els.modeValue.textContent = (data.mode || "mock").toUpperCase();
}

// Display results
function displayResults(result) {
  playSound('scan');
  
  const score = Number(result.threat_score || 0);
  const action = result.recommended_action || {};
  const severity = result.severity || "LOW";
  
  els.scoreValue.textContent = score.toFixed(3);
  els.threatFill.style.width = `${score * 100}%`;
  
  // Color based on severity
  if (severity === "CRITICAL" || severity === "HIGH") {
    els.threatFill.style.background = "var(--cyber-danger)";
    els.threatFill.style.boxShadow = "0 0 10px var(--cyber-glow-red)";
  } else {
    els.threatFill.style.background = "var(--cyber-primary)";
    els.threatFill.style.boxShadow = "0 0 10px var(--cyber-glow)";
  }
  
  els.severityBadge.textContent = severity;
  els.severityBadge.className = `severity-badge ${severity.toLowerCase()}`;
  
  els.actionText.textContent = action.action || "CONTINUE_MONITORING";
  els.resultsDisplay.style.display = "block";
  
  state.threatHistory.push(score);
  if (state.threatHistory.length > 60) state.threatHistory.shift();
  
  updateChart();
}

// Initialize chart
function initChart() {
  if (!els.threatChart) return;
  
  const ctx = els.threatChart.getContext("2d");
  state.chart = new Chart(ctx, {
    type: "line",
    data: {
      labels: [],
      datasets: [{
        label: "THREAT SCORE",
        data: [],
        borderColor: "#00ff9f",
        backgroundColor: "rgba(0, 255, 159, 0.1)",
        borderWidth: 2,
        fill: true,
        tension: 0.4,
        pointRadius: 0,
        pointHoverRadius: 5,
        pointHoverBackgroundColor: "#00ff9f",
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: "rgba(10, 14, 39, 0.9)",
          titleColor: "#00ff9f",
          bodyColor: "#e0e7ff",
          borderColor: "#00ff9f",
          borderWidth: 1,
        }
      },
      scales: {
        y: {
          beginAtZero: true,
          max: 1,
          grid: { color: "#1a2744" },
          ticks: { color: "#8b92b8" }
        },
        x: {
          grid: { display: false },
          ticks: { display: false }
        }
      }
    }
  });
}

function updateChart() {
  if (!state.chart) return;
  state.chart.data.labels = state.threatHistory.map((_, i) => i);
  state.chart.data.datasets[0].data = state.threatHistory;
  state.chart.update("none");
}

// Update threats table
function updateThreatsTable(threats) {
  if (!threats || threats.length === 0) {
    els.threatTableBody.innerHTML = '<tr class="empty-row"><td colspan="5">// MONITORING FOR THREATS...</td></tr>';
    return;
  }
  
  const recent = threats.slice().reverse().slice(0, 15);
  els.threatTableBody.innerHTML = recent.map(threat => {
    const action = threat.recommended_action || {};
    const severity = threat.severity || "LOW";
    const time = threat.timestamp ? new Date(threat.timestamp).toLocaleTimeString() : "--";
    const seq = (threat.sequence || []).slice(0, 5).join(" ");
    
    return `
      <tr>
        <td>${time}</td>
        <td><strong>${Number(threat.threat_score || 0).toFixed(3)}</strong></td>
        <td><span class="severity-badge ${severity.toLowerCase()}">${severity}</span></td>
        <td>${action.action || "MONITOR"}</td>
        <td><code>${seq}...</code></td>
      </tr>
    `;
  }).join("");
}

// Context payload
function getContext() {
  return {
    is_privileged: els.privilegedInput.checked,
    privileged_process: els.privilegedInput.checked,
    external_connection: els.externalInput.checked,
    known_good: els.knownGoodInput.checked,
  };
}

// Analyze sequence
async function analyzeSequence() {
  if (state.sequence.length === 0) {
    alert("Build a sequence first!");
    return;
  }
  
  els.analyzeBtn.disabled = true;
  els.analyzeBtn.innerHTML = '<span>⚡ ANALYZING...</span>';
  
  try {
    const result = await apiCall("/analyze", {
      method: "POST",
      body: JSON.stringify({
        sequence: state.sequence,
        context: getContext(),
      }),
    });
    
    displayResults(result);
    await refreshDashboard();
    setConnectionStatus(true, "ONLINE");
  } catch (error) {
    alert("Analysis failed. Check connection.");
  } finally {
    els.analyzeBtn.disabled = false;
    els.analyzeBtn.innerHTML = '<span>⚡ ANALYZE THREAT</span>';
  }
}

// Refresh dashboard
async function refreshDashboard() {
  try {
    const [statusData, threatsData, eventsData] = await Promise.all([
      apiCall("/status"),
      apiCall("/threats?limit=30"),
      apiCall("/events?limit=60"),
    ]);
    
    updateStats(statusData);
    updateThreatsTable(threatsData);
    
    if (eventsData && eventsData.length > 0) {
      state.threatHistory = eventsData.map(e => Number(e.threat_score || 0)).slice(-60);
      updateChart();
    }
    
    setConnectionStatus(true, "ONLINE");
  } catch (error) {
    console.error("Refresh failed:", error);
  }
}

// WebSocket
function connectWebSocket() {
  if (!location.protocol.startsWith("http")) return;
  
  const wsBase = API_BASE.replace(/^http/, "ws");
  const ws = new WebSocket(`${wsBase}/ws`);
  
  ws.addEventListener("open", () => {
    setConnectionStatus(true, "LIVE");
  });
  
  ws.addEventListener("message", (event) => {
    try {
      const payload = JSON.parse(event.data);
      if (payload.type === "status_update") {
        if (payload.data) updateStats(payload.data);
        if (payload.threats) updateThreatsTable(payload.threats);
        if (payload.events && payload.events.length > 0) {
          state.threatHistory = payload.events.map(e => Number(e.threat_score || 0)).slice(-60);
          updateChart();
        }
      }
    } catch (error) {
      console.error("WebSocket message error:", error);
    }
  });
  
  ws.addEventListener("close", () => {
    setConnectionStatus(false, "RECONNECTING");
    setTimeout(connectWebSocket, 5000);
  });
}

// Event listeners
els.clearBtn.addEventListener("click", clearSequence);
els.analyzeBtn.addEventListener("click", analyzeSequence);

document.querySelectorAll(".btn-preset").forEach(btn => {
  btn.addEventListener("click", () => {
    playSound('click');
    const preset = btn.dataset.preset;
    if (PRESETS[preset]) {
      state.sequence = [...PRESETS[preset]];
      renderSequence();
    }
  });
});

// Initialize
async function init() {
  initTagLibrary();
  initChart();
  await refreshDashboard();
  connectWebSocket();
  setInterval(refreshDashboard, 10000);
}

init();
