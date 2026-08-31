// =============================================================================
// AETHERIS Demo Data Engine
// Generates realistic simulated network traffic, forecasts, alerts
// for standalone preview without a backend.
// =============================================================================

const HOSTS = [
  { ip: "192.168.1.10", name: "Gateway Router", department: "Infrastructure", criticality: "CRITICAL", role: "gateway" },
  { ip: "192.168.1.20", name: "Public Web Server", department: "Engineering", criticality: "HIGH", role: "server" },
  { ip: "192.168.1.30", name: "Finance DB Server", department: "Finance", criticality: "CRITICAL", role: "database" },
  { ip: "192.168.1.40", name: "Dev Workstation", department: "Engineering", criticality: "MEDIUM", role: "workstation" },
  { ip: "192.168.1.50", name: "HR File Server", department: "HR", criticality: "MEDIUM", role: "server" },
  { ip: "192.168.1.60", name: "Backup NAS", department: "IT", criticality: "HIGH", role: "storage" },
  { ip: "192.168.1.70", name: "Email Server", department: "IT", criticality: "HIGH", role: "server" },
  { ip: "192.168.1.80", name: "Printer/Scanner", department: "Admin", criticality: "LOW", role: "printer" },
  { ip: "10.0.0.101", name: "Attacker Box", department: "External", criticality: "NONE", role: "attacker" },
  { ip: "10.0.0.102", name: "Botnet Node #3", department: "External", criticality: "NONE", role: "attacker" },
];

const ATTACK_STAGES = ["Normal", "Reconnaissance", "Initial Access", "Lateral Movement", "Command & Control", "Exfiltration"];

const MITRE_TECHNIQUES = {
  Normal: [],
  Reconnaissance: ["T1046 - Network Service Discovery", "T1595 - Active Scanning", "T1018 - Remote System Discovery"],
  "Initial Access": ["T1190 - Exploit Public-Facing App", "T1133 - External Remote Services", "T1566 - Phishing"],
  "Lateral Movement": ["T1021 - Remote Services", "T1550 - Use Alternate Auth", "T1570 - Lateral Tool Transfer"],
  "Command & Control": ["T1071 - Application Layer Protocol", "T1573 - Encrypted Channel", "T1105 - Ingress Tool Transfer"],
  Exfiltration: ["T1041 - Exfil Over C2 Channel", "T1567 - Exfil Over Web Service", "T1048 - Exfil Over Alt Protocol"],
};

const SEVERITY_MAP = {
  Normal: "none",
  Reconnaissance: "low",
  "Initial Access": "medium",
  "Lateral Movement": "high",
  "Command & Control": "high",
  Exfiltration: "critical",
};

const STAGE_COLORS = {
  Normal: "#22c55e",
  Reconnaissance: "#38bdf8",
  "Initial Access": "#f59e0b",
  "Lateral Movement": "#f97316",
  "Command & Control": "#ef4444",
  Exfiltration: "#ff0055",
};

const STAGE_INDEX = {
  Normal: 10,
  Reconnaissance: 30,
  "Initial Access": 50,
  "Lateral Movement": 70,
  "Command & Control": 85,
  Exfiltration: 95,
};

// Feature importance for explainability
const FEATURE_IMPORTANCE = [
  { name: "Port Entropy", value: 0.92, description: "Shannon entropy of destination ports - high values indicate port scanning" },
  { name: "SYN Ratio", value: 0.87, description: "Proportion of SYN flags in TCP packets - spike indicates scan/exploit attempt" },
  { name: "IAT Variance", value: 0.81, description: "Inter-arrival time variance - sudden drops suggest automated tooling" },
  { name: "Failed Connection Rate", value: 0.78, description: "Rate of failed connection attempts - high values indicate brute force" },
  { name: "Connection Rate", value: 0.73, description: "Connections per second - abnormal spikes indicate DDoS or scanning" },
  { name: "Unique Dst Ports", value: 0.69, description: "Number of distinct destination ports contacted" },
  { name: "Packet Size Variance", value: 0.64, description: "Variance in packet sizes - low may indicate tunneling" },
  { name: "Inbound/Outbound Ratio", value: 0.58, description: "Ratio of inbound to outbound traffic" },
  { name: "RST Ratio", value: 0.52, description: "Reset flag ratio - high values indicate rejected connections" },
  { name: "Mean IAT", value: 0.47, description: "Average inter-arrival time between packets" },
];

// Model performance data
const MODEL_BENCHMARKS = [
  { model: "Static LR (Baseline)", precision: 0.944, recall: 0.944, f1: 0.944, fpr: 5.56, mae: null, rmse: null, color: "#64748b" },
  { model: "Temporal LR (Baseline B)", precision: 0.942, recall: 0.907, f1: 0.925, fpr: 5.56, mae: null, rmse: null, color: "#94a3b8" },
  { model: "LSTM World Model", precision: 0.944, recall: 0.944, f1: 0.944, fpr: 5.56, mae: 0.386, rmse: 0.657, color: "#00f0ff" },
  { model: "Temporal GNN World Model", precision: 0.944, recall: 0.944, f1: 0.944, fpr: 5.56, mae: 0.336, rmse: 0.634, color: "#9d4edd" },
];

// K-step forecast data generator
function generateRolloutData(currentStage) {
  const stageIdx = ATTACK_STAGES.indexOf(currentStage);
  const steps = 6;
  const scenarios = {
    do_nothing: [],
    rate_limit: [],
    block_port: [],
    isolate_host: [],
  };

  for (let t = 0; t < steps; t++) {
    const base = Math.min(0.95, 0.2 + stageIdx * 0.15 + t * 0.08);
    // Deterministic curves (no Math.random) so the chart doesn't jitter on re-render
    const jitter = (t * 0.007) % 0.05; // tiny stable offset per step
    scenarios.do_nothing.push({ threat: base + jitter, step: `T+${(t + 1) * 5}s` });
    scenarios.rate_limit.push({ threat: Math.max(0.1, base - t * 0.06 + jitter * 0.6), step: `T+${(t + 1) * 5}s` });
    scenarios.block_port.push({ threat: Math.max(0.05, base - t * 0.1 + jitter * 0.6), step: `T+${(t + 1) * 5}s` });
    scenarios.isolate_host.push({ threat: Math.max(0.02, base - t * 0.14 - 0.1 + jitter * 0.4), step: `T+${(t + 1) * 5}s` });
  }
  return scenarios;
}

// Simulate progressive attack over time
let tick = 0;
let currentAttackPhase = 0;
const PHASE_DURATIONS = [25, 15, 10, 8, 8, 6]; // ticks per stage

function getSimulatedHostState(hostIp) {
  const hash = hostIp.split("").reduce((a, c) => a + c.charCodeAt(0), 0);
  const phaseOffset = hash % 3;

  // External attacker hosts are always in attack mode
  if (hostIp.startsWith("10.0.0.")) {
    const attIdx = Math.floor((tick / 8) % ATTACK_STAGES.length);
    return ATTACK_STAGES[Math.min(attIdx + 1, ATTACK_STAGES.length - 1)];
  }

  const adjustedTick = (tick + phaseOffset * 20) % 80;
  let accumulated = 0;
  for (let i = 0; i < PHASE_DURATIONS.length; i++) {
    accumulated += PHASE_DURATIONS[i];
    if (adjustedTick < accumulated) return ATTACK_STAGES[i];
  }
  return "Normal";
}

function generateTrafficEvent(hosts) {
  tick++;
  const srcIdx = Math.floor(Math.random() * hosts.length);
  const dstIdx = (srcIdx + 1 + Math.floor(Math.random() * (hosts.length - 1))) % hosts.length;
  const src = hosts[srcIdx];
  const dst = hosts[dstIdx];
  const stage = getSimulatedHostState(dst.ip);
  const isAttacker = src.role === "attacker";

  const protocols = ["TCP", "UDP", "ICMP"];
  const proto = protocols[Math.floor(Math.random() * 3)];

  return {
    id: `evt-${tick}-${Date.now()}`,
    timestamp: new Date().toISOString(),
    srcIp: src.ip,
    dstIp: dst.ip,
    srcPort: Math.floor(Math.random() * 60000) + 1024,
    dstPort: [80, 443, 22, 3306, 5432, 3389, 8080, 445, 135][Math.floor(Math.random() * 9)],
    protocol: proto,
    duration: +(Math.random() * 5 + 0.01).toFixed(3),
    packetCount: Math.floor(Math.random() * 500) + 1,
    byteCount: Math.floor(Math.random() * 150000) + 64,
    synCount: proto === "TCP" ? Math.floor(Math.random() * 10) : 0,
    ackCount: proto === "TCP" ? Math.floor(Math.random() * 20) : 0,
    rstCount: proto === "TCP" ? Math.floor(Math.random() * 5) : 0,
    finCount: proto === "TCP" ? Math.floor(Math.random() * 5) : 0,
    portDanger: isAttacker ? +(Math.random() * 0.8 + 0.2).toFixed(2) : +(Math.random() * 0.3).toFixed(2),
    severity: isAttacker ? SEVERITY_MAP[stage] : "none",
    attackType: isAttacker ? (stage === "Reconnaissance" ? "Port Scan" : stage === "Initial Access" ? "Exploit Attempt" : "Data Theft") : "Benign",
    stage,
  };
}

function generateForecast(hostIp) {
  const stage = getSimulatedHostState(hostIp);
  const confidence = stage === "Normal" ? +(Math.random() * 0.1 + 0.85).toFixed(3) : +(Math.random() * 0.25 + 0.65).toFixed(3);

  return {
    hostIp,
    predictedStage: stage,
    confidence: parseFloat(confidence),
    mitreTechniques: MITRE_TECHNIQUES[stage] || [],
    stageIndex: STAGE_INDEX[stage],
    color: STAGE_COLORS[stage],
    severity: SEVERITY_MAP[stage],
    timestamp: new Date().toISOString(),
    riskScore: stage === "Normal" ? Math.random() * 0.1 : 0.3 + Math.random() * 0.6,
  };
}

function generateAlert(hostIp, forecast) {
  if (forecast.predictedStage === "Normal") return null;
  return {
    _id: `alert-${Date.now()}-${Math.floor(Math.random() * 10000)}`,
    timestamp: new Date().toISOString(),
    hostIp,
    predictedStage: forecast.predictedStage,
    confidence: forecast.confidence,
    severity: forecast.severity.toUpperCase(),
    mitreTechniques: forecast.mitreTechniques,
    blockchainTxHash: `0x${Array.from({ length: 64 }, () => "0123456789abcdef"[Math.floor(Math.random() * 16)]).join("")}`,
    mitigationSuggested: forecast.predictedStage === "Exfiltration" ? "ISOLATE_HOST" : forecast.predictedStage === "Lateral Movement" ? "BLOCK_PORTS" : "RATE_LIMIT",
  };
}

// State vector feature names (23-dim from CyberForecaster)
const STATE_FEATURES = [
  "total_packets", "total_bytes", "unique_src_ips", "unique_dst_ips", "unique_dst_ports",
  "tcp_ratio", "udp_ratio", "syn_ratio", "ack_ratio", "rst_ratio", "fin_ratio",
  "mean_packet_size", "packet_size_variance", "mean_IAT", "IAT_variance", "max_IAT",
  "retransmission_rate", "ttl_mean", "ttl_variance", "inbound_outbound_ratio",
  "failed_connection_rate", "port_entropy", "connection_rate",
];

function generateStateVector() {
  return STATE_FEATURES.map((name) => ({
    name,
    value: +(Math.random()).toFixed(4),
    previousValue: +(Math.random()).toFixed(4),
  }));
}

// Timeline history for charts
function generateTimelineHistory(hostIp, steps = 20) {
  const history = [];
  const baseStageIdx = ATTACK_STAGES.indexOf(getSimulatedHostState(hostIp));

  for (let i = 0; i < steps; i++) {
    const t = steps - i;
    const idx = Math.max(0, baseStageIdx - Math.floor(t / 4));
    const risk = Math.max(0.05, 0.1 + idx * 0.12 + Math.random() * 0.08 - i * 0.01);
    history.unshift({
      time: `T-${(i + 1) * 5}s`,
      risk: +Math.min(0.99, risk).toFixed(3),
      stageIdx: idx,
      stage: ATTACK_STAGES[idx],
    });
  }
  return history;
}

// Network state transition probability matrix
const TRANSITION_PROBS = [
  [0.70, 0.15, 0.10, 0.03, 0.02, 0.00], // Normal
  [0.05, 0.50, 0.30, 0.10, 0.05, 0.00], // Recon
  [0.02, 0.05, 0.40, 0.35, 0.13, 0.05], // Initial Access
  [0.01, 0.01, 0.05, 0.45, 0.35, 0.13], // Lateral
  [0.01, 0.01, 0.02, 0.06, 0.50, 0.40], // C2
  [0.00, 0.00, 0.01, 0.02, 0.10, 0.87], // Exfil
];

export {
  HOSTS,
  ATTACK_STAGES,
  MITRE_TECHNIQUES,
  SEVERITY_MAP,
  STAGE_COLORS,
  STAGE_INDEX,
  FEATURE_IMPORTANCE,
  MODEL_BENCHMARKS,
  STATE_FEATURES,
  generateRolloutData,
  getSimulatedHostState,
  generateTrafficEvent,
  generateForecast,
  generateAlert,
  generateStateVector,
  generateTimelineHistory,
  TRANSITION_PROBS,
};
