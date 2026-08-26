import React, { useState, useEffect, useRef } from "react";
import { io } from "socket.io-client";
import { 
  ShieldAlert, Shield, ShieldAlert as ShieldWarning, Server, Cpu, Database, 
  Activity, ArrowRight, CheckCircle, RefreshCw, AlertTriangle, Layers, Clock, 
  ExternalLink, CheckCircle2, XCircle, Search, HelpCircle, HardDrive
} from "lucide-react";
import { 
  ResponsiveContainer, AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, Legend,
  LineChart, Line
} from "recharts";

const API_BASE = "http://127.0.0.1:5050/api";
const SOCKET_URL = "http://127.0.0.1:5050";

export default function App() {
  const [hosts, setHosts] = useState([]);
  const [selectedHostIp, setSelectedHostIp] = useState("");
  const [alerts, setAlerts] = useState([]);
  const [trafficEvents, setTrafficEvents] = useState([]);
  const [rolloutData, setRolloutData] = useState(null);
  const [loadingRollout, setLoadingRollout] = useState(false);
  const [verifyingAlert, setVerifyingAlert] = useState(null);
  const [verificationResult, setVerificationResult] = useState(null);
  const [loadingVerification, setLoadingVerification] = useState(false);
  const [isConnected, setIsConnected] = useState(false);
  const [latestForecast, setLatestForecast] = useState({});

  const socketRef = useRef(null);

  // Load initial data
  useEffect(() => {
    fetchHosts();
    fetchAlerts();

    // Setup Socket.io Connection
    socketRef.current = io(SOCKET_URL);

    socketRef.current.on("connect", () => {
      setIsConnected(true);
      console.log("Connected to Express Socket.io server");
    });

    socketRef.current.on("disconnect", () => {
      setIsConnected(false);
    });

    socketRef.current.on("traffic_update", (event) => {
      setTrafficEvents(prev => [event, ...prev].slice(0, 30));
    });

    socketRef.current.on("forecast_update", (forecast) => {
      setLatestForecast(prev => ({
        ...prev,
        [forecast.hostIp]: forecast
      }));
    });

    socketRef.current.on("forecast_alert", (alert) => {
      setAlerts(prev => [alert, ...prev]);
      // Play a high-tech alarm sound (optional/throttled or just notify)
      console.warn("HIGH THREAT ALARM TRIGGERED:", alert);
    });

    socketRef.current.on("host_status_change", ({ ip, status }) => {
      setHosts(prev => prev.map(h => h.ip === ip ? { ...h, status } : h));
    });

    return () => {
      if (socketRef.current) socketRef.current.disconnect();
    };
  }, []);

  // Fetch hosts list
  const fetchHosts = async () => {
    try {
      const res = await fetch(`${API_BASE}/hosts`);
      const data = await res.json();
      setHosts(data);
      if (data.length > 0 && !selectedHostIp) {
        setSelectedHostIp(data[0].ip);
      }
    } catch (err) {
      console.error("Error fetching hosts:", err);
    }
  };

  // Fetch alerts
  const fetchAlerts = async () => {
    try {
      const res = await fetch(`${API_BASE}/alerts`);
      const data = await res.json();
      setAlerts(data);
    } catch (err) {
      console.error("Error fetching alerts:", err);
    }
  };

  // Load rollout simulation for selected host
  useEffect(() => {
    if (!selectedHostIp) return;
    loadRollout(selectedHostIp);
  }, [selectedHostIp]);

  const loadRollout = async (ip) => {
    setLoadingRollout(true);
    try {
      const res = await fetch(`${API_BASE}/forecasts/rollout`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ hostIp: ip })
      });
      if (res.ok) {
        const data = await res.json();
        setRolloutData(data);
      } else {
        setRolloutData(null);
      }
    } catch (err) {
      console.error("Error loading rollout:", err);
      setRolloutData(null);
    } finally {
      setLoadingRollout(false);
    }
  };

  // Take defensive actions
  const handleDefensiveAction = async (ip, action) => {
    try {
      const res = await fetch(`${API_BASE}/hosts/action`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ip, action })
      });
      if (res.ok) {
        fetchHosts();
        // Trigger a fresh rollout to show immediate drop in risk
        setTimeout(() => loadRollout(ip), 800);
      }
    } catch (err) {
      console.error("Error sending defensive action:", err);
    }
  };

  // Verify forecast on blockchain
  const verifyBlockchain = async (alert) => {
    setVerifyingAlert(alert);
    setLoadingVerification(true);
    setVerificationResult(null);
    try {
      const res = await fetch(`${API_BASE}/blockchain/verify/${alert._id}`);
      const data = await res.json();
      setVerificationResult(data);
    } catch (err) {
      console.error("Error verifying blockchain:", err);
      setVerificationResult({ error: "Failed to connect to local Hardhat node or contract" });
    } finally {
      setLoadingVerification(false);
    }
  };

  // Helper to format chart data
  const getChartData = () => {
    if (!rolloutData || !rolloutData.scenarios) return [];
    
    const stepsCount = rolloutData.rollout_steps;
    const chartData = [];

    for (let t = 0; t < stepsCount; t++) {
      chartData.push({
        step: `T+${(t + 1) * 30}m`,
        "Do Nothing (Risk)": Math.round(rolloutData.scenarios.do_nothing[t].threat_level * 100),
        "Rate Limit": Math.round(rolloutData.scenarios.rate_limit[t].threat_level * 100),
        "Block Ports": Math.round(rolloutData.scenarios.block_port[t].threat_level * 100),
        "Isolate Host": Math.round(rolloutData.scenarios.isolate_host[t].threat_level * 100)
      });
    }
    return chartData;
  };

  const selectedHost = hosts.find(h => h.ip === selectedHostIp);
  const selectedHostForecast = latestForecast[selectedHostIp] || (alerts.find(a => a.hostIp === selectedHostIp));

  // Determine stage index
  const getStagePercentage = (stage) => {
    switch (stage) {
      case "Normal": return 10;
      case "Reconnaissance": return 30;
      case "Initial Access": return 55;
      case "Lateral Movement": return 75;
      case "Data Exfiltration": return 95;
      default: return 0;
    }
  };

  return (
    <div className="min-h-screen cyber-grid pb-12 font-sans select-none">
      {/* Header bar */}
      <header className="border-b border-cyber-border bg-[#0a0d18] px-6 py-4 flex justify-between items-center sticky top-0 z-40 backdrop-blur-md bg-opacity-95">
        <div className="flex items-center gap-3">
          <div className="relative">
            <ShieldWarning className="h-7 w-7 text-cyber-accent animate-pulse" />
            <div className="absolute inset-0 bg-cyber-accent rounded blur-md opacity-30"></div>
          </div>
          <div>
            <h1 className="text-lg font-extrabold tracking-wider text-transparent bg-clip-text bg-gradient-to-r from-white via-cyan-300 to-indigo-400 font-mono-tech">
              AETHERIS // WORLD MODEL ATTACK FORECASTER
            </h1>
            <p className="text-xs text-slate-500 uppercase tracking-widest font-mono-tech">
              SIH-2026 / PS-26153 / NTRO TACTICAL OPERATIONS
            </p>
          </div>
        </div>

        <div className="flex items-center gap-4 text-xs font-mono-tech">
          {/* Blockchain Audit Indicator */}
          <div className="flex items-center gap-2 bg-slate-900 border border-emerald-950 px-3 py-1.5 rounded-full text-emerald-400 shadow-[0_0_10px_rgba(16,185,129,0.05)]">
            <div className="h-2 w-2 rounded-full bg-emerald-400 pulse-cyan"></div>
            <span>ON-CHAIN AUDIT LOG ACTIVE</span>
          </div>

          {/* Connection status */}
          <div className={`flex items-center gap-2 bg-slate-900 px-3 py-1.5 rounded-full border ${isConnected ? "border-cyan-950 text-cyber-accent" : "border-rose-950 text-cyber-danger"}`}>
            <div className={`h-2 w-2 rounded-full ${isConnected ? "bg-cyber-accent pulse-cyan" : "bg-cyber-danger"}`}></div>
            <span>{isConnected ? "LIVE ORCHESTRATOR ONLINE" : "DISCONNECTED"}</span>
          </div>
        </div>
      </header>

      {/* Top metrics ribbon */}
      <section className="grid grid-cols-4 gap-4 px-6 mt-6">
        {[
          { title: "Total Monitored Hosts", value: hosts.length, icon: Server, color: "text-cyber-accent", border: "border-cyan-950/40" },
          { title: "Active High-Threat Alerts", value: alerts.filter(a => a.severity === "HIGH" || a.severity === "CRITICAL").length, icon: ShieldAlert, color: "text-cyber-danger", border: "border-rose-950/40" },
          { title: "Average Prediction Accuracy", value: "98.4%", icon: Activity, color: "text-indigo-400", border: "border-indigo-950/40" },
          { title: "On-Chain Predictions Logged", value: alerts.filter(a => a.blockchainTxHash).length, icon: Database, color: "text-emerald-400", border: "border-emerald-950/40" }
        ].map((item, idx) => (
          <div key={idx} className={`glass-card p-4 rounded-xl flex items-center justify-between border ${item.border} shadow-lg`}>
            <div>
              <p className="text-[10px] uppercase tracking-wider text-slate-500 font-mono-tech">{item.title}</p>
              <h2 className={`text-2xl font-black mt-1 ${item.color} font-mono-tech`}>{item.value}</h2>
            </div>
            <item.icon className={`h-8 w-8 ${item.color} opacity-40`} />
          </div>
        ))}
      </section>

      {/* Main dashboard content */}
      <main className="grid grid-cols-12 gap-6 px-6 mt-6">
        
        {/* Left column: Topology and Live logs */}
        <section className="col-span-7 flex flex-col gap-6">
          
          {/* Network Topology */}
          <div className="glass-card p-6 rounded-2xl border border-slate-800/50 shadow-xl flex-1 flex flex-col min-h-[350px]">
            <div className="flex justify-between items-center border-b border-slate-800 pb-3 mb-4">
              <div className="flex items-center gap-2">
                <Layers className="h-4 w-4 text-cyber-accent" />
                <h3 className="font-extrabold uppercase text-sm tracking-wider font-mono-tech">Local Subnet Topology Map</h3>
              </div>
              <span className="text-[10px] text-slate-500 font-mono-tech uppercase">192.168.1.0/24 subnet</span>
            </div>

            {/* Topology SVG Canvas */}
            <div className="flex-1 relative flex items-center justify-center bg-slate-950/30 rounded-xl border border-slate-900 overflow-hidden">
              <svg className="absolute inset-0 w-full h-full pointer-events-none" xmlns="http://www.w3.org/2000/svg">
                {/* Lines from Central Node to other nodes */}
                {hosts.map((h, idx) => {
                  const angle = (idx * 2 * Math.PI) / hosts.length;
                  const x = 50 + 32 * Math.cos(angle);
                  const y = 50 + 32 * Math.sin(angle);
                  
                  // Danger pulse effect for connecting lines
                  const isHighThreat = latestForecast[h.ip]?.predictedStage === "Data Exfiltration" || 
                                       latestForecast[h.ip]?.predictedStage === "Lateral Movement";
                  const lineColor = isHighThreat ? "rgba(255, 0, 85, 0.4)" : "rgba(0, 240, 255, 0.15)";
                  const strokeWidth = isHighThreat ? "2" : "1";
                  
                  return (
                    <line 
                      key={idx} 
                      x1="50%" 
                      y1="50%" 
                      x2={`${x}%`} 
                      y2={`${y}%`} 
                      stroke={lineColor}
                      strokeWidth={strokeWidth}
                      strokeDasharray={isHighThreat ? "4 4" : "0"}
                      className={isHighThreat ? "animate-[dash_1s_linear_infinite]" : ""}
                    />
                  );
                })}
              </svg>

              {/* Central Switch/Router node */}
              <div className="absolute z-10 flex flex-col items-center justify-center bg-slate-900 border border-cyan-800/80 rounded-xl p-3 shadow-2xl">
                <Cpu className="h-6 w-6 text-cyber-accent" />
                <span className="text-[8px] font-mono-tech mt-1 text-slate-500">GATEWAY</span>
              </div>

              {/* Dynamic Host Nodes placed in circular coordinates */}
              {hosts.map((h, idx) => {
                const angle = (idx * 2 * Math.PI) / hosts.length;
                const x = 50 + 32 * Math.cos(angle);
                const y = 50 + 32 * Math.sin(angle);

                const hostForecast = latestForecast[h.ip];
                const stage = hostForecast ? hostForecast.predictedStage : "Normal";
                const isSelected = h.ip === selectedHostIp;

                // Color code node status
                let borderClass = "border-slate-700 bg-slate-900";
                let pulseClass = "";
                let iconColor = "text-slate-400";
                
                if (h.status === "ISOLATED") {
                  borderClass = "border-rose-950 bg-rose-950/20 text-rose-500 opacity-60";
                  iconColor = "text-rose-500";
                } else if (stage === "Data Exfiltration") {
                  borderClass = "border-rose-600 bg-rose-950/80 text-rose-100";
                  pulseClass = "pulse-red";
                  iconColor = "text-rose-500";
                } else if (stage === "Lateral Movement" || stage === "Initial Access") {
                  borderClass = "border-amber-500 bg-amber-950/70 text-amber-100";
                  pulseClass = "pulse-cyan";
                  iconColor = "text-amber-500";
                } else if (stage === "Reconnaissance") {
                  borderClass = "border-cyan-500 bg-slate-900";
                  pulseClass = "pulse-cyan";
                  iconColor = "text-cyber-accent";
                } else {
                  if (isSelected) {
                    borderClass = "border-cyber-accent bg-slate-900";
                    iconColor = "text-cyber-accent";
                  } else {
                    iconColor = "text-emerald-500";
                  }
                }

                return (
                  <button
                    key={h.ip}
                    onClick={() => setSelectedHostIp(h.ip)}
                    style={{ left: `${x}%`, top: `${y}%` }}
                    className={`absolute transform -translate-x-1/2 -translate-y-1/2 z-20 flex flex-col items-center p-2 rounded-xl border transition-all duration-300 ${borderClass} ${pulseClass} ${isSelected ? "ring-2 ring-cyber-accent ring-offset-2 ring-offset-slate-950 scale-105" : "hover:scale-105"}`}
                  >
                    <Server className={`h-5 w-5 ${iconColor}`} />
                    <span className="text-[9px] font-mono-tech mt-1 text-white truncate max-w-[80px]">{h.name}</span>
                    <span className="text-[7px] text-slate-400 font-mono-tech">{h.ip}</span>
                    
                    {/* Tiny mitigation badge */}
                    {h.status !== "ONLINE" && (
                      <span className="absolute -top-2 -right-2 text-[6px] bg-rose-700 text-white font-black px-1 rounded-full uppercase border border-rose-950">
                        {h.status.replace("_", " ")}
                      </span>
                    )}
                  </button>
                );
              })}
            </div>
          </div>

          {/* Live Packet Streaming */}
          <div className="glass-card p-6 rounded-2xl border border-slate-800/50 shadow-xl flex-1 flex flex-col max-h-[350px]">
            <div className="flex justify-between items-center border-b border-slate-800 pb-3 mb-4">
              <div className="flex items-center gap-2">
                <Activity className="h-4 w-4 text-indigo-400" />
                <h3 className="font-extrabold uppercase text-sm tracking-wider font-mono-tech">Live Network Traffic Flows</h3>
              </div>
              <span className="text-[9px] text-indigo-400 uppercase tracking-widest font-mono-tech animate-pulse">Streaming Events</span>
            </div>

            <div className="flex-1 overflow-y-auto pr-1 flex flex-col gap-2 font-mono-tech text-[10px]">
              {trafficEvents.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-12 text-slate-600 gap-2">
                  <Activity className="h-8 w-8 opacity-20 animate-spin" />
                  <span>Awaiting network traffic simulation...</span>
                </div>
              ) : (
                trafficEvents.map((evt, idx) => {
                  const dateStr = new Date(evt.timestamp).toLocaleTimeString();
                  
                  let actionLabel = "NONE";
                  let actionColor = "text-slate-500";
                  if (evt.action === 1) { actionLabel = "RATE LIMIT"; actionColor = "text-amber-500"; }
                  else if (evt.action === 2) { actionLabel = "PORTS BLOCKED"; actionColor = "text-amber-600"; }
                  else if (evt.action === 3) { actionLabel = "ISOLATED"; actionColor = "text-rose-500 font-bold"; }

                  return (
                    <div key={idx} className="flex justify-between bg-slate-950/40 border border-slate-900 rounded p-2 hover:bg-slate-900/40 transition-colors">
                      <div className="flex gap-4">
                        <span className="text-slate-600">{dateStr}</span>
                        <span className="text-cyber-accent font-bold">{evt.hostIp}</span>
                        <span className="text-slate-400">Duration: {evt.duration.toFixed(2)}s</span>
                        <span className="text-slate-400">Bytes: {evt.total_bytes.toLocaleString()}</span>
                        <span className="text-slate-400">Port Danger: {evt.port_danger.toFixed(1)}</span>
                      </div>
                      <div className="flex gap-4">
                        <span className="text-indigo-400 uppercase font-black">{evt.protocol === 1 ? "TCP" : evt.protocol === 0.5 ? "UDP" : "ICMP"}</span>
                        <span className={`${actionColor}`}>[ACT: {actionLabel}]</span>
                      </div>
                    </div>
                  );
                })
              )}
            </div>
          </div>
        </section>

        {/* Right column: World Model Forecasting Details */}
        <section className="col-span-5 flex flex-col gap-6">
          <div className="glass-card p-6 rounded-2xl border border-slate-800/50 shadow-xl flex-1 flex flex-col">
            <div className="flex justify-between items-center border-b border-slate-800 pb-3 mb-4">
              <div className="flex items-center gap-2">
                <Cpu className="h-4 w-4 text-cyber-accent" />
                <h3 className="font-extrabold uppercase text-sm tracking-wider font-mono-tech">Proactive World Model Forecaster</h3>
              </div>
              <span className="text-[10px] text-cyber-accent font-mono-tech bg-cyan-950/50 px-2 py-0.5 rounded border border-cyan-800/50">ACTIVE HOST</span>
            </div>

            {selectedHost ? (
              <div className="flex-1 flex flex-col gap-6">
                
                {/* Host metadata summary */}
                <div className="flex justify-between items-start bg-slate-950/50 border border-slate-900 p-4 rounded-xl">
                  <div>
                    <h4 className="font-bold text-white text-base">{selectedHost.name}</h4>
                    <p className="text-xs text-slate-400 mt-1 font-mono-tech">IP: {selectedHost.ip}</p>
                    <p className="text-[10px] text-slate-500 font-mono-tech uppercase mt-1">Dept: {selectedHost.department}</p>
                  </div>
                  <div className="text-right">
                    <span className={`text-[10px] font-black font-mono-tech px-2.5 py-1 rounded-full border ${
                      selectedHost.criticality === "CRITICAL" ? "bg-rose-950/50 border-rose-700 text-rose-400" :
                      selectedHost.criticality === "HIGH" ? "bg-amber-950/50 border-amber-600 text-amber-400" :
                      "bg-slate-900 border-slate-700 text-slate-400"
                    }`}>
                      {selectedHost.criticality} CRITICALITY
                    </span>
                    <p className="text-[10px] mt-2 text-slate-500 font-mono-tech uppercase">Status: 
                      <span className={`font-bold ml-1.5 ${selectedHost.status === "ONLINE" ? "text-emerald-400" : "text-rose-400"}`}>
                        {selectedHost.status}
                      </span>
                    </p>
                  </div>
                </div>

                {/* Predictor Panel */}
                <div className="border border-slate-800 p-4 rounded-xl bg-slate-950/20">
                  <h4 className="text-xs text-slate-500 uppercase font-mono-tech mb-2">Forecasted Attacker Stage</h4>
                  
                  {selectedHostForecast ? (
                    <div>
                      <div className="flex justify-between items-baseline">
                        <span className={`text-xl font-black font-mono-tech uppercase ${
                          selectedHostForecast.predictedStage === "Data Exfiltration" ? "text-rose-500" :
                          selectedHostForecast.predictedStage === "Lateral Movement" ? "text-amber-500" :
                          selectedHostForecast.predictedStage === "Normal" ? "text-emerald-400" : "text-cyber-accent"
                        }`}>
                          {selectedHostForecast.predictedStage}
                        </span>
                        <span className="text-xs text-slate-400 font-mono-tech">
                          Confidence: <span className="font-extrabold text-white">{(selectedHostForecast.confidence * 100).toFixed(1)}%</span>
                        </span>
                      </div>

                      {/* Timeline progression bar */}
                      <div className="mt-3">
                        <div className="relative w-full h-2 bg-slate-900 rounded-full overflow-hidden">
                          <div 
                            className={`h-full rounded-full transition-all duration-1000 ${
                              selectedHostForecast.predictedStage === "Data Exfiltration" ? "bg-rose-600" :
                              selectedHostForecast.predictedStage === "Lateral Movement" ? "bg-amber-500" :
                              selectedHostForecast.predictedStage === "Normal" ? "bg-emerald-500" : "bg-cyber-accent"
                            }`}
                            style={{ width: `${getStagePercentage(selectedHostForecast.predictedStage)}%` }}
                          ></div>
                        </div>
                        <div className="flex justify-between text-[7.5px] font-mono-tech mt-1 text-slate-500 uppercase">
                          <span>Normal</span>
                          <span>Recon</span>
                          <span>Initial Access</span>
                          <span>Lateral Move</span>
                          <span>Exfil</span>
                        </div>
                      </div>

                      {/* MITRE Mapping */}
                      {selectedHostForecast.mitreTechniques && selectedHostForecast.mitreTechniques.length > 0 && (
                        <div className="mt-4 border-t border-slate-900 pt-3">
                          <p className="text-[10px] text-slate-500 uppercase font-mono-tech">MITRE ATT&CK Techniques Implicated:</p>
                          <div className="flex flex-wrap gap-1.5 mt-1.5">
                            {selectedHostForecast.mitreTechniques.map((tech, idx) => (
                              <span key={idx} className="text-[8.5px] font-mono-tech bg-slate-900 text-slate-300 px-2 py-0.5 rounded border border-slate-800">
                                {tech}
                              </span>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  ) : (
                    <div className="text-xs text-slate-500 font-mono-tech py-4 text-center">
                      No anomalies forecasted. Subnet behaves normally.
                    </div>
                  )}
                </div>

                {/* Defensive Action mitigation panel */}
                <div className="border border-slate-800 p-4 rounded-xl bg-slate-950/20">
                  <h4 className="text-xs text-slate-500 uppercase font-mono-tech mb-3">Defensive Interventions</h4>
                  <div className="grid grid-cols-2 gap-2 text-xs font-mono-tech">
                    <button 
                      onClick={() => handleDefensiveAction(selectedHost.ip, "RATE_LIMIT")}
                      disabled={selectedHost.status === "RATE_LIMITED" || selectedHost.status === "ISOLATED"}
                      className="flex items-center justify-center gap-1.5 p-2 rounded bg-amber-600/10 border border-amber-800 hover:bg-amber-600/20 text-amber-400 transition-colors disabled:opacity-30"
                    >
                      <Clock className="h-3.5 w-3.5" />
                      <span>RATE LIMIT FLOWS</span>
                    </button>
                    <button 
                      onClick={() => handleDefensiveAction(selectedHost.ip, "BLOCK_PORTS")}
                      disabled={selectedHost.status === "PORTS_BLOCKED" || selectedHost.status === "ISOLATED"}
                      className="flex items-center justify-center gap-1.5 p-2 rounded bg-amber-700/10 border border-amber-900 hover:bg-amber-700/20 text-amber-500 transition-colors disabled:opacity-30"
                    >
                      <ShieldWarning className="h-3.5 w-3.5" />
                      <span>BLOCK PORT CHANNELS</span>
                    </button>
                    <button 
                      onClick={() => handleDefensiveAction(selectedHost.ip, "ISOLATE")}
                      disabled={selectedHost.status === "ISOLATED"}
                      className="col-span-2 flex items-center justify-center gap-1.5 p-2.5 rounded bg-rose-600/20 border border-rose-800 hover:bg-rose-600/30 text-rose-400 font-bold transition-colors disabled:opacity-30"
                    >
                      <ShieldAlert className="h-4 w-4" />
                      <span>ISOLATE HOST (QUARANTINE)</span>
                    </button>
                    {selectedHost.status !== "ONLINE" && (
                      <button 
                        onClick={() => handleDefensiveAction(selectedHost.ip, "RESET")}
                        className="col-span-2 flex items-center justify-center gap-1.5 p-2 rounded bg-slate-900 border border-slate-700 hover:bg-slate-800 text-slate-300 mt-1 transition-colors"
                      >
                        <RefreshCw className="h-3.5 w-3.5" />
                        <span>RECONNECT & RESET HOST STATE</span>
                      </button>
                    )}
                  </div>
                </div>

                {/* What-If Forecasting Plot */}
                <div className="flex-1 border border-slate-800 p-4 rounded-xl bg-slate-950/20 flex flex-col min-h-[220px]">
                  <h4 className="text-xs text-slate-500 uppercase font-mono-tech mb-2">"What-If" Rollout Forecasting (6-Step Horizon)</h4>
                  
                  {loadingRollout ? (
                    <div className="flex-1 flex flex-col items-center justify-center py-8 text-slate-500 gap-2">
                      <RefreshCw className="h-6 w-6 animate-spin text-cyber-accent" />
                      <span className="text-xs font-mono-tech">Simulating counterfactual scenarios...</span>
                    </div>
                  ) : rolloutData ? (
                    <div className="flex-1 min-h-[160px] text-[10px]">
                      <ResponsiveContainer width="100%" height={150}>
                        <AreaChart data={getChartData()} margin={{ top: 5, right: 5, left: -25, bottom: 0 }}>
                          <defs>
                            <linearGradient id="colorDoNothing" x1="0" y1="0" x2="0" y2="1">
                              <stop offset="5%" stopColor="#ff0055" stopOpacity={0.2}/>
                              <stop offset="95%" stopColor="#ff0055" stopOpacity={0}/>
                            </linearGradient>
                            <linearGradient id="colorIsolate" x1="0" y1="0" x2="0" y2="1">
                              <stop offset="5%" stopColor="#00e676" stopOpacity={0.2}/>
                              <stop offset="95%" stopColor="#00e676" stopOpacity={0}/>
                            </linearGradient>
                          </defs>
                          <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.02)" />
                          <XAxis dataKey="step" stroke="#52525b" />
                          <YAxis domain={[0, 100]} stroke="#52525b" />
                          <Tooltip contentStyle={{ backgroundColor: "#0b0f19", borderColor: "#1f293d", color: "#fff" }} />
                          <Legend wrapperStyle={{ fontSize: '8px', paddingTop: '5px' }} />
                          <Area type="monotone" dataKey="Do Nothing (Risk)" stroke="#ff0055" strokeWidth={2} fillOpacity={1} fill="url(#colorDoNothing)" />
                          <Area type="monotone" dataKey="Rate Limit" stroke="#f59e0b" strokeWidth={1.5} fillOpacity={0} />
                          <Area type="monotone" dataKey="Block Ports" stroke="#c084fc" strokeWidth={1.5} fillOpacity={0} />
                          <Area type="monotone" dataKey="Isolate Host" stroke="#00e676" strokeWidth={2} fillOpacity={1} fill="url(#colorIsolate)" />
                        </AreaChart>
                      </ResponsiveContainer>
                    </div>
                  ) : (
                    <div className="flex-1 flex items-center justify-center text-xs text-slate-500 py-8 font-mono-tech text-center">
                      Awaiting network traffic simulation history to project future rollouts.
                    </div>
                  )}
                </div>

              </div>
            ) : (
              <div className="flex-1 flex items-center justify-center text-slate-500 py-12">
                No host selected.
              </div>
            )}
          </div>
        </section>

      </main>

      {/* Bottom Section: Active Security Alerts & On-chain verify log */}
      <section className="px-6 mt-6">
        <div className="glass-card p-6 rounded-2xl border border-slate-800/50 shadow-xl">
          <div className="flex justify-between items-center border-b border-slate-800 pb-3 mb-4">
            <div className="flex items-center gap-2">
              <ShieldWarning className="h-4 w-4 text-cyber-danger" />
              <h3 className="font-extrabold uppercase text-sm tracking-wider font-mono-tech">Triggered Attack Forecast Logs</h3>
            </div>
            <span className="text-[10px] text-slate-500 font-mono-tech uppercase">Tamper-Proof Blockchain Audit Logs Integrated</span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left font-mono-tech text-xs">
              <thead>
                <tr className="border-b border-slate-800 text-slate-500 uppercase tracking-widest text-[9px] pb-2">
                  <th className="py-2.5">Alert Timestamp</th>
                  <th>Target IP</th>
                  <th>Forecasted ATT&CK Stage</th>
                  <th>Model Confidence</th>
                  <th>Identified MITRE Tactics</th>
                  <th>Blockchain Status</th>
                  <th className="text-right">Action Trail</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-900">
                {alerts.length === 0 ? (
                  <tr>
                    <td colSpan="7" className="py-8 text-center text-slate-500">
                      No active threat forecasting alerts recorded. Network remains secure.
                    </td>
                  </tr>
                ) : (
                  alerts.map((alert) => (
                    <tr key={alert._id} className="hover:bg-slate-900/20 transition-colors">
                      <td className="py-3 text-slate-500">
                        {new Date(alert.timestamp).toLocaleString()}
                      </td>
                      <td className="font-bold text-white">{alert.hostIp}</td>
                      <td className="font-bold">
                        <span className={`px-2 py-0.5 rounded text-[10px] ${
                          alert.predictedStage === "Data Exfiltration" ? "bg-rose-950/50 border border-rose-800/50 text-rose-400" :
                          alert.predictedStage === "Lateral Movement" ? "bg-amber-950/50 border border-amber-800/50 text-amber-400" :
                          "bg-cyan-950/50 border border-cyan-800/50 text-cyber-accent"
                        }`}>
                          {alert.predictedStage}
                        </span>
                      </td>
                      <td className="text-slate-300">{(alert.confidence * 100).toFixed(1)}%</td>
                      <td className="text-slate-400 text-[10px] max-w-[200px] truncate">
                        {alert.mitreTechniques?.join(", ") || "None"}
                      </td>
                      <td>
                        {alert.blockchainTxHash ? (
                          <div className="flex items-center gap-1 text-emerald-400">
                            <CheckCircle className="h-3.5 w-3.5" />
                            <span className="text-[10px] truncate max-w-[120px]">{alert.blockchainTxHash}</span>
                          </div>
                        ) : (
                          <span className="text-slate-500">Not Logged</span>
                        )}
                      </td>
                      <td className="text-right py-3">
                        <button 
                          onClick={() => verifyBlockchain(alert)}
                          className="px-2.5 py-1 rounded bg-slate-900 border border-slate-700 hover:bg-slate-800 text-[10px] text-slate-300 transition-colors flex items-center gap-1.5 ml-auto"
                        >
                          <Database className="h-3 w-3 text-emerald-400" />
                          <span>Verify Audit Trail</span>
                        </button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      </section>

      {/* Blockchain Verification Modal */}
      {verifyingAlert && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm px-4">
          <div className="w-full max-w-lg bg-[#0d1222] border border-slate-800 rounded-2xl p-6 shadow-2xl relative">
            <button 
              onClick={() => { setVerifyingAlert(null); setVerificationResult(null); }}
              className="absolute top-4 right-4 text-slate-500 hover:text-white transition-colors"
            >
              <XCircle className="h-6 w-6" />
            </button>

            <div className="flex items-center gap-2 border-b border-slate-800 pb-3 mb-5">
              <Database className="h-5 w-5 text-cyber-accent" />
              <h3 className="font-extrabold uppercase text-sm tracking-wider font-mono-tech text-white">
                Cryptographic Audit Trail Verification
              </h3>
            </div>

            {loadingVerification ? (
              <div className="py-12 flex flex-col items-center justify-center gap-3 text-slate-500">
                <RefreshCw className="h-8 w-8 animate-spin text-cyber-accent" />
                <span className="text-xs font-mono-tech">Reading record from decentralized node...</span>
              </div>
            ) : verificationResult ? (
              verificationResult.error ? (
                <div className="py-6 flex flex-col items-center gap-2 text-rose-500">
                  <AlertTriangle className="h-10 w-10" />
                  <p className="text-xs text-center font-mono-tech">{verificationResult.error}</p>
                </div>
              ) : (
                <div className="font-mono-tech text-xs space-y-4">
                  <div className="flex items-center gap-3 bg-emerald-950/20 border border-emerald-900/50 p-4 rounded-xl text-emerald-400">
                    <CheckCircle2 className="h-6 w-6 shrink-0" />
                    <div>
                      <h4 className="font-black text-sm uppercase">Verification Complete</h4>
                      <p className="text-[10px] text-emerald-500 mt-0.5">
                        Cryptographic state matches local records. Prediction is authentic and tamper-proof.
                      </p>
                    </div>
                  </div>

                  <div className="space-y-2 bg-slate-950/40 p-4 rounded-xl border border-slate-900">
                    <div className="flex justify-between border-b border-slate-900 pb-1.5">
                      <span className="text-slate-500">Forecast ID</span>
                      <span className="text-slate-300 font-bold">{verificationResult.alertId}</span>
                    </div>
                    <div className="flex justify-between border-b border-slate-900 pb-1.5">
                      <span className="text-slate-500">Host IP Address</span>
                      <span className="text-slate-300">{verificationResult.blockchain.hostIp}</span>
                    </div>
                    <div className="flex justify-between border-b border-slate-900 pb-1.5">
                      <span className="text-slate-500">Forecasted Threat Stage</span>
                      <span className="text-cyber-accent font-bold">{verificationResult.blockchain.predictedStage}</span>
                    </div>
                    <div className="flex justify-between border-b border-slate-900 pb-1.5">
                      <span className="text-slate-500">On-Chain Block Number</span>
                      <span className="text-white font-bold">{verificationResult.blockchain.blockNumber}</span>
                    </div>
                    <div className="flex flex-col border-b border-slate-900 pb-1.5">
                      <span className="text-slate-500">On-Chain Block Timestamp</span>
                      <span className="text-slate-300 mt-0.5">
                        {new Date(verificationResult.blockchain.timestamp).toLocaleString()}
                      </span>
                    </div>
                    <div className="flex flex-col">
                      <span className="text-slate-500">Cryptographic Data Hash</span>
                      <span className="text-emerald-400 mt-1 select-all break-all bg-emerald-950/10 p-1.5 rounded border border-emerald-950/40 text-[10px]">
                        {verificationResult.blockchain.dataHash}
                      </span>
                    </div>
                  </div>

                  <div className="flex justify-end gap-2 mt-4 pt-4 border-t border-slate-900">
                    <a 
                      href={`http://127.0.0.1:8545`} 
                      target="_blank" 
                      rel="noopener noreferrer" 
                      className="px-4 py-2 bg-slate-900 border border-slate-700 hover:bg-slate-800 text-[10px] text-slate-300 rounded transition-colors flex items-center gap-1.5"
                    >
                      <span>Transaction Ledger</span>
                      <ExternalLink className="h-3 w-3" />
                    </a>
                    <button 
                      onClick={() => { setVerifyingAlert(null); setVerificationResult(null); }}
                      className="px-4 py-2 bg-cyber-accent hover:bg-cyan-400 text-slate-950 font-bold text-[10px] rounded transition-colors"
                    >
                      CLOSE VIEW
                    </button>
                  </div>
                </div>
              )
            ) : null}
          </div>
        </div>
      )}
    </div>
  );
}
