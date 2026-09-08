import React, { useState, useMemo, useEffect, useCallback, useRef } from "react";
import {
  Target, ShieldAlert, Cpu, Clock, AlertTriangle,
  TrendingUp, RefreshCw, Zap, ChevronRight, Shield, Wifi,
  Globe, Server, Activity, Ban, Lock, Unlock, CheckCircle2,
  Gauge, ArrowRight, ArrowUpRight, ArrowDownRight, Layers,
  Radio, FileText, AlertCircle, HardDrive, Filter, ChevronDown
} from "lucide-react";
import {
  ATTACK_STAGES, STAGE_COLORS, MITRE_TECHNIQUES
} from "../demoData";

const _HOST = import.meta.env.VITE_CAPTURE_HOST ?? "127.0.0.1";
const _PORT = import.meta.env.VITE_CAPTURE_PORT ?? "8080";
const CAPTURE_API = `http://${_HOST}:${_PORT}`;

// Kill chain stage progress bar
function KillChainBar({ currentStage }) {
  const idx = ATTACK_STAGES.indexOf(currentStage);
  return (
    <div className="flex items-center gap-1 flex-wrap">
      {ATTACK_STAGES.map((stage, i) => (
        <React.Fragment key={stage}>
          <div
            className={`flex items-center gap-1 px-2.5 py-1.5 rounded text-[9px] font-mono-tech font-bold uppercase transition-all duration-500 ${
              i <= idx
                ? "text-white"
                : "text-slate-600 bg-slate-900/50 border border-slate-800/80"
            }`}
            style={i <= idx ? {
              backgroundColor: `${STAGE_COLORS[stage] || '#00f0ff'}20`,
              border: `1px solid ${STAGE_COLORS[stage] || '#00f0ff'}50`,
              color: STAGE_COLORS[stage] || '#00f0ff',
            } : {}}
          >
            <div
              className="h-1.5 w-1.5 rounded-full"
              style={{ backgroundColor: i <= idx ? (STAGE_COLORS[stage] || '#00f0ff') : "#334155" }}
            ></div>
            <span className="hidden lg:inline">{stage}</span>
            <span className="lg:hidden">{stage.split(" ").map(w => w[0]).join("")}</span>
          </div>
          {i < ATTACK_STAGES.length - 1 && (
            <ChevronRight className={`h-3 w-3 ${i < idx ? "text-slate-500" : "text-slate-800"}`} />
          )}
        </React.Fragment>
      ))}
    </div>
  );
}

// Defense action button with toggle state
function DefenseButton({ label, icon: Icon, color, activeColor, isActive, onClick, loading }) {
  return (
    <button
      onClick={onClick}
      disabled={loading}
      className={`flex items-center justify-center gap-2 p-3.5 rounded-xl border text-[10px] font-mono-tech font-bold uppercase transition-all disabled:opacity-50 ${
        isActive ? activeColor : color
      }`}
    >
      {loading ? (
        <RefreshCw className="h-4 w-4 animate-spin" />
      ) : (
        <Icon className="h-4 w-4" />
      )}
      <span>{label}</span>
      {isActive && <CheckCircle2 className="h-3.5 w-3.5 ml-auto" />}
    </button>
  );
}

export default function AttackForecast({
  selectedInterface,
  selectedInterfaceInfo,
  liveFlows,
  livePackets,
  attackFlows,
  selectedFlow,
  isCapturing
}) {
  const [mlForecasts, setMlForecasts] = useState({});
  const [defenseState, setDefenseState] = useState({});
  const [defenseLoading, setDefenseLoading] = useState({});
  const [packetRatePps, setPacketRatePps] = useState(0);
  const prevPktCountRef = useRef(0);
  const prevPktTimeRef = useRef(Date.now());

  // Map backend stage name to frontend stage name
  const mapStageName = useCallback((stage) => {
    if (!stage) return "Normal";
    const s = stage.toLowerCase().replace(/_/g, ' ');
    if (s === "normal") return "Normal";
    if (s === "reconnaissance") return "Reconnaissance";
    if (s === "initial access") return "Initial Access";
    if (s === "lateral movement") return "Lateral Movement";
    if (s === "command control" || s === "command & control") return "Command & Control";
    if (s === "exfiltration") return "Exfiltration";
    return stage.charAt(0).toUpperCase() + stage.slice(1);
  }, []);

  // Collect active live host IPs from live traffic flows & packets
  const activeHostsList = useMemo(() => {
    const ipSet = new Set();
    (attackFlows || []).forEach(f => { if (f.src_ip) ipSet.add(f.src_ip); });
    Object.values(liveFlows || {}).forEach(f => {
      if (f.src_ip) ipSet.add(f.src_ip);
      if (f.dst_ip) ipSet.add(f.dst_ip);
    });
    (livePackets || []).forEach(p => {
      if (p.src_ip) ipSet.add(p.src_ip);
      if (p.dst_ip) ipSet.add(p.dst_ip);
    });
    Object.keys(mlForecasts || {}).forEach(ip => ipSet.add(ip));
    return Array.from(ipSet);
  }, [attackFlows, liveFlows, livePackets, mlForecasts]);

  // Automatically derive primary focus host IP without requiring manual selection
  const effectiveHostIp = useMemo(() => {
    return selectedFlow?.src_ip || attackFlows?.[0]?.src_ip || activeHostsList?.[0] || "";
  }, [selectedFlow, attackFlows, activeHostsList]);

  // Poll real-time forecasts from REST API + WebSocket global object
  useEffect(() => {
    const fetchForecasts = async () => {
      try {
        const res = await fetch(`${CAPTURE_API}/api/forecasts`);
        if (res.ok) {
          const data = await res.json();
          setMlForecasts(prev => ({ ...prev, ...data }));
        }
      } catch (_) {}

      if (window.__mlStageForecasts) {
        setMlForecasts(prev => ({ ...prev, ...window.__mlStageForecasts }));
      }
    };

    fetchForecasts();
    const interval = setInterval(fetchForecasts, 500); // 500ms update
    return () => clearInterval(interval);
  }, []);

  // Compute live packet rate (pps) from actual packet stream
  useEffect(() => {
    const calcRate = () => {
      const now = Date.now();
      const dt = Math.max((now - prevPktTimeRef.current) / 1000, 0.5);
      const currPkts = (livePackets || []).length;
      const dp = Math.max(0, currPkts - prevPktCountRef.current);
      const pps = Math.round(dp / dt);
      setPacketRatePps(pps);
      prevPktCountRef.current = currPkts;
      prevPktTimeRef.current = now;
    };
    const iv = setInterval(calcRate, 1000);
    return () => clearInterval(iv);
  }, [livePackets]);

  // Fetch defense state from capture server
  useEffect(() => {
    const fetchDefense = () => {
      fetch(`${CAPTURE_API}/api/defense/state`)
        .then(r => r.json())
        .then(data => setDefenseState(data))
        .catch(() => {});
    };
    fetchDefense();
    const iv = setInterval(fetchDefense, 3000);
    return () => clearInterval(iv);
  }, []);

  const currentDefense = useMemo(() => {
    return defenseState[selectedInterface] || {
      firewall_raised: false,
      blocked_ips: [],
      rate_limited_ips: [],
      isolated_ports: [],
    };
  }, [defenseState, selectedInterface]);

  // Defense API handlers
  const callDefenseApi = useCallback(async (endpoint, body, loadingKey) => {
    setDefenseLoading(prev => ({ ...prev, [loadingKey]: true }));
    try {
      const res = await fetch(`${CAPTURE_API}/api/defense/${endpoint}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const data = await res.json();
      const stateRes = await fetch(`${CAPTURE_API}/api/defense/state`);
      const stateData = await stateRes.json();
      setDefenseState(stateData);
      return data;
    } catch (e) {
      console.error("Defense action failed:", e);
      return null;
    } finally {
      setDefenseLoading(prev => ({ ...prev, [loadingKey]: false }));
    }
  }, [selectedInterface]);

  const handleFirewallToggle = useCallback(async () => {
    if (currentDefense.firewall_raised) {
      await callDefenseApi("firewall/drop", { interface: selectedInterface }, "firewall");
    } else {
      await callDefenseApi("firewall/raise", { interface: selectedInterface }, "firewall");
    }
  }, [currentDefense, selectedInterface, callDefenseApi]);

  const handleBlockIpToggle = useCallback(async () => {
    if (!effectiveHostIp) return;
    const isBlocked = currentDefense.blocked_ips?.includes(effectiveHostIp);
    if (isBlocked) {
      await callDefenseApi("unblock-ip", { ip: effectiveHostIp, interface: selectedInterface }, "blockIp");
    } else {
      await callDefenseApi("block-ip", { ip: effectiveHostIp, interface: selectedInterface }, "blockIp");
    }
  }, [effectiveHostIp, currentDefense, selectedInterface, callDefenseApi]);

  const handleRateLimitToggle = useCallback(async () => {
    if (!effectiveHostIp) return;
    const isLimited = currentDefense.rate_limited_ips?.includes(effectiveHostIp);
    if (isLimited) {
      await callDefenseApi("unrate-limit", { ip: effectiveHostIp, interface: selectedInterface }, "rateLimit");
    } else {
      await callDefenseApi("rate-limit", { ip: effectiveHostIp, interface: selectedInterface }, "rateLimit");
    }
  }, [effectiveHostIp, currentDefense, selectedInterface, callDefenseApi]);

  const handleIsolatePortToggle = useCallback(async () => {
    const port = selectedFlow?.dst_port || 443;
    const isIsolated = currentDefense.isolated_ports?.includes(port);
    if (isIsolated) {
      await callDefenseApi("unisolate-port", { port, interface: selectedInterface }, "isolatePort");
    } else {
      await callDefenseApi("isolate-port", { port, interface: selectedInterface }, "isolatePort");
    }
  }, [selectedFlow, currentDefense, selectedInterface, callDefenseApi]);

  // Determine GRU threat forecast for effectiveHostIp with live traffic fallback
  const threatInfo = useMemo(() => {
    const activeAttacks = (attackFlows || []).filter(f => f.severity && f.severity !== "none" && f.attack_type && f.attack_type !== "Benign");

    // 100% BENIGN NORMAL TRAFFIC BASELINE
    if (activeAttacks.length === 0) {
      return {
        state: "ready",
        stage: "Normal",
        color: STAGE_COLORS.Normal,
        confidence: 0.98,
        riskScore: 0.02,
        mlProbs: { Normal: 0.98, Reconnaissance: 0.01, "Initial Access": 0.005, "Lateral Movement": 0.003, "Command & Control": 0.001, Exfiltration: 0.001 },
        techniques: [],
        projectedRiskCurve: [0.02, 0.02, 0.02, 0.02, 0.02, 0.02],
        recentRiskHistory: [0.02],
        source: "Live Traffic Baseline (Normal)",
      };
    }

    const primaryHost = activeAttacks[0].src_ip || effectiveHostIp;
    const mlForecast = primaryHost ? mlForecasts[primaryHost] : null;

    if (mlForecast && mlForecast.predicted_stage && mlForecast.predicted_stage !== "normal" && mlForecast.projected_risk_curve && mlForecast.projected_risk_curve.length > 0) {
      const stage = mapStageName(mlForecast.predicted_stage);
      const confidence = mlForecast.confidence || (mlForecast.stage_probs && mlForecast.stage_probs[mlForecast.predicted_stage]) || 0.85;
      const riskScore = mlForecast.risk_score || 0.5;

      const mlProbsMapped = {};
      if (mlForecast.stage_probs) {
        Object.entries(mlForecast.stage_probs).forEach(([sName, prob]) => {
          mlProbsMapped[mapStageName(sName)] = prob;
        });
      }

      return {
        state: "ready",
        stage,
        color: STAGE_COLORS[stage] || STAGE_COLORS.Normal,
        confidence,
        riskScore,
        mlProbs: mlProbsMapped,
        techniques: MITRE_TECHNIQUES[stage] || [],
        projectedRiskCurve: mlForecast.projected_risk_curve,
        recentRiskHistory: mlForecast.recent_risk_history || [riskScore],
        source: "GRU ML Model",
      };
    }

    // Live Telemetry Fallback for active attacks
    const primaryAtk = activeAttacks[0].attack_type;
    let stage = "Reconnaissance";
    let riskScore = 0.5;

    if (primaryAtk === "Port Scan") {
      stage = "Reconnaissance";
      riskScore = 0.45;
    } else if (primaryAtk === "Brute Force") {
      stage = "Initial Access";
      riskScore = 0.65;
    } else if (primaryAtk === "SYN Flood" || primaryAtk === "DDoS" || primaryAtk === "ICMP Flood") {
      stage = "Command & Control";
      riskScore = 0.85;
    } else if (primaryAtk === "Data Exfiltration") {
      stage = "Exfiltration";
      riskScore = 0.95;
    }

    const projectedRiskCurve = [
      riskScore,
      Math.min(1.0, riskScore + 0.05),
      Math.min(1.0, riskScore + 0.1),
      Math.min(1.0, riskScore + 0.12),
      Math.min(1.0, riskScore + 0.14),
      Math.min(1.0, riskScore + 0.15)
    ];

    const stageProbs = {
      Normal: 0.05,
      Reconnaissance: stage === "Reconnaissance" ? 0.80 : 0.05,
      "Initial Access": stage === "Initial Access" ? 0.80 : 0.05,
      "Lateral Movement": 0.05,
      "Command & Control": stage === "Command & Control" ? 0.80 : 0.05,
      Exfiltration: stage === "Exfiltration" ? 0.80 : 0.05,
    };

    return {
      state: "ready",
      stage,
      color: STAGE_COLORS[stage] || STAGE_COLORS.Normal,
      confidence: 0.90,
      riskScore,
      mlProbs: stageProbs,
      techniques: MITRE_TECHNIQUES[stage] || [],
      projectedRiskCurve,
      recentRiskHistory: [riskScore],
      source: "Live Telemetry Analysis",
    };
  }, [attackFlows, effectiveHostIp, mlForecasts, mapStageName]);

  // Calculate live evidence and telemetry statistics
  const liveSignals = useMemo(() => {
    const allFlows = Object.values(liveFlows || {});
    const flowCount = allFlows.length;
    const activeAlerts = (attackFlows || []).length;
    const primaryAttack = attackFlows && attackFlows.length > 0 ? attackFlows[0].attack_type : "No active attack";
    const primarySeverity = attackFlows && attackFlows.length > 0 ? attackFlows[0].severity : "none";

    const srcCounts = {};
    const dstCounts = {};
    const uniqueDports = new Set();

    allFlows.forEach(f => {
      if (f.src_ip) srcCounts[f.src_ip] = (srcCounts[f.src_ip] || 0) + (f.packet_count || 1);
      if (f.dst_ip) dstCounts[f.dst_ip] = (dstCounts[f.dst_ip] || 0) + (f.packet_count || 1);
      if (f.dst_port) uniqueDports.add(f.dst_port);
    });

    const topSrc = Object.entries(srcCounts).sort((a, b) => b[1] - a[1])[0]?.[0] || effectiveHostIp || "N/A";
    const topDst = Object.entries(dstCounts).sort((a, b) => b[1] - a[1])[0]?.[0] || "N/A";

    return {
      pps: packetRatePps,
      flowCount,
      activeAlerts,
      primaryAttack,
      primarySeverity,
      topSrc,
      topDst,
      uniquePortsCount: uniqueDports.size,
    };
  }, [liveFlows, attackFlows, packetRatePps, effectiveHostIp]);

  // Derive time horizon forecast cards from actual GRU risk curve
  const forecastHorizons = useMemo(() => {
    if (threatInfo.state !== "ready" || !threatInfo.projectedRiskCurve) {
      return null;
    }

    const curve = threatInfo.projectedRiskCurve;
    const history = threatInfo.recentRiskHistory || [];

    let trend = "Stable";
    let trendIcon = ArrowRight;
    let trendColor = "text-slate-400";

    if (history.length >= 2) {
      const diff = history[history.length - 1] - history[0];
      if (diff > 0.05) {
        trend = "Rising";
        trendIcon = ArrowUpRight;
        trendColor = "text-rose-400";
      } else if (diff < -0.05) {
        trend = "Decreasing";
        trendIcon = ArrowDownRight;
        trendColor = "text-emerald-400";
      }
    } else if (curve.length >= 2) {
      const diff = curve[curve.length - 1] - curve[0];
      if (diff > 0.05) {
        trend = "Rising";
        trendIcon = ArrowUpRight;
        trendColor = "text-rose-400";
      } else if (diff < -0.05) {
        trend = "Decreasing";
        trendIcon = ArrowDownRight;
        trendColor = "text-emerald-400";
      }
    }

    const getRiskLabel = (val) => {
      if (val >= 0.8) return { label: "CRITICAL", color: "text-rose-400 border-rose-900/50 bg-rose-950/20" };
      if (val >= 0.5) return { label: "HIGH", color: "text-amber-400 border-amber-900/50 bg-amber-950/20" };
      if (val >= 0.2) return { label: "MEDIUM", color: "text-yellow-400 border-yellow-900/50 bg-yellow-950/20" };
      return { label: "LOW", color: "text-emerald-400 border-emerald-900/50 bg-emerald-950/20" };
    };

    const nearVal = (curve[0] + (curve[1] || curve[0])) / 2.0;
    const shortVal = ((curve[2] || curve[0]) + (curve[3] || curve[0])) / 2.0;
    const mediumVal = ((curve[4] || curve[0]) + (curve[5] || curve[0])) / 2.0;

    return [
      {
        horizon: "NEAR TERM",
        window: "0–10 min",
        riskVal: nearVal,
        risk: getRiskLabel(nearVal),
        confidence: Math.round(threatInfo.confidence * 100),
        trend,
        trendIcon,
        trendColor,
        evidence: `Stage probability: ${Math.round((threatInfo.mlProbs?.[threatInfo.stage] || threatInfo.confidence) * 100)}% (${threatInfo.source})`,
      },
      {
        horizon: "SHORT TERM",
        window: "10–30 min",
        riskVal: shortVal,
        risk: getRiskLabel(shortVal),
        confidence: Math.round(Math.max(50, threatInfo.confidence * 100 - 5)),
        trend,
        trendIcon,
        trendColor,
        evidence: `Extrapolated risk trajectory (${(shortVal * 100).toFixed(1)}%)`,
      },
      {
        horizon: "MEDIUM TERM",
        window: "30–60 min",
        riskVal: mediumVal,
        risk: getRiskLabel(mediumVal),
        confidence: Math.round(Math.max(40, threatInfo.confidence * 100 - 12)),
        trend,
        trendIcon,
        trendColor,
        evidence: `Stage progression tendency: ${threatInfo.stage}`,
      },
    ];
  }, [threatInfo]);

  // Dynamic Recommended Action based on real traffic & threats
  const recommendation = useMemo(() => {
    const atk = liveSignals.primaryAttack;
    const stage = threatInfo.stage;
    const src = effectiveHostIp || liveSignals.topSrc;
    const dst = liveSignals.topDst;

    if (atk === "Port Scan" || stage === "Reconnaissance") {
      return {
        action: "RATE LIMIT / ISOLATE PORT",
        reason: `Destination port scanning detected from source host (${liveSignals.uniquePortsCount} target ports probed).`,
        source: src,
        target: dst,
        priority: "MEDIUM",
        color: "text-amber-400",
      };
    } else if (atk === "Brute Force" || stage === "Initial Access") {
      return {
        action: "BLOCK IP IMMEDIATELY",
        reason: `Repeated authentication attempts against service port from single source IP.`,
        source: src,
        target: dst,
        priority: "HIGH",
        color: "text-amber-400",
      };
    } else if (atk === "ICMP Flood" || atk === "DDoS" || stage === "Lateral Movement") {
      return {
        action: "RAISE FIREWALL & BLOCK IP",
        reason: `High volumetric packet flood detected (${liveSignals.pps} pps).`,
        source: src,
        target: dst,
        priority: "CRITICAL",
        color: "text-rose-400",
      };
    } else if (atk === "Data Exfiltration" || stage === "Exfiltration") {
      return {
        action: "RAISE FIREWALL & ISOLATE PORT",
        reason: `Large data exfiltration payload transfer in progress.`,
        source: src,
        target: dst,
        priority: "CRITICAL",
        color: "text-rose-400",
      };
    }

    return {
      action: "NO IMMEDIATE ACTION REQUIRED",
      reason: "Network traffic patterns and host risk levels are currently normal.",
      source: src,
      target: dst,
      priority: "LOW",
      color: "text-emerald-400",
    };
  }, [liveSignals, threatInfo, effectiveHostIp]);

  const ifaceName = selectedInterface || "No interface selected";
  const ifaceInfo = selectedInterfaceInfo;

  return (
    <div className="space-y-6 animate-fade-in pb-8">
      {/* ── 1. Monitored Host Banner + Live Host Selector ─────────────────── */}
      <section className="glass-card rounded-xl border border-cyan-900/30 p-5">
        <div className="flex items-center justify-between flex-wrap gap-4">
          <div className="flex items-center gap-4">
            <div className="relative">
              <Server className="h-8 w-8 text-cyan-400" />
              <div className="absolute inset-0 bg-cyan-400 rounded blur-lg opacity-15"></div>
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-sm font-bold uppercase tracking-wider font-mono-tech text-white">Monitored Target Host</h3>
                <span className="text-[8px] font-mono-tech text-cyan-400 bg-cyan-950/40 px-2 py-0.5 rounded border border-cyan-900/50 flex items-center gap-1">
                  <Radio className="h-2.5 w-2.5 animate-pulse" /> LIVE TELEMETRY
                </span>
              </div>
              <div className="flex items-center gap-2 mt-1">
                <span className="text-[10px] text-slate-400 font-mono-tech">Interface: <span className="text-cyan-400 font-bold">{ifaceName}</span></span>
                <span className="text-slate-600">|</span>
                <span className="text-[10px] text-slate-400 font-mono-tech">Active Hosts Discovered: <span className="text-white font-bold">{activeHostsList.length}</span></span>
              </div>
            </div>
          </div>

          <div className="flex items-center gap-3 flex-wrap">
            <div className="text-[9px] font-mono-tech bg-slate-900/80 px-3 py-1.5 rounded-lg border border-slate-800">
              <span className="text-slate-500">IP:</span>
              <span className="ml-1 font-bold text-white">{ifaceInfo?.ip || effectiveHostIp || "N/A"}</span>
            </div>
            <div className="text-[9px] font-mono-tech bg-slate-900/80 px-3 py-1.5 rounded-lg border border-slate-800">
              <span className="text-slate-500">Status:</span>
              <span className={`ml-1 font-bold ${isCapturing ? "text-emerald-400" : "text-slate-500"}`}>
                {isCapturing ? "SNIFFING LIVE" : "IDLE"}
              </span>
            </div>
          </div>
        </div>
      </section>

      {/* ── 2. MITRE ATT&CK Kill Chain Progression ──────────────────────── */}
      <section className="glass-card rounded-xl border border-slate-800/50 p-5">
        <div className="flex items-center justify-between flex-wrap gap-2 mb-4">
          <div className="flex items-center gap-2">
            <Target className="h-4 w-4 text-amber-400" />
            <h3 className="text-xs font-bold uppercase tracking-wider font-mono-tech">MITRE ATT&CK Kill Chain Progression</h3>
          </div>
          <span className="text-[8px] font-mono-tech text-slate-500 bg-slate-900 px-2 py-0.5 rounded border border-slate-800">
            Target Host: {effectiveHostIp || "All Network Hosts"}
          </span>
        </div>
        <KillChainBar currentStage={threatInfo.state === "ready" ? threatInfo.stage : "Normal"} />
      </section>

      {/* ── 3. Main Grid: Threat Prediction + Time Horizons ────────────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left (5 cols): Threat Prediction Card */}
        <div className="lg:col-span-5 space-y-6">
          <div className="glass-card rounded-xl border border-slate-800/50 p-5">
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-2">
                <ShieldAlert className="h-4 w-4 text-rose-400" />
                <h3 className="text-xs font-bold uppercase tracking-wider font-mono-tech">Threat Prediction</h3>
              </div>
              <span className="text-[8px] font-mono-tech text-cyan-400 bg-cyan-950/30 px-2 py-0.5 rounded border border-cyan-900/50">
                {threatInfo.source || "Live ML Output"}
              </span>
            </div>

            {threatInfo.state === "ready" ? (
              <div className="space-y-4">
                <div>
                  <p className="text-[9px] text-slate-500 uppercase tracking-wider font-mono-tech mb-1">Forecasted Attack Stage</p>
                  <p className="text-2xl font-black font-mono-tech tracking-wide" style={{ color: threatInfo.color }}>
                    {threatInfo.stage}
                  </p>
                  <p className="text-xs text-slate-400 font-mono-tech mt-1">
                    Confidence: <span className="text-white font-bold">{(threatInfo.confidence * 100).toFixed(1)}%</span>
                    {" "}| Risk Score: <span className="text-white font-bold">{(threatInfo.riskScore * 100).toFixed(1)}%</span>
                  </p>
                </div>

                {/* ML Stage Probabilities */}
                {threatInfo.mlProbs && (
                  <div className="space-y-2 pt-2 border-t border-slate-800/80">
                    <p className="text-[8px] text-slate-500 uppercase tracking-wider font-mono-tech">Stage Probability Distribution</p>
                    {Object.entries(threatInfo.mlProbs).map(([stage, prob]) => {
                      const pPct = Math.round(prob * 100);
                      return (
                        <div key={stage} className="space-y-0.5">
                          <div className="flex justify-between text-[9px] font-mono-tech">
                            <span className="text-slate-400">{stage}</span>
                            <span className="text-slate-300 font-bold">{pPct}%</span>
                          </div>
                          <div className="h-1.5 bg-slate-900 rounded-full overflow-hidden border border-slate-800">
                            <div
                              className="h-full rounded-full transition-all duration-500"
                              style={{ width: `${pPct}%`, backgroundColor: STAGE_COLORS[stage] || '#64748b' }}
                            />
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}

                {/* Monitored Target IP details */}
                <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-900">
                  <p className="text-[9px] text-slate-500 uppercase font-mono-tech mb-1">Target Host IP</p>
                  <p className="text-sm font-bold text-cyan-400 font-mono-tech">{effectiveHostIp || "N/A"}</p>
                  {selectedFlow && (
                    <div className="mt-2 space-y-1 text-[9px] font-mono-tech border-t border-slate-900 pt-2">
                      <div className="flex justify-between">
                        <span className="text-slate-500">Attack Classification:</span>
                        <span className="text-amber-400 font-bold">{selectedFlow.attack_type}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-slate-500">Destination Port:</span>
                        <span className="text-white font-bold">{selectedFlow.dst_port}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-slate-500">Protocol:</span>
                        <span className="text-white font-bold">{selectedFlow.protocol}</span>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            ) : (
              <div className="text-center py-8 text-slate-600 text-[10px] font-mono-tech space-y-1">
                <Target className="h-6 w-6 mx-auto mb-2 opacity-20 text-cyan-400" />
                <p className="text-slate-400 font-bold">Waiting for live traffic stream…</p>
                <p>Start a capture on Live Traffic to see real model forecasts.</p>
              </div>
            )}
          </div>
        </div>

      {/* ── 3. Main Dashboard Grid ─────────────────────────────────────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Left Column (5 cols): Threat Prediction Card — spans both rows */}
        <div className="lg:col-span-5 lg:row-span-2">
          <div className="glass-card rounded-xl border border-slate-800/50 p-5 h-full flex flex-col justify-between">
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-2">
                <ShieldAlert className="h-4 w-4 text-rose-400" />
                <h3 className="text-xs font-bold uppercase tracking-wider font-mono-tech">Threat Prediction</h3>
              </div>
              <span className="text-[8px] font-mono-tech text-cyan-400 bg-cyan-950/30 px-2 py-0.5 rounded border border-cyan-900/50">
                {threatInfo.source || "Live ML Output"}
              </span>
            </div>

            {threatInfo.state === "ready" ? (
              <div className="space-y-4">
                <div>
                  <p className="text-[9px] text-slate-500 uppercase tracking-wider font-mono-tech mb-1">Forecasted Attack Stage</p>
                  <p className="text-2xl font-black font-mono-tech tracking-wide" style={{ color: threatInfo.color }}>
                    {threatInfo.stage}
                  </p>
                  <p className="text-xs text-slate-400 font-mono-tech mt-1">
                    Confidence: <span className="text-white font-bold">{(threatInfo.confidence * 100).toFixed(1)}%</span>
                    {" "}| Risk Score: <span className="text-white font-bold">{(threatInfo.riskScore * 100).toFixed(1)}%</span>
                  </p>
                </div>

                {/* ML Stage Probabilities */}
                {threatInfo.mlProbs && (
                  <div className="space-y-2 pt-2 border-t border-slate-800/80">
                    <p className="text-[8px] text-slate-500 uppercase tracking-wider font-mono-tech">Stage Probability Distribution</p>
                    {Object.entries(threatInfo.mlProbs).map(([stage, prob]) => {
                      const pPct = Math.round(prob * 100);
                      return (
                        <div key={stage} className="space-y-0.5">
                          <div className="flex justify-between text-[9px] font-mono-tech">
                            <span className="text-slate-400">{stage}</span>
                            <span className="text-slate-300 font-bold">{pPct}%</span>
                          </div>
                          <div className="h-1.5 bg-slate-900 rounded-full overflow-hidden border border-slate-800">
                            <div
                              className="h-full rounded-full transition-all duration-500"
                              style={{ width: `${pPct}%`, backgroundColor: STAGE_COLORS[stage] || '#64748b' }}
                            />
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}

                {/* Monitored Target IP details */}
                <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-900">
                  <p className="text-[9px] text-slate-500 uppercase font-mono-tech mb-1">Target Host IP</p>
                  <p className="text-sm font-bold text-cyan-400 font-mono-tech">{effectiveHostIp || "N/A"}</p>
                  {selectedFlow && (
                    <div className="mt-2 space-y-1 text-[9px] font-mono-tech border-t border-slate-900 pt-2">
                      <div className="flex justify-between">
                        <span className="text-slate-500">Attack Classification:</span>
                        <span className="text-amber-400 font-bold">{selectedFlow.attack_type}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-slate-500">Destination Port:</span>
                        <span className="text-white font-bold">{selectedFlow.dst_port}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-slate-500">Protocol:</span>
                        <span className="text-white font-bold">{selectedFlow.protocol}</span>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            ) : (
              <div className="text-center py-8 text-slate-600 text-[10px] font-mono-tech space-y-1">
                <Target className="h-6 w-6 mx-auto mb-2 opacity-20 text-cyan-400" />
                <p className="text-slate-400 font-bold">Waiting for live traffic stream…</p>
                <p>Start a capture on Live Traffic to see real model forecasts.</p>
              </div>
            )}
          </div>
        </div>

        {/* Right Top Row (7 cols): Forecast Summary + Evidence & Signals */}
        <div className="lg:col-span-7">
          <div className="grid grid-cols-1 xl:grid-cols-12 gap-4">
            {/* Forecast Summary (7 cols) */}
            <div className="xl:col-span-7">
              <div className="glass-card rounded-xl border border-slate-800/50 p-5 h-full flex flex-col justify-between">
                <div className="flex items-center justify-between mb-3">
                  <div className="flex items-center gap-2">
                    <TrendingUp className="h-4 w-4 text-purple-400" />
                    <h3 className="text-xs font-bold uppercase tracking-wider font-mono-tech">Forecast Summary</h3>
                  </div>
                  <span className="text-[8px] font-mono-tech text-purple-400 bg-purple-950/30 px-2 py-0.5 rounded border border-purple-900/50">
                    Live
                  </span>
                </div>

                {forecastHorizons ? (
                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
                    {forecastHorizons.map((h) => {
                      const Icon = h.trendIcon;
                      return (
                        <div key={h.horizon} className="p-2.5 rounded-xl bg-slate-950/60 border border-slate-800/80 flex flex-col justify-between space-y-2">
                          <div>
                            <div className="flex items-center justify-between text-[8px] font-mono-tech text-slate-400 mb-1">
                              <span className="font-bold">{h.horizon}</span>
                              <span className="text-slate-500">{h.window}</span>
                            </div>

                            <div className="mt-1 flex items-center justify-between">
                              <span className={`px-1.5 py-0.5 rounded text-[9px] font-mono-tech font-bold border ${h.risk.color}`}>
                                {h.risk.label}
                              </span>
                              <span className="text-sm font-bold font-mono-tech text-white">
                                {(h.riskVal * 100).toFixed(0)}%
                              </span>
                            </div>
                          </div>

                          <div className="space-y-1 pt-1.5 border-t border-slate-900 text-[8px] font-mono-tech">
                            <div className="flex justify-between items-center text-slate-400">
                              <span>Conf:</span>
                              <span className="text-white font-bold">{h.confidence}%</span>
                            </div>
                            <div className="flex justify-between items-center text-slate-400">
                              <span>Trend:</span>
                              <div className={`flex items-center gap-0.5 font-bold ${h.trendColor}`}>
                                <Icon className="h-2.5 w-2.5" />
                                <span>{h.trend}</span>
                              </div>
                            </div>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                ) : (
                  <div className="p-6 text-center text-[10px] font-mono-tech text-slate-500 bg-slate-950/40 rounded-xl border border-slate-900">
                    <Clock className="h-5 w-5 mx-auto mb-1 opacity-30 text-cyan-400" />
                    <p className="text-slate-300 font-bold">Collecting live history…</p>
                  </div>
                )}
              </div>
            </div>

            {/* Evidence & Signals (5 cols) */}
            <div className="xl:col-span-5">
              <div className="glass-card rounded-xl border border-slate-800/50 p-5 h-full flex flex-col justify-between">
                <div className="flex items-center justify-between mb-3">
                  <div className="flex items-center gap-2">
                    <Activity className="h-4 w-4 text-cyan-400" />
                    <h3 className="text-xs font-bold uppercase tracking-wider font-mono-tech">Evidence & Signals</h3>
                  </div>
                  <span className="text-[8px] font-mono-tech text-cyan-400 bg-cyan-950/30 px-2 py-0.5 rounded border border-cyan-900/50">
                    Live
                  </span>
                </div>

                <div className="space-y-1.5 text-[9px] font-mono-tech">
                  <div className="flex justify-between items-center py-1 border-b border-slate-900">
                    <span className="text-slate-400">Packet Rate:</span>
                    <span className="text-cyan-400 font-bold">{liveSignals.pps} pps</span>
                  </div>
                  <div className="flex justify-between items-center py-1 border-b border-slate-900">
                    <span className="text-slate-400">Flow Rate:</span>
                    <span className="text-white font-bold">{liveSignals.flowCount} flows</span>
                  </div>
                  <div className="flex justify-between items-center py-1 border-b border-slate-900">
                    <span className="text-slate-400">Alert Count:</span>
                    <span className={`font-bold ${liveSignals.activeAlerts > 0 ? "text-rose-400" : "text-emerald-400"}`}>
                      {liveSignals.activeAlerts}
                    </span>
                  </div>
                  <div className="flex justify-between items-center py-1 border-b border-slate-900">
                    <span className="text-slate-400">Attack Type:</span>
                    <span className="text-amber-400 font-bold truncate max-w-[100px]">{liveSignals.primaryAttack}</span>
                  </div>
                  <div className="flex justify-between items-center py-1 border-b border-slate-900">
                    <span className="text-slate-400">Source IP:</span>
                    <span className="text-white font-bold truncate max-w-[100px]">{liveSignals.topSrc}</span>
                  </div>
                  <div className="flex justify-between items-center py-1 border-b border-slate-900">
                    <span className="text-slate-400">Destination IP:</span>
                    <span className="text-slate-300 font-bold truncate max-w-[100px]">{liveSignals.topDst}</span>
                  </div>
                  <div className="flex justify-between items-center py-1">
                    <span className="text-slate-400">Unique Dst Ports:</span>
                    <span className="text-purple-400 font-bold">{liveSignals.uniquePortsCount}</span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Right Bottom Row (7 cols): Recommended Action — full width of right area */}
        <div className="lg:col-span-7">
          <div className="glass-card rounded-xl border border-slate-800/50 p-5">
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-2">
                <Zap className="h-4 w-4 text-amber-400" />
                <h3 className="text-xs font-bold uppercase tracking-wider font-mono-tech">Recommended Action</h3>
              </div>
              <span className={`px-2 py-0.5 rounded text-[8px] font-mono-tech font-bold uppercase ${
                recommendation.priority === "CRITICAL" ? "bg-rose-950/50 text-rose-400 border border-rose-900/50" :
                recommendation.priority === "HIGH" ? "bg-amber-950/50 text-amber-400 border border-amber-900/50" :
                recommendation.priority === "MEDIUM" ? "bg-yellow-950/50 text-yellow-400 border border-yellow-900/50" :
                "bg-emerald-950/50 text-emerald-400 border border-emerald-900/50"
              }`}>
                {recommendation.priority} PRIORITY
              </span>
            </div>

            <div className="flex items-center justify-between flex-wrap gap-4">
              <div className="space-y-1 max-w-xl">
                <p className={`text-sm font-black font-mono-tech tracking-wide ${recommendation.color}`}>
                  {recommendation.action}
                </p>
                <p className="text-[10px] text-slate-400 font-mono-tech leading-relaxed">
                  {recommendation.reason}
                </p>
              </div>

              <div className="flex items-center gap-4 text-[9px] font-mono-tech text-slate-400">
                <div>
                  <span className="text-slate-500">Source:</span>
                  <span className="ml-1 text-white font-bold">{recommendation.source}</span>
                </div>
                <div>
                  <span className="text-slate-500">Target:</span>
                  <span className="ml-1 text-slate-300 font-bold">{recommendation.target}</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* ── 4. Full Width Bottom Section: Defensive Interventions ─────────── */}
      <section className="glass-card rounded-xl border border-slate-800/50 p-5">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <Shield className="h-4 w-4 text-emerald-400" />
            <h3 className="text-xs font-bold uppercase tracking-wider font-mono-tech">Defensive Interventions</h3>
          </div>
          <span className="text-[8px] font-mono-tech text-emerald-400 bg-emerald-950/30 px-2 py-0.5 rounded border border-emerald-900/50">
            ACTIONS ARE LIVE
          </span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <DefenseButton
            label="Rate Limit"
            icon={Gauge}
            color="bg-amber-950/10 border border-amber-800/60 hover:bg-amber-600/20 text-amber-400"
            activeColor="bg-amber-600/25 border border-amber-500 text-amber-300 glow-amber"
            isActive={currentDefense.rate_limited_ips?.includes(effectiveHostIp)}
            onClick={handleRateLimitToggle}
            loading={defenseLoading.rateLimit}
          />
          <DefenseButton
            label="Block IP"
            icon={Ban}
            color="bg-rose-950/10 border border-rose-800/60 hover:bg-rose-600/20 text-rose-400"
            activeColor="bg-rose-600/25 border border-rose-500 text-rose-300 glow-red"
            isActive={currentDefense.blocked_ips?.includes(effectiveHostIp)}
            onClick={handleBlockIpToggle}
            loading={defenseLoading.blockIp}
          />
          <DefenseButton
            label="Isolate Port"
            icon={Lock}
            color="bg-purple-950/10 border border-purple-800/60 hover:bg-purple-600/20 text-purple-400"
            activeColor="bg-purple-600/25 border border-purple-500 text-purple-300"
            isActive={currentDefense.isolated_ports?.includes(selectedFlow?.dst_port || 443)}
            onClick={handleIsolatePortToggle}
            loading={defenseLoading.isolatePort}
          />
          <DefenseButton
            label="Raise Firewall"
            icon={ShieldAlert}
            color="bg-cyan-950/10 border border-cyan-800/60 hover:bg-cyan-600/20 text-cyan-400"
            activeColor="bg-cyan-600/25 border border-cyan-500 text-cyan-300 glow-cyan"
            isActive={currentDefense.firewall_raised}
            onClick={handleFirewallToggle}
            loading={defenseLoading.firewall}
          />
        </div>

        {/* Active defense status log */}
        <div className="mt-4 space-y-1.5">
          {currentDefense.firewall_raised && (
            <div className="flex items-center gap-2 p-2 rounded-lg bg-cyan-950/20 border border-cyan-900/30 text-[10px] font-mono-tech text-cyan-400">
              <ShieldAlert className="h-3.5 w-3.5 shrink-0" />
              <span>Firewall RAISED on <span className="font-bold">{selectedInterface}</span> — all inbound traffic blocked</span>
            </div>
          )}
          {currentDefense.blocked_ips?.map(ip => (
            <div key={ip} className="flex items-center gap-2 p-2 rounded-lg bg-rose-950/20 border border-rose-900/30 text-[10px] font-mono-tech text-rose-400">
              <Ban className="h-3.5 w-3.5 shrink-0" />
              <span>IP <span className="font-bold">{ip}</span> is BLOCKED</span>
            </div>
          ))}
          {currentDefense.rate_limited_ips?.map(ip => (
            <div key={ip} className="flex items-center gap-2 p-2 rounded-lg bg-amber-950/20 border border-amber-900/30 text-[10px] font-mono-tech text-amber-400">
              <Gauge className="h-3.5 w-3.5 shrink-0" />
              <span>IP <span className="font-bold">{ip}</span> is RATE LIMITED (10 pps threshold)</span>
            </div>
          ))}
          {currentDefense.isolated_ports?.map(port => (
            <div key={port} className="flex items-center gap-2 p-2 rounded-lg bg-purple-950/20 border border-purple-900/30 text-[10px] font-mono-tech text-purple-400">
              <Lock className="h-3.5 w-3.5 shrink-0" />
              <span>Port <span className="font-bold">{port}</span> is ISOLATED</span>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}
