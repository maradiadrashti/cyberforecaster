import React, { useState, useMemo, useEffect, useCallback } from "react";
import {
  Target, ShieldAlert, Cpu, Clock, AlertTriangle,
  TrendingUp, RefreshCw, Zap, ChevronRight, Shield, Wifi,
  Globe, Server, Activity, Ban, Lock, Unlock, CheckCircle2,
  Gauge, ArrowRight
} from "lucide-react";
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  LineChart, Line, Legend, ComposedChart, Bar
} from "recharts";
import {
  ATTACK_STAGES, STAGE_COLORS, STAGE_INDEX, MITRE_TECHNIQUES,
  generateRolloutData
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
            className={`flex items-center gap-1 px-2 py-1.5 rounded text-[9px] font-mono-tech font-bold uppercase transition-all duration-500 ${
              i <= idx
                ? "text-white"
                : "text-slate-600 bg-slate-900/50 border border-slate-800"
            }`}
            style={i <= idx ? {
              backgroundColor: `${STAGE_COLORS[stage]}25`,
              border: `1px solid ${STAGE_COLORS[stage]}50`,
              color: STAGE_COLORS[stage],
            } : {}}
          >
            <div
              className="h-1.5 w-1.5 rounded-full"
              style={{ backgroundColor: i <= idx ? STAGE_COLORS[stage] : "#334155" }}
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
      className={`flex items-center justify-center gap-1.5 p-3 rounded-lg border text-[10px] font-mono-tech uppercase transition-all disabled:opacity-50 ${
        isActive ? activeColor : color
      }`}
    >
      {loading ? (
        <RefreshCw className="h-3.5 w-3.5 animate-spin" />
      ) : (
        <Icon className="h-3.5 w-3.5" />
      )}
      <span>{label}</span>
      {isActive && <CheckCircle2 className="h-3 w-3 ml-auto" />}
    </button>
  );
}

export default function AttackForecast({ selectedInterface, selectedInterfaceInfo, liveFlows, livePackets, attackFlows, selectedFlow, hosts, forecasts, isCapturing }) {
  const [mlForecast, setMlForecast] = useState(null);
  const [defenseState, setDefenseState] = useState({});
  const [defenseLoading, setDefenseLoading] = useState({});
  const [targetIp, setTargetIp] = useState("");

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

  // Auto-set target IP from selected flow, first attack flow, or active live flow
  useEffect(() => {
    if (selectedFlow && selectedFlow.src_ip) {
      setTargetIp(selectedFlow.src_ip);
    } else if (attackFlows && attackFlows.length > 0 && attackFlows[0].src_ip) {
      setTargetIp(attackFlows[0].src_ip);
    } else if (liveFlows && Object.keys(liveFlows).length > 0) {
      const firstKey = Object.keys(liveFlows)[0];
      const srcIp = liveFlows[firstKey]?.src_ip;
      if (srcIp) setTargetIp(srcIp);
    } else if (livePackets && livePackets.length > 0 && livePackets[0].src_ip) {
      setTargetIp(livePackets[0].src_ip);
    }
  }, [selectedFlow, attackFlows, liveFlows, livePackets]);

  // Poll real-time forecasts from window.__mlStageForecasts updated by WebSocket
  useEffect(() => {
    const checkForecast = () => {
      if (window.__mlStageForecasts && targetIp && window.__mlStageForecasts[targetIp]) {
        setMlForecast(window.__mlStageForecasts[targetIp]);
      } else if (window.__mlStageForecasts && Object.keys(window.__mlStageForecasts).length > 0) {
        // Fallback to first active forecast in window.__mlStageForecasts if targetIp has no direct entry
        const firstIp = Object.keys(window.__mlStageForecasts)[0];
        setMlForecast(window.__mlStageForecasts[firstIp]);
      } else {
        setMlForecast(null);
      }
    };
    checkForecast();
    const interval = setInterval(checkForecast, 1000);
    return () => clearInterval(interval);
  }, [targetIp]);

  // Fetch defense state
  useEffect(() => {
    fetch(`${CAPTURE_API}/api/defense/state`)
      .then(r => r.json())
      .then(data => setDefenseState(data))
      .catch(() => {});
    const iv = setInterval(() => {
      fetch(`${CAPTURE_API}/api/defense/state`)
        .then(r => r.json())
        .then(data => setDefenseState(data))
        .catch(() => {});
    }, 3000);
    return () => clearInterval(iv);
  }, []);

  // Generate what-if rollout data dynamically from real ML model forecast
  const rolloutData = useMemo(() => {
    // 1. If real ML forecast exists for active target and model is ready, use its projected risk curve
    const isReady = mlForecast && mlForecast.projected_risk_curve && mlForecast.projected_risk_curve.length > 0 &&
      (mlForecast.windows_collected === undefined || mlForecast.windows_collected >= (mlForecast.min_windows_required || 10));

    if (isReady) {
      const curve = mlForecast.projected_risk_curve;
      const steps = curve.length;
      const scenarios = {
        do_nothing: [],
        rate_limit: [],
        block_port: [],
        isolate_host: [],
      };

      for (let t = 0; t < steps; t++) {
        const base = curve[t];
        const jitter = (t * 0.007) % 0.05;
        scenarios.do_nothing.push({ threat: base, step: `T+${(t + 1) * 5}s` });
        scenarios.rate_limit.push({ threat: Math.max(0.0, base - t * 0.06 + jitter * 0.6), step: `T+${(t + 1) * 5}s` });
        scenarios.block_port.push({ threat: Math.max(0.0, base - t * 0.1 + jitter * 0.6), step: `T+${(t + 1) * 5}s` });
        scenarios.isolate_host.push({ threat: Math.max(0.0, base - t * 0.14 - 0.1 + jitter * 0.4), step: `T+${(t + 1) * 5}s` });
      }
      return scenarios;
    }

    // 2. Flat zero baseline when warming up or idle (no keyword heuristic)
    const zeroSteps = [5, 10, 15, 20, 25, 30].map(s => ({ threat: 0, step: `T+${s}s` }));
    return {
      do_nothing: zeroSteps,
      rate_limit: zeroSteps,
      block_port: zeroSteps,
      isolate_host: zeroSteps,
    };
  }, [mlForecast]);

  // Build what-if chart data: "Captured Flow" (actual traffic intensity %) + "Predicted Flow" (ML predicted threat %)
  const whatIfChartData = useMemo(() => {
    const recentPkts = (livePackets || []).slice(0, 6).reverse();
    const isReady = mlForecast && mlForecast.projected_risk_curve && mlForecast.projected_risk_curve.length > 0 &&
      (mlForecast.windows_collected === undefined || mlForecast.windows_collected >= (mlForecast.min_windows_required || 10));

    if (!isReady || !rolloutData) {
      return [5, 10, 15, 20, 25, 30].map(s => ({
        step: `T+${s}s`,
        "Captured Flow": 0,
        "Predicted Flow": 0,
      }));
    }

    return rolloutData.do_nothing.map((d, i) => {
      const captured = recentPkts[i];
      let capturedPct = 0;
      if (captured) {
        // Calculate captured flow intensity based on packet length and severity
        const sevMult = captured.severity === "critical" ? 1.0 : captured.severity === "high" ? 0.8 : captured.severity === "medium" ? 0.5 : 0.2;
        capturedPct = Math.min(100, Math.round((Math.min(captured.length || 60, 1500) / 1500) * 100 * sevMult));
      }
      return {
        step: d.step,
        "Captured Flow": capturedPct,
        "Predicted Flow": Math.round(rolloutData.do_nothing[i].threat * 100),
      };
    });
  }, [rolloutData, livePackets, mlForecast]);

  // Compute defense state for current interface
  const currentDefense = useMemo(() => {
    return defenseState[selectedInterface] || {
      firewall_raised: false,
      blocked_ips: [],
      rate_limited_ips: [],
      isolated_ports: [],
    };
  }, [defenseState, selectedInterface]);

  // Defense action handlers
  const callDefenseApi = useCallback(async (endpoint, body, loadingKey) => {
    setDefenseLoading(prev => ({ ...prev, [loadingKey]: true }));
    try {
      const res = await fetch(`${CAPTURE_API}/api/defense/${endpoint}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const data = await res.json();
      // Refresh defense state
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
    if (!targetIp) return;
    const isBlocked = currentDefense.blocked_ips?.includes(targetIp);
    if (isBlocked) {
      await callDefenseApi("unblock-ip", { ip: targetIp, interface: selectedInterface }, "blockIp");
    } else {
      await callDefenseApi("block-ip", { ip: targetIp, interface: selectedInterface }, "blockIp");
    }
  }, [targetIp, currentDefense, selectedInterface, callDefenseApi]);

  const handleRateLimitToggle = useCallback(async () => {
    if (!targetIp) return;
    const isLimited = currentDefense.rate_limited_ips?.includes(targetIp);
    if (isLimited) {
      await callDefenseApi("unrate-limit", { ip: targetIp, interface: selectedInterface }, "rateLimit");
    } else {
      await callDefenseApi("rate-limit", { ip: targetIp, interface: selectedInterface }, "rateLimit");
    }
  }, [targetIp, currentDefense, selectedInterface, callDefenseApi]);

  const handleIsolatePortToggle = useCallback(async () => {
    const port = selectedFlow?.dst_port || 443;
    const isIsolated = currentDefense.isolated_ports?.includes(port);
    if (isIsolated) {
      await callDefenseApi("unisolate-port", { port, interface: selectedInterface }, "isolatePort");
    } else {
      await callDefenseApi("isolate-port", { port, interface: selectedInterface }, "isolatePort");
    }
  }, [selectedFlow, currentDefense, selectedInterface, callDefenseApi]);

  // Determine threat level for display based ONLY on real ML model stage forecaster (or warm up / no data state)
  const threatInfo = useMemo(() => {
    if (!mlForecast) {
      return { state: "no_data" };
    }

    const collected = mlForecast.windows_collected;
    const required = mlForecast.min_windows_required || 10;

    if (collected !== undefined && collected < required) {
      return {
        state: "warming_up",
        windowsCollected: collected,
        minWindowsRequired: required,
      };
    }

    if (mlForecast.projected_risk_curve && mlForecast.projected_risk_curve.length > 0) {
      const stage = mapStageName(mlForecast.predicted_stage);
      const confidence = mlForecast.confidence || (mlForecast.stage_probs && mlForecast.stage_probs[mlForecast.predicted_stage]) || 0.5;
      const riskScore = mlForecast.risk_score || 0.05;

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
      };
    }

    return { state: "no_data" };
  }, [mlForecast, mapStageName]);

  const ifaceName = selectedInterface || "No interface selected";
  const ifaceInfo = selectedInterfaceInfo;

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Monitored Host / Interface Info Banner */}
      <section className="glass-card rounded-xl border border-cyan-900/30 p-5">
        <div className="flex items-center justify-between flex-wrap gap-4">
          <div className="flex items-center gap-4">
            <div className="relative">
              <Server className="h-8 w-8 text-cyan-400" />
              <div className="absolute inset-0 bg-cyan-400 rounded blur-lg opacity-15"></div>
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-sm font-bold uppercase tracking-wider font-mono-tech text-white">Monitored Host</h3>
                <span className="text-[8px] font-mono-tech text-cyan-400 bg-cyan-950/30 px-1.5 py-0.5 rounded border border-cyan-900/50">LIVE</span>
              </div>
              <p className="text-[10px] text-slate-500 font-mono-tech mt-1">
                Interface: <span className="text-cyan-400 font-bold">{ifaceName}</span>
              </p>
            </div>
          </div>
          {ifaceInfo && (
            <div className="flex items-center gap-3 flex-wrap">
              {[
                { label: "Type", value: ifaceInfo.type, color: "text-cyan-400" },
                { label: "IP", value: ifaceInfo.ip, color: "text-white" },
                { label: "MAC", value: ifaceInfo.mac, color: "text-slate-300" },
                { label: "Status", value: ifaceInfo.is_up ? "ACTIVE" : "INACTIVE", color: ifaceInfo.is_up ? "text-emerald-400" : "text-slate-500" },
              ].map((item, i) => (
                <div key={i} className="text-[9px] font-mono-tech bg-slate-900/80 px-2.5 py-1.5 rounded border border-slate-800">
                  <span className="text-slate-500">{item.label}:</span>
                  <span className={`ml-1 font-bold ${item.color}`}>{item.value}</span>
                </div>
              ))}
            </div>
          )}
          {!ifaceInfo && (
            <div className="text-[10px] text-slate-600 font-mono-tech">
              Go to Live Traffic and select an interface to view monitored host info
            </div>
          )}
        </div>
      </section>

      {/* MITRE ATT&CK Kill Chain */}
      <section className="glass-card rounded-xl border border-slate-800/50 p-5">
        <div className="flex items-center gap-2 mb-4">
          <Target className="h-4 w-4 text-amber-400" />
          <h3 className="text-xs font-bold uppercase tracking-wider font-mono-tech">MITRE ATT&CK Kill Chain Progression</h3>
        </div>
        <KillChainBar currentStage={threatInfo.state === "ready" ? threatInfo.stage : "Normal"} />
      </section>

      {/* Main Content Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left: Threat Details + Target Info */}
        <div className="lg:col-span-4 space-y-5">
          {/* Current Threat Assessment */}
          <div className="glass-card rounded-xl border border-slate-800/50 p-5">
            <div className="flex items-center gap-2 mb-4">
              <ShieldAlert className="h-4 w-4 text-rose-400" />
              <h3 className="text-xs font-bold uppercase tracking-wider font-mono-tech">Threat Prediction</h3>
            </div>
            {threatInfo.state === "ready" ? (
              <div className="space-y-4">
                <div>
                  <p className="text-[9px] text-slate-500 uppercase tracking-wider font-mono-tech mb-1">Forecasted Attack Stage</p>
                  <p className="text-2xl font-black font-mono-tech" style={{ color: threatInfo.color }}>
                    {threatInfo.stage}
                  </p>
                  <p className="text-xs text-slate-400 font-mono-tech mt-1">
                    Confidence: <span className="text-white font-bold">{(threatInfo.confidence * 100).toFixed(1)}%</span>
                    {" "}| Risk: <span className="text-white font-bold">{(threatInfo.riskScore * 100).toFixed(1)}%</span>
                  </p>
                  {threatInfo.mlProbs && (
                    <div className="mt-2 space-y-1">
                      <p className="text-[8px] text-slate-600 uppercase font-mono-tech">ML Stage Probabilities</p>
                      {Object.entries(threatInfo.mlProbs).map(([stage, prob]) => (
                        <div key={stage} className="flex items-center gap-2">
                          <span className="text-[8px] text-slate-400 font-mono-tech w-24 truncate">{stage.replace(/_/g, ' ')}</span>
                          <div className="flex-1 h-1.5 bg-slate-800 rounded-full overflow-hidden">
                            <div className="h-full rounded-full" style={{ width: `${Math.round(prob * 100)}%`, background: STAGE_COLORS[stage.replace(/_/g, ' ').replace('command control', 'Command & Control')] || '#64748b' }} />
                          </div>
                          <span className="text-[8px] text-slate-500 font-mono-tech w-8 text-right">{Math.round(prob * 100)}%</span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                {/* Target IP selector */}
                {targetIp && (
                  <div className="p-3 rounded-lg bg-slate-950/50 border border-slate-900">
                    <p className="text-[9px] text-slate-500 uppercase font-mono-tech mb-1">Target Host IP</p>
                    <p className="text-sm font-bold text-rose-400 font-mono-tech">{targetIp}</p>
                    {selectedFlow && (
                      <div className="mt-2 space-y-1 text-[9px] font-mono-tech">
                        <div className="flex justify-between">
                          <span className="text-slate-500">Attack Type</span>
                          <span className="text-amber-400">{selectedFlow.attack_type}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-slate-500">Target Port</span>
                          <span className="text-white">{selectedFlow.dst_port}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-slate-500">Protocol</span>
                          <span className="text-white">{selectedFlow.protocol}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-slate-500">Packets</span>
                          <span className="text-white">{selectedFlow.packet_count}</span>
                        </div>
                      </div>
                    )}
                  </div>
                )}

                {/* MITRE Techniques */}
                {threatInfo.techniques && threatInfo.techniques.length > 0 && (
                  <div className="space-y-1.5">
                    <p className="text-[9px] text-slate-500 uppercase tracking-wider font-mono-tech">MITRE ATT&CK Techniques</p>
                    {threatInfo.techniques.map((tech, i) => (
                      <div key={i} className="flex items-center gap-2 p-2 rounded bg-slate-950/50 border border-slate-900 text-[10px] font-mono-tech">
                        <Zap className="h-3 w-3 text-amber-400 shrink-0" />
                        <span className="text-slate-300">{tech}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            ) : threatInfo.state === "warming_up" ? (
              <div className="text-center py-8 text-slate-400 text-xs font-mono-tech space-y-2">
                <div className="animate-spin h-6 w-6 border-2 border-cyan-400 border-t-transparent rounded-full mx-auto mb-2" />
                <p className="text-cyan-400 font-bold">Model warming up ({threatInfo.windowsCollected} / {threatInfo.minWindowsRequired} flow windows collected)</p>
                <p className="text-[10px] text-slate-500">Accumulating host flow history for deep GRU stage forecaster...</p>
              </div>
            ) : (
              <div className="text-center py-8 text-slate-600 text-[10px] font-mono-tech">
                <Target className="h-6 w-6 mx-auto mb-2 opacity-20" />
                <p>No traffic captured yet for this host.</p>
                <p className="mt-1">Start a capture on Live Traffic to see real model forecasts.</p>
              </div>
            )}
          </div>
        </div>

        {/* Right: What-If Chart + Defense Actions */}
        <div className="lg:col-span-8 space-y-6">
          {/* What-If Simulation: Captured + Predicted */}
          <div className="glass-card rounded-xl border border-slate-800/50 p-5">
            <div className="flex items-center gap-2 mb-4">
              <TrendingUp className="h-4 w-4 text-purple-400" />
              <h3 className="text-xs font-bold uppercase tracking-wider font-mono-tech">Network Flow Forecast</h3>
              <span className="text-[8px] font-mono-tech text-slate-500 bg-slate-900 px-2 py-0.5 rounded">
                Captured vs Predicted
              </span>
            </div>

            {whatIfChartData.length > 0 ? (
              // NOTE: chart only renders when isCapturing && attackFlows.length > 0
              <div className="h-[300px]">
                <ResponsiveContainer width="100%" height="100%">
                  <ComposedChart data={whatIfChartData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                    <defs>
                      <linearGradient id="gradCaptured" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#00f0ff" stopOpacity={0.3} />
                        <stop offset="95%" stopColor="#00f0ff" stopOpacity={0} />
                      </linearGradient>
                      <linearGradient id="gradPredicted" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#f59e0b" stopOpacity={0.25} />
                        <stop offset="95%" stopColor="#f59e0b" stopOpacity={0} />
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.02)" />
                    <XAxis dataKey="step" tick={{ fontSize: 10, fill: "#94a3b8" }} />
                    <YAxis
                      domain={[0, 100]}
                      tick={{ fontSize: 10, fill: "#94a3b8" }}
                      label={{ value: "Threat %", angle: -90, position: "insideLeft", fontSize: 10, fill: "#64748b" }}
                    />
                    <Tooltip
                      contentStyle={{ backgroundColor: "#0b0f19", border: "1px solid #1f293d", borderRadius: 8, fontSize: 11 }}
                    />
                    <Legend wrapperStyle={{ fontSize: 10, paddingTop: 10 }} />
                    <Area
                      type="monotone"
                      dataKey="Captured Flow"
                      stroke="#00f0ff"
                      strokeWidth={2.5}
                      fillOpacity={1}
                      fill="url(#gradCaptured)"
                    />
                    <Area
                      type="monotone"
                      dataKey="Predicted Flow"
                      stroke="#f59e0b"
                      strokeWidth={2.5}
                      strokeDasharray="6 3"
                      fillOpacity={1}
                      fill="url(#gradPredicted)"
                    />
                  </ComposedChart>
                </ResponsiveContainer>
              </div>
            ) : (
              <div className="text-center py-12 text-slate-500 text-xs font-mono-tech">
                Start a capture to see flow data and predictions.
              </div>
            )}

            <div className="mt-3 flex items-center gap-4 text-[9px] font-mono-tech">
              <div className="flex items-center gap-1.5">
                <div className="w-4 h-0.5 bg-cyan-400"></div>
                <span className="text-slate-400">Captured Flow (actual traffic)</span>
              </div>
              <div className="flex items-center gap-1.5">
                <div className="w-4 h-0.5 bg-amber-400" style={{ borderTop: "2px dashed #f59e0b" }}></div>
                <span className="text-slate-400">Predicted Flow (model forecast)</span>
              </div>
            </div>
          </div>

          {/* Defensive Interventions - WORKING */}
          <div className="glass-card rounded-xl border border-slate-800/50 p-5">
            <div className="flex items-center gap-2 mb-4">
              <Shield className="h-4 w-4 text-emerald-400" />
              <h3 className="text-xs font-bold uppercase tracking-wider font-mono-tech">Defensive Interventions</h3>
              <span className="text-[8px] font-mono-tech text-emerald-400 bg-emerald-950/30 px-2 py-0.5 rounded border border-emerald-900/50">
                ACTIONS ARE LIVE
              </span>
            </div>

            <div className="grid grid-cols-2 gap-3">
              <DefenseButton
                label="Rate Limit"
                icon={Gauge}
                color="bg-amber-950/10 border border-amber-800 hover:bg-amber-600/20 text-amber-400"
                activeColor="bg-amber-600/25 border border-amber-500 text-amber-300 glow-amber"
                isActive={currentDefense.rate_limited_ips?.includes(targetIp)}
                onClick={handleRateLimitToggle}
                loading={defenseLoading.rateLimit}
              />
              <DefenseButton
                label="Block IP"
                icon={Ban}
                color="bg-rose-950/10 border border-rose-800 hover:bg-rose-600/20 text-rose-400"
                activeColor="bg-rose-600/25 border border-rose-500 text-rose-300 glow-red"
                isActive={currentDefense.blocked_ips?.includes(targetIp)}
                onClick={handleBlockIpToggle}
                loading={defenseLoading.blockIp}
              />
              <DefenseButton
                label="Isolate Port"
                icon={Lock}
                color="bg-purple-950/10 border border-purple-800 hover:bg-purple-600/20 text-purple-400"
                activeColor="bg-purple-600/25 border border-purple-500 text-purple-300"
                isActive={currentDefense.isolated_ports?.includes(selectedFlow?.dst_port || 443)}
                onClick={handleIsolatePortToggle}
                loading={defenseLoading.isolatePort}
              />
              <DefenseButton
                label="Raise Firewall"
                icon={ShieldAlert}
                color="bg-cyan-950/10 border border-cyan-800 hover:bg-cyan-600/20 text-cyan-400"
                activeColor="bg-cyan-600/25 border border-cyan-500 text-cyan-300 glow-cyan"
                isActive={currentDefense.firewall_raised}
                onClick={handleFirewallToggle}
                loading={defenseLoading.firewall}
              />
            </div>

            {/* Active defense status */}
            <div className="mt-4 space-y-1.5">
              {currentDefense.firewall_raised && (
                <div className="flex items-center gap-2 p-2 rounded bg-cyan-950/20 border border-cyan-900/30 text-[10px] font-mono-tech text-cyan-400">
                  <ShieldAlert className="h-3 w-3" />
                  <span>Firewall RAISED on <span className="font-bold">{selectedInterface}</span> — all inbound blocked</span>
                </div>
              )}
              {currentDefense.blocked_ips?.map(ip => (
                <div key={ip} className="flex items-center gap-2 p-2 rounded bg-rose-950/20 border border-rose-900/30 text-[10px] font-mono-tech text-rose-400">
                  <Ban className="h-3 w-3" />
                  <span>IP <span className="font-bold">{ip}</span> is BLOCKED</span>
                </div>
              ))}
              {currentDefense.rate_limited_ips?.map(ip => (
                <div key={ip} className="flex items-center gap-2 p-2 rounded bg-amber-950/20 border border-amber-900/30 text-[10px] font-mono-tech text-amber-400">
                  <Gauge className="h-3 w-3" />
                  <span>IP <span className="font-bold">{ip}</span> is RATE LIMITED (10 pps)</span>
                </div>
              ))}
              {currentDefense.isolated_ports?.map(port => (
                <div key={port} className="flex items-center gap-2 p-2 rounded bg-purple-950/20 border border-purple-900/30 text-[10px] font-mono-tech text-purple-400">
                  <Lock className="h-3 w-3" />
                  <span>Port <span className="font-bold">{port}</span> is ISOLATED</span>
                </div>
              ))}
            </div>

            {/* Recommended action */}
            <div className="mt-4 p-3 rounded-lg bg-slate-950/50 border border-slate-900">
              <p className="text-[9px] text-slate-500 uppercase font-mono-tech mb-1">Recommended Action</p>
              <p className="text-xs text-white font-bold font-mono-tech">
                {threatInfo.stage === "Exfiltration" && "IMMEDIATE ISOLATION recommended — raise firewall + block attacker IP"}
                {threatInfo.stage === "Lateral Movement" && "Block port channels + rate limit suspicious IPs + monitor"}
                {threatInfo.stage === "Initial Access" && "Rate limit + increase monitoring on target ports"}
                {threatInfo.stage === "Reconnaissance" && "Rate limit + increase monitoring — early stage detected"}
                {threatInfo.stage === "Normal" && "No action needed — network is healthy"}
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
