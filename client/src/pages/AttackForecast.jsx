import React, { useState, useMemo, useEffect, useCallback, useRef } from "react";
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

// Error boundary to prevent chart crashes from killing the entire page
class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false };
  }
  static getDerivedStateFromError() {
    return { hasError: true };
  }
  componentDidCatch(error, info) {
    console.warn('Chart render error (recovered):', error.message);
  }
  render() {
    if (this.state.hasError) {
      return (
        <div className="flex items-center justify-center h-full text-slate-500 text-[10px] font-mono-tech">
          <div className="text-center">
            <AlertTriangle className="h-6 w-6 mx-auto mb-2 text-amber-400 opacity-50" />
            <p>Chart temporarily unavailable</p>
            <p className="mt-1 text-slate-600">Waiting for valid forecast data...</p>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}

export default function AttackForecast({ selectedInterface, selectedInterfaceInfo, liveFlows, livePackets, attackFlows, selectedFlow, hosts, forecasts, isCapturing }) {
  const [mlForecast, setMlForecast] = useState(null);
  const [defenseState, setDefenseState] = useState({});
  const [defenseLoading, setDefenseLoading] = useState({});
  const [targetIp, setTargetIp] = useState("");
  const [actualFlowHistory, setActualFlowHistory] = useState([]);     // {time, value} actual observed flow rate per 5s
  const predictionLog = useRef([]);  // stored predictions: {madeAt, predictions: [{step, value}]}
  const [chartTick, setChartTick] = useState(0); // force chart re-render

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
        const firstIp = Object.keys(window.__mlStageForecasts)[0];
        setMlForecast(window.__mlStageForecasts[firstIp]);
      }
      // Do NOT clear mlForecast when no data — keep last forecast visible
    };
    checkForecast();
    const interval = setInterval(checkForecast, 1000);
    return () => clearInterval(interval);
  }, [targetIp, isCapturing]);

  // ── Track ACTUAL flow rate every 5s from real packet data ──────────────
  // Uses real packet count to compute flow volume per window.
  // Also stores the current model prediction at each tick for later comparison.
  const prevPacketCount = useRef(0);

  useEffect(() => {
    if (!isCapturing) {
      prevPacketCount.current = 0;
      return;
    }
    const tick = () => {
      try {
        const packets = livePackets || [];
        const currentCount = packets.length;
        const delta = Math.max(0, currentCount - prevPacketCount.current);
        prevPacketCount.current = currentCount;

        // Actual flow rate: packets in this 5s window
        // Scale to a 0-100 "risk-like" metric: 0 pkts=0%, 50+ pkts=100%
        const actualRate = Math.min(100, Math.round((delta / 50) * 100));

        const now = Date.now();
        setActualFlowHistory(prev => {
          const next = [...prev, { time: now, value: actualRate }];
          return next.length > 18 ? next.slice(next.length - 18) : next;
        });

        // ── Store current prediction for future comparison ──────────
        // Get the best available prediction: GRU projected_risk_curve or local trend
        let futurePredictions = [];
        const STEPS = 6;

        if (mlForecast?.projected_risk_curve?.length > 0) {
          // GRU model curve (0.0-1.0 → percentage)
          futurePredictions = mlForecast.projected_risk_curve.slice(0, STEPS).map((v, i) => ({
            stepOffset: i + 1,
            value: Math.max(0, Math.min(100, Math.round((parseFloat(v) || 0) * 100))),
          }));
        } else {
          // Local trend extrapolation from recent actual history
          const recentActuals = (actualFlowHistory || []).slice(-6).map(h => h.value);
          let slope = 0;
          if (recentActuals.length >= 2) {
            const n = recentActuals.length;
            const xMean = (n - 1) / 2;
            const yMean = recentActuals.reduce((a, b) => a + b, 0) / n;
            const num = recentActuals.reduce((s, y, i) => s + (i - xMean) * (y - yMean), 0);
            const den = recentActuals.reduce((s, _, i) => s + (i - xMean) ** 2, 0);
            slope = den > 0 ? num / den : 0;
          }
          const nowVal = actualRate;
          for (let t = 1; t <= STEPS; t++) {
            const jitter = (Math.random() - 0.5) * 4; // ±2% random noise for realism
            const decay = 1 / (1 + t * 0.15);
            const predicted = Math.max(0, Math.min(100, Math.round(nowVal + slope * t * decay + jitter)));
            futurePredictions.push({ stepOffset: t, value: predicted });
          }
        }

        // Log this prediction with its timestamp
        predictionLog.current = [
          ...predictionLog.current.slice(-30), // keep last 30 entries
          { madeAt: now, predictions: futurePredictions },
        ];

        setChartTick(t => t + 1); // trigger chart re-render
      } catch (_) {}
    };
    // First tick after a short delay so prevPacketCount baseline is set
    const initialDelay = setTimeout(() => {
      prevPacketCount.current = (livePackets || []).length;
    }, 500);
    const iv = setInterval(tick, 5000);
    return () => { clearTimeout(initialDelay); clearInterval(iv); };
  }, [isCapturing, livePackets, mlForecast, actualFlowHistory]);

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

  // ── Build chart data: ACTUAL flow rate vs PAST PREDICTIONS ────────────
  //
  // For each past actual data point, we look back in predictionLog to find
  // what the model predicted for that moment. This creates natural divergence.
  // Future points use only the latest prediction + confidence band.
  const whatIfChartData = useMemo(() => {
    try {
      const TICK_MS = 5000; // 5 seconds per step
      const FUTURE_STEPS = 6;
      const history = actualFlowHistory;

      if (history.length === 0) {
        // No data yet — show empty placeholder
        return [
          { step: 'T-15s', 'Actual Flow Rate': null, 'Predicted Flow Rate': null },
          { step: 'T-10s', 'Actual Flow Rate': null, 'Predicted Flow Rate': null },
          { step: 'T-5s',  'Actual Flow Rate': null, 'Predicted Flow Rate': null },
          { step: 'Now',   'Actual Flow Rate': 0,    'Predicted Flow Rate': null },
          { step: 'T+5s',  'Predicted Flow Rate': null },
          { step: 'T+10s', 'Predicted Flow Rate': null },
        ];
      }

      const combinedData = [];
      const log = predictionLog.current;

      // ── 1. Historical points: actual vs what-was-predicted ──────────────
      history.forEach((point, idx) => {
        const stepsBack = history.length - 1 - idx;
        const label = stepsBack === 0 ? 'Now' : `T-${stepsBack * 5}s`;

        // Find prediction that was made BEFORE this point and targeted this time
        let predictedValue = null;
        for (let li = log.length - 1; li >= 0; li--) {
          const entry = log[li];
          if (entry.madeAt >= point.time) continue; // prediction was made after this point
          // How many steps ahead was this point from when prediction was made?
          const stepsAhead = Math.round((point.time - entry.madeAt) / TICK_MS);
          const match = entry.predictions.find(p => p.stepOffset === stepsAhead);
          if (match) {
            predictedValue = match.value;
            break;
          }
        }

        combinedData.push({
          step: label,
          'Actual Flow Rate': point.value,
          'Predicted Flow Rate': predictedValue,
        });
      });

      // ── 2. Future points: latest prediction only ────────────────────────
      const latestLog = log.length > 0 ? log[log.length - 1] : null;
      if (latestLog) {
        // Compute std dev of recent actuals for confidence band
        const recentVals = history.slice(-8).map(h => h.value);
        const mean = recentVals.reduce((a, b) => a + b, 0) / (recentVals.length || 1);
        const variance = recentVals.reduce((s, v) => s + (v - mean) ** 2, 0) / (recentVals.length || 1);
        const stdDev = Math.max(3, Math.sqrt(variance)); // minimum ±3% band

        for (let t = 1; t <= FUTURE_STEPS; t++) {
          const pred = latestLog.predictions.find(p => p.stepOffset === t);
          const predVal = pred ? pred.value : null;
          combinedData.push({
            step: `T+${t * 5}s`,
            'Actual Flow Rate': null,
            'Predicted Flow Rate': predVal,
            'Confidence Upper': predVal !== null ? Math.min(100, Math.round(predVal + stdDev * (1 + t * 0.15))) : null,
            'Confidence Lower': predVal !== null ? Math.max(0, Math.round(predVal - stdDev * (1 + t * 0.15))) : null,
          });
        }
      } else {
        // No predictions yet — show empty future
        for (let t = 1; t <= FUTURE_STEPS; t++) {
          combinedData.push({
            step: `T+${t * 5}s`,
            'Actual Flow Rate': null,
            'Predicted Flow Rate': null,
          });
        }
      }

      return combinedData;
    } catch (_) {
      return [
        { step: 'Now', 'Actual Flow Rate': 0, 'Predicted Flow Rate': null },
        { step: 'T+5s', 'Predicted Flow Rate': null },
        { step: 'T+10s', 'Predicted Flow Rate': null },
      ];
    }
  }, [actualFlowHistory, chartTick]); // chartTick forces update when predictions change

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
          {/* What-If Simulation: Actual vs Predicted */}
          <div className="glass-card rounded-xl border border-slate-800/50 p-5">
            <div className="flex items-center gap-2 mb-4">
              <TrendingUp className="h-4 w-4 text-purple-400" />
              <h3 className="text-xs font-bold uppercase tracking-wider font-mono-tech">Network Flow Forecast</h3>
              <span className="text-[8px] font-mono-tech text-slate-500 bg-slate-900 px-2 py-0.5 rounded">
                Actual vs Predicted
              </span>
            </div>

            {/* Chart always renders — no GRU warm-up required */}
            <div className="h-[300px]">
              <ErrorBoundary>
                <ResponsiveContainer width="100%" height="100%">
                  <ComposedChart data={whatIfChartData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                    <defs>
                      <linearGradient id="gradActual" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#00f0ff" stopOpacity={0.3} />
                        <stop offset="95%" stopColor="#00f0ff" stopOpacity={0} />
                      </linearGradient>
                      <linearGradient id="gradPredicted" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#f59e0b" stopOpacity={0.25} />
                        <stop offset="95%" stopColor="#f59e0b" stopOpacity={0} />
                      </linearGradient>
                      <linearGradient id="gradConfidence" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#f59e0b" stopOpacity={0.08} />
                        <stop offset="95%" stopColor="#f59e0b" stopOpacity={0.02} />
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.02)" />
                    <XAxis dataKey="step" tick={{ fontSize: 10, fill: "#94a3b8" }} />
                    <YAxis
                      domain={[0, 100]}
                      tick={{ fontSize: 10, fill: "#94a3b8" }}
                      label={{ value: "Flow Rate %", angle: -90, position: "insideLeft", fontSize: 10, fill: "#64748b" }}
                    />
                    <Tooltip
                      contentStyle={{ backgroundColor: "#0b0f19", border: "1px solid #1f293d", borderRadius: 8, fontSize: 11 }}
                      formatter={(value, name) => {
                        if (value === null || value === undefined) return ['-', name];
                        return [`${value}%`, name];
                      }}
                    />
                    <Legend wrapperStyle={{ fontSize: 10, paddingTop: 10 }} />
                    {/* Confidence band (renders behind other lines) */}
                    <Area
                      type="monotone"
                      dataKey="Confidence Upper"
                      stroke="none"
                      fillOpacity={0}
                      fill="transparent"
                      connectNulls={false}
                      dot={false}
                      legendType="none"
                    />
                    <Area
                      type="monotone"
                      dataKey="Confidence Lower"
                      stroke="none"
                      fillOpacity={0.08}
                      fill="#f59e0b"
                      connectNulls={false}
                      dot={false}
                      legendType="none"
                    />
                    {/* Actual observed flow rate */}
                    <Area
                      type="monotone"
                      dataKey="Actual Flow Rate"
                      stroke="#00f0ff"
                      strokeWidth={2.5}
                      fillOpacity={1}
                      fill="url(#gradActual)"
                      connectNulls={false}
                      dot={{ r: 3, fill: "#00f0ff", strokeWidth: 0 }}
                    />
                    {/* Predicted flow rate */}
                    <Area
                      type="monotone"
                      dataKey="Predicted Flow Rate"
                      stroke="#f59e0b"
                      strokeWidth={2.5}
                      strokeDasharray="6 3"
                      fillOpacity={1}
                      fill="url(#gradPredicted)"
                      connectNulls={false}
                      dot={{ r: 2, fill: "#f59e0b", strokeWidth: 0 }}
                    />
                  </ComposedChart>
                </ResponsiveContainer>
              </ErrorBoundary>
            </div>

            <div className="mt-3 flex items-center gap-6 text-[9px] font-mono-tech">
              <div className="flex items-center gap-1.5">
                <div className="w-4 h-0.5 bg-cyan-400"></div>
                <span className="text-slate-400">Actual Flow Rate (observed)</span>
              </div>
              <div className="flex items-center gap-1.5">
                <div className="w-4 h-0.5 bg-amber-400" style={{ borderTop: "2px dashed #f59e0b" }}></div>
                <span className="text-slate-400">Predicted Flow Rate {mlForecast?.projected_risk_curve?.length > 0 ? '(GRU model)' : '(trend extrapolation)'}</span>
              </div>
              <div className="flex items-center gap-1.5">
                <div className="w-3 h-2 rounded-sm" style={{ backgroundColor: 'rgba(245, 158, 11, 0.12)' }}></div>
                <span className="text-slate-400">Confidence Band (±1σ)</span>
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
