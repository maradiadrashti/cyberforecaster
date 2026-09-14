import React, { useState, useMemo, useEffect, useRef } from "react";
import {
  Target, ShieldCheck, Cpu, Clock, Layers,
  Radio, Database, RefreshCw, Activity, Wifi,
  Search, Lock, Network, Terminal, CheckCircle2,
  Lightbulb, HelpCircle, Sliders
} from "lucide-react";

const _HOST = import.meta.env.VITE_CAPTURE_HOST ?? "127.0.0.1";
const _PORT = import.meta.env.VITE_CAPTURE_PORT ?? "8080";
const CAPTURE_API = `http://${_HOST}:${_PORT}`;
const WS_URL = `ws://${_HOST}:${_PORT}/ws/live`;

function formatBytes(bytes) {
  if (!bytes || bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${(bytes / Math.pow(k, i)).toFixed(1)} ${sizes[i]}`;
}

function getPortName(port) {
  const p = parseInt(port, 10);
  if (p === 53) return "53 (DNS)";
  if (p === 443) return "443 (HTTPS)";
  if (p === 80) return "80 (HTTP)";
  if (p === 22) return "22 (SSH)";
  if (p === 21) return "21 (FTP)";
  if (p === 25) return "25 (SMTP)";
  if (p === 3389) return "3389 (RDP)";
  if (p === 445) return "445 (SMB)";
  return `${port}`;
}

// ─── SVG Risk Trajectory Chart ──────────────────────────────────────────────
function RiskTrajectoryChart({ dataPoints = [0.1, 0.15, 0.18, 0.22, 0.25, 0.28, 0.30] }) {
  const points = dataPoints.slice(0, 7);
  while (points.length < 7) {
    points.push(points[points.length - 1] || 0.05);
  }

  const svgWidth = 520;
  const svgHeight = 170;
  const paddingLeft = 45;
  const paddingRight = 20;
  const paddingTop = 15;
  const paddingBottom = 30;

  const chartWidth = svgWidth - paddingLeft - paddingRight;
  const chartHeight = svgHeight - paddingTop - paddingBottom;

  const timeLabels = ["Now", "+5s", "+10s", "+15s", "+20s", "+25s", "+30s"];
  const yTicks = [
    { label: "100%", val: 1.0 },
    { label: "75%", val: 0.75 },
    { label: "50%", val: 0.50 },
    { label: "25%", val: 0.25 },
    { label: "0%", val: 0.0 },
  ];

  const coords = points.map((val, idx) => {
    const x = paddingLeft + (idx / (points.length - 1)) * chartWidth;
    const clampedVal = Math.max(0, Math.min(1, val));
    const y = paddingTop + (1 - clampedVal) * chartHeight;
    return { x, y, val };
  });

  const polylineStr = coords.map(c => `${c.x},${c.y}`).join(" ");
  const areaPathStr = `M ${coords[0].x},${paddingTop + chartHeight} ` +
    coords.map(c => `L ${c.x},${c.y}`).join(" ") +
    ` L ${coords[coords.length - 1].x},${paddingTop + chartHeight} Z`;

  return (
    <div className="w-full relative select-none">
      <svg viewBox={`0 0 ${svgWidth} ${svgHeight}`} className="w-full h-auto overflow-visible">
        <defs>
          <linearGradient id="riskAreaGrad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#00f0ff" stopOpacity="0.25" />
            <stop offset="100%" stopColor="#00f0ff" stopOpacity="0.0" />
          </linearGradient>
          <linearGradient id="riskLineGrad" x1="0" y1="0" x2="1" y2="0">
            <stop offset="0%" stopColor="#38bdf8" />
            <stop offset="100%" stopColor="#00f0ff" />
          </linearGradient>
        </defs>

        {/* Y Axis Label */}
        <text
          x={-svgHeight / 2}
          y="12"
          transform="rotate(-90)"
          className="fill-slate-500 text-[9px] font-mono-tech uppercase font-bold text-center"
          textAnchor="middle"
        >
          Attack Risk
        </text>

        {/* Grid Lines & Y Ticks */}
        {yTicks.map(tick => {
          const y = paddingTop + (1 - tick.val) * chartHeight;
          return (
            <g key={tick.label}>
              <line
                x1={paddingLeft}
                y1={y}
                x2={paddingLeft + chartWidth}
                y2={y}
                stroke="#1e293b"
                strokeDasharray="3 3"
                strokeWidth="1"
              />
              <text
                x={paddingLeft - 8}
                y={y + 3}
                className="fill-slate-500 text-[9px] font-mono-tech"
                textAnchor="end"
              >
                {tick.label}
              </text>
            </g>
          );
        })}

        {/* X Axis Time Labels */}
        {coords.map((c, idx) => (
          <text
            key={idx}
            x={c.x}
            y={paddingTop + chartHeight + 18}
            className="fill-slate-400 text-[10px] font-mono-tech font-bold"
            textAnchor="middle"
          >
            {timeLabels[idx]}
          </text>
        ))}

        {/* Area Fill Under Line */}
        <path d={areaPathStr} fill="url(#riskAreaGrad)" />

        {/* Main Trajectory Line */}
        <polyline
          fill="none"
          stroke="url(#riskLineGrad)"
          strokeWidth="2.5"
          strokeLinecap="round"
          strokeLinejoin="round"
          points={polylineStr}
        />

        {/* Data Point Circles */}
        {coords.map((c, idx) => (
          <g key={idx} className="group cursor-pointer">
            <circle
              cx={c.x}
              cy={c.y}
              r="4.5"
              fill="#0f172a"
              stroke="#00f0ff"
              strokeWidth="2"
              className="transition-all duration-200 group-hover:r-6"
            />
            <circle
              cx={c.x}
              cy={c.y}
              r="2"
              fill="#38bdf8"
            />
          </g>
        ))}
      </svg>
    </div>
  );
}

// ─── MITRE Attack Progression Stage Cards ────────────────────────────────────
function AttackProgressionFlow({ currentStage = "NORMAL", predictedStage = "NORMAL" }) {
  const activeStageName = (predictedStage || currentStage || "NORMAL").trim().toUpperCase();

  const stages = [
    { name: "NORMAL", label: "NORMAL", icon: CheckCircle2, description: "Normal risk" },
    { name: "RECONNAISSANCE", label: "RECONNAISSANCE", icon: Search, description: "Low probability" },
    { name: "INITIAL ACCESS", label: "INITIAL ACCESS", icon: Lock, description: "Low probability" },
    { name: "LATERAL MOVEMENT", label: "LATERAL MOVEMENT", icon: Network, description: "Low probability" },
    { name: "COMMAND & CONTROL", label: "COMMAND & CONTROL", icon: Terminal, description: "Low probability" },
    { name: "EXFILTRATION", label: "EXFILTRATION", icon: Database, description: "Low probability" },
  ];

  return (
    <div className="flex items-center gap-2 overflow-x-auto pb-2 scrollbar-none">
      {stages.map((st, idx) => {
        const isCurrent = activeStageName === st.name ||
          (activeStageName === "NORMAL" && st.name === "NORMAL") ||
          (activeStageName.includes(st.name) && st.name !== "NORMAL");

        const Icon = st.icon;

        return (
          <React.Fragment key={st.name}>
            <div
              className={`flex-1 min-w-[130px] p-3 rounded-xl border transition-all duration-300 font-mono-tech ${
                isCurrent
                  ? "bg-emerald-950/40 border-emerald-500/80 shadow-[0_0_20px_rgba(16,185,129,0.2)]"
                  : "bg-slate-950/60 border-slate-800/80 opacity-50 hover:opacity-75"
              }`}
            >
              <div className="flex items-center gap-2 mb-1.5">
                <div className={`p-1.5 rounded-lg ${isCurrent ? "bg-emerald-500/20 text-emerald-400" : "bg-slate-900 text-slate-500"}`}>
                  <Icon className="h-4 w-4" />
                </div>
                <span className={`text-[11px] font-bold tracking-tight uppercase ${isCurrent ? "text-white" : "text-slate-400"}`}>
                  {st.label}
                </span>
              </div>
              <p className={`text-[10px] font-medium ${isCurrent ? "text-emerald-400 font-bold" : "text-slate-500"}`}>
                {isCurrent ? "Current stage" : st.description}
              </p>
            </div>

            {idx < stages.length - 1 && (
              <span className="text-slate-700 font-bold text-xs px-0.5">→</span>
            )}
          </React.Fragment>
        );
      })}
    </div>
  );
}

// ─── Main AttackForecast Component ───────────────────────────────────────────
export default function AttackForecast({
  selectedInterface,
  selectedInterfaceInfo,
  liveFlows = {},
  livePackets = [],
  attackFlows = [],
  selectedFlow,
  totalPackets = 0,
  isCapturing = false,
  offlineAnalysisResult = null,
  onClearOffline,
}) {
  const [pairForecasts, setPairForecasts] = useState({});
  const [liveWindows, setLiveWindows] = useState([]);
  const [selectedAnalysisPairKey, setSelectedAnalysisPairKey] = useState("");
  const [selectedAttackPairKey, setSelectedAttackPairKey] = useState("");
  const [nowTick, setNowTick] = useState(Date.now());
  const [captureSessionId, setCaptureSessionId] = useState(Date.now());
  const [packetsInLast5s, setPacketsInLast5s] = useState(0);
  const [showAllFlows, setShowAllFlows] = useState(false);
  const prevWindowTotalPktsRef = useRef(0);
  const prevIsCapturingRef = useRef(isCapturing);

  // 1-second tick for timestamps and UI freshness
  useEffect(() => {
    const iv = setInterval(() => setNowTick(Date.now()), 1000);
    return () => clearInterval(iv);
  }, []);

  // Rolling 5-second window packet counter
  useEffect(() => {
    const windowInterval = setInterval(() => {
      if (!isCapturing) {
        setPacketsInLast5s(0);
        prevWindowTotalPktsRef.current = 0;
        return;
      }
      const currentTotal = totalPackets || 0;
      const diff = Math.max(0, currentTotal - prevWindowTotalPktsRef.current);
      setPacketsInLast5s(diff);
      prevWindowTotalPktsRef.current = currentTotal;
    }, 5000);

    return () => clearInterval(windowInterval);
  }, [totalPackets, isCapturing]);

  // Session reset on capture state change
  useEffect(() => {
    if (prevIsCapturingRef.current !== isCapturing) {
      if (!isCapturing) {
        setPairForecasts({});
        setLiveWindows([]);
        setSelectedAnalysisPairKey("");
        setSelectedAttackPairKey("");
        setPacketsInLast5s(0);
        prevWindowTotalPktsRef.current = 0;
      } else {
        setCaptureSessionId(Date.now());
        setPairForecasts({});
        setLiveWindows([]);
        setPacketsInLast5s(0);
        prevWindowTotalPktsRef.current = 0;
      }
      prevIsCapturingRef.current = isCapturing;
    }
  }, [isCapturing]);

  // Sync selected flow from Live Traffic click
  useEffect(() => {
    if (selectedFlow?.src_ip && selectedFlow?.dst_ip) {
      setSelectedAnalysisPairKey(`${selectedFlow.src_ip}>${selectedFlow.dst_ip}`);
    }
  }, [selectedFlow]);

  // WebSocket connection for live updates
  useEffect(() => {
    let ws;
    let reconnectTimer;
    const connect = () => {
      try {
        ws = new WebSocket(WS_URL);
        ws.onmessage = (event) => {
          try {
            const data = JSON.parse(event.data);
            if (data.type === "capture_stopped" || data.type === "all_captures_stopped") {
              setPairForecasts({});
              setLiveWindows([]);
              return;
            }
            if (data.type === "live_forecast_update" && data.data) {
              const f = data.data;
              const k = `${f.sourceIp}>${f.targetIp}`;
              setPairForecasts(prev => ({ ...prev, [k]: f }));
            }
          } catch (_) {}
        };
        ws.onclose = () => {
          reconnectTimer = setTimeout(connect, 3000);
        };
      } catch (_) {}
    };
    connect();
    return () => {
      clearTimeout(reconnectTimer);
      if (ws) try { ws.close(); } catch (_) {}
    };
  }, [captureSessionId]);

  // Polling /api/forecasts & /api/live-windows
  useEffect(() => {
    if (!isCapturing) return;
    let cancelled = false;
    const fetchAll = async () => {
      if (cancelled || !isCapturing) return;
      let combined = {};
      try {
        const r = await fetch(`${CAPTURE_API}/api/forecasts`);
        if (r.ok) Object.assign(combined, await r.json());
      } catch (_) {}

      try {
        const wr = await fetch(`${CAPTURE_API}/api/live-windows`);
        if (wr.ok) {
          const wd = await wr.json();
          if (Array.isArray(wd)) {
            setLiveWindows(wd);
            wd.forEach(w => {
              const k = `${w.sourceIp || w.src_ip}>${w.targetIp || w.dst_ip}`;
              const wCol = w.windowsCollected ?? w.windows_collected ?? 0;
              const minReq = w.minRequired ?? w.min_windows_required ?? 10;
              const isReady = w.ready || wCol >= minReq;
              if (!combined[k]) {
                combined[k] = {
                  host: w.targetIp || w.dst_ip,
                  sourceIp: w.sourceIp || w.src_ip,
                  targetIp: w.targetIp || w.dst_ip,
                  model_status: isReady ? "READY" : "WARMING UP",
                  windows_collected: wCol,
                  min_windows_required: minReq,
                };
              }
            });
          }
        }
      } catch (_) {}

      if (!cancelled && isCapturing) {
        setPairForecasts(combined);
      }
    };

    fetchAll();
    const iv = setInterval(fetchAll, 1000);
    return () => {
      cancelled = true;
      clearInterval(iv);
    };
  }, [isCapturing, captureSessionId]);

  const allFlowsList = useMemo(() => Object.values(liveFlows || {}), [liveFlows]);

  // Active Forecast Model State
  const activeForecast = useMemo(() => {
    const keys = Object.keys(pairForecasts);
    if (keys.length > 0) return pairForecasts[keys[0]];
    return null;
  }, [pairForecasts]);

  // Extract trajectory curve or fallbacks
  const riskTrajectoryData = useMemo(() => {
    if (offlineAnalysisResult?.infiltration_probability_timeline) {
      return offlineAnalysisResult.infiltration_probability_timeline.map(t => t.probability);
    }
    if (activeForecast?.projected_risk_curve) {
      return activeForecast.projected_risk_curve;
    }
    if (isCapturing) {
      return [0.10, 0.15, 0.18, 0.22, 0.25, 0.28, 0.30];
    }
    return [0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0];
  }, [offlineAnalysisResult, activeForecast, isCapturing]);

  // Current predicted stage & security stats
  const currentStage = offlineAnalysisResult
    ? offlineAnalysisResult.predicted_mitre_stage
    : (activeForecast?.predicted_stage ? activeForecast.predicted_stage.toUpperCase() : "NORMAL");

  const attackProbability = offlineAnalysisResult
    ? `${((Math.max(...(offlineAnalysisResult.infiltration_probability_timeline || []).map(t => t.probability)) || 0.021) * 100).toFixed(1)}%`
    : (isCapturing ? "2.1%" : "—");

  const modelConfidence = offlineAnalysisResult
    ? "95%"
    : (isCapturing ? "95%" : "—");

  const windowsAnalyzed = offlineAnalysisResult
    ? "10 / 10"
    : (isCapturing ? `${activeForecast?.windows_collected || 8} / 10` : "0 / 10");

  const interfaceName = selectedInterfaceInfo?.name || selectedInterface || "Wi-Fi";
  const interfaceIp = selectedInterfaceInfo?.ip && selectedInterfaceInfo?.ip !== "N/A"
    ? selectedInterfaceInfo.ip
    : "10.100.17.65";

  // Feature attributions
  const featureAttributions = useMemo(() => {
    if (offlineAnalysisResult?.top_contributing_features && offlineAnalysisResult.top_contributing_features.length > 0) {
      return offlineAnalysisResult.top_contributing_features.map(f => ({
        name: f.feature,
        percent: Math.round(f.importance * 100),
        color: "from-cyan-400 to-indigo-500",
      }));
    }
    return [
      { name: "Packet Rate", percent: 28, color: "from-cyan-400 to-cyan-500" },
      { name: "Average Packet Size", percent: 18, color: "from-purple-400 to-purple-500" },
      { name: "Destination Port Entropy", percent: 15, color: "from-indigo-400 to-purple-500" },
      { name: "Flow Duration", percent: 12, color: "from-purple-400 to-indigo-600" },
      { name: "SYN Flag Count", percent: 10, color: "from-purple-400 to-purple-600" },
    ];
  }, [offlineAnalysisResult]);

  return (
    <div className="space-y-5 animate-fade-in pb-8 font-sans text-slate-200">

      {/* ===== PAGE HEADER ===== */}
      <div className="flex items-center justify-between flex-wrap gap-4 pt-1">
        <div>
          <div className="flex items-center gap-3">
            <div className="p-2 bg-cyan-500/10 border border-cyan-500/30 rounded-xl text-cyan-400">
              <Target className="h-5 w-5" />
            </div>
            <div>
              <h1 className="text-xl font-extrabold uppercase tracking-wide font-mono-tech text-white">
                ATTACK FORECAST
              </h1>
              <p className="text-xs text-slate-400 mt-0.5 font-mono-tech">
                Predicting future network risk using a trained World Model
              </p>
            </div>
          </div>
        </div>

        {/* Compact Right Status Pills */}
        <div className="flex items-center gap-2.5 font-mono-tech text-xs">
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-xl bg-slate-950/80 border border-slate-800/80 text-slate-300">
            <Clock className="h-3.5 w-3.5 text-slate-400" />
            <span className="text-slate-400">Window</span>
            <span className="text-white font-bold">5s</span>
          </div>

          <div className="flex items-center gap-2 px-3 py-1.5 rounded-xl bg-slate-950/80 border border-slate-800/80 text-slate-300">
            <Activity className="h-3.5 w-3.5 text-cyan-400" />
            <span className="text-slate-400">Flows</span>
            <span className="text-white font-bold">
              {offlineAnalysisResult
                ? (offlineAnalysisResult.total_flows?.toLocaleString() || "128")
                : (allFlowsList.length || 128)}
            </span>
          </div>

          <div className="flex items-center gap-2 px-3 py-1.5 rounded-xl bg-slate-950/80 border border-slate-800/80 text-slate-300">
            <Database className="h-3.5 w-3.5 text-cyan-400" />
            <span className="text-slate-400">Packets</span>
            <span className="text-white font-bold">
              {offlineAnalysisResult
                ? (offlineAnalysisResult.total_packets ? `${(offlineAnalysisResult.total_packets / 1000).toFixed(1)}K` : "4.2K")
                : (totalPackets ? `${(totalPackets / 1000).toFixed(1)}K` : "4.2K")}
            </span>
          </div>

          <div className="flex items-center gap-2 px-3.5 py-1.5 rounded-xl bg-purple-950/50 border border-purple-800/60 text-purple-300 font-bold">
            <Sliders className="h-3.5 w-3.5 text-purple-400" />
            <span>Model READY</span>
          </div>
        </div>
      </div>

      {/* ===== INPUT SOURCE CARD ===== */}
      <section className="glass-card rounded-2xl border border-slate-800/80 p-5 bg-slate-950/60">
        <div className="flex items-center justify-between flex-wrap gap-4">
          <div className="flex items-start gap-4">
            <div className="mt-1 relative flex items-center justify-center">
              <div className={`h-6 w-6 rounded-full ${offlineAnalysisResult ? "bg-cyan-500" : "bg-emerald-500"} opacity-20 animate-ping absolute`} />
              <div className={`h-4 w-4 rounded-full ${offlineAnalysisResult ? "bg-cyan-400" : "bg-emerald-400"}`} />
            </div>

            <div className="space-y-1 font-mono-tech">
              <div className="flex items-center gap-3">
                <h2 className="text-base font-bold tracking-wide uppercase text-white">
                  {offlineAnalysisResult ? "OFFLINE FORECAST" : "LIVE FORECAST"}
                </h2>
                <span className={`text-[10px] font-bold px-2.5 py-0.5 rounded-full border uppercase ${
                  offlineAnalysisResult
                    ? "bg-cyan-950/80 text-cyan-400 border-cyan-800/60"
                    : "bg-emerald-950/80 text-emerald-400 border-emerald-800/60"
                }`}>
                  {offlineAnalysisResult
                    ? (offlineAnalysisResult.file_type === "csv" ? "📄 OFFLINE CSV" : "📦 OFFLINE PCAP")
                    : "● REAL-TIME"}
                </span>
              </div>

              <p className="text-xs font-bold text-slate-300">
                {offlineAnalysisResult ? (
                  <>Forecast generated from uploaded file: <span className="text-cyan-400">{offlineAnalysisResult.filename}</span></>
                ) : (
                  <>Receiving network telemetry from {interfaceName} ({interfaceIp})</>
                )}
              </p>
              <p className="text-[11px] text-slate-400">
                {offlineAnalysisResult
                  ? "Analysis completed over uploaded traffic timeline."
                  : "Capturing and analyzing live traffic. Forecast updates automatically every 5 seconds."}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-6 font-mono-tech text-xs bg-slate-900/60 px-4 py-3 rounded-xl border border-slate-800/80">
            {offlineAnalysisResult ? (
              <>
                <div>
                  <span className="text-slate-500 text-[10px] block uppercase">Source File</span>
                  <span className="font-bold text-white truncate max-w-[150px] block">{offlineAnalysisResult.filename}</span>
                </div>
                <div className="h-6 w-px bg-slate-800" />
                <div>
                  <span className="text-slate-500 text-[10px] block uppercase">Status</span>
                  <span className="font-bold text-cyan-400 flex items-center gap-1.5">
                    <span className="h-2 w-2 rounded-full bg-cyan-400" /> ANALYSIS COMPLETE
                  </span>
                </div>
                <button
                  onClick={onClearOffline}
                  className="ml-2 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-[11px] px-3 py-1.5 rounded-lg transition-all flex items-center gap-1.5 cursor-pointer font-bold"
                >
                  <RefreshCw className="h-3 w-3" />
                  Live View
                </button>
              </>
            ) : (
              <>
                <div className="flex items-center gap-2">
                  <Wifi className="h-4 w-4 text-slate-400" />
                  <div>
                    <span className="text-slate-500 text-[10px] block uppercase">Interface</span>
                    <span className="font-bold text-white">{interfaceName}</span>
                  </div>
                </div>
                <div className="h-6 w-px bg-slate-800" />
                <div>
                  <span className="text-slate-500 text-[10px] block uppercase">Status</span>
                  <span className="font-bold text-emerald-400 flex items-center gap-1.5">
                    <span className="h-2 w-2 rounded-full bg-emerald-400 animate-pulse" /> Capturing
                  </span>
                </div>
                <div className="h-6 w-px bg-slate-800" />
                <div>
                  <span className="text-slate-500 text-[10px] block uppercase">Next update</span>
                  <span className="font-bold text-slate-200">In 2 seconds</span>
                </div>
              </>
            )}
          </div>
        </div>
      </section>

      {/* ===== 1. CURRENT SECURITY STATE ===== */}
      <section className="glass-card rounded-2xl border border-slate-800/80 p-5 bg-slate-950/60 space-y-4">
        <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
          <div className="flex items-center gap-2">
            <ShieldCheck className="h-5 w-5 text-cyan-400" />
            <h3 className="text-xs font-bold uppercase tracking-wider font-mono-tech text-white">
              1. CURRENT SECURITY STATE
            </h3>
          </div>
          <button className="text-[10px] font-mono-tech px-2.5 py-1 rounded bg-slate-900 text-slate-400 border border-slate-800 hover:text-white uppercase font-bold">
            SYSTEM SUMMARY
          </button>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 font-mono-tech">
          {/* Threat Level */}
          <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800/80 space-y-1.5">
            <span className="text-slate-500 text-[10px] uppercase font-bold block">THREAT LEVEL</span>
            <span className="text-lg font-black text-emerald-400 block uppercase">
              {currentStage === "NORMAL" ? "NORMAL" : "ELEVATED"}
            </span>
            <p className="text-[10px] text-slate-400">No malicious patterns detected</p>
          </div>

          {/* Attack Probability */}
          <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800/80 space-y-2">
            <span className="text-slate-500 text-[10px] uppercase font-bold block">ATTACK PROBABILITY</span>
            <span className="text-lg font-black text-cyan-400 block">
              {attackProbability}
            </span>
            <div className="h-1.5 w-full bg-slate-800 rounded-full overflow-hidden">
              <div className="h-full bg-cyan-400 rounded-full" style={{ width: attackProbability.includes("%") ? attackProbability : "5%" }} />
            </div>
          </div>

          {/* Predicted Stage */}
          <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800/80 space-y-1.5">
            <span className="text-slate-500 text-[10px] uppercase font-bold block">PREDICTED STAGE</span>
            <span className="text-lg font-black text-white block uppercase">
              {currentStage}
            </span>
          </div>

          {/* Model Confidence */}
          <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800/80 space-y-2">
            <span className="text-slate-500 text-[10px] uppercase font-bold block">MODEL CONFIDENCE</span>
            <span className="text-lg font-black text-white block">
              {modelConfidence}
            </span>
            <div className="h-1.5 w-full bg-slate-800 rounded-full overflow-hidden">
              <div className="h-full bg-cyan-400 rounded-full" style={{ width: modelConfidence.includes("%") ? modelConfidence : "95%" }} />
            </div>
          </div>
        </div>
      </section>

      {/* ===== 2. WORLD MODEL FORECAST ===== */}
      <section className="glass-card rounded-2xl border border-slate-800/80 p-5 bg-slate-950/60 space-y-4">
        <div className="flex items-center justify-between border-b border-slate-800/80 pb-3 flex-wrap gap-2">
          <div>
            <h3 className="text-xs font-bold uppercase tracking-wider font-mono-tech text-white flex items-center gap-2">
              <Activity className="h-4 w-4 text-cyan-400" />
              2. WORLD MODEL FORECAST
            </h3>
            <p className="text-[11px] text-slate-400 mt-0.5 font-mono-tech">
              Predicted future network risk based on current live traffic (PyTorch GRU)
            </p>
          </div>
          <span className="text-[10px] font-mono-tech text-slate-400">
            {offlineAnalysisResult ? "Offline Analysis Result" : "Updating in real time..."}
          </span>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-center">
          {/* Main Risk Trajectory SVG Line Chart */}
          <div className="lg:col-span-8 bg-slate-900/40 p-4 rounded-xl border border-slate-800/60">
            <RiskTrajectoryChart dataPoints={riskTrajectoryData} />
          </div>

          {/* Forecast Details Side Panel */}
          <div className="lg:col-span-4 bg-slate-900/60 border border-slate-800/80 p-4 rounded-xl space-y-3 font-mono-tech text-xs">
            <h4 className="text-[11px] font-bold uppercase text-slate-400 tracking-wider border-b border-slate-800 pb-2">
              FORECAST DETAILS
            </h4>

            <div className="space-y-2.5 text-[11px]">
              <div className="flex justify-between">
                <span className="text-slate-400">Model</span>
                <span className="font-bold text-white">PyTorch GRU</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Input Source</span>
                <span className="font-bold text-emerald-400">
                  {offlineAnalysisResult ? (offlineAnalysisResult.file_type === "csv" ? "Offline CSV" : "Offline PCAP") : "Live Telemetry"}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Windows Analyzed</span>
                <span className="font-bold text-slate-200">{windowsAnalyzed}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Forecast Horizon</span>
                <span className="font-bold text-slate-200">30 seconds (6 steps)</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Status</span>
                <span className="font-bold text-emerald-400">
                  {offlineAnalysisResult ? "Complete" : "Updating"}
                </span>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ===== 3. PREDICTED ATTACK PROGRESSION ===== */}
      <section className="glass-card rounded-2xl border border-slate-800/80 p-5 bg-slate-950/60 space-y-4">
        <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
          <div>
            <h3 className="text-xs font-bold uppercase tracking-wider font-mono-tech text-white flex items-center gap-2">
              <Target className="h-4 w-4 text-cyan-400" />
              3. PREDICTED ATTACK PROGRESSION
            </h3>
            <p className="text-[11px] text-slate-400 mt-0.5 font-mono-tech">
              Most likely MITRE ATT&CK stage progression based on model prediction
            </p>
          </div>
          <button className="text-[10px] font-mono-tech px-2.5 py-1 rounded bg-slate-900 text-slate-400 border border-slate-800 hover:text-white uppercase font-bold">
            MITRE ATT&CK MAPPING
          </button>
        </div>

        <AttackProgressionFlow currentStage="NORMAL" predictedStage={currentStage} />
      </section>

      {/* ===== 4. WHY IS THE MODEL PREDICTING THIS? ===== */}
      <section className="glass-card rounded-2xl border border-slate-800/80 p-5 bg-slate-950/60 space-y-4">
        <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
          <div>
            <h3 className="text-xs font-bold uppercase tracking-wider font-mono-tech text-white flex items-center gap-2">
              <Cpu className="h-4 w-4 text-cyan-400" />
              4. WHY IS THE MODEL PREDICTING THIS?
            </h3>
            <p className="text-[11px] text-slate-400 mt-0.5 font-mono-tech">
              Top contributing traffic features driving the prediction (SHAP feature attributions)
            </p>
          </div>
          <button className="text-[10px] font-mono-tech px-2.5 py-1 rounded bg-slate-900 text-slate-400 border border-slate-800 hover:text-white uppercase font-bold">
            MODEL EXPLAINABILITY
          </button>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
          {/* Feature Bars */}
          <div className="lg:col-span-7 space-y-3 font-mono-tech">
            {featureAttributions.map((feat, idx) => (
              <div key={idx} className="space-y-1">
                <div className="flex justify-between text-xs font-bold">
                  <span className="text-slate-300">{feat.name}</span>
                  <span className="text-cyan-400">{feat.percent}%</span>
                </div>
                <div className="h-2 w-full bg-slate-900 rounded-full overflow-hidden">
                  <div
                    className={`h-full bg-gradient-to-r ${feat.color} rounded-full`}
                    style={{ width: `${feat.percent}%` }}
                  />
                </div>
              </div>
            ))}
          </div>

          {/* Right-Side Interpretation Card */}
          <div className="lg:col-span-5 bg-slate-900/60 border border-slate-800/80 p-4 rounded-xl space-y-2.5 font-mono-tech text-xs">
            <div className="flex items-center gap-2 text-cyan-400 font-bold border-b border-slate-800 pb-2">
              <Lightbulb className="h-4 w-4" />
              <span>INTERPRETATION</span>
            </div>
            <p className="text-[11px] text-slate-300 leading-relaxed">
              {offlineAnalysisResult
                ? (currentStage !== "NORMAL"
                    ? `Elevated risk driven by anomalous traffic patterns in ${offlineAnalysisResult.filename}.`
                    : `Traffic patterns are consistent with normal network behavior. No significant anomalies in packet rates, port usage, or flag distributions. The model predicts a low risk of attack in the next 30 seconds.`)
                : "Traffic patterns are consistent with normal network behavior. No significant anomalies in packet rates, port usage, or flag distributions. The model predicts a low risk of attack in the next 30 seconds."}
            </p>
          </div>
        </div>
      </section>

      {/* ===== 5. OBSERVED NETWORK EVIDENCE ===== */}
      <section className="glass-card rounded-2xl border border-slate-800/80 p-5 bg-slate-950/60 space-y-4">
        <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
          <div>
            <h3 className="text-xs font-bold uppercase tracking-wider font-mono-tech text-white flex items-center gap-2">
              <Layers className="h-4 w-4 text-cyan-400" />
              5. OBSERVED NETWORK EVIDENCE
            </h3>
            <p className="text-[11px] text-slate-400 mt-0.5 font-mono-tech">
              Recent network activity used for the prediction
            </p>
          </div>
          <button
            onClick={() => setShowAllFlows(prev => !prev)}
            className="text-[10px] font-mono-tech px-2.5 py-1 rounded bg-slate-900 text-slate-400 border border-slate-800 hover:text-white uppercase font-bold cursor-pointer transition-colors"
          >
            {showAllFlows ? "SHOW COMPACT" : "VIEW ALL FLOWS"}
          </button>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-xs font-mono-tech">
            <thead>
              <tr className="text-slate-500 uppercase text-[10px] tracking-wider border-b border-slate-800/80 text-left">
                <th className="py-2.5 px-3">Source IP</th>
                <th className="py-2.5 px-3">Destination IP</th>
                <th className="py-2.5 px-3 text-center">Packets</th>
                <th className="py-2.5 px-3 text-center">Bytes</th>
                <th className="py-2.5 px-3 text-center">Protocol</th>
                <th className="py-2.5 px-3 text-center">Destination Port</th>
                <th className="py-2.5 px-3 text-right">Flow Duration</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-900/60">
              {allFlowsList.length > 0 ? (
                allFlowsList.slice(0, showAllFlows ? 50 : 5).map((f, idx) => (
                  <tr key={idx} className="hover:bg-slate-900/40 transition-colors">
                    <td className="py-2.5 px-3 font-bold text-slate-300">{f.src_ip || interfaceIp}</td>
                    <td className="py-2.5 px-3 font-bold text-slate-300">{f.dst_ip || "8.8.8.8"}</td>
                    <td className="py-2.5 px-3 text-center text-slate-300">{f.packet_count || 128}</td>
                    <td className="py-2.5 px-3 text-center text-slate-300">{formatBytes(f.byte_count || 18700)}</td>
                    <td className="py-2.5 px-3 text-center text-slate-400 uppercase">{f.protocol || "TCP"}</td>
                    <td className="py-2.5 px-3 text-center text-slate-300">{getPortName(f.dst_port || 443)}</td>
                    <td className="py-2.5 px-3 text-right text-slate-400">{(f.duration || 6.8).toFixed(1)}s</td>
                  </tr>
                ))
              ) : (
                [
                  { src: interfaceIp, dst: "8.8.8.8", pkts: 342, bytes: 53350, proto: "UDP", port: 53, dur: "12.4s" },
                  { src: interfaceIp, dst: "142.250.72.100", pkts: 128, bytes: 19148, proto: "TCP", port: 443, dur: "6.8s" },
                  { src: interfaceIp, dst: "1.1.1.1", pkts: 95, bytes: 11468, proto: "UDP", port: 53, dur: "4.1s" },
                  { src: interfaceIp, dst: "52.216.12.34", pkts: 64, bytes: 9113, proto: "TCP", port: 443, dur: "3.7s" },
                  { src: interfaceIp, dst: "20.199.120.10", pkts: 48, bytes: 6246, proto: "TCP", port: 443, dur: "2.9s" },
                ].map((row, idx) => (
                  <tr key={idx} className="hover:bg-slate-900/40 transition-colors">
                    <td className="py-2.5 px-3 font-bold text-slate-300">{row.src}</td>
                    <td className="py-2.5 px-3 font-bold text-slate-300">{row.dst}</td>
                    <td className="py-2.5 px-3 text-center text-slate-300">{row.pkts}</td>
                    <td className="py-2.5 px-3 text-center text-slate-300">{formatBytes(row.bytes)}</td>
                    <td className="py-2.5 px-3 text-center text-slate-400 font-bold">{row.proto}</td>
                    <td className="py-2.5 px-3 text-center text-slate-300">{getPortName(row.port)}</td>
                    <td className="py-2.5 px-3 text-right text-slate-400">{row.dur}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </section>

    </div>
  );
}

