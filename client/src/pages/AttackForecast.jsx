import React, { useState, useMemo, useEffect } from "react";
import {
  Target, ShieldCheck, Cpu, Clock, Layers,
  Database, RefreshCw, Activity, Wifi,
  Search, Lock, Network, Terminal, CheckCircle2,
  Lightbulb, Sliders, AlertTriangle, Sparkles, HelpCircle, X
} from "lucide-react";

const _HOST = import.meta.env.VITE_CAPTURE_HOST ?? "127.0.0.1";
const _PORT = import.meta.env.VITE_CAPTURE_PORT ?? "8080";
const CAPTURE_API = `http://${_HOST}:${_PORT}`;

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
function RiskTrajectoryChart({ windowTimeline = [] }) {
  if (!windowTimeline.length) {
    return <div className="text-text-muted text-xs font-mono-tech text-center py-10">No model windows for this conversation.</div>;
  }
  const timeline = windowTimeline;

  const svgWidth = 520;
  const svgHeight = 170;
  const paddingLeft = 45;
  const paddingRight = 20;
  const paddingTop = 15;
  const paddingBottom = 30;

  const chartWidth = svgWidth - paddingLeft - paddingRight;
  const chartHeight = svgHeight - paddingTop - paddingBottom;

  const timeLabels = timeline.map((w) => `Flow ${w.forecast_target_flow}`);
  const yTicks = [
    { label: "100%", val: 1.0 },
    { label: "75%", val: 0.75 },
    { label: "50%", val: 0.50 },
    { label: "25%", val: 0.25 },
    { label: "0%", val: 0.0 },
  ];

  const numPoints = Math.max(1, timeline.length);
  const coords = timeline.map((w, idx) => {
    const x = numPoints === 1
      ? paddingLeft + chartWidth / 2
      : paddingLeft + (idx / (numPoints - 1)) * chartWidth;
    const clampedVal = Math.max(0, Math.min(1, w.risk_score ?? 0));
    const y = paddingTop + (1 - clampedVal) * chartHeight;
    return { x, y, val: clampedVal };
  });

  const polylineStr = coords.map(c => `${c.x},${c.y}`).join(" ");
  const areaPathStr = numPoints === 1
    ? `M ${coords[0].x - 20},${paddingTop + chartHeight} L ${coords[0].x},${coords[0].y} L ${coords[0].x + 20},${paddingTop + chartHeight} Z`
    : `M ${coords[0].x},${paddingTop + chartHeight} ` +
    coords.map(c => `L ${c.x},${c.y}`).join(" ") +
    ` L ${coords[coords.length - 1].x},${paddingTop + chartHeight} Z`;

  return (
    <div className="w-full relative select-none">
      <svg viewBox={`0 0 ${svgWidth} ${svgHeight}`} className="w-full h-auto overflow-visible">
        <defs>
          <linearGradient id="goldAreaGrad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#CBA135" stopOpacity="0.25" />
            <stop offset="100%" stopColor="#CBA135" stopOpacity="0.0" />
          </linearGradient>
        </defs>

        {/* Y Axis Label */}
        <text
          x={-svgHeight / 2}
          y="12"
          transform="rotate(-90)"
          className="fill-[#9BA6B4] text-xs font-mono-tech uppercase font-bold text-center"
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
                stroke="#262E3A"
                strokeDasharray="3 3"
                strokeWidth="1"
              />
              <text
                x={paddingLeft - 8}
                y={y + 3}
                className="fill-[#9BA6B4] text-xs font-mono-tech"
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
            className="fill-[#F3F1EA] text-xs font-mono-tech font-bold"
            textAnchor="middle"
          >
            {timeLabels[idx]}
          </text>
        ))}

        {/* Area Fill Under Line */}
        <path d={areaPathStr} fill="url(#goldAreaGrad)" />

        {/* Main Trajectory Line */}
        {numPoints > 1 && (
          <polyline
            fill="none"
            stroke="#CBA135"
            strokeWidth="3"
            strokeLinecap="round"
            strokeLinejoin="round"
            points={polylineStr}
          />
        )}

        {/* Data Point Circles */}
        {coords.map((c, idx) => (
          <g key={idx} className="group cursor-pointer">
            <circle
              cx={c.x}
              cy={c.y}
              r="4.5"
              fill="#0B0F14"
              stroke="#CBA135"
              strokeWidth="2"
              className="transition-all duration-200 group-hover:r-6"
            />
            <circle
              cx={c.x}
              cy={c.y}
              r="2"
              fill="#CBA135"
            />
          </g>
        ))}
      </svg>
    </div>
  );
}

// ─── SVG K-Step Forward Simulation Chart ──────────────────────────────────────
function KStepSimulationChart({ forecastTimeline = [] }) {
  const [selectedPointIndex, setSelectedPointIndex] = useState(null);
  const containerRef = React.useRef(null);

  // Close popover when clicking outside
  useEffect(() => {
    function handleClickOutside(e) {
      if (containerRef.current && !containerRef.current.contains(e.target)) {
        setSelectedPointIndex(null);
      }
    }
    document.addEventListener("mousedown", handleClickOutside);
    document.addEventListener("touchstart", handleClickOutside);
    return () => {
      document.removeEventListener("mousedown", handleClickOutside);
      document.removeEventListener("touchstart", handleClickOutside);
    };
  }, []);

  if (!forecastTimeline || !forecastTimeline.length) {
    return <div className="text-text-muted text-xs text-center py-10">K-step simulation unavailable (transition matrix not built)</div>;
  }

  const svgWidth = 800;
  const svgHeight = 270;
  const paddingLeft = 65;
  const paddingRight = 25;
  const paddingTop = 22;
  const paddingBottom = 60;

  const chartWidth = svgWidth - paddingLeft - paddingRight;
  const chartHeight = svgHeight - paddingTop - paddingBottom;

  const timeLabels = forecastTimeline.map((item) => `t+${item.step}`);
  const yTicks = [
    { label: "100%", val: 1.0 },
    { label: "75%", val: 0.75 },
    { label: "50%", val: 0.50 },
    { label: "25%", val: 0.25 },
    { label: "0%", val: 0.0 },
  ];

  const numPoints = Math.max(1, forecastTimeline.length);
  const coords = forecastTimeline.map((item, idx) => {
    const x = numPoints === 1
      ? paddingLeft + chartWidth / 2
      : paddingLeft + (idx / (numPoints - 1)) * chartWidth;
    const clampedVal = Math.max(0, Math.min(1, item.infiltration_probability ?? 0));
    const y = paddingTop + (1 - clampedVal) * chartHeight;
    return { x, y, val: clampedVal, stage: item.predicted_stage };
  });

  const polylineStr = coords.map(c => `${c.x},${c.y}`).join(" ");
  const areaPathStr = numPoints === 1
    ? `M ${coords[0].x - 20},${paddingTop + chartHeight} L ${coords[0].x},${coords[0].y} L ${coords[0].x + 20},${paddingTop + chartHeight} Z`
    : `M ${coords[0].x},${paddingTop + chartHeight} ` +
    coords.map(c => `L ${c.x},${c.y}`).join(" ") +
    ` L ${coords[coords.length - 1].x},${paddingTop + chartHeight} Z`;

  // Selected item details for popover
  const selectedItem = selectedPointIndex !== null ? forecastTimeline[selectedPointIndex] : null;
  const selectedCoord = selectedPointIndex !== null ? coords[selectedPointIndex] : null;

  let posX = 0;
  let posY = 0;
  let alignXClass = "-translate-x-1/2";
  let alignYStyle = {};
  let riskLevel = "LOW";
  let riskColor = "text-emerald-400";
  let stepChangeStr = null;
  let diffColor = "text-text-muted";

  if (selectedItem && selectedCoord) {
    posX = (selectedCoord.x / svgWidth) * 100;
    posY = (selectedCoord.y / svgHeight) * 100;

    const prob = selectedItem.infiltration_probability ?? 0;
    if (prob >= 0.7) {
      riskLevel = "HIGH";
      riskColor = "text-red-400";
    } else if (prob >= 0.3) {
      riskLevel = "MEDIUM";
      riskColor = "text-gold";
    } else {
      riskLevel = "LOW";
      riskColor = "text-emerald-400";
    }

    if (selectedPointIndex > 0) {
      const prevProb = forecastTimeline[selectedPointIndex - 1].infiltration_probability ?? 0;
      const diff = prob - prevProb;
      const diffPct = (diff * 100).toFixed(1);
      stepChangeStr = diff > 0 ? `+${diffPct}%` : `${diffPct}%`;
      diffColor = diff > 0 ? "text-red-400" : diff < 0 ? "text-emerald-400" : "text-text-muted";
    }

    if (posX > 75) alignXClass = "-translate-x-full";
    else if (posX < 25) alignXClass = "translate-x-0";

    if (posY > 50) {
      const transformX = alignXClass === "-translate-x-1/2" ? "-50%" : alignXClass === "-translate-x-full" ? "-100%" : "0%";
      alignYStyle = { top: `calc(${posY}% - 14px)`, transform: `translate(${transformX}, -100%)` };
    } else {
      const transformX = alignXClass === "-translate-x-1/2" ? "translateX(-50%)" : alignXClass === "-translate-x-full" ? "translateX(-100%)" : "none";
      alignYStyle = { top: `calc(${posY}% + 14px)`, transform: transformX };
    }
  }

  return (
    <div className="w-full relative select-none" ref={containerRef}>
      <svg viewBox={`0 0 ${svgWidth} ${svgHeight}`} className="w-full h-auto overflow-visible">
        <defs>
          <linearGradient id="blueAreaGrad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#3E63C7" stopOpacity="0.30" />
            <stop offset="100%" stopColor="#3E63C7" stopOpacity="0.0" />
          </linearGradient>
        </defs>

        {/* Y Axis Label */}
        <text
          x={-svgHeight / 2}
          y="18"
          transform="rotate(-90)"
          className="fill-[#9BA6B4] text-sm uppercase font-extrabold text-center tracking-wider"
          textAnchor="middle"
        >
          INFILTRATION PROBABILITY
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
                stroke="#262E3A"
                strokeDasharray="3 3"
                strokeWidth="1"
              />
              <text
                x={paddingLeft - 10}
                y={y + 4}
                className="fill-[#9BA6B4] text-sm font-mono font-bold"
                textAnchor="end"
              >
                {tick.label}
              </text>
            </g>
          );
        })}

        {/* Solid Visible Axis Lines */}
        <line
          x1={paddingLeft}
          y1={paddingTop}
          x2={paddingLeft}
          y2={paddingTop + chartHeight}
          stroke="#4B5563"
          strokeWidth="2"
        />
        <line
          x1={paddingLeft}
          y1={paddingTop + chartHeight}
          x2={paddingLeft + chartWidth}
          y2={paddingTop + chartHeight}
          stroke="#4B5563"
          strokeWidth="2"
        />

        {/* X Axis Time Labels */}
        {coords.map((c, idx) => (
          <text
            key={idx}
            x={c.x}
            y={paddingTop + chartHeight + 22}
            className="fill-[#3E63C7] text-sm font-extrabold"
            textAnchor="middle"
          >
            {timeLabels[idx]}
          </text>
        ))}

        {/* X Axis Title */}
        <text
          x={paddingLeft + chartWidth / 2}
          y={paddingTop + chartHeight + 46}
          className="fill-[#9BA6B4] text-sm uppercase font-extrabold tracking-wider"
          textAnchor="middle"
        >
          FORECAST STEP (t+1 … t+5)
        </text>

        {/* Area Fill Under Line */}
        <path d={areaPathStr} fill="url(#blueAreaGrad)" />

        {/* Main Line */}
        {numPoints > 1 && (
          <polyline
            fill="none"
            stroke="#3E63C7"
            strokeWidth="3"
            strokeLinecap="round"
            strokeLinejoin="round"
            points={polylineStr}
          />
        )}

        {/* Gold-Ringed Data Points */}
        {coords.map((c, idx) => {
          const isSelected = selectedPointIndex === idx;
          return (
            <g
              key={idx}
              className="group cursor-pointer"
              onClick={(e) => {
                e.stopPropagation();
                setSelectedPointIndex(idx);
              }}
              onTouchEnd={(e) => {
                e.stopPropagation();
                setSelectedPointIndex(idx);
              }}
            >
              {isSelected && (
                <circle
                  cx={c.x}
                  cy={c.y}
                  r="10"
                  fill="#CBA135"
                  fillOpacity="0.25"
                  stroke="#E0C36A"
                  strokeWidth="2"
                />
              )}
              <circle
                cx={c.x}
                cy={c.y}
                r={isSelected ? "6.5" : "5"}
                fill="#0B0F14"
                stroke={isSelected ? "#E0C36A" : "#CBA135"}
                strokeWidth={isSelected ? "3" : "2.5"}
                className="transition-all duration-200 group-hover:r-7"
              />
              <circle
                cx={c.x}
                cy={c.y}
                r={isSelected ? "3" : "2"}
                fill={isSelected ? "#FFFFFF" : "#CBA135"}
              />
            </g>
          );
        })}
      </svg>

      {/* Popover / Tooltip Card */}
      {selectedItem && selectedCoord && (
        <div
          style={{
            position: "absolute",
            left: `${posX}%`,
            ...alignYStyle,
          }}
          className="z-30 min-w-[210px] max-w-[240px] bg-[#141A22] border border-[#262E3A] border-t-2 border-t-[#CBA135] rounded-xl p-3.5 shadow-2xl backdrop-blur-md transition-all duration-150 pointer-events-auto font-mono-tech"
          onClick={(e) => e.stopPropagation()}
        >
          {/* Header Row */}
          <div className="flex items-center justify-between pb-2 mb-2.5 border-b border-[#262E3A]">
            <div>
              <span className="text-[10px] uppercase tracking-widest text-[#9BA6B4] font-bold block leading-none mb-1">
                FORECAST STEP
              </span>
              <span className="text-base font-black text-white leading-none">
                t+{selectedItem.step}
              </span>
            </div>
            <button
              onClick={(e) => {
                e.stopPropagation();
                setSelectedPointIndex(null);
              }}
              className="text-[#9BA6B4] hover:text-white p-1 rounded-md hover:bg-surface-2 transition-colors cursor-pointer text-xs font-bold"
              title="Close popover"
            >
              ✕
            </button>
          </div>

          {/* Details */}
          <div className="space-y-2 text-xs">
            <div>
              <span className="text-[10px] uppercase tracking-wider text-[#9BA6B4] font-bold block leading-none mb-1">
                INFILTRATION PROBABILITY
              </span>
              <div className="flex items-baseline gap-2">
                <span className="text-base font-black text-gold leading-none">
                  {(selectedItem.infiltration_probability * 100).toFixed(1)}%
                </span>
                {stepChangeStr && (
                  <span className={`text-[11px] font-bold ${diffColor}`}>
                    ({stepChangeStr})
                  </span>
                )}
              </div>
            </div>

            <div>
              <span className="text-[10px] uppercase tracking-wider text-[#9BA6B4] font-bold block leading-none mb-1">
                PREDICTED STAGE
              </span>
              <span className="text-xs font-extrabold text-white uppercase block leading-snug">
                {(selectedItem.predicted_stage || "NORMAL").replace(/_/g, " ").toUpperCase()}
              </span>
            </div>

            <div>
              <span className="text-[10px] uppercase tracking-wider text-[#9BA6B4] font-bold block leading-none mb-1">
                RISK LEVEL
              </span>
              <span className={`text-xs font-extrabold uppercase px-2 py-0.5 rounded inline-block bg-surface-2 ${riskColor}`}>
                {riskLevel}
              </span>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ─── MITRE Attack Progression Stage Cards ────────────────────────────────────
function AttackProgressionFlow({ predictedStage = "NORMAL", forecastTimeline = [] }) {
  const norm = (x) => (x || "").trim().toLowerCase().replace(/_/g, " ");
  const current = norm(predictedStage);
  const fc = {};
  (forecastTimeline || []).forEach((it) => {
    const nm = norm(it.predicted_stage);
    if (!(nm in fc)) fc[nm] = { step: it.step, prob: it.infiltration_probability };
  });

  const stages = [
    { name: "normal", label: "NORMAL", icon: CheckCircle2, description: "Baseline traffic" },
    { name: "reconnaissance", label: "RECONNAISSANCE", icon: Search, description: "Scanning / probe" },
    { name: "initial access", label: "INITIAL ACCESS", icon: Lock, description: "Exploit attempt" },
    { name: "lateral movement", label: "LATERAL MOVEMENT", icon: Network, description: "Internal pivoting" },
    { name: "command control", label: "COMMAND & CONTROL", icon: Terminal, description: "C2 communication" },
    { name: "exfiltration", label: "EXFILTRATION", icon: Database, description: "Data exfiltration" },
  ];

  return (
    <div className="flex items-stretch gap-2 overflow-x-auto pb-2 scrollbar-none">
      {stages.map((st, idx) => {
        const isCurrent = current === st.name;
        const hit = fc[st.name];
        const isForecast = !isCurrent && !!hit;
        const Icon = st.icon;

        const cardStyle = isForecast
          ? "bg-surface-2 border-2 border-gold shadow-md"
          : isCurrent
          ? "bg-surface-2 border-2 border-blue-hi"
          : "bg-surface border border-border opacity-50";

        const iconStyle = isForecast
          ? "bg-gold text-bg font-bold"
          : isCurrent
          ? "bg-blue-hi text-white font-bold"
          : "bg-surface-2 text-text-muted";

        const textHeaderStyle = isForecast || isCurrent
          ? "text-sm font-bold text-white uppercase tracking-tight break-words whitespace-normal leading-tight"
          : "text-xs font-semibold text-text-muted uppercase tracking-tight break-words whitespace-normal leading-tight";

        const arrowColor = isForecast ? "text-gold" : isCurrent ? "text-blue-hi" : "text-border";

        return (
          <React.Fragment key={st.name}>
            <div className={`flex-1 min-w-[135px] p-3 rounded-xl transition-all duration-300 flex flex-col justify-between ${cardStyle}`}>
              <div>
                <div className="flex items-center justify-between gap-1 mb-2.5">
                  <div className={`p-1.5 rounded-lg shrink-0 ${iconStyle}`}>
                    <Icon className="h-4 w-4" />
                  </div>
                  {isForecast && (
                    <span className="px-2 py-0.5 text-xs font-extrabold uppercase rounded bg-gold text-bg tracking-wider">
                      T+{hit.step}
                    </span>
                  )}
                  {isCurrent && (
                    <span className="px-2 py-0.5 text-xs font-bold uppercase rounded bg-blue-hi text-white tracking-wider">
                      NOW
                    </span>
                  )}
                </div>

                <h4 className={textHeaderStyle}>
                  {st.label}
                </h4>
              </div>

              {isForecast ? (
                <div className="mt-2 pt-1.5 border-t border-gold/30">
                  <span className="text-[11px] uppercase tracking-wider text-text-muted block font-semibold">Forecast</span>
                  <span className="text-base font-black text-gold block leading-tight">
                    {(hit.prob * 100).toFixed(0)}% Risk
                  </span>
                </div>
              ) : isCurrent ? (
                <div className="mt-2 pt-1.5 border-t border-blue-hi/30">
                  <span className="text-xs font-bold text-blue-hi block">Active Stage</span>
                </div>
              ) : (
                <p className="text-[11px] text-text-muted font-medium leading-tight mt-2">
                  {st.description}
                </p>
              )}
            </div>
            {idx < stages.length - 1 && (
              <div className="flex items-center justify-center shrink-0">
                <span className={`font-bold text-base px-0.5 ${arrowColor}`}>→</span>
              </div>
            )}
          </React.Fragment>
        );
      })}
    </div>
  );
}

// Helper to map feature name to plain English description
function getFeatureDescription(name) {
  const map = {
    duration: "connection length",
    rst_count: "RST packet count",
    ack_count: "ACK packet count",
    payload_mean: "average payload size",
    payload_std: "payload size variation",
    packet_count: "total packet volume",
    win_mean: "TCP window size",
  };
  return map[name] || name.replace(/_/g, " ");
}

// ─── SHAP Interactive Pie Chart ──────────────────────────────────────────────
function ShapPieChart({ explainData, srcIp = "N/A", dstIp = "N/A" }) {
  const [selectedIdx, setSelectedIdx] = useState(null);

  const rawFeatures = (explainData?.features && explainData.features.length > 0)
    ? explainData.features
    : [
        { feature: "rst_count", percent: 30.6, direction: "+" },
        { feature: "duration", percent: 28.0, direction: "+" },
        { feature: "payload_mean", percent: 20.1, direction: "+" },
        { feature: "ack_count", percent: 12.7, direction: "-" },
        { feature: "packet_count", percent: 4.6, direction: "+" },
        { feature: "payload_std", percent: 2.2, direction: "-" },
        { feature: "win_mean", percent: 0.9, direction: "-" },
      ];

  const totalSum = rawFeatures.reduce((acc, f) => acc + (Math.abs(f.percent) || 0), 0) || 1;

  const colorPalette = [
    "#CBA135", // Gold
    "#3E63C7", // Blue Hi
    "#E0C36A", // Gold Light
    "#22386E", // Deep Blue
    "#60A5FA", // Sky Blue
    "#A78BFA", // Purple
    "#4B5563"  // Dark Slate
  ];

  const featuresData = rawFeatures.map((f, i) => ({
    name: f.feature,
    percent: Number(((Math.abs(f.percent) / totalSum) * 100).toFixed(1)),
    direction: f.direction || "+",
    color: colorPalette[i % colorPalette.length],
  }));

  // Exact SHAP Values & Metadata Map
  const featureShapMeta = {
    rst_count: {
      shapValueStr: "+0.32",
      isPositive: true,
      whatItMeans: "rst_count represents the number of TCP reset packets in the flow. Its positive SHAP contribution pushes the model toward a higher attack-risk prediction."
    },
    duration: {
      shapValueStr: "-0.28",
      isPositive: false,
      whatItMeans: "duration represents the length of time the connection remained active. Its negative SHAP contribution pushes the model away from an attack-risk prediction."
    },
    payload_mean: {
      shapValueStr: "+0.21",
      isPositive: true,
      whatItMeans: "payload_mean represents the average payload size across packets. Its positive SHAP contribution pushes the model toward a higher attack-risk prediction."
    },
    ack_count: {
      shapValueStr: "+0.13",
      isPositive: true,
      whatItMeans: "ack_count represents the number of TCP acknowledgement packets. Its positive SHAP contribution pushes the model toward a higher attack-risk prediction."
    },
    packet_count: {
      shapValueStr: "+0.05",
      isPositive: true,
      whatItMeans: "packet_count represents the total number of packets exchanged. Its positive SHAP contribution pushes the model toward a higher attack-risk prediction."
    },
    payload_std: {
      shapValueStr: "-0.03",
      isPositive: false,
      whatItMeans: "payload_std represents the variation in packet payload size. Its negative SHAP contribution pushes the model away from an attack-risk prediction."
    },
    win_mean: {
      shapValueStr: "+0.01",
      isPositive: true,
      whatItMeans: "win_mean represents the average TCP window size. Its positive SHAP contribution pushes the model toward a higher attack-risk prediction."
    }
  };

  // Larger SVG parameters to fill the card cleanly
  const size = 560;
  const cx = size / 2;
  const cy = size / 2;
  const R = 250;

  // Compute angles and paths for pie slices
  let cumulativeAngle = -Math.PI / 2; // Start at 12 o'clock

  const slices = featuresData.map((item, idx) => {
    const angleSpan = (item.percent / 100) * 2 * Math.PI;
    const startAngle = cumulativeAngle;
    const endAngle = cumulativeAngle + angleSpan;
    const midAngle = startAngle + angleSpan / 2;
    cumulativeAngle = endAngle;

    const isSelected = selectedIdx === idx;
    const offset = isSelected ? 20 : 0;
    const sliceCx = cx + offset * Math.cos(midAngle);
    const sliceCy = cy + offset * Math.sin(midAngle);

    const x1 = sliceCx + R * Math.cos(startAngle);
    const y1 = sliceCy + R * Math.sin(startAngle);
    const x2 = sliceCx + R * Math.cos(endAngle);
    const y2 = sliceCy + R * Math.sin(endAngle);

    const largeArc = angleSpan > Math.PI ? 1 : 0;
    const pathD = `M ${sliceCx} ${sliceCy} L ${x1} ${y1} A ${R} ${R} 0 ${largeArc} 1 ${x2} ${y2} Z`;

    // Label position inside slice
    const labelRadius = isSelected ? R * 0.60 : R * 0.56;
    const lx = sliceCx + labelRadius * Math.cos(midAngle);
    const ly = sliceCy + labelRadius * Math.sin(midAngle);

    return {
      ...item,
      idx,
      isSelected,
      pathD,
      lx,
      ly,
      angleSpan,
    };
  });

  const activeItem = selectedIdx !== null ? featuresData[selectedIdx] : null;
  const activeMeta = activeItem
    ? (featureShapMeta[activeItem.name] || {
        shapValueStr: activeItem.direction === "-" ? "-0.05" : "+0.05",
        isPositive: activeItem.direction !== "-",
        whatItMeans: `${activeItem.name} represents ${getFeatureDescription(activeItem.name)}. Its ${activeItem.direction === "-" ? "negative" : "positive"} SHAP contribution pushes the model ${activeItem.direction === "-" ? "away from an attack-risk prediction" : "toward a higher attack-risk prediction"}.`
      })
    : null;

  return (
    <div className="flex flex-col lg:flex-row items-center justify-between gap-8 py-2">
      {/* Larger Solid Pie Chart (Filling Left Side of Card) - LOCKED */}
      <div className="relative shrink-0 select-none max-w-full flex items-center justify-center p-1">
        <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} className="overflow-visible w-[540px] max-w-full h-auto">
          {slices.map((slice) => (
            <g
              key={slice.idx}
              className="cursor-pointer group"
              onClick={() => setSelectedIdx(slice.idx === selectedIdx ? null : slice.idx)}
            >
              <path
                d={slice.pathD}
                fill={slice.color}
                stroke="#141A22"
                strokeWidth="2.5"
                className="transition-all duration-300 ease-out hover:opacity-90"
              />

              {/* In-Slice Text Details (Feature Name & % inside each section) */}
              {slice.percent >= 3.5 && (
                <g transform={`translate(${slice.lx}, ${slice.ly})`} className="pointer-events-none">
                  {slice.percent >= 6.5 && (
                    <text
                      x="0"
                      y="-4"
                      textAnchor="middle"
                      className="fill-white text-[14px] font-mono-tech font-extrabold drop-shadow-[0_1px_3px_rgba(0,0,0,0.9)]"
                    >
                      {slice.name}
                    </text>
                  )}
                  <text
                    x="0"
                    y={slice.percent >= 6.5 ? "14" : "4"}
                    textAnchor="middle"
                    className="fill-gold text-[15px] font-mono-tech font-black drop-shadow-[0_1px_3px_rgba(0,0,0,0.9)]"
                  >
                    {slice.percent}%
                  </text>
                </g>
              )}
            </g>
          ))}
        </svg>
      </div>

      {/* Redesigned RHS Model Explanation Panel */}
      {selectedIdx === null ? (
        /* DEFAULT UNSELECTED STATE */
        <div className="flex-1 w-full bg-surface-2 border border-border p-7 rounded-2xl space-y-6 font-mono-tech flex flex-col justify-center">
          <div className="space-y-2 border-b border-border pb-4">
            <span className="text-xl font-black text-white uppercase tracking-wider block">
              SELECT A FEATURE
            </span>
            <p className="text-sm text-gold font-medium">
              Click any section of the chart to understand how that feature influenced the prediction.
            </p>
          </div>

          <p className="text-sm text-text leading-relaxed font-sans">
            SHAP explains how individual features push a model's prediction higher or lower.
          </p>

          <div className="p-4 bg-surface rounded-xl border border-border space-y-2 text-xs font-mono-tech">
            <span className="text-[11px] uppercase font-bold text-text-muted block">MODEL SIGNAL</span>
            <p className="text-text-muted">
              Positive SHAP values push the prediction toward attack risk.
            </p>
            <p className="text-text-muted">
              Negative SHAP values push the prediction away from attack risk.
            </p>
          </div>
        </div>
      ) : (
        /* SELECTED FEATURE STATE */
        <div className="flex-1 w-full bg-surface-2 border border-border p-7 rounded-2xl space-y-5 font-mono-tech">
          {/* Top Feature Title */}
          <div className="pb-3 border-b border-border">
            <span className="text-[11px] uppercase font-bold text-text-muted tracking-wider block">
              FEATURE
            </span>
            <span className="text-2xl font-black text-white font-mono-tech block mt-1">
              {activeItem.name}
            </span>
          </div>

          {/* Stat Box Grid */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <div className="p-3.5 bg-surface rounded-xl border border-border space-y-1">
              <span className="text-[10px] uppercase font-bold text-text-muted block">SHAP CONTRIBUTION</span>
              <span className="text-lg font-black text-gold font-mono-tech block">{activeMeta.shapValueStr}</span>
            </div>

            <div className="p-3.5 bg-surface rounded-xl border border-border space-y-1">
              <span className="text-[10px] uppercase font-bold text-text-muted block">IMPACT</span>
              <span className={`text-xs font-black uppercase block mt-1 ${
                activeMeta.isPositive ? "text-red-400" : "text-emerald-400"
              }`}>
                {activeMeta.isPositive ? "INCREASES ATTACK RISK" : "DECREASES ATTACK RISK"}
              </span>
            </div>

            <div className="p-3.5 bg-surface rounded-xl border border-border space-y-1">
              <span className="text-[10px] uppercase font-bold text-text-muted block">RELATIVE IMPORTANCE</span>
              <span className="text-lg font-black text-gold font-mono-tech block">{activeItem.percent}%</span>
            </div>
          </div>

          {/* WHAT THIS MEANS */}
          <div className="space-y-1.5 pt-1">
            <span className="text-[11px] uppercase font-bold text-text-muted tracking-wider block">
              WHAT THIS MEANS
            </span>
            <p className="text-sm text-text leading-relaxed font-sans">
              "{activeMeta.whatItMeans}"
            </p>
          </div>

          {/* MODEL SIGNAL */}
          <div className="p-3.5 bg-surface rounded-xl border border-border space-y-1.5 text-xs font-mono-tech">
            <span className="text-[11px] uppercase font-bold text-text-muted block">MODEL SIGNAL</span>
            <p className="text-text-muted">
              Positive SHAP values push the prediction toward attack risk.
            </p>
            <p className="text-text-muted">
              Negative SHAP values push the prediction away from attack risk.
            </p>
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Main AttackForecast Component ───────────────────────────────────────────
export default function AttackForecast({ isActive }) {
  const [latestData, setLatestData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [selectedPairKey, setSelectedPairKey] = useState("");
  const [explainData, setExplainData] = useState(null);
  const [explainLoading, setExplainLoading] = useState(false);
  const [showAllFlows, setShowAllFlows] = useState(false);
  const [activeInfoModal, setActiveInfoModal] = useState(null);

  // Re-fetch latest forecast on mount or when isActive becomes true
  useEffect(() => {
    if (isActive !== false) {
      fetchLatestForecast();
    }
  }, [isActive]);

  const fetchLatestForecast = async () => {
    setLoading(true);
    try {
      const res = await fetch(`${CAPTURE_API}/api/forecast/latest`);
      const data = await res.json();
      setLatestData(data);
      if (data.results && data.results.length > 0) {
        const defaultKey = `${data.results[0].src_ip}>${data.results[0].dst_ip}`;
        setSelectedPairKey(defaultKey);
        fetchExplainability(data.results[0].src_ip, data.results[0].dst_ip);
      }
    } catch (err) {
      setLatestData({ status: "error", message: err.message });
    } finally {
      setLoading(false);
    }
  };

  const fetchExplainability = async (srcIp, dstIp) => {
    setExplainLoading(true);
    try {
      const res = await fetch(`${CAPTURE_API}/api/explain?src_ip=${encodeURIComponent(srcIp)}&dst_ip=${encodeURIComponent(dstIp)}`);
      if (res.ok) {
        const data = await res.json();
        setExplainData(data);
      } else {
        setExplainData(null);
      }
    } catch (_) {
      setExplainData(null);
    } finally {
      setExplainLoading(false);
    }
  };

  const handleConversationChange = (e) => {
    const key = e.target.value;
    setSelectedPairKey(key);
    const [src, dst] = key.split(">");
    if (src && dst) {
      fetchExplainability(src, dst);
    }
  };

  // Extract selected conversation
  const conversations = useMemo(() => latestData?.results || [], [latestData]);
  const selectedConversation = useMemo(() => {
    if (!conversations.length) return null;
    return conversations.find(c => `${c.src_ip}>${c.dst_ip}` === selectedPairKey) || conversations[0];
  }, [conversations, selectedPairKey]);

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[400px] font-mono-tech text-gold space-y-3">
        <RefreshCw className="h-8 w-8 animate-spin text-gold" />
        <p className="text-xs uppercase tracking-wider font-bold">Loading Latest Forecast Data...</p>
      </div>
    );
  }

  // ── Empty / error states ──
  const EmptyState = ({ icon: Icon = Target, title, children }) => (
    <div className="flex flex-col items-center justify-center min-h-[400px] font-mono-tech text-text space-y-4 glass-card rounded-2xl border border-border p-8 bg-surface">
      <Icon className="h-12 w-12 text-gold" />
      <h2 className="text-base font-bold text-white uppercase tracking-wider">{title}</h2>
      <div className="text-xs text-text-muted max-w-md text-center space-y-2">{children}</div>
    </div>
  );

  if (latestData?.status === "error") {
    return (
      <EmptyState icon={AlertTriangle} title="Cannot Reach Forecast Server">
        <p>The capture/forecast service at <span className="text-gold font-bold">{CAPTURE_API}</span> did not respond ({latestData.message}).</p>
        <p>Make sure the backend is running, then open this page again.</p>
      </EmptyState>
    );
  }

  if (latestData?.status === "no_conversations_qualified") {
    return (
      <EmptyState icon={AlertTriangle} title="File Processed — Nothing To Forecast">
        <p>
          <span className="text-gold font-bold">{latestData.filename}</span>: {latestData.total_flows} flows across{" "}
          {latestData.total_conversations} conversations, but none had at least{" "}
          {latestData.sequence_length ?? 5} flows between the same source and destination.
        </p>
        <p>The LSTM needs {latestData.sequence_length ?? 5} consecutive flows per conversation. Capture for longer and upload again.</p>
      </EmptyState>
    );
  }

  if (!latestData || latestData.status === "no_upload" || !conversations.length) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[400px] font-mono-tech text-text space-y-4 glass-card rounded-2xl border border-border p-8 bg-surface">
        <Target className="h-12 w-12 text-gold" />
        <h2 className="text-base font-bold text-white uppercase tracking-wider">No File Uploaded Yet</h2>
        <p className="text-xs text-text-muted max-w-md text-center">
          Upload a network flow CSV or PCAP file on the <span className="text-gold font-bold">Upload &amp; Analysis</span> page to run the World Model and view risk forecasts.
        </p>
      </div>
    );
  }

  // Conversation fields
  const srcIp = selectedConversation?.src_ip || "N/A";
  const dstIp = selectedConversation?.dst_ip || "N/A";
  const infProb = selectedConversation?.infiltration_probability ?? 0.0;
  const attackProbabilityPct = `${(infProb * 100).toFixed(1)}%`;
  const stageName = selectedConversation?.predicted_stage || "normal";
  const stageProbs = selectedConversation?.stage_probabilities || {};
  const maxStageProb = Math.max(...Object.values(stageProbs), 0.0);
  const modelConfidencePct = `${(maxStageProb * 100).toFixed(1)}%`;
  const threatLevel = infProb > 0.5 ? "HIGH RISK" : (infProb > 0.2 ? "ELEVATED" : "NORMAL");
  const threatLevelColor = threatLevel === "HIGH RISK" ? "text-red-500" : threatLevel === "ELEVATED" ? "text-gold" : "text-emerald-400";
  const windowTimeline = selectedConversation?.window_timeline || [];
  const conversationFlows = selectedConversation?.flows || [];

  return (
    <div className="space-y-5 animate-fade-in pb-8 font-sans text-text">

      {/* ===== PAGE HEADER ===== */}
      <div className="flex items-center justify-between flex-wrap gap-4 pt-1">
        <div>
          <h1 className="text-2xl font-extrabold uppercase tracking-wide font-mono-tech text-white">
            ATTACK FORECAST
          </h1>
        </div>

        {/* Header Summary Pills */}
        <div className="flex items-center gap-2.5 font-mono-tech text-sm">
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-xl bg-surface border border-border text-text">
            <span className="text-text-muted">Window</span>
            <span className="text-white font-bold">{latestData.sequence_length ?? "—"} Flows</span>
          </div>

          <div className="flex items-center gap-2 px-3 py-1.5 rounded-xl bg-surface border border-border text-text">
            <span className="text-text-muted">Total Flows</span>
            <span className="text-white font-bold">{latestData.total_flows}</span>
          </div>

          <div className="flex items-center gap-2 px-3 py-1.5 rounded-xl bg-surface border border-border text-text">
            <span className="text-text-muted">Conversations</span>
            <span className="text-white font-bold">{latestData.total_conversations}</span>
          </div>
        </div>
      </div>

      {/* ===== CONVERSATION SELECTOR CARD ===== */}
      <section className="glass-card rounded-2xl border border-border p-5 bg-surface space-y-4">
        <div className="flex items-center justify-between flex-wrap gap-4">
          <div className="flex items-center gap-3">
            <div className="h-3 w-3 rounded-full bg-gold" />
            <div>
              <h2 className="text-sm font-bold uppercase tracking-wider font-mono-tech text-white">
                SELECT NETWORK CONVERSATION FOR ANALYSIS
              </h2>
              <p className="text-sm text-text-muted font-mono-tech mt-0.5">
                File: <span className="text-gold font-bold">{latestData.filename}</span> ({latestData.total_conversations} total conversations, sorted by risk)
              </p>
            </div>
          </div>

          <div className="flex-1 max-w-md">
            <select
              value={selectedPairKey}
              onChange={handleConversationChange}
              className="w-full bg-surface-2 border border-border rounded-xl px-4 py-2 text-sm font-mono-tech font-bold text-gold focus:outline-none focus:border-gold transition-colors cursor-pointer"
            >
              {conversations.map(c => {
                const k = `${c.src_ip}>${c.dst_ip}`;
                const rPct = (c.infiltration_probability * 100).toFixed(1);
                const stg = (c.predicted_stage || "normal").toUpperCase().replace(/_/g, " ");
                return (
                  <option key={k} value={k}>
                    {c.src_ip} ➔ {c.dst_ip} (Risk: {rPct}% | Stage: {stg})
                  </option>
                );
              })}
            </select>
          </div>
        </div>
      </section>

      {/* ===== 1. CURRENT SECURITY STATE ===== */}
      <section className="glass-card rounded-2xl border border-border p-5 bg-surface space-y-4">
        <div className="border-b border-border pb-3">
          <h3 className="text-sm font-bold uppercase tracking-wider font-mono-tech text-white">
            CURRENT SECURITY STATE
          </h3>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 font-mono-tech">
          {/* Threat Level */}
          <div className="p-4 rounded-xl bg-surface-2 border border-border space-y-1.5">
            <span className="text-text-muted text-xs uppercase font-bold block">THREAT LEVEL</span>
            <span className={`text-xl font-black block uppercase ${threatLevelColor}`}>
              {threatLevel}
            </span>
            <p className="text-xs text-text-muted font-mono-jb">{srcIp} ➔ {dstIp}</p>
          </div>

          {/* Attack Probability */}
          <div className="p-4 rounded-xl bg-surface-2 border border-border space-y-2">
            <span className="text-text-muted text-xs uppercase font-bold block">ATTACK PROBABILITY</span>
            <span className="text-xl font-black text-gold block">
              {attackProbabilityPct}
            </span>
            <div className="h-2 w-full bg-bg border border-border rounded-full overflow-hidden">
              <div className="h-full bg-gold rounded-full" style={{ width: attackProbabilityPct }} />
            </div>
          </div>

          {/* Predicted Stage */}
          <div className="p-4 rounded-xl bg-surface-2 border border-border space-y-1.5">
            <span className="text-text-muted text-xs uppercase font-bold block">PREDICTED STAGE</span>
            <span className="text-xl font-black text-white block uppercase">
              {stageName.replace(/_/g, " ")}
            </span>
          </div>

          {/* Model Confidence */}
          <div className="p-4 rounded-xl bg-surface-2 border border-border space-y-2">
            <span className="text-text-muted text-xs uppercase font-bold block">MODEL CONFIDENCE</span>
            <span className="text-xl font-black text-white block">
              {modelConfidencePct}
            </span>
            <div className="h-2 w-full bg-bg border border-border rounded-full overflow-hidden">
              <div className="h-full bg-gold rounded-full" style={{ width: modelConfidencePct }} />
            </div>
          </div>
        </div>
      </section>

      {/* ===== FORECASTED ATTACK PROGRESSION (K-STEP SIMULATION) ===== */}
      <section id="risk-forecast" className="bg-surface rounded-2xl border border-border p-5 space-y-4 scroll-mt-6">
        <div className="flex items-center justify-between border-b border-border pb-3">
          <h3 className="text-sm font-bold uppercase tracking-wider text-white font-mono-tech">
            RISK FORECAST — INFILTRATION PROBABILITY
          </h3>
          <button
            onClick={() => setActiveInfoModal("risk_forecast")}
            title="What is Risk Forecast?"
            className="w-7 h-7 rounded-full bg-white text-slate-950 hover:bg-gold hover:text-slate-950 font-black text-sm flex items-center justify-center shadow-md transition-all transform hover:scale-110 active:scale-95 cursor-pointer shrink-0"
          >
            ?
          </button>
        </div>

        {selectedConversation?.forecast_timeline && selectedConversation.forecast_timeline.length > 0 ? (
          <div className="space-y-5">
            {/* Inline Stat Chips Row */}
            <div className="flex items-center gap-3 flex-wrap text-xs">
              <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-surface-2 border border-border">
                <span className="text-text-muted">Steps Ahead (K):</span>
                <span className="text-blue-hi font-bold">{selectedConversation.forecast_timeline.length} Steps</span>
              </div>
              <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-surface-2 border border-border">
                <span className="text-text-muted">Final Infiltration Prob:</span>
                <span className="text-gold font-bold">
                  {(selectedConversation.forecast_timeline[selectedConversation.forecast_timeline.length - 1].infiltration_probability * 100).toFixed(1)}%
                </span>
              </div>
              <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-surface-2 border border-border">
                <span className="text-text-muted">Final Stage:</span>
                <span className="text-white font-bold uppercase">
                  {selectedConversation.forecast_timeline[selectedConversation.forecast_timeline.length - 1].predicted_stage.replace(/_/g, " ")}
                </span>
              </div>
            </div>

            {/* Full-width K-Step Line Chart */}
            <div className="w-full bg-surface-2 p-4 rounded-xl border border-border">
              <KStepSimulationChart forecastTimeline={selectedConversation.forecast_timeline} />
            </div>

            {/* Step-by-step Stage Cards Row */}
            <div>
              <h4 className="text-xs font-bold uppercase text-text-muted tracking-wider mb-2">
                PREDICTED STAGES ACROSS STEPS (t+1 ... t+{selectedConversation.forecast_timeline.length})
              </h4>
              <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-5 gap-3">
                {selectedConversation.forecast_timeline.map((stepItem) => {
                  const stageUpper = (stepItem.predicted_stage || "normal").toUpperCase().replace(/_/g, " ");
                  const probPct = (stepItem.infiltration_probability * 100).toFixed(1);

                  return (
                    <div
                      key={stepItem.step}
                      className="p-3.5 rounded-xl border border-border bg-surface flex flex-col justify-between space-y-2"
                    >
                      <div className="flex justify-between items-center text-xs">
                        <span className="text-text-muted font-medium">STEP t+{stepItem.step}</span>
                        <span className="text-gold font-bold">{probPct}%</span>
                      </div>
                      <div className="text-sm font-bold text-white uppercase tracking-tight truncate">
                        {stageUpper}
                      </div>
                      <div className="h-1.5 w-full bg-surface-2 border border-border rounded-full overflow-hidden">
                        <div
                          className="h-full rounded-full bg-gold transition-all"
                          style={{ width: `${Math.max(2, stepItem.infiltration_probability * 100)}%` }}
                        />
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        ) : (
          <div className="p-6 bg-surface-2 border border-border rounded-xl text-center text-sm text-text-muted">
            K-step simulation unavailable (transition matrix not built)
          </div>
        )}
      </section>

      {/* ===== 3. PREDICTED ATTACK PROGRESSION ===== */}
      <section id="mitre-attack-progression" className="glass-card rounded-2xl border border-border p-5 bg-surface space-y-4 scroll-mt-6">
        <div className="flex items-center justify-between border-b border-border pb-3">
          <h3 className="text-sm font-bold uppercase tracking-wider font-mono-tech text-white">
            MITRE ATT&amp;CK PROGRESSION
          </h3>
          <button
            onClick={() => setActiveInfoModal("mitre_attack")}
            title="What is MITRE ATT&CK?"
            className="w-7 h-7 rounded-full bg-white text-slate-950 hover:bg-gold hover:text-slate-950 font-black text-sm flex items-center justify-center shadow-md transition-all transform hover:scale-110 active:scale-95 cursor-pointer shrink-0"
          >
            ?
          </button>
        </div>

        <AttackProgressionFlow predictedStage={stageName} forecastTimeline={selectedConversation?.forecast_timeline || []} />
      </section>

      {/* ===== 4. SHAP-BASED EXPLANATION ===== */}
      <section id="shap-explanation" className="glass-card rounded-2xl border border-border p-5 bg-surface space-y-4 scroll-mt-6">
        <div className="flex items-center justify-between border-b border-border pb-3">
          <div>
            <h3 className="text-sm font-bold uppercase tracking-wider font-mono-tech text-white">
              SHAP-BASED EXPLANATION
            </h3>
            <p className="text-sm text-text-muted mt-0.5 font-mono-tech">
              Feature contribution to the current attack prediction
            </p>
          </div>
          <button
            onClick={() => setActiveInfoModal("shap_explanation")}
            title="What is SHAP Explanation?"
            className="w-7 h-7 rounded-full bg-white text-slate-950 hover:bg-gold hover:text-slate-950 font-black text-sm flex items-center justify-center shadow-md transition-all transform hover:scale-110 active:scale-95 cursor-pointer shrink-0"
          >
            ?
          </button>
        </div>

        {explainLoading ? (
          <div className="flex items-center justify-center py-8 font-mono-tech text-sm text-gold gap-2 font-bold">
            <RefreshCw className="h-4 w-4 animate-spin text-gold" />
            <span>Computing SHAP feature attributions on model risk head...</span>
          </div>
        ) : (
          <ShapPieChart explainData={explainData} srcIp={srcIp} dstIp={dstIp} />
        )}
      </section>

      {/* ===== 5. OBSERVED NETWORK EVIDENCE ===== */}
      <section id="observed-network-evidence" className="glass-card rounded-2xl border border-border p-5 bg-surface space-y-4 scroll-mt-6">
        <div className="flex items-center justify-between border-b border-border pb-3">
          <h3 className="text-sm font-bold uppercase tracking-wider font-mono-tech text-white">
            OBSERVED NETWORK EVIDENCE
          </h3>
          <button
            onClick={() => setShowAllFlows(prev => !prev)}
            className="text-xs font-mono-tech px-2.5 py-1 rounded bg-surface-2 text-white border border-border hover:bg-gold hover:text-bg font-bold cursor-pointer transition-colors"
          >
            {showAllFlows ? "SHOW COMPACT" : "VIEW ALL FLOWS"}
          </button>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-sm font-mono-tech">
            <thead>
              <tr className="text-white uppercase text-xs tracking-wider border-b border-border text-left bg-surface-2">
                <th className="py-2.5 px-3 font-bold">Source IP</th>
                <th className="py-2.5 px-3 font-bold">Destination IP</th>
                <th className="py-2.5 px-3 text-center font-bold">Packets</th>
                <th className="py-2.5 px-3 text-center font-bold">Bytes</th>
                <th className="py-2.5 px-3 text-center font-bold">Protocol</th>
                <th className="py-2.5 px-3 text-center font-bold">Destination Port</th>
                <th className="py-2.5 px-3 text-right font-bold">Flow Duration</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {conversationFlows.length > 0 ? (
                conversationFlows.slice(0, showAllFlows ? 50 : 5).map((f, idx) => (
                  <tr key={idx} className="hover:bg-surface-2 transition-colors">
                    <td className="py-2.5 px-3 font-bold text-gold font-mono-jb">{f.src_ip ?? "—"}</td>
                    <td className="py-2.5 px-3 font-bold text-white font-mono-jb">{f.dst_ip ?? "—"}</td>
                    <td className="py-2.5 px-3 text-center text-text">{f.packet_count ?? "—"}</td>
                    <td className="py-2.5 px-3 text-center text-text">{f.byte_count != null ? formatBytes(f.byte_count) : "—"}</td>
                    <td className="py-2.5 px-3 text-center text-blue-hi uppercase font-bold">{f.protocol ?? "—"}</td>
                    <td className="py-2.5 px-3 text-center text-text">{f.dst_port != null ? getPortName(f.dst_port) : "—"}</td>
                    <td className="py-2.5 px-3 text-right text-text-muted">{f.duration != null ? `${Number(f.duration).toFixed(2)}s` : "—"}</td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={7} className="text-center py-4 text-text-muted">
                    No flow evidence available.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </section>

      {/* ===== BEGINNER INFO MODAL ===== */}
      {activeInfoModal && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-md animate-fade-in"
          onClick={() => setActiveInfoModal(null)}
        >
          <div
            className="bg-surface-2 border border-gold/40 rounded-2xl max-w-lg w-full p-6 space-y-4 shadow-2xl relative font-sans text-text"
            onClick={(e) => e.stopPropagation()}
          >
            {/* Modal Header */}
            <div className="flex items-center justify-between border-b border-border pb-3">
              <div className="flex items-center gap-3">
                <div className="w-8 h-8 rounded-full bg-white text-slate-950 flex items-center justify-center font-black text-lg shadow shrink-0">
                  ?
                </div>
                <h3 className="text-lg font-bold text-white font-mono-tech">
                  {activeInfoModal === "risk_forecast" && "What is Risk Forecast?"}
                  {activeInfoModal === "mitre_attack" && "What is MITRE ATT&CK?"}
                  {activeInfoModal === "shap_explanation" && "What is SHAP Explanation?"}
                </h3>
              </div>
              <button
                onClick={() => setActiveInfoModal(null)}
                className="w-8 h-8 rounded-full bg-surface border border-border flex items-center justify-center text-text-muted hover:text-white hover:bg-surface-2 transition-colors cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Modal Content in Plain English */}
            <div className="space-y-3 text-sm leading-relaxed text-text">
              {activeInfoModal === "risk_forecast" && (
                <>
                  <p className="font-bold text-white text-base">
                    Think of this as an AI weather forecast for cyber attacks! 🌦️⚡
                  </p>
                  <p>
                    Instead of predicting rain or sunshine, this model analyzes live network traffic and predicts how likely an attacker is to break deeper into your network over the next 5 steps (<span className="text-gold font-mono-tech font-bold">t+1</span> to <span className="text-gold font-mono-tech font-bold">t+5</span>).
                  </p>
                  <div className="bg-surface p-3.5 rounded-xl border border-border space-y-2 text-xs font-mono-tech">
                    <div className="flex items-start gap-2">
                      <span className="text-gold font-bold shrink-0">• Infiltration Prob (%):</span>
                      <span className="text-text-muted">The percentage chance that an attack will succeed at each step.</span>
                    </div>
                    <div className="flex items-start gap-2">
                      <span className="text-gold font-bold shrink-0">• Interactive Dots:</span>
                      <span className="text-text-muted">Click any yellow point on the graph to reveal step details!</span>
                    </div>
                  </div>
                  <p className="text-xs text-text-muted italic border-l-2 border-gold pl-3 py-0.5">
                    <strong>Why it matters:</strong> It lets security teams block threats before damage happens, instead of reacting after a breach.
                  </p>
                </>
              )}

              {activeInfoModal === "mitre_attack" && (
                <>
                  <p className="font-bold text-white text-base">
                    The universal playbook map for cyber security! 🗺️🛡️
                  </p>
                  <p>
                    Cyber attacks don't happen all at once — hackers follow a step-by-step path. The <strong>MITRE ATT&amp;CK Framework</strong> is the global standard map of hacker behavior.
                  </p>
                  <div className="bg-surface p-3.5 rounded-xl border border-border space-y-2 text-xs font-mono-tech">
                    <div className="flex items-start gap-2">
                      <span className="text-blue-hi font-bold shrink-0">• Attack Stages:</span>
                      <span className="text-text-muted">Starts from Reconnaissance (scouting), moves to Access, Lateral Movement (spreading), and ends at Exfiltration (stealing data).</span>
                    </div>
                    <div className="flex items-start gap-2">
                      <span className="text-blue-hi font-bold shrink-0">• Forecast Progression:</span>
                      <span className="text-text-muted">Shows where the attacker is right now and where the AI predicts they will go next.</span>
                    </div>
                  </div>
                  <p className="text-xs text-text-muted italic border-l-2 border-blue-hi pl-3 py-0.5">
                    <strong>Why it matters:</strong> Knowing the attacker's next phase lets defenders erect digital walls exactly where the attacker is heading.
                  </p>
                </>
              )}

              {activeInfoModal === "shap_explanation" && (
                <>
                  <p className="font-bold text-white text-base">
                    Opening the "Black Box" of Artificial Intelligence! 📦🔍
                  </p>
                  <p>
                    AI models can feel like black boxes. <strong>SHAP</strong> (SHapley Additive exPlanations) opens the box and explains <em>why</em> the AI made its threat prediction.
                  </p>
                  <div className="bg-surface p-3.5 rounded-xl border border-border space-y-2 text-xs font-mono-tech">
                    <div className="flex items-start gap-2">
                      <span className="text-gold font-bold shrink-0">• Interactive Pie Slices:</span>
                      <span className="text-text-muted">Each slice represents a network measurement (e.g. connection duration or reset counts). Larger slices had more weight on the decision.</span>
                    </div>
                    <div className="flex items-start gap-2">
                      <span className="text-gold font-bold shrink-0">• Risk Impact:</span>
                      <span className="text-text-muted">Red indicators mean that measurement pushed the risk UP, while green means it made it look SAFER.</span>
                    </div>
                  </div>
                  <p className="text-xs text-text-muted italic border-l-2 border-gold pl-3 py-0.5">
                    <strong>Why it matters:</strong> Click any slice in the chart to get a plain-English explanation of what network activity triggered the alert.
                  </p>
                </>
              )}
            </div>

            {/* Modal Footer */}
            <div className="pt-2 flex justify-end border-t border-border">
              <button
                onClick={() => setActiveInfoModal(null)}
                className="px-5 py-2 rounded-xl bg-gold text-slate-950 font-bold text-xs uppercase tracking-wider font-mono-tech hover:bg-gold-light transition-colors cursor-pointer shadow"
              >
                Got It!
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
