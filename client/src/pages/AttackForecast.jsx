import React, { useState, useMemo, useEffect, useRef } from "react";
import {
  Target, AlertTriangle, RefreshCw, Menu, ChevronDown, X, UploadCloud, Trash2
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

export const TIMELINE_STAGE_COLORS = {
  normal: "#383835",
  reconnaissance: "#3987e5",
  "initial access": "#d95926",
  initial_access: "#d95926",
  "command and control": "#199e70",
  command_control: "#199e70",
  command_and_control: "#199e70",
  "lateral movement": "#c98500",
  lateral_movement: "#c98500",
  exfiltration: "#d55181",
  other: "#8f8e86",
};

export function getStageThemeColor(stage) {
  if (!stage) return TIMELINE_STAGE_COLORS.normal;
  const key = String(stage).toLowerCase().trim();
  return (
    TIMELINE_STAGE_COLORS[key] ||
    TIMELINE_STAGE_COLORS[key.replace(/ /g, "_")] ||
    TIMELINE_STAGE_COLORS[key.replace(/_/g, " ")] ||
    "#8f8e86"
  );
}

function formatStageDisplayName(stageKey) {
  if (!stageKey) return "No attack stage";
  const strKey = typeof stageKey === "string" ? stageKey : String(stageKey);
  const key = strKey.toLowerCase().trim();
  if (key === "normal") return "No attack stage";
  if (key === "command_control" || key === "command_and_control" || key === "c2") return "Command and Control";
  if (key === "lateral_movement") return "Lateral Movement";
  if (key === "initial_access") return "Initial Access";
  if (key === "reconnaissance") return "Reconnaissance";
  if (key === "exfiltration") return "Exfiltration";
  return strKey.replace(/_/g, " ").replace(/\b\w/g, c => c.toUpperCase());
}

function getMonotonePath(pts) {
  if (!pts || pts.length === 0) return "";
  if (pts.length === 1) return `M ${pts[0].x.toFixed(1)},${pts[0].y.toFixed(1)}`;
  let path = `M ${pts[0].x.toFixed(1)},${pts[0].y.toFixed(1)}`;
  for (let i = 0; i < pts.length - 1; i++) {
    const p0 = pts[i === 0 ? 0 : i - 1];
    const p1 = pts[i];
    const p2 = pts[i + 1];
    const p3 = pts[i + 2 < pts.length ? i + 2 : i + 1];

    const cp1x = p1.x + (p2.x - p0.x) / 6;
    const cp1y = p1.y + (p2.y - p0.y) / 6;
    const cp2x = p2.x - (p3.x - p1.x) / 6;
    const cp2y = p2.y - (p3.y - p1.y) / 6;

    path += ` C ${cp1x.toFixed(1)},${cp1y.toFixed(1)} ${cp2x.toFixed(1)},${cp2y.toFixed(1)} ${p2.x.toFixed(1)},${p2.y.toFixed(1)}`;
  }
  return path;
}

// ─── SECTION 2: Risk Trajectory & K-Step Simulation Chart ────────────────────
function KStepSimulationChart({
  H,
  threshold = 0.5,
  modelCopies = 3,
  baselineAvailable = false,
  notices = [],
  selectedWindowIdx = null,
  onSelectWindow,
}) {
  const [hoveredIndex, setHoveredIndex] = useState(null);
  const [isDragging, setIsDragging] = useState(false);
  const [isScrubberDragging, setIsScrubberDragging] = useState(false);

  const dragRef = useRef({ isDown: false, startX: 0, startW: 0, hasMoved: false });
  const scrubberTrackRef = useRef(null);

  const totalObserved = H?.time?.length || 0;
  const w = (selectedWindowIdx !== null && selectedWindowIdx >= 0 && selectedWindowIdx < totalObserved)
    ? selectedWindowIdx
    : Math.max(0, totalObserved - 1);

  // Compute 12 observed windows up to w (fewer if host has fewer)
  const wStart = Math.max(0, w - 11);

  const timelineData = useMemo(() => {
    if (!H || totalObserved === 0) return [];

    const observed = [];
    for (let i = wStart; i <= w; i++) {
      const timeStr = H.time?.[i] || `W${i + 1}`;
      const shortTime = timeStr.includes(" ") ? timeStr.split(" ").pop() : timeStr;
      const _st0 = H.stage_forecast?.[i]?.[0] || "normal";
      const _pr0 = H.stage_forecast_prob?.[i]?.[0];
      const wmRisk = _pr0 == null ? (H.risk_60s?.[i] ?? 0) : (String(_st0).toLowerCase() !== "normal" ? _pr0 : 1 - _pr0);
      const lrRisk = (baselineAvailable && H.baseline_risk_60s && H.baseline_risk_60s[i] != null)
        ? H.baseline_risk_60s[i]
        : null;
      const stage = H.stage_forecast?.[i]?.[0] || "normal";
      const trueStage = H.true_stage?.[i] || null;
      const p0 = H.stage_forecast_prob?.[i]?.[0];
      const nowAttack = p0 == null ? null : (String(stage).toLowerCase() !== "normal" ? p0 : 1 - p0);

      observed.push({
        id: `obs-${i}`,
        obsIdx: i,
        label: shortTime,
        sub: "Observed",
        wmRisk: Math.max(0, Math.min(1, wmRisk)),
        lrRisk: lrRisk != null ? Math.max(0, Math.min(1, lrRisk)) : null,
        stage,
        trueStage,
        nowAttack: nowAttack != null ? Math.max(0, Math.min(1, nowAttack)) : null,
        stageProb: H.stage_forecast_prob?.[i]?.[0] ?? null,
        second: H.stage_forecast_second?.[i]?.[0] ?? null,
        secondProb: H.stage_forecast_second_prob?.[i]?.[0] ?? null,
        flows: H.flows?.[i] ?? null,
        isForecast: false,
      });
    }

    // 6 Forecast steps (k = 1..6)
    const forecast = [];
    for (let k = 1; k <= 6; k++) {
      const stage = H.stage_forecast?.[w]?.[k] || "normal";
      const _prk = H.stage_forecast_prob?.[w]?.[k];
      const wmRisk = _prk == null ? 0 : (String(stage).toLowerCase() !== "normal" ? _prk : 1 - _prk);
      const cMin = wmRisk;
      const cMax = wmRisk;

      forecast.push({
        id: `f-${k}`,
        label: `t+${k}`,
        sub: "Forecast",
        wmRisk: Math.max(0, Math.min(1, wmRisk)),
        lrRisk: null,
        stage,
        trueStage: null,
        stageProb: H.stage_forecast_prob?.[w]?.[k] ?? null,
        second: H.stage_forecast_second?.[w]?.[k] ?? null,
        secondProb: H.stage_forecast_second_prob?.[w]?.[k] ?? null,
        flows: null,
        aheadSeconds: k * 10,
        isForecast: true,
        coneUpper: Math.max(0, Math.min(1, cMax)),
        coneLower: Math.max(0, Math.min(1, cMin)),
      });
    }

    return [...observed, ...forecast];
  }, [H, w, wStart, totalObserved, baselineAvailable]);

  // Chart Dimensions
  const svgWidth = 840;
  const svgHeight = 286;
  const paddingLeft = 52;
  const paddingRight = 24;
  const paddingTop = 26;
  const paddingBottom = 54;

  const chartWidth = svgWidth - paddingLeft - paddingRight;
  const chartHeight = svgHeight - paddingTop - paddingBottom;

  const yTicks = [
    { label: "1.0", val: 1.0 },
    { label: "0.75", val: 0.75 },
    { label: "0.5", val: 0.50 },
    { label: "0.25", val: 0.25 },
    { label: "0", val: 0.0 },
  ];

  const numPoints = timelineData.length;
  const stepW = numPoints > 1 ? chartWidth / (numPoints - 1) : chartWidth;

  // Plain-language reading of the graph for the selected window
  const graphFacts = useMemo(() => {
    const obs = timelineData.filter((p) => !p.isForecast);
    const fc = timelineData.filter((p) => p.isForecast);
    if (obs.length === 0) return [];
    const thr = Number(threshold) || 0.5;
    const pc = (x) => `${(x * 100).toFixed(0)}%`;
    const nice = (st) => String(st || "normal").replace(/_/g, " ");
    const cur = obs[obs.length - 1];
    const facts = [];
    facts.push(
      cur.wmRisk >= thr
        ? `Selected window ${cur.label}: attack probability ${pc(cur.wmRisk)}. The model reads this host as attacking now (${nice(cur.stage)}).`
        : `Selected window ${cur.label}: attack probability ${pc(cur.wmRisk)}. The model reads this host as normal right now.`
    );
    const hot = fc.map((p, i) => ({ ...p, k: i + 1 })).filter((p) => p.wmRisk >= thr);
    if (hot.length > 0) {
      const top = hot.reduce((a, b) => (b.wmRisk > a.wmRisk ? b : a));
      facts.push(`Forecast (right of NOW): ${nice(top.stage)} expected between +${hot[0].k * 10} s and +${hot[hot.length - 1].k * 10} s, up to ${pc(top.wmRisk)}.`);
    } else if (fc.length > 0) {
      facts.push(`Forecast (right of NOW): no attack expected in the next 60 seconds (highest ${pc(Math.max(...fc.map((p) => p.wmRisk)))}).`);
    }
    const above = obs.filter((p) => p.wmRisk >= thr).length;
    const lab = obs.filter((p) => p.trueStage && !["normal", "ambiguous"].includes(String(p.trueStage).toLowerCase()));
    let line = `Of the ${obs.length} observed windows shown, the model reads ${above} as attack (probability 50% or more).`;
    if (obs.some((p) => p.trueStage)) {
      line += lab.length > 0
        ? ` The file's own labels mark ${lab.length} of them as attack (red bands); the model reads ${lab.filter((p) => p.wmRisk >= thr).length} of those as attack.`
        : " The file's own labels mark none of them as attack.";
    }
    facts.push(line);
    if (cur.lrRisk != null) {
      facts.push(`Grey dashed line: the LR baseline (a simple logistic-regression model). At this window it gives ${pc(cur.lrRisk)}.`);
    }
    facts.push("Solid blue line: what the model detected in the traffic that is in the file. Dashed gold line: what the model forecasts for the next 60 seconds. High = attack, low = normal. Red bands: the true answer written in the file, shown only to check the model.");
    return facts;
  }, [timelineData, threshold]);

  const coords = useMemo(() => {
    return timelineData.map((pt, idx) => {
      const x = numPoints === 1
        ? paddingLeft + chartWidth / 2
        : paddingLeft + (idx / (numPoints - 1)) * chartWidth;
      const yWm = paddingTop + (1 - pt.wmRisk) * chartHeight;
      const yLr = pt.lrRisk != null ? paddingTop + (1 - pt.lrRisk) * chartHeight : null;
      const yNow = pt.nowAttack != null ? paddingTop + (1 - pt.nowAttack) * chartHeight : null;
      const yUpper = pt.isForecast ? paddingTop + (1 - pt.coneUpper) * chartHeight : yWm;
      const yLower = pt.isForecast ? paddingTop + (1 - pt.coneLower) * chartHeight : yWm;
      return {
        ...pt,
        x,
        y: yWm,
        yLr,
        yNow,
        yUpper,
        yLower,
      };
    });
  }, [timelineData, numPoints, chartWidth, chartHeight, paddingLeft, paddingTop]);

  // World-model line points
  const wmPts = useMemo(() => coords.map((c) => ({ x: c.x, y: c.y })), [coords]);
  const wmPath = useMemo(() => getMonotonePath(wmPts), [wmPts]);
  // The same line in two parts: what the model DETECTED on traffic in the file, and what it FORECASTS after NOW.
  const obsPath = useMemo(() => getMonotonePath(coords.filter((c) => !c.isForecast).map((c) => ({ x: c.x, y: c.y }))), [coords]);
  const fcPath = useMemo(() => {
    const lastObs = coords.filter((c) => !c.isForecast).slice(-1);
    return getMonotonePath([...lastObs, ...coords.filter((c) => c.isForecast)].map((c) => ({ x: c.x, y: c.y })));
  }, [coords]);
  const nowX = useMemo(() => {
    const o = coords.filter((c) => !c.isForecast);
    return o.length ? o[o.length - 1].x : paddingLeft;
  }, [coords, paddingLeft]);

  // LR baseline points (only over observed windows)
  const lrCoords = useMemo(() => coords.filter(c => !c.isForecast && c.yLr != null), [coords]);
  const lrPts = useMemo(() => lrCoords.map(c => ({ x: c.x, y: c.yLr })), [lrCoords]);
  const lrPath = useMemo(() => getMonotonePath(lrPts), [lrPts]);

  // "Attack happening now" line (observed windows only)
  const nowCoords = useMemo(() => coords.filter(c => !c.isForecast && c.yNow != null), [coords]);
  const nowPath = useMemo(() => getMonotonePath(nowCoords.map(c => ({ x: c.x, y: c.yNow }))), [nowCoords]);

  // Forecast cone points (starting from last observed window w)
  const { coneAreaPath, coneUpperPath, coneLowerPath } = useMemo(() => {
    const lastObs = coords.find(c => c.obsIdx === w);
    const forecastCoords = coords.filter(c => c.isForecast);
    let area = "";
    let upper = "";
    let lower = "";

    if (lastObs && forecastCoords.length > 0) {
      const conePts = [lastObs, ...forecastCoords];
      const upperPts = conePts.map(c => ({ x: c.x, y: c.yUpper }));
      const lowerPts = conePts.map(c => ({ x: c.x, y: c.yLower }));
      upper = getMonotonePath(upperPts);
      lower = getMonotonePath(lowerPts);
      const lowerRev = [...lowerPts].reverse();
      area = `${upper} L ${lowerRev.map(p => `${p.x.toFixed(1)},${p.y.toFixed(1)}`).join(" L ")} Z`;
    }
    return { coneAreaPath: area, coneUpperPath: upper, coneLowerPath: lower };
  }, [coords, w]);

  // Pointer drag on main SVG chart canvas
  const handlePointerDown = (e) => {
    if (totalObserved <= 1) return;
    dragRef.current = {
      isDown: true,
      startX: e.clientX,
      startW: w,
      hasMoved: false,
    };
    try {
      e.currentTarget.setPointerCapture(e.pointerId);
    } catch (_) {}
  };

  const handlePointerMove = (e) => {
    if (dragRef.current.isDown) {
      const dx = e.clientX - dragRef.current.startX;
      if (Math.abs(dx) > 3) {
        dragRef.current.hasMoved = true;
        setIsDragging(true);
        setHoveredIndex(null);

        // Tactile scrub sensitivity: ~14px of drag per window
        const pxPerStep = 14;
        const stepShift = Math.round(dx / pxPerStep);
        const nextW = Math.max(0, Math.min(totalObserved - 1, dragRef.current.startW + stepShift));
        if (nextW !== w && onSelectWindow) {
          onSelectWindow(nextW);
        }
      }
    }
  };

  const handlePointerUp = (e) => {
    if (dragRef.current.isDown) {
      if (!dragRef.current.hasMoved) {
        // Direct click on chart: find clicked horizontal position
        const rect = e.currentTarget.getBoundingClientRect();
        const clientX = e.clientX - rect.left;
        const svgX = (clientX / rect.width) * svgWidth;
        if (svgX >= paddingLeft && svgX <= paddingLeft + chartWidth) {
          const ratio = (svgX - paddingLeft) / chartWidth;
          const pointIdx = Math.round(ratio * (numPoints - 1));
          if (pointIdx >= 0 && pointIdx < coords.length) {
            const targetCoord = coords[pointIdx];
            if (targetCoord && !targetCoord.isForecast && targetCoord.obsIdx != null && onSelectWindow) {
              onSelectWindow(targetCoord.obsIdx);
            }
          }
        }
      }
      dragRef.current.isDown = false;
      setIsDragging(false);
      try {
        e.currentTarget.releasePointerCapture(e.pointerId);
      } catch (_) {}
    }
  };

  const handlePointerCancel = (e) => {
    dragRef.current.isDown = false;
    setIsDragging(false);
    try {
      e.currentTarget.releasePointerCapture(e.pointerId);
    } catch (_) {}
  };

  // Mouse wheel / trackpad scroll left/right to scrub time
  const handleWheel = (e) => {
    if (totalObserved <= 1 || !onSelectWindow) return;
    const delta = Math.abs(e.deltaX) > Math.abs(e.deltaY) ? e.deltaX : e.deltaY;
    if (Math.abs(delta) > 10) {
      const step = delta > 0 ? 1 : -1;
      const nextW = Math.max(0, Math.min(totalObserved - 1, w + step));
      if (nextW !== w) {
        onSelectWindow(nextW);
      }
    }
  };

  // Mini scrubber track drag
  const handleScrubberAction = (clientX) => {
    if (!scrubberTrackRef.current || totalObserved <= 1 || !onSelectWindow) return;
    const rect = scrubberTrackRef.current.getBoundingClientRect();
    const ratio = Math.max(0, Math.min(1, (clientX - rect.left) / rect.width));
    const targetIdx = Math.max(0, Math.min(totalObserved - 1, Math.round(ratio * (totalObserved - 1))));
    if (targetIdx !== w) {
      onSelectWindow(targetIdx);
    }
  };

  const handleScrubberPointerDown = (e) => {
    if (totalObserved <= 1) return;
    setIsScrubberDragging(true);
    handleScrubberAction(e.clientX);
    try {
      e.currentTarget.setPointerCapture(e.pointerId);
    } catch (_) {}
  };

  const handleScrubberPointerMove = (e) => {
    if (isScrubberDragging) {
      handleScrubberAction(e.clientX);
    }
  };

  const handleScrubberPointerUp = (e) => {
    setIsScrubberDragging(false);
    try {
      e.currentTarget.releasePointerCapture(e.pointerId);
    } catch (_) {}
  };

  if (!timelineData.length) {
    return (
      <div className="py-8 text-center text-[#8f8e86] text-xs font-mono-jb">
        Timeline unavailable for this host
      </div>
    );
  }

  const threshVal = Math.max(0, Math.min(1, threshold));
  const thresholdY = paddingTop + (1 - threshVal) * chartHeight;

  const hasTrueStage = H?.true_stage != null && Array.isArray(H.true_stage) && H.true_stage.some(s => s != null);
  const activeCoord = hoveredIndex !== null && coords[hoveredIndex] ? coords[hoveredIndex] : null;
  const currentWindowTime = H?.time?.[w] || `Window ${w + 1}`;

  return (
    <div className="w-full relative select-none">
      {/* Interactive Controls & Legend Header */}
      <div className="flex items-center justify-between flex-wrap gap-3 pb-3 mb-2 text-[11px] border-b border-white/20">
        {/* Left: Legend */}
        <div className="flex items-center gap-4 flex-wrap">
          {/* World Model */}
          <div className="flex items-center gap-1.5">
            <span className="w-4 h-[2px] bg-[#3987e5] inline-block rounded-full" />
            <span className="text-[#f4f3ee] font-medium font-sans">Detected by the model (traffic in the file)</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span
              className="w-5 h-[2px] inline-block"
              style={{ backgroundImage: "linear-gradient(to right, #cba135 60%, transparent 60%)", backgroundSize: "6px 2px" }}
            />
            <span className="text-[#cba135] font-medium font-sans">Forecast by the model (next 60 s)</span>
          </div>

          {/* LR baseline */}
          {baselineAvailable && (
            <div className="flex items-center gap-1.5">
              <span
                className="w-4 h-[1.5px] inline-block"
                style={{
                  backgroundImage: "linear-gradient(to right, #8f8e86 50%, transparent 50%)",
                  backgroundSize: "6px 1.5px",
                }}
              />
              <span className="text-[#8f8e86] font-medium font-sans">LR baseline</span>
            </div>
          )}

          {/* Labelled malicious */}
          {hasTrueStage && (
            <div className="flex items-center gap-1.5">
              <span className="w-3 h-2.5 bg-[rgba(208,59,59,0.18)] border border-[rgba(208,59,59,0.4)] inline-block rounded-sm" />
              <span className="text-[#8f8e86] font-medium font-sans">True answer in the file: attack (for checking only)</span>
            </div>
          )}
        </div>

        {/* Forecast Horizon Label */}
        <span className="text-[11px] font-mono-jb text-[#8f8e86]">
          Horizon: 60s (K=6)
        </span>
      </div>

      {/* SVG Canvas with Direct Left/Right Drag Scrubbing */}
      <div className="w-full relative group">
        <svg
          viewBox={`0 0 ${svgWidth} ${svgHeight}`}
          className={`w-full h-auto overflow-visible select-none touch-none transition-colors ${
            isDragging ? "cursor-grabbing" : "cursor-grab"
          }`}
          onPointerDown={handlePointerDown}
          onPointerMove={handlePointerMove}
          onPointerUp={handlePointerUp}
          onPointerCancel={handlePointerCancel}
          onWheel={handleWheel}
          onMouseLeave={() => {
            if (!dragRef.current.isDown) setHoveredIndex(null);
          }}
        >
          {/* Ground truth full-height attack bars */}
          {coords.map((c, idx) => {
            if (c.isForecast) return null;
            const isAttack = Boolean(c.trueStage && c.trueStage !== "normal" && c.trueStage !== "ambiguous");
            if (!isAttack) return null;
            return (
              <rect
                key={`gt-${idx}`}
                x={c.x - stepW / 2}
                y={paddingTop}
                width={stepW}
                height={chartHeight}
                fill="rgba(208,59,59,0.13)"
              />
            );
          })}

          {/* Grid Lines & Y Ticks */}
          {yTicks.map((tick) => {
            const y = paddingTop + (1 - tick.val) * chartHeight;
            return (
              <g key={tick.label}>
                <line
                  x1={paddingLeft}
                  y1={y}
                  x2={paddingLeft + chartWidth}
                  y2={y}
                  stroke="rgba(255,255,255,0.055)"
                  strokeWidth="1"
                />
                <text
                  x={paddingLeft - 8}
                  y={y + 4}
                  fill="#8f8e86"
                  fontSize="11.5"
                  fontFamily="JetBrains Mono, monospace"
                  fontWeight="normal"
                  textAnchor="end"
                >
                  {tick.label}
                </text>
              </g>
            );
          })}

          {/* Vertical Grid Lines */}
          {coords.map((c, idx) => (
            <line
              key={`v-grid-${idx}`}
              x1={c.x}
              y1={paddingTop}
              x2={c.x}
              y2={paddingTop + chartHeight}
              stroke="rgba(255,255,255,0.055)"
              strokeWidth="1"
            />
          ))}

          {/* Axis Titles */}
          <text
            x={paddingLeft}
            y={paddingTop - 10}
            fill="#8f8e86"
            fontSize="11"
            fontFamily="Inter, sans-serif"
            fontWeight="normal"
          >
            attack probability
          </text>
          {/* X Axis Region Labels */}
          {(() => {
            const nowCoord = coords.find((c) => c.obsIdx === w);
            const nowX = nowCoord ? nowCoord.x : paddingLeft + chartWidth * 0.65;
            const obsMidX = (paddingLeft + nowX) / 2;
            const predMidX = (nowX + (paddingLeft + chartWidth)) / 2;

            return (
              <g className="select-none pointer-events-none">
                {/* Observed / Labelled Traffic */}
                <text
                  x={obsMidX}
                  y={paddingTop + chartHeight + 43}
                  fill="#8f8e86"
                  fontSize="11"
                  fontFamily="Inter, sans-serif"
                  fontWeight="600"
                  textAnchor="middle"
                  letterSpacing="0.04em"
                >
                  ◀ LABELLED TRAFFIC
                </text>

                {/* Predicted Traffic */}
                <text
                  x={predMidX}
                  y={paddingTop + chartHeight + 43}
                  fill="#cba135"
                  fontSize="11"
                  fontFamily="Inter, sans-serif"
                  fontWeight="600"
                  textAnchor="middle"
                  letterSpacing="0.04em"
                >
                  PREDICTED ▶
                </text>
              </g>
            );
          })()}

          {/* X Axis Ticks */}
          {(() => {
            const obsCoords = coords.filter((c) => !c.isForecast);
            const numObs = obsCoords.length;
            const visibleObsIndices = new Set();
            const count = Math.min(7, numObs);
            if (count > 0) {
              for (let step = 0; step < count; step++) {
                const idx = count === 1 ? 0 : Math.round((step * (numObs - 1)) / (count - 1));
                visibleObsIndices.add(idx);
              }
            }

            return coords.map((c, idx) => {
              if (!c.isForecast) {
                const obsIdxInList = obsCoords.findIndex((o) => o.id === c.id);
                const isSelected = c.obsIdx === w;
                if (!visibleObsIndices.has(obsIdxInList) && !isSelected) {
                  return null;
                }
              }
              return (
                <text
                  key={`x-tick-${idx}`}
                  x={c.x}
                  y={paddingTop + chartHeight + 17}
                  fill={c.obsIdx === w ? "#CBA135" : "#8f8e86"}
                  fontSize="11"
                  fontFamily="Inter, sans-serif"
                  fontWeight={c.obsIdx === w ? "bold" : "normal"}
                  textAnchor="middle"
                >
                  {c.label}
                </text>
              );
            });
          })()}

          {/* Logistic-Regression Baseline Line */}
          {baselineAvailable && lrPath && (
            <path
              d={lrPath}
              fill="none"
              stroke="#8f8e86"
              strokeWidth="1.5"
              strokeDasharray="4 4"
            />
          )}

          {/* World-Model Line */}
          <path d={obsPath} fill="none" stroke="#3987e5" strokeWidth="2" strokeLinecap="round" />
          <path d={fcPath} fill="none" stroke="#cba135" strokeWidth="2" strokeLinecap="round" strokeDasharray="6 5" />

          {/* Selected-Window Cursor Marker */}
          {coords.map((c) => {
            if (c.obsIdx === w) {
              return (
                <g key="selected-window-marker">
                  <line
                    x1={c.x}
                    y1={paddingTop}
                    x2={c.x}
                    y2={paddingTop + chartHeight}
                    stroke="#CBA135"
                    strokeWidth="2"
                    strokeDasharray="2 2"
                  />
                  {/* Top scrubber badge indicator */}
                  <rect
                    x={c.x - 14}
                    y={paddingTop - 12}
                    width={28}
                    height={12}
                    rx={3}
                    fill="#CBA135"
                  />
                  <text
                    x={c.x}
                    y={paddingTop - 3}
                    fill="#0B0F14"
                    fontSize="8.5"
                    fontFamily="JetBrains Mono, monospace"
                    fontWeight="bold"
                    textAnchor="middle"
                  >
                    NOW
                  </text>
                  <circle cx={c.x} cy={c.y} r="5.5" fill="#0B0F14" stroke="#CBA135" strokeWidth="2.5" />
                </g>
              );
            }
            return null;
          })}

          {/* Active Hover Circle */}
          {activeCoord && !isDragging && (
            <circle
              cx={activeCoord.x}
              cy={activeCoord.y}
              r="4"
              fill="#3987e5"
            />
          )}

          {/* Hitboxes for Hover and Selection */}
          {coords.map((c, idx) => (
            <rect
              key={`hit-${idx}`}
              x={c.x - stepW / 2}
              y={paddingTop}
              width={stepW}
              height={chartHeight}
              fill="transparent"
              onMouseEnter={() => {
                if (!dragRef.current.isDown) setHoveredIndex(idx);
              }}
            />
          ))}
        </svg>

        {/* Hover Tooltip (hidden during active dragging) */}
        {activeCoord && !isDragging && (
          <div
            style={{
              position: "absolute",
              left: `${(activeCoord.x / svgWidth) * 100}%`,
              top: `${Math.max(8, (activeCoord.y / svgHeight) * 100 - 24)}%`,
              transform: activeCoord.x > svgWidth * 0.72 ? "translate(-105%, -50%)" : "translate(16px, -50%)",
            }}
            className="z-30 p-3 bg-[#262624] border border-[#3a3a37] rounded-lg shadow-xl pointer-events-none min-w-[200px]"
          >
            {(() => {
              const c = activeCoord;
              const nm = (st) => (!st || String(st).toLowerCase() === "normal" ? "Normal" : formatStageDisplayName(st));
              const pct = (x) => (x == null || !Number.isFinite(Number(x)) ? "" : `${(Number(x) * 100).toFixed(0)}%`);
              const modelAttack = String(c.stage || "normal").toLowerCase() !== "normal";
              const lbl = c.trueStage ? String(c.trueStage).toLowerCase() : null;
              const labelAttack = lbl != null && lbl !== "normal" && lbl !== "ambiguous";
              const row = (k, v, cls = "text-[#f4f3ee]") => (
                <div className="flex justify-between items-center gap-4">
                  <span className="text-[#8f8e86] font-sans">{k}</span>
                  <span className={`font-mono-jb font-bold ${cls}`}>{v}</span>
                </div>
              );
              return (
                <>
                  <div className="pb-1.5 mb-2 border-b border-[#3a3a37]">
                    <div className="text-[12px] font-semibold text-[#f4f3ee] font-sans">
                      {c.isForecast ? `+${c.aheadSeconds} seconds from NOW` : `Time ${c.label}`}
                    </div>
                    <div className={`text-[10px] font-bold uppercase tracking-wider ${c.isForecast ? "text-gold" : "text-[#8f8e86]"}`}>
                      {c.isForecast ? "Forecast: has not happened yet" : "Observed: traffic that is in the file"}
                    </div>
                  </div>
                  <div className="space-y-1.5 text-[11px] text-[#c3c2b7]">
                    {row(c.isForecast ? "Model expects:" : "Model says:", `${nm(c.stage)} ${pct(c.stageProb)}`, modelAttack ? "text-[#e5484d]" : "text-[#3fb950]")}
                    {row("Attack probability:", `${(c.wmRisk * 100).toFixed(1)}%`)}
                    {c.second && pct(c.secondProb) && row("Other possibility:", `${nm(c.second)} ${pct(c.secondProb)}`, "text-[#c3c2b7]")}
                    {!c.isForecast && c.flows != null && row("Flows in these 10 s:", String(c.flows), "text-[#c3c2b7]")}
                    {!c.isForecast && baselineAvailable && c.lrRisk != null && row("LR baseline:", `${(c.lrRisk * 100).toFixed(1)}%`, "text-[#c3c2b7]")}
                    {!c.isForecast && lbl != null && (
                      <div className="pt-1.5 mt-1 border-t border-[#3a3a37] space-y-1.5">
                        {row("True answer in the file:", lbl === "ambiguous" ? "Mixed" : labelAttack ? nm(lbl) : "Normal", labelAttack ? "text-[#e5484d]" : "text-[#3fb950]")}
                        {lbl !== "ambiguous" && row("Model vs true answer:", modelAttack === labelAttack ? "agree" : "differ", modelAttack === labelAttack ? "text-[#3fb950]" : "text-[#f59e0b]")}
                      </div>
                    )}
                    {c.isForecast && (
                      <div className="pt-1.5 mt-1 border-t border-[#3a3a37] text-[10px] text-[#8f8e86]">
                        No true answer yet: this is the model's prediction.
                      </div>
                    )}
                  </div>
                </>
              );
            })()}
          </div>
        )}
      </div>

      {/* Below Graph Controls (Scroll to Latest Button on the right) */}
      <div className="flex items-center justify-end pt-2">
        {totalObserved > 1 && (
          <button
            type="button"
            onClick={() => onSelectWindow && onSelectWindow(totalObserved - 1)}
            disabled={w === totalObserved - 1}
            className={`px-3 py-1.5 text-xs font-semibold rounded-md border transition-colors flex items-center gap-1.5 ${
              w === totalObserved - 1
                ? "bg-white/5 text-[#8f8e86] border-white/10 opacity-40 cursor-default"
                : "bg-surface-2 hover:bg-surface-3 text-text hover:text-white border-white/20 hover:border-white/40 cursor-pointer"
            }`}
            title="Scroll graph to the latest window"
          >
            <span>Scroll to Latest</span>
            <span className="font-mono-jb text-[10px] text-text-muted">(W{totalObserved})</span>
            <span>→</span>
          </button>
        )}
      </div>
      {graphFacts.length > 0 && (
        <div className="mt-4 pt-3 border-t border-white/10 space-y-1.5 text-xs text-[#c3c2b7]">
          <p className="font-bold text-white uppercase tracking-wider text-[11px]">What the graph shows</p>
          <ul className="list-disc list-inside space-y-1 font-medium">
            {graphFacts.map((t, idx) => (
              <li key={idx}>{t}</li>
            ))}
          </ul>
          {notices && notices.length > 0 && (
            <details className="pt-1 text-[#8f8e86]">
              <summary className="cursor-pointer text-[11px]">Notes about this file ({notices.length})</summary>
              <ul className="list-disc list-inside space-y-1 mt-1">
                {notices.map((notice, idx) => (
                  <li key={idx}>{notice}</li>
                ))}
              </ul>
            </details>
          )}
        </div>
      )}
    </div>
  );
}

function formatDelay(mins) {
  if (mins == null || isNaN(mins)) return "";
  if (mins < 60) return `${Math.round(mins)} min`;
  if (mins < 1440) return `about ${Math.round(mins / 60)} h`;
  const days = Math.round(mins / 1440);
  return `about ${days} day${days === 1 ? "" : "s"}`;
}

// ─── SECTION 3: Attack Forecast Tree ─────────────────────────────────────────
function AttackForecastTree({ P }) {
  const [hoveredNodeId, setHoveredNodeId] = useState(null);

  const treeData = useMemo(() => {
    if (!P || P.available === false || !Array.isArray(P.nodes) || P.nodes.length === 0 || !Array.isArray(P.levels)) {
      return null;
    }

    const numCols = P.levels.length;
    const colWidth = 280;
    const colSpacing = 320;
    const paddingLeft = 15;
    const initialY = 40;
    const ySpacing = 245;

    // Headers per level
    const colHeaders = P.levels.map((_, colIdx) => {
      if (Array.isArray(P.col_headers) && P.col_headers[colIdx]) return P.col_headers[colIdx];
      if (colIdx === 0) return P.start_from === "within 60 s" ? "WITHIN 60 S" : "NOW";
      if (colIdx === 1) return "NEXT STAGE";
      if (colIdx === 2) return "THEN";
      if (colIdx === 3) return "AFTER THAT";
      return `STEP ${colIdx + 1}`;
    });

    const nodeYMap = {};
    P.levels.forEach((col, colIdx) => {
      let lastY = initialY - ySpacing;
      col.forEach((id) => {
        const node = P.nodes.find(n => n.id === id);
        let desiredY = initialY;
        if (node && node.parent !== null && nodeYMap[node.parent] != null) {
          const parentY = nodeYMap[node.parent];
          const siblings = P.nodes.filter(s => s.parent === node.parent);
          const sibIdx = siblings.findIndex(s => s.id === id);
          desiredY = parentY + sibIdx * ySpacing;
        }
        const finalY = Math.max(desiredY, lastY + ySpacing);
        nodeYMap[id] = finalY;
        lastY = finalY;
      });
    });

    const mostLikelySet = new Set(Array.isArray(P.most_likely_path) ? P.most_likely_path : []);

    const nodes = P.nodes.map(n => {
      const colIdx = n.level != null ? n.level : 0;
      const x = paddingLeft + colIdx * colSpacing;
      const y = nodeYMap[n.id] ?? initialY;
      const w = colWidth;
      const h = colIdx === 0 ? 120 : 175;
      const isGold = mostLikelySet.has(n.id);
      const isRoot = n.parent === null && isGold;
      const hasChildren = P.nodes.some(child => child.parent === n.id);

      return {
        ...n,
        x,
        y,
        w,
        h,
        centerY: y + h / 2,
        stageDisplayName: n.display || formatStageDisplayName(n.stage),
        probPct: Math.round((n.prob || 0) * 100),
        probText: n.prob_text || `${Math.round((n.prob || 0) * 100)}%`,
        isGold,
        isRoot,
        hasChildren,
      };
    });

    // Compute links
    const links = [];
    nodes.forEach(child => {
      if (child.parent === null || child.parent === undefined) return;
      const parent = nodes.find(p => p.id === child.parent);
      if (!parent) return;

      const parentRightX = parent.x + parent.w;
      const parentCenterY = parent.y + 55;
      const childLeftX = child.x;
      const childCenterY = child.y + 55;
      const midX = parentRightX + (childLeftX - parentRightX) * 0.5;

      const path = `M ${parentRightX} ${parentCenterY} C ${midX} ${parentCenterY}, ${midX} ${childCenterY}, ${childLeftX} ${childCenterY}`;
      
      const isGoldLink = parent.isGold && child.isGold && 
        (P.most_likely_path.indexOf(child.id) === P.most_likely_path.indexOf(parent.id) + 1);

      const strokeWidth = isGoldLink
        ? Math.max(3, Math.min(6, 3 + (child.prob || 0) * 3))
        : Math.max(2, Math.min(4, 2 + (child.prob || 0) * 2));

      links.push({
        id: `${parent.id}->${child.id}`,
        path,
        parentId: parent.id,
        childId: child.id,
        isGold: isGoldLink,
        strokeWidth,
      });
    });

    const maxCanvasWidth = Math.max(980, paddingLeft + numCols * colSpacing + 40);
    const maxY = Math.max(...nodes.map(n => n.y + n.h), 420);
    const maxCanvasHeight = maxY + 30;

    return { nodes, links, colHeaders, numCols, colSpacing, paddingLeft, maxCanvasWidth, maxCanvasHeight };
  }, [P]);

  const activeElements = useMemo(() => {
    if (!treeData) return { nodeIds: new Set(), isHovered: false };
    if (hoveredNodeId === null) {
      return { nodeIds: new Set(treeData.nodes.filter(n => n.isGold).map(n => n.id)), isHovered: false };
    }
    const nodeMap = new Map(treeData.nodes.map(n => [n.id, n]));
    const active = new Set([hoveredNodeId]);
    let curr = nodeMap.get(hoveredNodeId);
    while (curr && curr.parent !== null) {
      active.add(curr.parent);
      curr = nodeMap.get(curr.parent);
    }
    return { nodeIds: active, isHovered: true };
  }, [hoveredNodeId, treeData]);

  if (!treeData) {
    return (
      <div className="py-12 text-center text-[#8f8e86] font-mono-jb text-sm border border-dashed border-white/10 rounded-xl">
        {P?.reason || "The model sees no attack stage for this host, so there is no progression to show."}
      </div>
    );
  }

  return (
    <div className="w-full select-none">
      <div className="w-full overflow-x-auto overflow-y-hidden rounded-xl border border-white/10 bg-[#0B0F14]">
        <svg
          viewBox={`0 0 ${treeData.maxCanvasWidth} ${treeData.maxCanvasHeight}`}
          className="w-full h-auto min-w-[850px] block"
          preserveAspectRatio="xMidYMid meet"
        >
          <defs>
            <pattern id="treeGridPattern" width="40" height="40" patternUnits="userSpaceOnUse">
              <path d="M 40 0 L 0 0 0 40" fill="none" stroke="rgba(57, 135, 229, 0.15)" strokeWidth="1" />
              <circle cx="40" cy="40" r="1.5" fill="rgba(203, 161, 53, 0.3)" />
            </pattern>
          </defs>

          {/* Cyber Background Surface & Grid */}
          <rect
            x="0"
            y="0"
            width={treeData.maxCanvasWidth}
            height={treeData.maxCanvasHeight}
            fill="#0B0F14"
            rx="12"
          />
          <rect
            x="0"
            y="0"
            width={treeData.maxCanvasWidth}
            height={treeData.maxCanvasHeight}
            fill="url(#treeGridPattern)"
            rx="12"
          />

          {/* Column Headers */}
          <g className="select-none pointer-events-none">
            {treeData.colHeaders.map((hdr, cIdx) => (
              <text
                key={cIdx}
                x={treeData.paddingLeft + cIdx * treeData.colSpacing}
                y={24}
                fill="#F4F3EE"
                fontSize="14"
                fontWeight="800"
                letterSpacing="0.06em"
                fontFamily="Inter, sans-serif"
              >
                {hdr}
              </text>
            ))}
          </g>

          {/* Links and Nodes Container */}
          <g transform="translate(0, 16)">
            {/* Links */}
            <g className="transition-all duration-300">
              {treeData.links.map(link => {
                const isActive = activeElements.nodeIds.has(link.parentId) && activeElements.nodeIds.has(link.childId);
                let strokeColor = link.isGold ? "#F59E0B" : "#60A5FA";
                let strokeOpacity = link.isGold ? 1.0 : 0.8;

                if (activeElements.isHovered) {
                  if (isActive) {
                    strokeColor = link.isGold ? "#F59E0B" : "#60A5FA";
                    strokeOpacity = 1.0;
                  } else {
                    strokeColor = link.isGold ? "#D97706" : "#3E63C7";
                    strokeOpacity = 0.2;
                  }
                }

                return (
                  <path
                    key={link.id}
                    d={link.path}
                    fill="none"
                    stroke={strokeColor}
                    strokeWidth={link.strokeWidth}
                    strokeOpacity={strokeOpacity}
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    className="transition-all duration-200"
                  />
                );
              })}
            </g>

            {/* Nodes */}
            {treeData.nodes.map(node => {
              const isActive = activeElements.nodeIds.has(node.id);
              const isRoot = node.isRoot;
              const isFirstColumn = node.level === 0;

              let opacityClass = "opacity-100 scale-100";
              if (activeElements.isHovered) {
                opacityClass = isActive ? "opacity-100 scale-100" : "opacity-25 scale-[0.98]";
              }

              let basisText = node.note || "from the model";
              if (node.basis !== "model") {
                const delayText = node.median_delay_min != null ? ` · ${formatDelay(node.median_delay_min)}` : "";
                basisText = `seen ${node.observed ?? 0} of ${node.observed_total ?? 0} times${delayText}`;
              }

              return (
                <foreignObject
                  key={node.id}
                  x={node.x}
                  y={node.y}
                  width={node.w}
                  height={node.h}
                  className="overflow-visible"
                >
                  <div
                    onMouseEnter={() => setHoveredNodeId(node.id)}
                    onMouseLeave={() => setHoveredNodeId(null)}
                    style={{ width: `${node.w}px` }}
                    className={`flex flex-col justify-between p-4 rounded-xl transition-all duration-200 cursor-pointer ${opacityClass} ${
                      isRoot
                        ? "bg-[#121826] border-2 border-gold"
                        : node.isGold
                        ? "bg-[#162032] border-2 border-gold"
                        : "bg-[#101522]/90 border border-white/25 hover:border-white/50 hover:bg-[#151c2c]"
                    }`}
                  >
                    <div>
                      {/* Badge for Current State */}
                      {isRoot && (
                        <div className="mb-1.5">
                          <span className="px-2 py-0.5 rounded text-[10px] font-black uppercase tracking-wider bg-gold text-bg">
                            {P.root_badge || "CURRENT STATE"}
                          </span>
                        </div>
                      )}

                      {/* Stage Title */}
                      <div className="flex items-center justify-between gap-1">
                        <span className={`font-bold tracking-tight ${
                          isRoot ? "text-base text-white font-extrabold" : "text-sm sm:text-base text-white font-bold"
                        }`}>
                          {node.stageDisplayName}
                        </span>
                      </div>

                      {/* Probability */}
                      <div className="flex items-center justify-between text-xs sm:text-sm mt-1 text-text-muted">
                        <span>
                          Probability: <strong className={node.isGold ? "text-gold font-bold" : "text-white font-semibold"}>{node.probText}</strong>
                        </span>
                      </div>

                      {/* Basis line (omitted for first column) */}
                      {!isFirstColumn && (
                        <div className="text-xs text-[#a3a299] font-mono-jb mt-1 leading-normal">
                          {basisText}
                        </div>
                      )}
                    </div>

                    {/* Footer notes under node (omitted for first column, only rendered if data exists) */}
                    {!isFirstColumn && ((node.hasChildren && node.hosts_moved_on != null && node.hosts_reached != null) || (node.leaf && node.leaf_reason)) && (
                      <div className="pt-2 mt-2 space-y-1">
                        {node.hasChildren && node.hosts_moved_on != null && node.hosts_reached != null && (
                          <div className="text-xs text-[#a3a299] font-mono-jb leading-normal">
                            {node.hosts_moved_on} of {node.hosts_reached} hosts in this stage moved on
                          </div>
                        )}
                        {node.leaf && node.leaf_reason && (
                          <div className="text-xs text-[#a3a299] font-mono-jb leading-normal italic" title={node.leaf_reason}>
                            {node.leaf_reason}
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                </foreignObject>
              );
            })}
          </g>
        </svg>
      </div>
    </div>
  );
}

// ─── SECTION 4: MITRE ATT&CK Analysis Cards ─────────────────────────────────
function MitreAttackAnalysis({ stageSegments, mitreDict }) {
  if (!stageSegments || !Array.isArray(stageSegments) || stageSegments.length === 0) {
    return (
      <div className="py-12 text-center text-[#8f8e86] font-sans text-sm border border-dashed border-white/10 rounded-xl">
        No stage forecast for this host.
      </div>
    );
  }

  return (
    <div className="w-full select-none">
      <div className="flex flex-col md:flex-row items-stretch justify-between gap-3">
        {stageSegments.map((seg, i) => {
          const isNow = i === 0 || seg.from === 0;
          const isAttack = Boolean(seg.isAttack || (seg.stage && String(seg.stage).toLowerCase() !== "normal"));
          const stageKey = String(seg.stage || "normal").toLowerCase().trim();
          const stageColor = isAttack ? getStageThemeColor(stageKey) : "#8f8e86";
          const stageDisplayName = isAttack ? formatStageDisplayName(stageKey) : "Normal";

          const lookupKey = stageKey;
          const mitreInfo = isAttack && mitreDict ? mitreDict[lookupKey] || mitreDict[seg.stage] || null : null;
          const tacticId = mitreInfo?.tactic_id || null;
          const tacticName = mitreInfo?.tactic || null;
          const firstTech = mitreInfo?.techniques?.[0] || null;

          const pctMax = Math.round((seg.probMax || 0) * 100);
          const probText = seg.probText || `${pctMax}%`;
          const probWidth = Math.max(0, Math.min(100, pctMax));
          const timeSpanText = String(seg.when || (seg.from === 0 ? "NOW" : `+${seg.from * 10} S`)).toUpperCase();

          return (
            <React.Fragment key={i}>
              <div className="flex-1 min-w-0 flex flex-col">
                <div
                  className="h-full min-h-[210px] flex flex-col justify-between rounded-xl overflow-hidden transition-all duration-200 bg-[#101522]/90 border border-white/20 hover:border-white/40"
                >
                  {/* Top Timeline Strip */}
                  <div className="w-full px-4 py-2.5 border-b border-white/15 bg-white/[0.07] text-white flex items-center justify-between">
                    <span className="text-base font-black uppercase tracking-wider font-sans text-white">
                      {timeSpanText}
                    </span>
                  </div>

                  {/* Card Content */}
                  <div className="p-4 flex-1 flex flex-col justify-between space-y-3.5">
                    <div className="space-y-2.5">
                      {/* Stage Name */}
                      <h4
                        className="text-lg sm:text-xl font-black tracking-tight leading-snug line-clamp-2 font-sans"
                        style={{ color: stageColor }}
                      >
                        {stageDisplayName}
                      </h4>

                      {/* MITRE Tactic line */}
                      {isAttack && tacticId ? (
                        <div className="text-[13px] sm:text-sm truncate flex items-center gap-1.5 pt-0.5 font-sans">
                          <span className="font-mono-jb text-xs sm:text-[13px] text-gold font-bold shrink-0">
                            {tacticId}
                          </span>
                          <span className="text-[13px] sm:text-sm text-[#d4d3cb] font-semibold truncate">
                            {tacticName}
                          </span>
                        </div>
                      ) : (
                        <div className="text-[13px] sm:text-sm text-[#a3a299] font-sans font-medium pt-0.5">
                          No attack tactic (Normal)
                        </div>
                      )}

                      {/* First technique */}
                      {isAttack && firstTech ? (
                        <p
                          className="text-xs sm:text-[13px] text-[#a3a299] font-medium truncate mt-0.5 font-sans"
                          title={`${firstTech.id} ${firstTech.name}`}
                        >
                          {firstTech.id} {firstTech.name}
                        </p>
                      ) : (
                        <div className="h-4" />
                      )}
                    </div>

                    {/* Probability Bar */}
                    <div className="pt-2 space-y-1.5">
                      <div className="flex items-center justify-between text-xs sm:text-[13px] font-sans">
                        <span className="text-[#a3a299] font-medium">Probability</span>
                        <span className="font-sans font-extrabold text-sm sm:text-base text-white">
                          {probText}
                          {probText !== `${pctMax}%` && (
                            <span className="text-xs text-[#a3a299] font-normal ml-1">
                              ({pctMax}%)
                            </span>
                          )}
                        </span>
                      </div>
                      <div className="h-2 w-full bg-white/10 rounded-full overflow-hidden">
                        <div
                          className={`h-full rounded-full transition-all duration-300 ${isAttack ? "bg-gold" : "bg-[#8f8e86]"}`}
                          style={{ width: `${probWidth}%` }}
                        />
                      </div>
                      <p className="text-xs text-[#8f8e86] font-sans pt-0.5 truncate">
                        Model's forecast
                      </p>
                    </div>
                  </div>
                </div>
              </div>

              {i < stageSegments.length - 1 && (
                <div className="hidden md:flex items-center justify-center text-[#8f8e86] shrink-0 px-1">
                  <span className="text-xl font-light opacity-60">→</span>
                </div>
              )}
            </React.Fragment>
          );
        })}
      </div>
    </div>
  );
}

// ─── SECTION 5: Feature Attribution (Occlusion) ──────────────────────────────
function OcclusionFeatureGraph({ attributionLast, hostIp, dstIp, threatLevel, predictedStage, nextStage }) {
  const [selectedFeature, setSelectedFeature] = useState(null);
  const [copiedAction, setCopiedAction] = useState(false);
  const containerRef = useRef(null);

  const rawFeatures = Array.isArray(attributionLast?.features) ? attributionLast.features : null;
  const isAvailable = Boolean(rawFeatures && rawFeatures.length > 0 && !attributionLast?.error);

  const risk60s = attributionLast?.risk_60s ?? 0;
  const isNearZero = risk60s < 0.05;

  const features = useMemo(() => {
    if (!isAvailable || isNearZero) return [];
    return rawFeatures.slice(0, 7).map((f) => {
      const contribution = Number.isFinite(Number(f.contribution)) ? Number(f.contribution) : 0;
      const share = Number.isFinite(Number(f.share)) ? Number(f.share) : 0;
      return {
        name: f.feature,
        description: f.description || f.feature.replace(/_/g, " "),
        group: f.group || "",
        contribution,
        share,
        percent: share * 100,
        value: f.value,
        increases: contribution >= 0,
      };
    });
  }, [rawFeatures, isAvailable, isNearZero]);

  useEffect(() => { setSelectedFeature(null); }, [attributionLast]);

  useEffect(() => {
    const handler = (e) => {
      if (containerRef.current && !containerRef.current.contains(e.target)) setSelectedFeature(null);
    };
    document.addEventListener("mousedown", handler);
    document.addEventListener("touchstart", handler);
    return () => { document.removeEventListener("mousedown", handler); document.removeEventListener("touchstart", handler); };
  }, []);

  // Hooks must run on every render: keep this above the early returns below, otherwise React throws
  // "rendered more hooks than during the previous render" when switching between hosts.
  const activeItem = useMemo(() => {
    if (selectedFeature) { const f = features.find(f => f.name === selectedFeature); if (f) return f; }
    return features[0];
  }, [features, selectedFeature]);

  if (!isAvailable) {
    return (
      <div className="py-12 text-center text-[#8f8e86] font-mono-jb text-sm border border-dashed border-white/10 rounded-xl">
        Feature attribution is not available for this host.
      </div>
    );
  }

  if (isNearZero) {
    return (
      <div className="py-12 text-center text-[#8f8e86] font-mono-jb text-sm border border-dashed border-white/10 rounded-xl">
        Risk is near zero for this host, so there is nothing to attribute.
      </div>
    );
  }

  const isSelectedNonTop = Boolean(selectedFeature);

  const maxAbs = Math.max(...features.map(f => Math.abs(f.contribution)), 0.001);
  const W = 1000;
  const xLabel = 146, xBarStart = 158, xBarEnd = 862, xCenter = 510, xPercent = 998;
  const halfBarPx = xBarEnd - xCenter;
  const scale = halfBarPx / maxAbs;
  const rowH = 88, firstRowY = 70;
  const gridTopY = firstRowY - rowH / 2;
  const lastRowY = firstRowY + (features.length - 1) * rowH;
  const axisY = lastRowY + rowH / 2;
  const H_height = axisY + 56;
  const span = xBarEnd - xBarStart;

  const hGridLines = Array.from({ length: features.length + 1 }, (_, i) => gridTopY + i * rowH);
  const gridTicks = [-1, -0.75, -0.5, -0.25, 0, 0.25, 0.5, 0.75, 1].map((ratio, i) => {
    const val = ratio * maxAbs;
    const x = Math.round(xBarStart + i * span / 8);
    const label = val === 0 ? "0" : val.toFixed(3);
    return { val, x, label, ratio };
  });

  const displayHostIp = hostIp || "—";
  const displayDstIp = dstIp || "—";
  const blockCommand = `iptables -A INPUT -s ${displayHostIp} -j DROP`;
  const handleCopyCommand = () => {
    navigator.clipboard?.writeText(blockCommand);
    setCopiedAction(true);
    setTimeout(() => setCopiedAction(false), 2000);
  };

  const showActions = threatLevel === "HIGH RISK" || threatLevel === "ELEVATED";

  return (
    <div
      ref={containerRef}
      onClick={(e) => { if (!e.target.closest("[data-shap-row]")) setSelectedFeature(null); }}
      className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start pt-2 select-none"
    >
      {/* Left: Full-width Occlusion Graph */}
      <div className="lg:col-span-9 space-y-2 lg:border-r lg:border-white/10 lg:pr-6 w-full">
        <div className="flex items-center justify-end flex-wrap gap-2 pb-0.5">
          <div className="inline-flex items-center gap-4 text-xs font-sans">
            <div className="flex items-center gap-1.5 text-[#DE5252] font-semibold">
              <span className="text-xs font-black">↑</span>
              <span>Increases Risk</span>
            </div>
            <div className="flex items-center gap-1.5 text-[#3B82F6] font-semibold">
              <span className="text-xs font-black">↓</span>
              <span>Decreases Risk</span>
            </div>
          </div>
        </div>

        <div className="w-full">
          <svg viewBox={`0 0 ${W} ${H_height}`} className="w-full h-auto select-none overflow-visible">
            <text x={xPercent} y="20" textAnchor="end" fill="#9BA6B4" fontSize="10"
              fontWeight="800" letterSpacing="0.08em" fontFamily="Inter, sans-serif">
              SHARE %
            </text>

            {/* Grid lines */}
            {hGridLines.map((gy, idx) => (
              <line
                key={`h-grid-${idx}`}
                x1={xBarStart}
                y1={gy}
                x2={xBarEnd}
                y2={gy}
                stroke="rgba(255, 255, 255, 0.14)"
                strokeWidth="1"
                strokeDasharray="3 3"
                strokeOpacity="0.55"
              />
            ))}

            {gridTicks.map((t) => (
              <line
                key={`v-grid-${t.ratio}`}
                x1={t.x}
                y1={gridTopY}
                x2={t.x}
                y2={axisY}
                stroke={t.ratio === 0 ? "#CBA135" : "rgba(255, 255, 255, 0.14)"}
                strokeWidth={t.ratio === 0 ? "1.8" : "1"}
                strokeDasharray={t.ratio === 0 ? "4 3" : "3 3"}
                strokeOpacity={t.ratio === 0 ? "0.85" : "0.55"}
              />
            ))}

            {/* Feature rows */}
            {features.map((f, i) => {
              const y = firstRowY + i * rowH;
              const isSel = selectedFeature === f.name;
              const isPos = f.contribution >= 0;
              const bw = Math.min(halfBarPx, Math.abs(f.contribution) * scale);
              const bh = 36;
              return (
                <g key={f.name} data-shap-row="true" className="cursor-pointer group"
                  onClick={(e) => { e.stopPropagation(); setSelectedFeature(isSel ? null : f.name); }}>
                  <rect x="0" y={y - 25} width={W} height="50" rx="4"
                    fill={isSel ? "rgba(203,161,53,0.13)" : "transparent"}
                    stroke={isSel ? "#CBA135" : "transparent"} strokeWidth="1.2"
                    className="transition-all duration-150 group-hover:fill-white/[0.03]" />
                  
                  {/* Feature Label with description tooltip */}
                  <text x={xLabel} y={y + 5} textAnchor="end"
                    fill={isSel ? "#CBA135" : "#D1D5DB"} fontSize="13.5" fontWeight="600"
                    fontFamily="Inter, sans-serif">
                    <title>{f.description}</title>
                    {f.name}
                  </text>

                  {isPos ? (
                    <>
                      <rect x={xCenter} y={y - bh / 2} width={Math.max(bw, 4)} height={bh} rx="3"
                        fill="#DE5252" className="transition-all duration-200 group-hover:brightness-110" />
                      <text x={xCenter + Math.max(bw, 4) + 8} y={y + 5} fill="#DE5252"
                        fontSize="13.5" fontWeight="700" fontFamily="Inter, sans-serif">
                        +{f.contribution.toFixed(3)}
                      </text>
                    </>
                  ) : (
                    <>
                      <rect x={xCenter - Math.max(bw, 4)} y={y - bh / 2} width={Math.max(bw, 4)} height={bh} rx="3"
                        fill="#3B82F6" className="transition-all duration-200 group-hover:brightness-110" />
                      <text x={xCenter - Math.max(bw, 4) - 8} y={y + 5} textAnchor="end" fill="#3B82F6"
                        fontSize="13.5" fontWeight="700" fontFamily="Inter, sans-serif">
                        {f.contribution.toFixed(3)}
                      </text>
                    </>
                  )}
                  <text x={xPercent} y={y + 5} textAnchor="end" fill="#FFF"
                    fontSize="13.5" fontWeight="700" fontFamily="Inter, sans-serif">
                    {f.percent.toFixed(1)}%
                  </text>
                </g>
              );
            })}

            {/* X axis baseline */}
            <line x1={xBarStart} y1={axisY} x2={xBarEnd} y2={axisY}
              stroke="#4A5568" strokeWidth="1.2" strokeOpacity="0.8" />
            {gridTicks.map(t => (
              <g key={t.ratio}>
                <line x1={t.x} y1={axisY} x2={t.x} y2={axisY + (t.ratio === 0 ? 8 : 5)}
                  stroke="#FFF" strokeWidth={t.ratio === 0 ? 1.5 : 1}
                  strokeOpacity={t.ratio === 0 ? 0.9 : 0.4} />
                <text x={t.x} y={axisY + 22} textAnchor="middle"
                  fill={t.ratio === 0 ? "#FFF" : "#9BA6B4"}
                  fontSize={t.ratio === 0 ? "13" : "12"}
                  fontWeight={t.ratio === 0 ? "900" : "700"}
                  fontFamily="Inter, sans-serif">
                  {t.label}
                </text>
              </g>
            ))}
            <text x={xCenter} y={axisY + 44} textAnchor="middle" fill="#9BA6B4"
              fontSize="12" fontWeight="800" letterSpacing="0.08em" fontFamily="Inter, sans-serif">
              CHANGE IN RISK WHEN THE FEATURE IS REMOVED
            </text>
          </svg>
        </div>
      </div>

      {/* Right Column: Feature Attribution Details & Recommended Actions */}
      <div className="lg:col-span-3 flex flex-col pt-1 font-sans">
        <div className="space-y-2.5 pb-4">
          <span className="text-xs uppercase font-black tracking-wider text-white block">
            {isSelectedNonTop ? "SELECTED FEATURE ATTRIBUTION" : "OVERALL PRIMARY DRIVING FEATURE"}
          </span>

          <div className="border-t border-white/20 w-full" />

          <div className="flex items-center justify-between gap-3">
            <span className="text-sm font-bold text-white font-mono-jb tracking-tight truncate">
              {activeItem.name}
            </span>
            {activeItem.increases ? (
              <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-[#DE5252]/10 border border-[#DE5252]/30 text-[#DE5252] text-[11px] font-bold uppercase tracking-wider shrink-0">
                <span className="text-xs leading-none font-black">↑</span>
                <span>Increases Risk</span>
              </div>
            ) : (
              <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-[#3B82F6]/10 border border-[#3B82F6]/30 text-[#3B82F6] text-[11px] font-bold uppercase tracking-wider shrink-0">
                <span className="text-xs leading-none font-black">↓</span>
                <span>Decreases Risk</span>
              </div>
            )}
          </div>

          <div className="grid grid-cols-2 gap-3 pt-1 items-center">
            <div className="pr-3 border-r border-white/20">
              <span className="text-[10px] uppercase font-bold text-[#9BA6B4] tracking-wider block">CONTRIBUTION</span>
              <span className={`text-xl font-bold font-mono-jb block mt-0.5 ${activeItem.increases ? "text-[#DE5252]" : "text-[#3B82F6]"}`}>
                {activeItem.contribution >= 0 ? `+${activeItem.contribution.toFixed(3)}` : activeItem.contribution.toFixed(3)}
              </span>
            </div>
            <div className="pl-1">
              <span className="text-[10px] uppercase font-bold text-[#9BA6B4] tracking-wider block">SHARE</span>
              <span className="text-xl font-bold text-gold font-mono-jb block mt-0.5">
                {activeItem.percent.toFixed(1)}%
              </span>
            </div>
          </div>
          <div className="space-y-1 pt-1">
            <span className="text-[10px] uppercase font-bold tracking-wider text-[#9BA6B4] block">
              FEATURE ROLE &amp; CONTEXT
            </span>
            <p className="text-[11px] text-[#C5CEE0] leading-relaxed">
              {activeItem.description}
              {activeItem.value != null ? ` (Observed value: ${activeItem.value})` : ""}
              {activeItem.group ? ` [Group: ${activeItem.group}]` : ""}
            </p>
          </div>
        </div>

        <div className="border-t border-white/20 w-full" />

        {/* Section: Recommended Actions */}
        <div className="space-y-3 pt-5">
          <div className="flex items-center justify-between">
            <span className="text-sm font-black uppercase tracking-wider text-white">
              RECOMMENDED ACTIONS
            </span>
          </div>

          {showActions ? (
            <div className="space-y-3 text-xs">
              <div className="space-y-1.5">
                <div className="flex items-center justify-between gap-2">
                  <span className="font-bold text-white text-xs truncate min-w-0">1. Block Source IP ({displayHostIp})</span>
                  <button type="button" onClick={handleCopyCommand}
                    className="px-2.5 py-0.5 rounded bg-white/5 hover:bg-gold hover:text-bg text-white text-[11px] font-medium border border-white/20 transition-colors cursor-pointer whitespace-nowrap shrink-0">
                    {copiedAction ? "Copied" : "Copy Rule"}
                  </button>
                </div>
                <div className="bg-[#090D14] border border-white/10 rounded-md px-3 py-2">
                  <code className="text-gold text-[11px] font-mono-jb block">{blockCommand}</code>
                </div>
              </div>

              <div className="border-t border-white/10 w-full" />

              <div className="space-y-0.5">
                <span className="font-bold text-white text-xs block">2. Isolate Target Host ({displayDstIp})</span>
                <p className="text-[11px] text-[#9BA6B4] leading-relaxed">
                  {nextStage
                    ? `Restrict lateral egress traffic to prevent progression to ${nextStage}.`
                    : predictedStage
                      ? `Restrict lateral egress traffic to contain the ${predictedStage} activity.`
                      : "Restrict lateral egress traffic from this host."}
                </p>
              </div>

              <div className="border-t border-white/10 w-full" />

              <div className="space-y-0.5">
                <span className="font-bold text-white text-xs block">3. Rate-Limit Target Service</span>
                <p className="text-[11px] text-[#9BA6B4] leading-relaxed">
                  Throttle incoming connection rate on destination port to mitigate automated burst traffic.
                </p>
              </div>
            </div>
          ) : (
            <p className="text-xs text-[#8f8e86] font-mono-jb">No action recommended.</p>
          )}
        </div>
      </div>
    </div>
  );
}


function EmptyState({ icon: Icon = Target, title, children, onToggleSidebar, onAction, actionLabel, actionIcon: ActionIcon }) {
  return (
    <div className="space-y-6 text-text pb-8 -m-6 p-6 min-h-screen w-full bg-[#111110] flex flex-col">
      {onToggleSidebar && (
        <button
          onClick={onToggleSidebar}
          className="p-2 rounded-lg bg-surface-2 hover:bg-surface border border-white/25 text-gold hover:text-white transition-colors cursor-pointer w-fit"
          title="Toggle Sidebar Nav"
        >
          <Menu className="h-4 w-4" />
        </button>
      )}
      <div className="flex-1 flex flex-col items-center justify-center min-h-[400px] text-text space-y-4 p-8 border-2 border-white/20 rounded-xl bg-[#0B0F14]/60">
        <div className="p-4 rounded-full bg-gold/10 border border-gold/30 shadow-[0_0_24px_rgba(203,161,53,0.15)]">
          <Icon className="h-10 w-10 text-gold" />
        </div>
        <h2 className="text-base font-extrabold text-white uppercase tracking-wider">{title}</h2>
        <div className="text-xs text-text-muted max-w-md text-center space-y-2 font-medium leading-relaxed">{children}</div>
        {onAction && actionLabel && (
          <button
            onClick={onAction}
            className="mt-4 px-5 py-2.5 rounded-lg bg-gold text-[#0B0F14] font-mono-tech font-bold text-xs uppercase tracking-wider hover:bg-gold-light transition-all shadow-md flex items-center gap-2 cursor-pointer"
          >
            {ActionIcon && <ActionIcon className="w-4 h-4" />}
            {actionLabel}
          </button>
        )}
      </div>
    </div>
  );
}

// ─── Main AttackForecast Page Component ──────────────────────────────────────
export default function AttackForecast({ isActive, onToggleSidebar, onNavigateToUpload }) {
  const [latestData, setLatestData] = useState(null);
  const [v2Data, setV2Data] = useState(null);
  const [selectedWindowIdx, setSelectedWindowIdx] = useState(null);
  const [loading, setLoading] = useState(true);
  const [selectedPairKey, setSelectedPairKey] = useState("");
  const [showAllFlows, setShowAllFlows] = useState(false);
  const [activeInfoModal, setActiveInfoModal] = useState(null);

  const fetchingRef = useRef(false);
  const pollCountRef = useRef(0);
  const pollTimerRef = useRef(null);

  const fetchLatestForecast = async () => {
    if (fetchingRef.current) return;
    fetchingRef.current = true;
    if (!latestData && !v2Data) {
      setLoading(true);
    }
    try {
      const [resV1, resV2] = await Promise.allSettled([
        fetch(`${CAPTURE_API}/api/forecast/latest`).then(r => r.ok ? r.json() : null),
        fetch(`${CAPTURE_API}/api/v2/forecast/latest`).then(r => r.ok ? r.json() : null),
      ]);

      if (resV1.status === "fulfilled" && resV1.value) {
        setLatestData(resV1.value);
      }

      if (resV2.status === "fulfilled" && resV2.value) {
        setV2Data(resV2.value);
      }
    } catch (err) {
      setLatestData({ status: "error", message: err.message });
    } finally {
      setLoading(false);
      fetchingRef.current = false;
    }
  };

  useEffect(() => {
    if (isActive !== false && !fetchingRef.current) {
      fetchLatestForecast();
    }
  }, [isActive]);

  // Poll v2 endpoint if status is "running" (up to 60s: 30 attempts of 2s)
  useEffect(() => {
    if (v2Data?.status === "running" && pollCountRef.current < 30) {
      pollTimerRef.current = setTimeout(async () => {
        pollCountRef.current += 1;
        try {
          const res = await fetch(`${CAPTURE_API}/api/v2/forecast/latest`);
          if (res.ok) {
            const data = await res.json();
            setV2Data(data);
          }
        } catch (_) {}
      }, 2000);
    }
    return () => {
      if (pollTimerRef.current) clearTimeout(pollTimerRef.current);
    };
  }, [v2Data?.status]);

  const isV2Running = v2Data?.status === "running";
  const isV2Success = v2Data?.status === "success";
  const isV2NoUpload = v2Data?.status === "no_upload";

  const hasOldResults = Array.isArray(latestData?.results) && latestData.results.length > 0;
  const hostOrder = v2Data?.chart?.host_order || (v2Data?.chart?.hosts ? Object.keys(v2Data.chart.hosts) : []);

  // Generate dropdown options:
  // Use conversations if present; else if v2 success use hostOrder
  const dropdownOptions = useMemo(() => {
    if (hasOldResults) {
      return latestData.results.map(c => {
        const k = `${c.src_ip}>${c.dst_ip}`;
        let label = `${c.src_ip} ➔ ${c.dst_ip}`;
        if (isV2Running) {
          return { key: k, label };
        }
        const srcHost = v2Data?.chart?.hosts?.[c.src_ip];
        const dstHost = c.dst_ip ? v2Data?.chart?.hosts?.[c.dst_ip] : null;

        if (!srcHost && !dstHost) {
          label += " (no forecast for this host)";
        } else {
          const cH = srcHost || dstHost;
          if (cH?.risk_60s?.length > 0) {
            const lastRisk = cH.risk_60s[cH.risk_60s.length - 1];
            const rPct = (lastRisk * 100).toFixed(1);
            const lastStageRow = cH.stage_forecast?.[cH.stage_forecast.length - 1];
            const lastLikely = cH.likely_attack_stage?.[cH.risk_60s.length - 1];
            const firstStage = (lastRisk >= (v2Data?.chart?.threshold ?? 0.5) && lastLikely)
              ? lastLikely
              : (lastStageRow ? lastStageRow[0] : "normal");
            const stg = (firstStage || "normal").toUpperCase().replace(/_/g, " ");
            label += ` (Risk: ${rPct}% | Stage: ${stg})`;
          }
        }
        return { key: k, label };
      });
    } else if (hostOrder.length > 0) {
      return hostOrder.map(ip => {
        let label = `${ip}`;
        if (isV2Running) {
          return { key: ip, label };
        }
        const cH = v2Data?.chart?.hosts?.[ip];
        if (cH?.risk_60s?.length > 0) {
          const lastRisk = cH.risk_60s[cH.risk_60s.length - 1];
          const rPct = (lastRisk * 100).toFixed(1);
          const lastStageRow = cH.stage_forecast?.[cH.stage_forecast.length - 1];
          const lastLikely = cH.likely_attack_stage?.[cH.risk_60s.length - 1];
          const firstStage = (lastRisk >= (v2Data?.chart?.threshold ?? 0.5) && lastLikely)
            ? lastLikely
            : (lastStageRow ? lastStageRow[0] : "normal");
          const stg = (firstStage || "normal").toUpperCase().replace(/_/g, " ");
          label += `  (Risk: ${rPct}% | Stage: ${stg})`;
        }
        return { key: ip, label };
      });
    }
    return [];
  }, [hasOldResults, latestData, hostOrder, v2Data, isV2Running]);

  // Set default selectedPairKey if not selected or invalid
  useEffect(() => {
    if (dropdownOptions.length > 0) {
      if (!selectedPairKey || !dropdownOptions.some(o => o.key === selectedPairKey)) {
        setSelectedPairKey(dropdownOptions[0].key);
      }
    }
  }, [dropdownOptions, selectedPairKey]);

  const selectedConversation = useMemo(() => {
    if (!hasOldResults) return null;
    return latestData.results.find(c => `${c.src_ip}>${c.dst_ip}` === selectedPairKey) || latestData.results[0];
  }, [hasOldResults, latestData, selectedPairKey]);

  const handleConversationChange = (e) => {
    const key = e.target.value;
    setSelectedPairKey(key);
    setSelectedWindowIdx(null);
  };

  const srcIp = selectedConversation?.src_ip || (selectedPairKey.includes(">") ? selectedPairKey.split(">")[0] : selectedPairKey);
  const dstIp = selectedConversation?.dst_ip || (selectedPairKey.includes(">") ? selectedPairKey.split(">")[1] : null);

  let hostIp = null;
  let isFallbackHost = false;

  if (v2Data?.chart?.hosts?.[selectedPairKey]) {
    hostIp = selectedPairKey;
  } else if (srcIp && v2Data?.chart?.hosts?.[srcIp]) {
    hostIp = srcIp;
  } else if (dstIp && v2Data?.chart?.hosts?.[dstIp]) {
    hostIp = dstIp;
  } else if (hostOrder.length > 0) {
    hostIp = hostOrder[0];
    if (srcIp && !hasOldResults) isFallbackHost = false;
  }

  const H = (hostIp && v2Data?.chart?.hosts) ? v2Data.chart.hosts[hostIp] : null;

  // Selected window index w (default H.time.length - 1)
  const totalWindows = H?.time?.length || 0;
  const w = (selectedWindowIdx !== null && selectedWindowIdx >= 0 && selectedWindowIdx < totalWindows)
    ? selectedWindowIdx
    : (totalWindows > 0 ? totalWindows - 1 : 0);

  const isLatestWindow = totalWindows === 0 || w === totalWindows - 1;
  const lastTimeStr = H?.time?.[totalWindows - 1] || "";
  const shortLastTime = lastTimeStr.includes(" ") ? lastTimeStr.split(" ").pop() : lastTimeStr;

  const threshold = v2Data?.chart?.threshold ?? 0.5;
  const riskW = H?.risk_60s?.[w] ?? 0;
  const soon5 = H?.start_soon?.["300"]?.[w];
  const soon10 = H?.start_soon?.["600"]?.[w];
  const soon5Level = v2Data?.chart?.start_outlook?.tested?.["300"]?.threshold;
  const hasSoon = Number.isFinite(Number(soon5));
  const pct1 = (x) => `${(Number(x) * 100).toFixed(0)}%`;

  // Stage forecast of the selected window (NOW, +10 s .. +60 s) merged into runs of the same stage.
  const stageSegments = [];
  {
    const sfRow = (H?.stage_forecast?.[w] || []).slice(0, 7);
    const spRow = H?.stage_forecast_prob?.[w] || [];
    const lab = (k) => (k === 0 ? "now" : `+${k * 10} s`);
    sfRow.forEach((st, k) => {
      const key = String(st || "normal").toLowerCase();
      const last = stageSegments[stageSegments.length - 1];
      const pr = Number(spRow[k]);
      if (last && last.stage === key) { last.to = k; last.probs.push(pr); }
      else stageSegments.push({ stage: key, from: k, to: k, probs: [pr], isAttack: key !== "normal" });
    });
    stageSegments.forEach((sg) => {
      sg.when = sg.from === sg.to ? lab(sg.from) : `${lab(sg.from)} to ${lab(sg.to)}`;
      const ok = sg.probs.filter((x) => Number.isFinite(x));
      const lo = ok.length ? Math.round(Math.min(...ok) * 100) : null;
      const hi = ok.length ? Math.round(Math.max(...ok) * 100) : null;
      sg.probMax = ok.length ? Math.max(...ok) : 0;
      sg.probText = lo == null ? "" : lo === hi ? `${hi}%` : `${lo}–${hi}%`;
    });
  }
  // The same forecast as a tree over time: one column per time span; the gold path is the most likely stage,
  // the blue cards are the model's second choice for that time span (shown when it has at least 5%).
  const timeTree = (() => {
    if (stageSegments.length === 0) return { available: false, reason: "No stage forecast for this host." };
    const sec = H?.stage_forecast_second?.[w] || [];
    const secP = H?.stage_forecast_second_prob?.[w] || [];
    const nodes = [], levels = [], path = [];
    let prevMain = null;
    stageSegments.forEach((sg, li) => {
      const main = { id: nodes.length, parent: prevMain, level: li, stage: sg.stage, display: sg.isAttack ? formatStageDisplayName(sg.stage) : "Normal",
        prob: sg.probMax, prob_text: sg.probText, basis: "model", note: "most likely stage" };
      nodes.push(main); path.push(main.id);
      const lvl = [main.id];
      const alt = {};                                        // second choice inside this time span: stage -> highest probability
      for (let k = sg.from; k <= sg.to; k++) {
        const st = String(sec[k] || "").toLowerCase(), pr = Number(secP[k]);
        if (st && st !== sg.stage && Number.isFinite(pr)) alt[st] = Math.max(alt[st] || 0, pr);
      }
      const best = Object.entries(alt).sort((a, b) => b[1] - a[1])[0];
      if (best && best[1] >= 0.05) {
        const an = { id: nodes.length, parent: prevMain, level: li, stage: best[0], display: best[0] === "normal" ? "Normal" : formatStageDisplayName(best[0]),
          prob: best[1], prob_text: `up to ${Math.round(best[1] * 100)}%`, basis: "model", note: "other possibility (second choice)" };
        nodes.push(an); lvl.push(an.id);
      }
      levels.push(lvl); prevMain = main.id;
    });
    return { available: true, nodes, levels, most_likely_path: path, root_badge: "NOW",
      col_headers: stageSegments.map((sg) => sg.when.toUpperCase()) };
  })();

  const _atkSegs = stageSegments.filter((sg) => sg.isAttack);
  const mitreFromForecast = _atkSegs.length
    ? { available: true, steps: _atkSegs.map((sg) => ({ stage: sg.stage, prob: sg.probMax, basis: "model", label: sg.when.toUpperCase() })) }
    : { available: false, reason: "The model sees no attack stage for this host now or in the next 60 seconds." };

  let threatLevel = "NORMAL";
  let threatLevelColor = "#10b981";
  let threatLevelSub = "";
  let attackProbabilityPct = `${(riskW * 100).toFixed(1)}%`;
  let predictedStageFormatted = "NONE";
  let stageProbabilityPct = "0.0%";
  let stageProbSub = "";

  if (isV2Running) {
    threatLevel = "Computing forecast…";
    threatLevelColor = "#8f8e86";
    attackProbabilityPct = "Computing forecast…";
    predictedStageFormatted = "Computing forecast…";
    stageProbabilityPct = "Computing forecast…";
  } else if (!H || !H.stage_forecast) {
    threatLevel = "NORMAL";
    threatLevelColor = "#10b981";
    attackProbabilityPct = "0.0%";
    predictedStageFormatted = "—";
    stageProbabilityPct = "—";
  } else {
    // Attack in progress in this window: the model's stage for "now" is an attack stage (probability >= 50%).
    const _s0 = H?.stage_forecast?.[w]?.[0];
    const _p0 = H?.stage_forecast_prob?.[w]?.[0];
    const attackNow = _s0 && String(_s0).toLowerCase() !== "normal" && Number(_p0) >= 0.5;
    if (attackNow) {
      threatLevel = "HIGH RISK";
      threatLevelColor = "#ef4444";
      threatLevelSub = `attack in progress now (${String(_s0).replace(/_/g, " ")})`;
    } else if (riskW >= threshold) {
      threatLevel = "HIGH RISK";
      threatLevelColor = "#ef4444";
      threatLevelSub = "attack expected within 60 s";
    } else if (riskW >= 0.5) {
      threatLevel = "ELEVATED";
      threatLevelColor = "#f59e0b";
      threatLevelSub = "possible attack within 60 s";
    } else if (riskW < threshold && hasSoon && typeof soon5Level === "number" && soon5 >= soon5Level) {
      threatLevel = "WATCH";
      threatLevelColor = "#f59e0b";
      threatLevelSub = "attack likely within 5 min";
    }

    const stageForecastRow = H?.stage_forecast?.[w] || [];
    const stageProbRow = H?.stage_forecast_prob?.[w] || [];

    // Alerting window: show the model's stage averaged over its whole forecast (now .. +60 s),
    // the same value the tree and the MITRE cards start from.
    const likelyStage = H?.likely_attack_stage?.[w];
    const likelyProb = H?.likely_attack_stage_prob?.[w];
    if (riskW >= threshold && likelyStage && likelyProb != null) {
      predictedStageFormatted = String(likelyStage).toUpperCase().replace(/_/g, " ");
      stageProbabilityPct = `${(likelyProb * 100).toFixed(1)}%`;
      stageProbSub = "average over now to +60 s";
    } else if (!stageForecastRow || !stageProbRow || stageForecastRow.length === 0) {
      predictedStageFormatted = "—";
      stageProbabilityPct = "—";
    } else {
      let predictedStageRaw = "normal";
      let stepIdx = null;

      if (stageForecastRow[0] && String(stageForecastRow[0]).toLowerCase() !== "normal") {
        predictedStageRaw = stageForecastRow[0];
        stepIdx = 0;
      } else {
        for (let i = 1; i < stageForecastRow.length; i++) {
          if (stageForecastRow[i] && String(stageForecastRow[i]).toLowerCase() !== "normal") {
            predictedStageRaw = `${stageForecastRow[i]} (in +${i * 10} s)`;
            stepIdx = i;
            break;
          }
        }
        if (stepIdx === null) {
          predictedStageRaw = "NONE";
        }
      }

      if (predictedStageRaw === "NONE") {
        predictedStageFormatted = "NONE";
        const normalProb = stageProbRow[0] != null ? stageProbRow[0] : 0;
        stageProbabilityPct = `${(normalProb * 100).toFixed(1)}%`;
        stageProbSub = "no attack stage";
      } else {
        predictedStageFormatted = predictedStageRaw.includes("(in +")
          ? predictedStageRaw.split(" (in +")[0].toUpperCase().replace(/_/g, " ") + ` (in +${predictedStageRaw.split(" (in +")[1]}`
          : predictedStageRaw.toUpperCase().replace(/_/g, " ");

        const stageProbVal = (stepIdx !== null && stageProbRow[stepIdx] != null) ? stageProbRow[stepIdx] : 0;
        stageProbabilityPct = `${(stageProbVal * 100).toFixed(1)}%`;
        stageProbSub = "";
      }
    }
  }

  // The attribution section always describes the LATEST window, so its recommended actions use the
  // threat level and stage of that same window (not of the window selected on the graph).
  const lastIdx = totalWindows > 0 ? totalWindows - 1 : 0;
  const riskLast = H?.risk_60s?.[lastIdx] ?? 0;
  const latestThreatLevel = !H ? "NORMAL" : riskLast >= threshold ? "HIGH RISK" : riskLast >= 0.5 ? "ELEVATED" : "NORMAL";
  let latestStageKey = null;
  if (H) {
    if (riskLast >= threshold && H?.likely_attack_stage?.[lastIdx]) {
      latestStageKey = H.likely_attack_stage[lastIdx];
    } else {
      latestStageKey = (H?.stage_forecast?.[lastIdx] || []).find(s => s && String(s).toLowerCase() !== "normal") || null;
    }
  }
  const latestStageName = latestStageKey ? formatStageDisplayName(latestStageKey) : "";
  const nextStep = H?.progression?.available !== false ? H?.progression?.steps?.[1] : null;
  const latestNextStageName = nextStep?.stage ? formatStageDisplayName(nextStep.stage) : "";

  if (loading) {
    return (
      <div className="space-y-6 animate-fade-in text-text pb-8 -m-6 p-6 min-h-full bg-[#111110]">
        {onToggleSidebar && (
          <button
            onClick={onToggleSidebar}
            className="p-2 rounded-lg bg-surface-2 hover:bg-surface border border-white/25 text-gold hover:text-white transition-colors cursor-pointer"
            title="Toggle Sidebar Nav"
          >
            <Menu className="h-4 w-4" />
          </button>
        )}
        <div className="flex flex-col items-center justify-center min-h-[400px] text-gold space-y-3">
          <RefreshCw className="h-8 w-8 animate-spin text-gold" />
          <p className="text-xs uppercase tracking-wider font-extrabold text-white">Loading Latest Forecast Data...</p>
        </div>
      </div>
    );
  }

  // Error and empty states: Show "No File Uploaded Yet" whenever no file has been uploaded
  const hasNoForecast = !isV2Running && (isV2NoUpload || (!isV2Success && !hasOldResults) || (hostOrder.length === 0 && !hasOldResults)) && (!latestData || latestData.status === "no_upload" || !hasOldResults);

  if (!isV2Running && (isV2NoUpload || hasNoForecast || (!isV2Success && !hasOldResults))) {
    return (
      <EmptyState
        icon={Target}
        title="No File Uploaded Yet"
        onToggleSidebar={onToggleSidebar}
        onAction={onNavigateToUpload}
        actionLabel="Go to File Upload"
        actionIcon={UploadCloud}
      >
        <p>
          Upload a network flow CSV or PCAP file on the <span className="text-gold font-bold">File Upload</span> page to run the World Model and view risk forecasts.
        </p>
      </EmptyState>
    );
  }

  if (v2Data?.status === "unusable_file" || (latestData?.status === "unusable_file" && !isV2Success)) {
    const reason = v2Data?.reason || latestData?.reason || "This CSV file does not contain IP columns required for forecasting.";
    return (
      <EmptyState
        icon={AlertTriangle}
        title="Unusable File Format"
        onToggleSidebar={onToggleSidebar}
        onAction={onNavigateToUpload}
        actionLabel="Upload Different File"
        actionIcon={UploadCloud}
      >
        <p className="text-gold font-bold">{reason}</p>
        <p className="pt-2 text-text-muted font-medium">Please upload a PCAP file or a CSV containing 'Source IP' and 'Destination IP' columns.</p>
      </EmptyState>
    );
  }

  if (v2Data?.status === "error" && !isV2Success) {
    const errorMsg = v2Data?.reason || latestData?.message || "Server error";
    return (
      <EmptyState
        icon={AlertTriangle}
        title="Cannot Reach Forecast Server"
        onToggleSidebar={onToggleSidebar}
        onAction={onNavigateToUpload}
        actionLabel="Go to File Upload"
        actionIcon={UploadCloud}
      >
        <p>The capture/forecast service at <span className="text-gold font-bold">{CAPTURE_API}</span> responded with an error ({errorMsg}).</p>
        <p>Make sure the backend is running, then try again.</p>
      </EmptyState>
    );
  }

  const conversationFlows = selectedConversation?.flows || [];

  return (
    <div className="space-y-6 animate-fade-in text-text pb-8 -m-6 p-6 min-h-full bg-[#111110]">
      {/* ===== CONVERSATION SELECTOR ===== */}
      <section className="pb-5 border-b-2 border-white/30">
        <div className="flex items-center gap-4 flex-wrap justify-between w-full">
          <div className="flex flex-col gap-1">
            <div className="flex items-center gap-3 flex-wrap">
              {onToggleSidebar && (
                <button
                  onClick={onToggleSidebar}
                  className="p-2 rounded-lg bg-surface-2 hover:bg-surface border border-white/25 text-gold hover:text-white transition-colors cursor-pointer"
                  title="Toggle Sidebar Nav"
                >
                  <Menu className="h-4 w-4" />
                </button>
              )}
              <div className="flex items-center gap-2">
                <span className="text-base md:text-lg font-black uppercase tracking-wider text-white whitespace-nowrap">
                  Network Conversation
                </span>
              </div>

              <div className="relative">
                <select
                  value={selectedPairKey}
                  onChange={handleConversationChange}
                  className="appearance-none bg-surface-2 border border-white/25 rounded-lg px-3 py-2 pr-8 text-sm text-white outline-none focus:border-gold cursor-pointer min-w-[260px] sm:min-w-[340px] font-semibold"
                >
                  {dropdownOptions.map(o => (
                    <option key={o.key} value={o.key} className="bg-surface-2 text-white">
                      {o.label}
                    </option>
                  ))}
                </select>
                <ChevronDown className="absolute right-2 top-1/2 -translate-y-1/2 h-4 w-4 text-text-muted pointer-events-none" />
              </div>
            </div>

            {/* Muted note when using fallback host */}
            {isFallbackHost && (
              <p className="text-xs text-[#8f8e86] font-mono-jb mt-1 pl-1">
                No forecast for {srcIp}; showing the highest-risk host {hostIp}.
              </p>
            )}
          </div>
        </div>
      </section>

      {/* ===== 1. KPI STATS ROW ===== */}
      <section className="grid grid-cols-2 sm:grid-cols-2 lg:grid-cols-3 gap-6 w-full pb-5 border-b-2 border-white/30">
        {[
          {
            label: "THREAT LEVEL",
            value: threatLevel,
            sub: threatLevelSub,
            styleColor: threatLevelColor,
            className: "text-2xl md:text-3xl font-black",
          },
          {
            label: "ATTACK PROBABILITY",
            value: attackProbabilityPct,
            sub: hasSoon
              ? `next 60 s · 5 min ${pct1(soon5)}` +
                (Number.isFinite(Number(soon10)) ? ` · 10 min ${pct1(soon10)}` : "")
              : "next 60 s",
            color: "text-gold",
            bar: isV2Running ? null : attackProbabilityPct,
            className: "text-xl md:text-2xl font-extrabold",
          },
          {
            label: "STAGE CONFIDENCE",
            value: stageProbabilityPct,
            sub: stageProbSub,
            color: "text-white",
            bar: isV2Running || stageProbabilityPct === "—" ? null : stageProbabilityPct,
            className: "text-xl md:text-2xl font-extrabold",
          },
        ].map((s, i, arr) => (
          <div
            key={i}
            className={`flex-1 min-w-0 ${
              i !== arr.length - 1 ? "border-r-2 border-white/30 pr-4 lg:pr-6" : ""
            }`}
          >
            <p className="text-[10px] font-bold uppercase tracking-wider text-text-muted mb-1.5 truncate">
              {s.label}
            </p>
            <p
              className={`leading-none tracking-tight truncate ${s.className || "text-xl md:text-2xl font-extrabold"} ${s.color || ""}`}
              style={s.styleColor ? { color: s.styleColor } : undefined}
            >
              {s.value}
            </p>
            {s.bar && (
              <div className="h-1.5 w-full bg-white/10 rounded-full overflow-hidden mt-2.5">
                <div className="h-full bg-gold rounded-full" style={{ width: s.bar }} />
              </div>
            )}
            {s.sub && (
              <p className="text-[11px] text-text-muted mt-1.5 truncate font-mono-jb">
                {s.sub}
              </p>
            )}
          </div>
        ))}
      </section>

      {/* ===== 2. RISK FORECAST — INFILTRATION PROBABILITY ===== */}
      <section id="risk-forecast" className="space-y-4 scroll-mt-6 pb-6 border-b-2 border-white/30">
        <div className="flex items-center justify-between border-b border-white/30 pb-2.5 flex-wrap gap-2">
          <h3 className="text-base md:text-lg font-black uppercase tracking-wider text-white">
            Risk Forecast — Infiltration Probability
          </h3>
          <button
            onClick={() => setActiveInfoModal("risk_forecast")}
            title="What is Risk Forecast?"
            className="w-6 h-6 rounded-full bg-surface-2 hover:bg-gold hover:text-bg border border-white/25 text-gold font-black text-xs flex items-center justify-center transition-all cursor-pointer shrink-0"
          >
            ?
          </button>
        </div>

        {H ? (
          <div className="w-full pt-1">
            <KStepSimulationChart
              H={H}
              threshold={0.5}
              modelCopies={v2Data?.chart?.model_copies ?? 3}
              baselineAvailable={Boolean(v2Data?.chart?.baseline_available)}
              notices={v2Data?.notices || []}
              selectedWindowIdx={w}
              onSelectWindow={(idx) => setSelectedWindowIdx(idx)}
            />
          </div>
        ) : (
          <div className="py-8 text-center text-sm text-[#8f8e86]">
            Select a network conversation to view the risk forecast timeline.
          </div>
        )}
      </section>

      {/* ===== 3. STAGE PROGRESSION TREE ===== */}
      <section id="mitre-attack-progression" className="space-y-4 scroll-mt-6 pb-6 border-b-2 border-white/30">
        <div className="flex items-center justify-between border-b border-white/30 pb-2.5 flex-wrap gap-3">
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-2">
              <h3 className="text-base md:text-lg font-black uppercase tracking-wider text-white">
                STAGE PROGRESSION TREE — NOW TO +60 SECONDS
              </h3>
            </div>
          </div>

          <div className="flex items-center gap-4 text-xs flex-wrap">
            <div className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-full bg-gold" />
              <span className="text-white font-bold">Most likely stage</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-full bg-[#3E63C7]" />
              <span className="text-text-muted font-semibold">Other possibility</span>
            </div>
            <button
              onClick={() => setActiveInfoModal("mitre_attack")}
              title="What is Stage Progression Tree?"
              className="w-6 h-6 rounded-full bg-surface-2 hover:bg-gold hover:text-bg border border-white/25 text-gold font-black text-xs flex items-center justify-center transition-all cursor-pointer shrink-0"
            >
              ?
            </button>
          </div>
        </div>

        {stageSegments.length > 0 ? (
          <AttackForecastTree P={timeTree} />
        ) : (
          <div className="py-12 text-center text-[#8f8e86] font-mono-jb text-sm border border-dashed border-white/10 rounded-xl">
            No stage forecast for this host.
          </div>
        )}
      </section>

      {/* ===== 4. MITRE ATT&CK MAPPING ===== */}
      <section id="mitre-attack-analysis" className="space-y-4 scroll-mt-6 pb-6 border-b-2 border-white/30">
        <div className="flex items-center justify-between border-b border-white/30 pb-2.5 flex-wrap gap-3">
          <div className="flex items-center gap-3">
            <h3 className="text-base md:text-lg font-black uppercase tracking-wider text-white">
              MITRE ATT&CK MAPPING
            </h3>
          </div>

          <div className="flex items-center gap-3 text-xs flex-wrap">
            <button
              onClick={() => setActiveInfoModal("mitre_attack")}
              title="What is MITRE ATT&CK Mapping?"
              className="w-6 h-6 rounded-full bg-surface-2 hover:bg-gold hover:text-bg border border-white/25 text-gold font-black text-xs flex items-center justify-center transition-all cursor-pointer shrink-0"
            >
              ?
            </button>
          </div>
        </div>

        <MitreAttackAnalysis
          stageSegments={stageSegments}
          mitreDict={v2Data?.chart?.mitre}
        />
      </section>

      {/* ===== 5. FEATURE ATTRIBUTION ===== */}
      <section id="shap-explanation" className="space-y-4 scroll-mt-6 pb-1 border-b-2 border-white/30">
        <div className="flex items-center justify-between border-b border-white/30 pb-2.5 flex-wrap gap-2">
          <div className="flex items-center gap-3">
            <h3 className="text-base md:text-lg font-black uppercase tracking-wider text-white">
              FEATURE ATTRIBUTION
            </h3>
          </div>
          <button
            onClick={() => setActiveInfoModal("shap_explanation")}
            title="What is Feature Attribution?"
            className="w-6 h-6 rounded-full bg-surface-2 hover:bg-gold hover:text-bg border border-white/25 text-gold font-black text-xs flex items-center justify-center transition-all cursor-pointer shrink-0"
          >
            ?
          </button>
        </div>

        <OcclusionFeatureGraph
          attributionLast={H?.attribution_last}
          hostIp={hostIp}
          dstIp={dstIp}
          threatLevel={latestThreatLevel}
          predictedStage={latestStageName}
          nextStage={latestNextStageName}
        />
      </section>

      {/* ===== 6. OBSERVED NETWORK EVIDENCE ===== */}
      <section id="observed-network-evidence" className="space-y-4 scroll-mt-6">
        <div className="flex items-center justify-between border-b border-white/30 pb-2.5 flex-wrap gap-4">
          <div className="flex items-center gap-2">
            <h3 className="text-base md:text-lg font-black uppercase tracking-wider text-white">
              Observed Network Evidence
            </h3>

            <span className="text-xs text-text-muted px-2 py-0.5 font-semibold">
              {conversationFlows.length} flows recorded
            </span>
          </div>
          <button
            onClick={() => setShowAllFlows(prev => !prev)}
            className="px-3 py-1.5 rounded-lg bg-surface-2 hover:bg-surface border border-white/25 text-white text-xs font-bold uppercase tracking-wider transition-all cursor-pointer"
          >
            {showAllFlows ? "SHOW COMPACT" : "VIEW ALL FLOWS"}
          </button>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b-2 border-white/30 text-white/90 uppercase tracking-wider bg-transparent">
                <th className="px-3 py-2.5 font-bold border-r border-white/25">Source IP</th>
                <th className="px-3 py-2.5 font-bold border-r border-white/25">Destination IP</th>
                <th className="px-3 py-2.5 font-bold border-r border-white/25">Packets</th>
                <th className="px-3 py-2.5 font-bold border-r border-white/25">Bytes</th>
                <th className="px-3 py-2.5 font-bold border-r border-white/25">Protocol</th>
                <th className="px-3 py-2.5 font-bold border-r border-white/25">Dst Port</th>
                <th className="px-3 py-2.5 font-bold">Flow Duration</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/20">
              {conversationFlows.length > 0 ? (
                conversationFlows.slice(0, showAllFlows ? 50 : 5).map((f, idx) => (
                  <tr key={idx} className="hover:bg-surface-2/50 text-text transition-colors">
                    <td className="px-3 py-2 font-bold text-white border-r border-white/20 font-mono-jb">{f.src_ip ?? "—"}</td>
                    <td className="px-3 py-2 font-bold text-white border-r border-white/20 font-mono-jb">{f.dst_ip ?? "—"}</td>
                    <td className="px-3 py-2 border-r border-white/20 font-bold text-text-muted">{f.packet_count ?? "—"}</td>
                    <td className="px-3 py-2 border-r border-white/20 font-bold text-text-muted">{f.byte_count != null ? formatBytes(f.byte_count) : "—"}</td>
                    <td className="px-3 py-2 border-r border-white/20">
                      <span className="px-1.5 py-0.5 rounded text-xs font-bold bg-surface-2 text-text border border-border uppercase">
                        {f.protocol ?? "—"}
                      </span>
                    </td>
                    <td className="px-3 py-2 border-r border-white/20 text-text-muted font-semibold">{f.dst_port != null ? getPortName(f.dst_port) : "—"}</td>
                    <td className="px-3 py-2 text-text-muted font-semibold">{f.duration != null ? `${Number(f.duration).toFixed(2)}s` : "—"}</td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={7} className="py-12 text-center text-text-muted font-mono-jb">
                    {!hasOldResults ? "Flow list not available for this file." : "No flow evidence available."}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </section>

      {/* ===== INFO MODAL ===== */}
      {activeInfoModal && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-md animate-fade-in"
          onClick={() => setActiveInfoModal(null)}
        >
          <div
            className="bg-surface-2 border border-white/30 rounded-xl max-w-lg w-full p-6 space-y-4 shadow-2xl relative font-sans text-text"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center justify-between border-b border-white/20 pb-3">
              <div className="flex items-center gap-3">
                <div className="w-7 h-7 rounded-full bg-gold text-bg flex items-center justify-center font-black text-sm shadow shrink-0">
                  ?
                </div>
                <h3 className="text-base font-extrabold text-white">
                  {activeInfoModal === "risk_forecast" && "What is Risk Forecast?"}
                  {activeInfoModal === "mitre_attack" && "What is MITRE ATT&CK?"}
                  {activeInfoModal === "shap_explanation" && "What is Feature Attribution?"}
                </h3>
              </div>
              <button
                onClick={() => setActiveInfoModal(null)}
                className="w-7 h-7 rounded-lg bg-surface border border-white/20 flex items-center justify-center text-text-muted hover:text-white hover:bg-surface-2 transition-colors cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="space-y-3 text-sm leading-relaxed text-text">
              {activeInfoModal === "risk_forecast" && (
                <>
                  <p className="font-bold text-white text-base">
                    AI Weather Forecast for Cyber Attacks 🌦️⚡
                  </p>
                  <p>
                    Instead of predicting rain or sunshine, this model analyzes network flows and predicts how likely an attacker is to break deeper into your network over the next 6 steps (<span className="text-gold font-bold">+10s</span> to <span className="text-gold font-bold">+60s</span>).
                  </p>
                  <div className="bg-surface/80 p-3.5 rounded-lg border border-white/20 space-y-2 text-xs">
                    <div className="flex items-start gap-2">
                      <span className="text-gold font-bold shrink-0">• Risk Score (%):</span>
                      <span className="text-text-muted">The percentage chance that an attack progresses within 60s.</span>
                    </div>
                    <div className="flex items-start gap-2">
                      <span className="text-gold font-bold shrink-0">• Interactive Windows:</span>
                      <span className="text-text-muted">Click any window on the graph to inspect that historical window.</span>
                    </div>
                  </div>
                </>
              )}

              {activeInfoModal === "mitre_attack" && (
                <>
                  <p className="font-bold text-white text-base">
                    Universal Playbook for Attack Tactics 🗺️🛡️
                  </p>
                  <p>
                    Cyber attacks don't happen all at once — hackers follow a step-by-step path. The <strong>MITRE ATT&amp;CK Framework</strong> is the global standard taxonomy of adversarial tactics.
                  </p>
                  <div className="bg-surface/80 p-3.5 rounded-lg border border-white/20 space-y-2 text-xs">
                    <div className="flex items-start gap-2">
                      <span className="text-blue-hi font-bold shrink-0">• Attack Stages:</span>
                      <span className="text-text-muted">Reconnaissance → Initial Access → Command &amp; Control → Lateral Movement → Exfiltration.</span>
                    </div>
                  </div>
                </>
              )}

              {activeInfoModal === "shap_explanation" && (
                <>
                  <p className="font-bold text-white text-base">
                    Opening the AI Model's Decisions 📦🔍
                  </p>
                  <p>
                    <strong>Occlusion Feature Attribution</strong> measures how much the risk score changes when each network feature is removed and replaced with its training average.
                  </p>
                  <div className="bg-surface/80 p-3.5 rounded-lg border border-white/20 space-y-2 text-xs">
                    <div className="flex items-start gap-2">
                      <span className="text-gold font-bold shrink-0">• Contribution:</span>
                      <span className="text-text-muted">Red bars pushed the risk score HIGHER; blue bars lowered the risk.</span>
                    </div>
                  </div>
                </>
              )}
            </div>

            <div className="pt-2 flex justify-end border-t border-white/20">
              <button
                onClick={() => setActiveInfoModal(null)}
                className="px-5 py-2 rounded-lg bg-gold text-bg font-extrabold text-xs uppercase tracking-wider hover:bg-gold-hi transition-colors cursor-pointer shadow"
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
