import React, { useMemo, useState } from "react";
import {
  Network, Server, ShieldAlert, Cpu, Activity, Globe, ArrowRight,
  Info, Maximize2
} from "lucide-react";
import { STAGE_COLORS, ATTACK_STAGES } from "../demoData";

export default function NetworkTopology({ hosts, forecasts, alerts }) {
  const [selectedHost, setSelectedHost] = useState(null);
  const [hoveredHost, setHoveredHost] = useState(null);

  // Calculate positions for nodes in a radial layout
  const nodePositions = useMemo(() => {
    const centerX = 400;
    const centerY = 250;
    const positions = {};

    // Gateway in center
    const gateway = hosts.find(h => h.role === "gateway");
    if (gateway) positions[gateway.ip] = { x: centerX, y: centerY, r: 28 };

    // Internal hosts in a ring
    const internal = hosts.filter(h => h.role !== "attacker" && h.role !== "gateway");
    internal.forEach((h, i) => {
      const angle = (i / internal.length) * Math.PI * 2 - Math.PI / 2;
      const radius = 170;
      positions[h.ip] = {
        x: centerX + radius * Math.cos(angle),
        y: centerY + radius * Math.sin(angle),
        r: 22,
      };
    });

    // Attackers in outer ring
    const attackers = hosts.filter(h => h.role === "attacker");
    attackers.forEach((h, i) => {
      const angle = (i / attackers.length) * Math.PI * 2 + Math.PI / 4;
      const radius = 290;
      positions[h.ip] = {
        x: centerX + radius * Math.cos(angle),
        y: centerY + radius * Math.sin(angle),
        r: 18,
      };
    });

    return positions;
  }, [hosts]);

  // Attack links
  const attackLinks = useMemo(() => {
    const links = [];
    alerts.slice(0, 10).forEach(alert => {
      const src = hosts.find(h => h.role === "attacker");
      if (src) {
        links.push({
          from: src.ip,
          to: alert.hostIp,
          severity: alert.severity?.toLowerCase() || "low",
          stage: alert.predictedStage,
        });
      }
    });
    return links;
  }, [alerts, hosts]);

  // Traffic links (between gateway and internal)
  const trafficLinks = useMemo(() => {
    const gateway = hosts.find(h => h.role === "gateway");
    if (!gateway) return [];
    return hosts
      .filter(h => h.role !== "attacker" && h.role !== "gateway")
      .map(h => ({
        from: gateway.ip,
        to: h.ip,
        severity: "none",
      }));
  }, [hosts]);

  const selectedHostInfo = hosts.find(h => h.ip === selectedHost);
  const selectedForecast = selectedHost ? forecasts[selectedHost] : null;

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Topology Header */}
      <section className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Network className="h-5 w-5 text-cyan-400" />
          <div>
            <h3 className="text-sm font-bold uppercase tracking-wider font-mono-tech">Network Topology Map</h3>
            <p className="text-[10px] text-slate-500 font-mono-tech">Interactive host visualization with threat indicators</p>
          </div>
        </div>
        <div className="flex items-center gap-3 text-[9px] font-mono-tech">
          {/* Legend */}
          {ATTACK_STAGES.filter(s => s !== "Normal").map(s => (
            <div key={s} className="flex items-center gap-1">
              <div className="w-2 h-2 rounded-full" style={{ backgroundColor: STAGE_COLORS[s] }}></div>
              <span className="text-slate-400">{s.split(" ")[0]}</span>
            </div>
          ))}
        </div>
      </section>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* SVG Topology Canvas */}
        <div className="lg:col-span-2 glass-card rounded-xl border border-slate-800/50 p-0 overflow-hidden">
          <div className="p-3 border-b border-slate-800 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Activity className="h-3.5 w-3.5 text-cyan-400 animate-pulse" />
              <span className="text-[10px] font-bold uppercase tracking-wider font-mono-tech">Live Network Map</span>
            </div>
            <span className="text-[9px] font-mono-tech text-slate-500">
              {hosts.length} Nodes · {attackLinks.length + trafficLinks.length} Links
            </span>
          </div>

          <div className="relative bg-[#060a12] scan-overlay" style={{ minHeight: 500 }}>
            <svg viewBox="0 0 800 500" className="w-full h-full" style={{ minHeight: 500 }}>
              {/* Background grid */}
              <defs>
                <pattern id="grid" width="40" height="40" patternUnits="userSpaceOnUse">
                  <path d="M 40 0 L 0 0 0 40" fill="none" stroke="rgba(255,255,255,0.015)" strokeWidth="0.5" />
                </pattern>
                <filter id="glow">
                  <feGaussianBlur stdDeviation="3" result="coloredBlur" />
                  <feMerge>
                    <feMergeNode in="coloredBlur" />
                    <feMergeNode in="SourceGraphic" />
                  </feMerge>
                </filter>
                <filter id="glowStrong">
                  <feGaussianBlur stdDeviation="6" result="coloredBlur" />
                  <feMerge>
                    <feMergeNode in="coloredBlur" />
                    <feMergeNode in="SourceGraphic" />
                  </feMerge>
                </filter>
              </defs>
              <rect width="800" height="500" fill="url(#grid)" />

              {/* Traffic links (gateway → internal) */}
              {trafficLinks.map((link, i) => {
                const from = nodePositions[link.from];
                const to = nodePositions[link.to];
                if (!from || !to) return null;
                return (
                  <line
                    key={`tl-${i}`}
                    x1={from.x} y1={from.y}
                    x2={to.x} y2={to.y}
                    stroke="rgba(0, 240, 255, 0.12)"
                    strokeWidth="1"
                  />
                );
              })}

              {/* Attack links */}
              {attackLinks.map((link, i) => {
                const from = nodePositions[link.from];
                const to = nodePositions[link.to];
                if (!from || !to) return null;
                const color = link.severity === "critical" ? "rgba(255, 0, 85, 0.7)" :
                             link.severity === "high" ? "rgba(245, 158, 11, 0.6)" :
                             "rgba(56, 189, 248, 0.4)";
                return (
                  <g key={`al-${i}`}>
                    <line
                      x1={from.x} y1={from.y}
                      x2={to.x} y2={to.y}
                      stroke={color}
                      strokeWidth={link.severity === "critical" ? "2.5" : "1.5"}
                      strokeDasharray={link.severity === "critical" ? "6 3" : "0"}
                      filter="url(#glow)"
                    >
                      <animate
                        attributeName="stroke-dashoffset"
                        from="18"
                        to="0"
                        dur="1s"
                        repeatCount="indefinite"
                      />
                    </line>
                    {/* Arrow at destination */}
                    <circle
                      cx={to.x}
                      cy={to.y}
                      r={nodePositions[link.to]?.r + 6 || 28}
                      fill="none"
                      stroke={color}
                      strokeWidth="1"
                      opacity="0.4"
                    >
                      <animate
                        attributeName="r"
                        from={nodePositions[link.to]?.r || 22}
                        to={nodePositions[link.to]?.r + 12 || 34}
                        dur="2s"
                        repeatCount="indefinite"
                      />
                      <animate
                        attributeName="opacity"
                        from="0.5"
                        to="0"
                        dur="2s"
                        repeatCount="indefinite"
                      />
                    </circle>
                  </g>
                );
              })}

              {/* Host Nodes */}
              {hosts.map(h => {
                const pos = nodePositions[h.ip];
                if (!pos) return null;
                const fc = forecasts[h.ip];
                const stage = fc?.predictedStage || "Normal";
                const color = STAGE_COLORS[stage];
                const isGateway = h.role === "gateway";
                const isAttacker = h.role === "attacker";
                const isSelected = selectedHost === h.ip;
                const isHovered = hoveredHost === h.ip;

                return (
                  <g
                    key={h.ip}
                    className="cursor-pointer"
                    onClick={() => setSelectedHost(h.ip)}
                    onMouseEnter={() => setHoveredHost(h.ip)}
                    onMouseLeave={() => setHoveredHost(null)}
                  >
                    {/* Selection ring */}
                    {isSelected && (
                      <circle cx={pos.x} cy={pos.y} r={pos.r + 8}
                        fill="none" stroke={color} strokeWidth="2" strokeDasharray="4 2"
                        filter="url(#glow)">
                        <animateTransform attributeName="transform" type="rotate"
                          from={`0 ${pos.x} ${pos.y}`} to={`360 ${pos.x} ${pos.y}`}
                          dur="4s" repeatCount="indefinite" />
                      </circle>
                    )}

                    {/* Node background */}
                    <circle
                      cx={pos.x} cy={pos.y} r={pos.r}
                      fill={isGateway ? "#0f172a" : isAttacker ? "#1a0a15" : `${color}15`}
                      stroke={color}
                      strokeWidth={isSelected || isHovered ? "2.5" : "1.5"}
                      filter={stage !== "Normal" ? "url(#glow)" : undefined}
                    />

                    {/* Inner icon placeholder */}
                    {isGateway ? (
                      <Cpu x={pos.x - 8} y={pos.y - 8} className="h-4 w-4 text-cyan-400" />
                    ) : isAttacker ? (
                      <text x={pos.x} y={pos.y + 4} textAnchor="middle" fontSize="14" fill={color}>⚡</text>
                    ) : (
                      <Server x={pos.x - 7} y={pos.y - 7} className="h-3.5 w-3.5" style={{ color }} />
                    )}

                    {/* Host name */}
                    <text
                      x={pos.x} y={pos.y + pos.r + 14}
                      textAnchor="middle"
                      fontSize="9"
                      fontFamily="'Share Tech Mono', monospace"
                      fill="#94a3b8"
                    >
                      {h.name}
                    </text>
                    <text
                      x={pos.x} y={pos.y + pos.r + 25}
                      textAnchor="middle"
                      fontSize="7"
                      fontFamily="'Share Tech Mono', monospace"
                      fill="#475569"
                    >
                      {h.ip}
                    </text>

                    {/* Stage label */}
                    {stage !== "Normal" && (
                      <text
                        x={pos.x} y={pos.y - pos.r - 6}
                        textAnchor="middle"
                        fontSize="8"
                        fontFamily="'Share Tech Mono', monospace"
                        fontWeight="bold"
                        fill={color}
                      >
                        {stage.toUpperCase()}
                      </text>
                    )}
                  </g>
                );
              })}
            </svg>
          </div>
        </div>

        {/* Host Details Sidebar */}
        <div className="glass-card rounded-xl border border-slate-800/50 p-5">
          <div className="flex items-center gap-2 mb-4">
            <Info className="h-4 w-4 text-cyan-400" />
            <h3 className="text-xs font-bold uppercase tracking-wider font-mono-tech">Host Details</h3>
          </div>

          {selectedHostInfo ? (
            <div className="space-y-4">
              <div className="p-3 rounded-lg bg-slate-950/50 border border-slate-900">
                <div className="flex items-center gap-2 mb-2">
                  <Server className="h-4 w-4" style={{ color: STAGE_COLORS[selectedForecast?.predictedStage || "Normal"] }} />
                  <span className="text-sm font-bold text-white">{selectedHostInfo.name}</span>
                </div>
                <div className="space-y-1 text-[10px] font-mono-tech">
                  <div className="flex justify-between">
                    <span className="text-slate-500">IP Address</span>
                    <span className="text-white">{selectedHostInfo.ip}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-500">Department</span>
                    <span className="text-white">{selectedHostInfo.department}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-500">Criticality</span>
                    <span className="text-white">{selectedHostInfo.criticality}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-500">Status</span>
                    <span className={selectedHostInfo.status === "ONLINE" ? "text-emerald-400" : "text-rose-400"}>
                      {selectedHostInfo.status}
                    </span>
                  </div>
                </div>
              </div>

              {selectedForecast && (
                <div className="p-3 rounded-lg bg-slate-950/50 border border-slate-900">
                  <p className="text-[9px] text-slate-500 uppercase font-mono-tech mb-2">Forecast</p>
                  <p className="text-lg font-black font-mono-tech" style={{ color: STAGE_COLORS[selectedForecast.predictedStage] }}>
                    {selectedForecast.predictedStage}
                  </p>
                  <p className="text-[10px] text-slate-400 font-mono-tech mt-1">
                    Confidence: <span className="text-white font-bold">{(selectedForecast.confidence * 100).toFixed(1)}%</span>
                  </p>

                  {/* Mini stage bar */}
                  <div className="mt-2 h-1.5 bg-slate-900 rounded-full overflow-hidden">
                    <div
                      className="h-full rounded-full transition-all duration-700"
                      style={{
                        width: `${STAGE_INDEX[selectedForecast.predictedStage]}%`,
                        backgroundColor: STAGE_COLORS[selectedForecast.predictedStage],
                      }}
                    ></div>
                  </div>
                </div>
              )}

              {/* Recent alerts for this host */}
              <div className="p-3 rounded-lg bg-slate-950/50 border border-slate-900">
                <p className="text-[9px] text-slate-500 uppercase font-mono-tech mb-2">Recent Alerts</p>
                <div className="space-y-1.5 max-h-[150px] overflow-y-auto">
                  {alerts.filter(a => a.hostIp === selectedHostInfo.ip).slice(0, 5).map((a, i) => (
                    <div key={i} className="flex items-center gap-2 text-[9px] font-mono-tech">
                      <ShieldAlert className="h-3 w-3 text-rose-400 shrink-0" />
                      <span className="text-slate-400">{new Date(a.timestamp).toLocaleTimeString()}</span>
                      <span className="text-white truncate">{a.predictedStage}</span>
                    </div>
                  ))}
                  {alerts.filter(a => a.hostIp === selectedHostInfo.ip).length === 0 && (
                    <p className="text-[9px] text-slate-600">No recent alerts</p>
                  )}
                </div>
              </div>
            </div>
          ) : (              <div className="text-center py-12 text-slate-600 text-xs font-mono-tech">
              Click a node to view details
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
