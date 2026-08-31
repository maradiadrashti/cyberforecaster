import React, { useState, useEffect, useRef, useMemo, useCallback } from "react";
import {
  Activity, Search, ShieldAlert, Wifi, Globe, Clock, Filter,
  AlertTriangle, Server, Zap, ArrowUpDown, RefreshCw, Radio,
  Play, Square, Network, ChevronDown, Signal, Usb, MonitorSmartphone,
  Link2, WifiOff, Target, Crosshair, CheckCircle2, Gauge, Ban, Lock, ChevronRight
} from "lucide-react";
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  BarChart, Bar, PieChart, Pie, Cell
} from "recharts";

const _HOST = import.meta.env.VITE_CAPTURE_HOST ?? "127.0.0.1";
const _PORT = import.meta.env.VITE_CAPTURE_PORT ?? "8080";
const CAPTURE_API = `http://${_HOST}:${_PORT}`;
const WS_URL = `ws://${_HOST}:${_PORT}/ws/live`;

// Interface type icons
const IFACE_ICONS = {
  WiFi: Wifi,
  Ethernet: Link2,
  Bluetooth: MonitorSmartphone,
  VPN: ShieldAlert,
  Virtual: Server,
  Docker: Server,
  Unknown: Globe,
};

// Severity color
const SEV_COLORS = {
  none: "#334155",
  low: "#38bdf8",
  medium: "#f59e0b",
  high: "#f97316",
  critical: "#ff0055",
};

// ── Force-Directed Topology Component ───────────────────────────────────────

function ForceDirectedTopology({ nodes, links, onNodeClick }) {
  const svgRef = useRef(null);
  const positionsRef = useRef({});
  const velocitiesRef = useRef({});
  const nodesRef = useRef(nodes);
  const linksRef = useRef(links);
  const [tick, setTick] = useState(0);

  // Keep refs in sync without causing re-render cascades
  nodesRef.current = nodes;
  linksRef.current = links;

  // Throttled physics tick — updates React state max 10x/sec
  useEffect(() => {
    let frameId;
    let lastRender = 0;
    const startTime = Date.now();

    const step = (ts) => {
      frameId = requestAnimationFrame(step);
      // Only update React state every 100ms
      if (ts - lastRender < 100) return;
      lastRender = ts;

      const curNodes = nodesRef.current;
      const curLinks = linksRef.current;
      const nodeIps = curNodes.map(n => n.ip);
      const pos = positionsRef.current;
      const vel = velocitiesRef.current;
      const elapsed = (Date.now() - startTime) / 1000;

      // Init new nodes
      nodeIps.forEach(ip => {
        if (!pos[ip]) {
          pos[ip] = { x: 400 + (Math.random() - 0.5) * 200, y: 175 + (Math.random() - 0.5) * 80 };
          vel[ip] = { x: 0, y: 0 };
        }
      });
      // Prune old
      Object.keys(pos).forEach(ip => { if (!nodeIps.includes(ip)) { delete pos[ip]; delete vel[ip]; } });

      const ALPHA = Math.max(0.01, 0.3 - elapsed * 0.003);
      const WIDTH = 800, HEIGHT = 350;

      nodeIps.forEach(a => {
        let fx = 0, fy = 0;
        nodeIps.forEach(b => {
          if (a === b) return;
          const dx = pos[a].x - pos[b].x, dy = pos[a].y - pos[b].y;
          const d = Math.sqrt(dx * dx + dy * dy) + 1;
          const f = 3000 / (d * d);
          fx += (dx / d) * f; fy += (dy / d) * f;
        });
        curLinks.forEach(lk => {
          let o = null;
          if (lk.source === a) o = lk.target;
          else if (lk.target === a) o = lk.source;
          if (!o || !pos[o]) return;
          fx += (pos[o].x - pos[a].x) * 0.005;
          fy += (pos[o].y - pos[a].y) * 0.005;
        });
        fx += (WIDTH / 2 - pos[a].x) * 0.002;
        fy += (HEIGHT / 2 - pos[a].y) * 0.002;
        vel[a].x = (vel[a].x + fx * ALPHA) * 0.85;
        vel[a].y = (vel[a].y + fy * ALPHA) * 0.85;
        pos[a].x = Math.max(50, Math.min(WIDTH - 50, pos[a].x + vel[a].x));
        pos[a].y = Math.max(40, Math.min(HEIGHT - 40, pos[a].y + vel[a].y));
      });

      setTick(n => n + 1);
    };
    frameId = requestAnimationFrame(step);
    return () => cancelAnimationFrame(frameId);
  }, []);

  const pos = positionsRef.current;
  const maxPackets = Math.max(1, ...nodes.map(n => n.packets || 1));

  return (
    <svg ref={svgRef} viewBox="0 0 800 350" className="w-full" style={{ minHeight: 300 }}>
      <defs>
        <pattern id="topoGrid" width="30" height="30" patternUnits="userSpaceOnUse">
          <path d="M 30 0 L 0 0 0 30" fill="none" stroke="rgba(255,255,255,0.015)" strokeWidth="0.5" />
        </pattern>
        <filter id="topoGlow">
          <feGaussianBlur stdDeviation="3" result="coloredBlur" />
          <feMerge>
            <feMergeNode in="coloredBlur" />
            <feMergeNode in="SourceGraphic" />
          </feMerge>
        </filter>
        <filter id="topoGlowStrong">
          <feGaussianBlur stdDeviation="5" result="coloredBlur" />
          <feMerge>
            <feMergeNode in="coloredBlur" />
            <feMergeNode in="SourceGraphic" />
          </feMerge>
        </filter>
        <marker id="arrowhead" markerWidth="6" markerHeight="4" refX="6" refY="2" orient="auto">
          <polygon points="0 0, 6 2, 0 4" fill="rgba(0,240,255,0.3)" />
        </marker>
      </defs>
      <rect width="800" height="350" fill="url(#topoGrid)" />

      {/* Links (edges) */}
      {links.map((link, i) => {
        const srcPos = pos[link.source];
        const dstPos = pos[link.target];
        if (!srcPos || !dstPos) return null;
        const color = SEV_COLORS[link.severity] || SEV_COLORS.none;
        const isAttack = link.severity && link.severity !== "none";

        // Curved link
        const midX = (srcPos.x + dstPos.x) / 2;
        const midY = (srcPos.y + dstPos.y) / 2;
        const dx = dstPos.x - srcPos.x;
        const dy = dstPos.y - srcPos.y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        const curve = Math.min(dist * 0.15, 30);
        // Perpendicular offset for curve
        const nx = -dy / dist;
        const ny = dx / dist;
        const cx = midX + nx * curve;
        const cy = midY + ny * curve;

        return (
          <g key={`link-${i}`}>
            <path
              d={`M ${srcPos.x} ${srcPos.y} Q ${cx} ${cy} ${dstPos.x} ${dstPos.y}`}
              fill="none"
              stroke={isAttack ? color : "rgba(0,240,255,0.12)"}
              strokeWidth={isAttack ? (link.severity === "critical" ? 2.5 : 1.5) : 1}
              strokeDasharray={link.severity === "critical" ? "6 3" : isAttack ? "4 2" : "0"}
              opacity={isAttack ? 0.7 : 0.3}
              filter={isAttack ? "url(#topoGlow)" : undefined}
              markerEnd={isAttack ? "url(#arrowhead)" : undefined}
            >
              {isAttack && (
                <animate
                  attributeName="stroke-dashoffset"
                  from="18"
                  to="0"
                  dur="1.2s"
                  repeatCount="indefinite"
                />
              )}
            </path>
            {/* Animated particle along attack edges */}
            {isAttack && (
              <circle r="2" fill={color} opacity="0.9">
                <animateMotion
                  dur="2s"
                  repeatCount="indefinite"
                  path={`M ${srcPos.x} ${srcPos.y} Q ${cx} ${cy} ${dstPos.x} ${dstPos.y}`}
                />
              </circle>
            )}
          </g>
        );
      })}

      {/* Nodes */}
      {nodes.map((node) => {
        const p = pos[node.ip];
        if (!p) return null;
        const color = SEV_COLORS[node.severity] || SEV_COLORS.none;
        const isAttacked = node.severity !== "none";
        const volume = node.packets || 1;
        const radius = 6 + (volume / maxPackets) * 18; // Size = traffic volume
        const opacity = isAttacked ? 1 : 0.7;

        return (
          <g
            key={node.ip}
            className="cursor-pointer"
            onClick={() => onNodeClick && onNodeClick(node)}
          >
            {/* Attack pulse ring */}
            {isAttacked && (
              <circle cx={p.x} cy={p.y} r={radius + 4} fill="none" stroke={color} strokeWidth="1" opacity="0.3">
                <animate attributeName="r" from={radius} to={radius + 12} dur="2s" repeatCount="indefinite" />
                <animate attributeName="opacity" from="0.5" to="0" dur="2s" repeatCount="indefinite" />
              </circle>
            )}

            {/* Volume ring */}
            <circle
              cx={p.x}
              cy={p.y}
              r={radius + 2}
              fill="none"
              stroke={color}
              strokeWidth="0.5"
              opacity={0.2}
            />

            {/* Node body */}
            <circle
              cx={p.x}
              cy={p.y}
              r={radius}
              fill={isAttacked ? color : "#1e293b"}
              stroke={color}
              strokeWidth={isAttacked ? 2 : 1}
              opacity={opacity}
              filter={isAttacked ? "url(#topoGlowStrong)" : undefined}
            />

            {/* Inner highlight */}
            <circle
              cx={p.x - radius * 0.2}
              cy={p.y - radius * 0.2}
              r={radius * 0.3}
              fill="rgba(255,255,255,0.15)"
            />

            {/* IP label */}
            <text
              x={p.x}
              y={p.y + radius + 14}
              textAnchor="middle"
              fontSize="7"
              fontFamily="'Share Tech Mono', monospace"
              fill="#94a3b8"
            >
              {node.ip}
            </text>

            {/* Severity label */}
            {isAttacked && (
              <text
                x={p.x}
                y={p.y - radius - 6}
                textAnchor="middle"
                fontSize="7"
                fontFamily="'Share Tech Mono', monospace"
                fontWeight="bold"
                fill={color}
              >
                {node.severity.toUpperCase()}
              </text>
            )}

            {/* Packet count badge */}
            <text
              x={p.x}
              y={p.y + 2}
              textAnchor="middle"
              fontSize={radius > 10 ? "6" : "5"}
              fontFamily="'Share Tech Mono', monospace"
              fill="white"
              fontWeight="bold"
            >
              {volume}
            </text>
          </g>
        );
      })}
    </svg>
  );
}


// ── Main Component ──────────────────────────────────────────────────────────

export default function LiveTraffic({ onInterfaceChange, onFlowsUpdate, onFlowClick }) {
  // --- State ---
  const [interfaces, setInterfaces] = useState([]);
  const [selectedIface, setSelectedIface] = useState("");
  const [isCapturing, setIsCapturing] = useState(false);
  const [packets, setPackets] = useState([]);
  const [flows, setFlows] = useState({});
  const [connected, setConnected] = useState(false);
  const [filter, setFilter] = useState("");
  const [showAttackOnly, setShowAttackOnly] = useState(false);
  const [totalPkts, setTotalPkts] = useState(0);
  const [totalBytes, setTotalBytes] = useState(0);
  const [bpsHistory, setBpsHistory] = useState([]);
  const [error, setError] = useState(null);
  const [topoNodes, setTopoNodes] = useState({});

  const wsRef = useRef(null);
  const bpsRef = useRef([]);
  const bytesWindowRef = useRef([]);
  const selectedIfaceRef = useRef(selectedIface);
  const isCapturingRef = useRef(isCapturing);
  const flowsRef = useRef(flows);

  // Synchronize refs
  useEffect(() => { selectedIfaceRef.current = selectedIface; }, [selectedIface]);
  useEffect(() => { isCapturingRef.current = isCapturing; }, [isCapturing]);
  useEffect(() => { flowsRef.current = flows; }, [flows]);

  const packetQueueRef = useRef([]);

  // --- Reset / Refresh dashboard state ---
  const resetDashboardState = useCallback(() => {
    setPackets([]);
    setFlows({});
    setTopoNodes({});
    setTotalPkts(0);
    setTotalBytes(0);
    setBpsHistory([]);
    bpsRef.current = [];
    bytesWindowRef.current = [];
    packetQueueRef.current = [];
  }, []);

  // --- Fetch real interfaces from Python server ---
  useEffect(() => {
    fetch(`${CAPTURE_API}/api/interfaces`)
      .then(r => r.json())
      .then(data => {
        setInterfaces(data);
        if (data.length > 0 && !selectedIface) {
          const firstIface = data[0].name;
          setSelectedIface(firstIface);
          selectedIfaceRef.current = firstIface;
          onInterfaceChange && onInterfaceChange(firstIface, data[0]);
        }
      })
      .catch(() => {
        setError("Capture server not reachable. Start it with: python capture_server.py");
      });
  }, []);

  // --- WebSocket connection ---
  useEffect(() => {
    let ws;
    let reconnectTimer;

    const connect = () => {
      try {
        ws = new WebSocket(WS_URL);
        wsRef.current = ws;

        ws.onopen = () => { setConnected(true); setError(null); };
        ws.onclose = () => { setConnected(false); reconnectTimer = setTimeout(connect, 2000); };
        ws.onerror = () => { try { ws.close(); } catch (_) {} };

        ws.onmessage = (event) => {
          try {
            const data = JSON.parse(event.data);
            if (data.type === "connected" || data.type === "capture_started" || data.type === "interface_switched") return;

            // Stage forecaster forecasts from ML background task
            if (data.type === "stage_forecasts" && data.data) {
              try { window.__mlStageForecasts = data.data; } catch (_) {}
              return;
            }

            // STRICT INTERFACE FILTER
            if (data.interface && selectedIfaceRef.current && data.interface !== selectedIfaceRef.current) return;

            // Enqueue regular packet event for batch processing
            if (data.src_ip && data.dst_ip) {
              packetQueueRef.current.push(data);
            }
          } catch (_) {}
        };
      } catch (_) {}
    };

    connect();
    return () => {
      clearTimeout(reconnectTimer);
      if (ws) try { ws.close(); } catch (_) {}
    };
  }, []);

  // --- Batched Packet Processing Interval (100ms / 10 FPS) ---
  useEffect(() => {
    const flushInterval = setInterval(() => {
      const queue = packetQueueRef.current;
      if (!queue || queue.length === 0) return;
      packetQueueRef.current = [];

      const now = Date.now();
      let batchBytes = 0;

      for (const data of queue) {
        batchBytes += (data.length || 0);
        bytesWindowRef.current.push({ time: now, bytes: data.length || 0 });
      }
      bytesWindowRef.current = bytesWindowRef.current.filter(e => now - e.time < 5000);

      setTotalPkts(p => p + queue.length);
      setTotalBytes(b => b + batchBytes);

      setPackets(prev => {
        const newPackets = [...queue].reverse();
        return [...newPackets, ...prev].slice(0, 200);
      });

      setTopoNodes(prev => {
        const next = { ...prev };
        for (const data of queue) {
          if (!next[data.src_ip]) {
            next[data.src_ip] = { ip: data.src_ip, role: "source", severity: data.severity, packets: 0 };
          }
          next[data.src_ip].packets++;
          next[data.src_ip].severity = data.severity;

          if (!next[data.dst_ip]) {
            next[data.dst_ip] = { ip: data.dst_ip, role: "target", severity: data.severity, packets: 0 };
          }
          next[data.dst_ip].packets++;
        }
        return next;
      });

      setFlows(prev => {
        const next = { ...prev };
        for (const data of queue) {
          const key = `${data.src_ip}:${data.src_port}-${data.dst_ip}:${data.dst_port}-${data.protocol}`;
          if (next[key]) {
            next[key] = {
              ...next[key],
              packet_count: next[key].packet_count + 1,
              byte_count: next[key].byte_count + (data.length || 0),
              last_seen: data.timestamp,
              // Always carry forward the latest severity/attack labels from backend
              severity: data.severity || next[key].severity,
              attack_type: data.attack_type || next[key].attack_type,
              ml_label: data.ml_label || next[key].ml_label,
              ml_confidence: data.ml_confidence || next[key].ml_confidence,
              interface: data.interface || next[key].interface,
            };
          } else {
            next[key] = {
              src_ip: data.src_ip,
              dst_ip: data.dst_ip,
              src_port: data.src_port,
              dst_port: data.dst_port,
              protocol: data.protocol,
              packet_count: 1,
              byte_count: data.length || 0,
              first_seen: data.timestamp,
              last_seen: data.timestamp,
              severity: data.severity,
              attack_type: data.attack_type,
              interface: data.interface || selectedIfaceRef.current,
            };
          }
        }
        return next;
      });
    }, 100);

    return () => clearInterval(flushInterval);
  }, []);

  // --- Lift flows up to parent ---
  useEffect(() => {
    onFlowsUpdate && onFlowsUpdate(flows, packets, totalPkts);
  }, [flows, packets, totalPkts, onFlowsUpdate]);

  // --- Compute BPS chart every second ---
  useEffect(() => {
    const interval = setInterval(() => {
      const now = Date.now();
      const windowMs = 5000;
      const active = bytesWindowRef.current.filter(e => now - e.time < windowMs);
      const totalB = active.reduce((s, e) => s + e.bytes, 0);
      const bps = (totalB * 8) / (windowMs / 1000);
      const timeStr = new Date().toLocaleTimeString("en", { hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit" });
      bpsRef.current = [...bpsRef.current, { time: timeStr, bps: Math.round(bps) }].slice(-30);
      setBpsHistory([...bpsRef.current]);
    }, 1000);
    return () => clearInterval(interval);
  }, []);

  // --- Expandable alert/flow state + defense actions ---
  const [expandedAlertKey, setExpandedAlertKey] = useState(null);
  const [expandedFlowKey, setExpandedFlowKey] = useState(null);
  const [defenseLoading, setDefenseLoading] = useState({});
  const [localDefenseState, setLocalDefenseState] = useState({});

  // Poll defense state from capture server
  useEffect(() => {
    const fetchDefense = () => {
      fetch(`${CAPTURE_API}/api/defense/state`)
        .then(r => r.json())
        .then(data => setLocalDefenseState(data))
        .catch(() => {});
    };
    fetchDefense();
    const iv = setInterval(fetchDefense, 3000);
    return () => clearInterval(iv);
  }, []);

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
      setLocalDefenseState(await stateRes.json());
      return data;
    } catch (e) {
      console.error("Defense action failed:", e);
      return null;
    } finally {
      setDefenseLoading(prev => ({ ...prev, [loadingKey]: false }));
    }
  }, []);

  // --- Switch Interface ---
  const handleInterfaceChange = useCallback((newIface) => {
    if (!newIface || newIface === selectedIface) return;
    setSelectedIface(newIface);
    selectedIfaceRef.current = newIface;
    resetDashboardState();

    const ifaceInfo = interfaces.find(i => i.name === newIface);
    onInterfaceChange && onInterfaceChange(newIface, ifaceInfo);

    if (isCapturingRef.current) {
      if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
        wsRef.current.send(JSON.stringify({ action: "switch_interface", interface: newIface }));
      } else {
        fetch(`${CAPTURE_API}/api/capture/switch/${encodeURIComponent(newIface)}`, { method: "POST" }).catch(() => {});
      }
    }
  }, [selectedIface, resetDashboardState, interfaces, onInterfaceChange]);

  // --- Start/Stop capture ---
  const startCapture = useCallback(() => {
    if (!selectedIface) return;
    resetDashboardState();
    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify({ action: "start_capture", interface: selectedIface }));
    } else {
      fetch(`${CAPTURE_API}/api/capture/start/${encodeURIComponent(selectedIface)}`, { method: "POST" }).catch(() => {});
    }
    setIsCapturing(true);
    isCapturingRef.current = true;
  }, [selectedIface, resetDashboardState]);

  const stopCapture = useCallback(() => {
    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify({ action: "stop_capture", interface: selectedIface }));
    } else {
      fetch(`${CAPTURE_API}/api/capture/stop/${encodeURIComponent(selectedIface)}`, { method: "POST" }).catch(() => {});
    }
    setIsCapturing(false);
    isCapturingRef.current = false;
  }, [selectedIface]);

  // --- Derived data ---
  const flowList = useMemo(() => {
    let list = Object.values(flows);
    if (showAttackOnly) {
      list = list.filter(f => f.severity && f.severity !== "none");
    }
    if (filter) {
      const q = filter.toLowerCase();
      list = list.filter(f =>
        f.src_ip.includes(q) || f.dst_ip.includes(q) ||
        f.protocol.toLowerCase().includes(q) ||
        (f.attack_type || "").toLowerCase().includes(q)
      );
    }
    return list.sort((a, b) => b.packet_count - a.packet_count).slice(0, 100);
  }, [flows, filter, showAttackOnly]);

  const protoDist = useMemo(() => {
    const counts = {};
    Object.values(flows).forEach(f => {
      counts[f.protocol] = (counts[f.protocol] || 0) + 1;
    });
    return Object.entries(counts).map(([name, count]) => ({ name, count }));
  }, [flows]);

  const attackFlows = useMemo(() =>
    Object.values(flows)
      .filter(f => f.severity && f.severity !== "none")
      .sort((a, b) => {
        const sevOrder = { critical: 4, high: 3, medium: 2, low: 1 };
        return (sevOrder[b.severity] || 0) - (sevOrder[a.severity] || 0);
      }),
    [flows]
  );

  const topoNodeList = useMemo(() => Object.values(topoNodes), [topoNodes]);
  const topoLinks = useMemo(() => {
    const links = [];
    Object.values(flows).forEach(f => {
      links.push({
        source: f.src_ip,
        target: f.dst_ip,
        severity: f.severity,
        protocol: f.protocol,
      });
    });
    return links;
  }, [flows]);

  const selectedIfaceInfo = interfaces.find(i => i.name === selectedIface);

  const formatBytes = (b) => {
    if (b >= 1000000) return `${(b / 1000000).toFixed(1)} MB`;
    if (b >= 1000) return `${(b / 1000).toFixed(1)} KB`;
    return `${b} B`;
  };

  const formatBps = (bps) => {
    if (bps >= 1000000) return `${(bps / 1000000).toFixed(1)} Mbps`;
    if (bps >= 1000) return `${(bps / 1000).toFixed(1)} Kbps`;
    return `${bps} bps`;
  };

  return (
    <div className="space-y-5 animate-fade-in">
      {/* Error banner */}
      {error && (
        <div className="bg-rose-950/30 border border-rose-800/50 rounded-xl p-4 flex items-center gap-3">
          <AlertTriangle className="h-5 w-5 text-rose-400 shrink-0" />
          <div>
            <p className="text-xs font-bold text-rose-400 font-mono-tech">Capture Server Offline</p>
            <p className="text-[10px] text-rose-500/70 font-mono-tech mt-0.5">{error}</p>
          </div>
        </div>
      )}

      {/* Interface Selector + Controls */}
      <section className="glass-card rounded-xl border border-slate-800/50 p-4">
        <div className="flex items-center justify-between gap-4 flex-wrap">
          <div className="flex items-center gap-3 flex-wrap">
            <div className="flex items-center gap-2">
              <Radio className="h-4 w-4 text-cyan-400" />
              <span className="text-xs font-bold uppercase tracking-wider font-mono-tech">Network Interface</span>
            </div>
            <div className="relative">
              <select
                value={selectedIface}
                onChange={(e) => handleInterfaceChange(e.target.value)}
                className="appearance-none bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 pr-8 text-xs font-mono-tech text-white outline-none focus:border-cyan-600 cursor-pointer min-w-[240px]"
              >
                <option value="">Select interface...</option>
                {interfaces.map(iface => {
                  const Icon = IFACE_ICONS[iface.type] || Globe;
                  return (
                    <option key={iface.name} value={iface.name}>
                      {iface.name} ({iface.type}) - {iface.ip} {iface.is_up ? "●" : "○"}
                    </option>
                  );
                })}
              </select>
              <ChevronDown className="absolute right-2 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-500 pointer-events-none" />
            </div>
            {selectedIfaceInfo && (
              <div className="flex items-center gap-2 text-[9px] font-mono-tech bg-slate-900/80 px-2.5 py-1.5 rounded-lg border border-slate-800">
                <span className="text-cyan-400 font-bold">{selectedIfaceInfo.type}</span>
                <span className="text-slate-600">|</span>
                <span className="text-slate-300">{selectedIfaceInfo.ip}</span>
                <span className="text-slate-600">|</span>
                <span className="text-slate-500">{selectedIfaceInfo.mac}</span>
                <span className="text-slate-600">|</span>
                <span className={selectedIfaceInfo.is_up ? "text-emerald-400" : "text-slate-600"}>
                  {selectedIfaceInfo.is_up ? "ACTIVE" : "INACTIVE"}
                </span>
              </div>
            )}
          </div>
          <div className="flex items-center gap-3">
            <div className={`flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[9px] font-mono-tech border ${
              connected
                ? "bg-emerald-950/30 border-emerald-900/50 text-emerald-400"
                : "bg-rose-950/30 border-rose-900/50 text-rose-400"
            }`}>
              <div className={`h-1.5 w-1.5 rounded-full ${connected ? "bg-emerald-400 pulse-cyan" : "bg-rose-500"}`}></div>
              <span>{connected ? "CAPTURE SERVER ONLINE" : "DISCONNECTED"}</span>
            </div>
            <button
              onClick={resetDashboardState}
              title="Reset dashboard metrics and start fresh"
              className="flex items-center gap-1 px-2.5 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-300 hover:text-white text-[10px] font-mono-tech transition-all"
            >
              <RefreshCw className="h-3 w-3 text-cyan-400" />
              <span>Clear / Reset</span>
            </button>
            {!isCapturing ? (
              <button
                onClick={startCapture}
                disabled={!selectedIface || !connected}
                className="flex items-center gap-1.5 px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-[10px] font-mono-tech font-bold uppercase transition-all disabled:opacity-30 disabled:cursor-not-allowed shadow-lg shadow-emerald-950/40"
              >
                <Play className="h-3.5 w-3.5" />
                <span>Start Capture</span>
              </button>
            ) : (
              <button
                onClick={stopCapture}
                className="flex items-center gap-1.5 px-4 py-2 rounded-lg bg-rose-600 hover:bg-rose-500 text-white text-[10px] font-mono-tech font-bold uppercase transition-all shadow-lg shadow-rose-950/40 animate-pulse"
              >
                <Square className="h-3.5 w-3.5" />
                <span>Stop Capture</span>
              </button>
            )}
          </div>
        </div>
        {selectedIface && (
          <div className="mt-3 pt-3 border-t border-slate-800/40 flex items-center justify-between text-[10px] font-mono-tech flex-wrap gap-2">
            <div className="flex items-center gap-2">
              <span className="text-slate-500">Live Capturing Target:</span>
              <span className="text-cyan-400 font-bold bg-cyan-950/40 border border-cyan-900/50 px-2 py-0.5 rounded">
                {selectedIface}
              </span>
              {isCapturing ? (
                <span className="text-emerald-400 flex items-center gap-1 animate-pulse">
                  ● SNIFFING {selectedIfaceInfo?.type?.toUpperCase() || "INTERFACE"}
                </span>
              ) : (
                <span className="text-slate-500">○ IDLE (Click Start Capture)</span>
              )}
            </div>
            <div className="text-slate-500 text-[9px]">
              Switching interface automatically isolates packets & refreshes the dashboard view.
            </div>
          </div>
        )}
      </section>

      {/* Stats Row */}
      <section className="grid grid-cols-2 lg:grid-cols-5 gap-3">
        {[
          { label: "Total Packets", value: totalPkts.toLocaleString(), icon: Activity, color: "text-cyan-400" },
          { label: "Total Data", value: formatBytes(totalBytes), icon: Globe, color: "text-indigo-400" },
          { label: "Unique Flows", value: Object.keys(flows).length, icon: Zap, color: "text-amber-400" },
          { label: "Attack Flows", value: attackFlows.length, icon: ShieldAlert, color: "text-rose-400" },
          { label: "Nodes Seen", value: topoNodeList.length, icon: Network, color: "text-purple-400" },
        ].map((s, i) => (
          <div key={i} className="glass-card rounded-lg border border-slate-800/50 p-3 flex items-center gap-3">
            <s.icon className={`h-5 w-5 ${s.color} opacity-50`} />
            <div>
              <p className="text-[9px] uppercase tracking-wider text-slate-500 font-mono-tech">{s.label}</p>
              <p className={`text-lg font-black font-mono-tech ${s.color}`}>{s.value}</p>
            </div>
          </div>
        ))}
      </section>

      {/* Charts Row: BPS + Protocol */}
      <section className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        <div className="lg:col-span-2 glass-card rounded-xl border border-slate-800/50 p-4">
          <div className="flex items-center gap-2 mb-3">
            <Activity className="h-4 w-4 text-cyan-400" />
            <h3 className="text-xs font-bold uppercase tracking-wider font-mono-tech">Live Network Traffic</h3>
            {isCapturing && <span className="text-[9px] text-cyan-400 font-mono-tech animate-pulse ml-auto">LIVE</span>}
          </div>
          <div className="h-[180px]">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={bpsHistory} margin={{ top: 5, right: 10, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="gradBps" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#00f0ff" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#00f0ff" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.02)" />
                <XAxis dataKey="time" tick={{ fontSize: 8, fill: "#64748b" }} interval={4} />
                <YAxis tick={{ fontSize: 9, fill: "#64748b" }} tickFormatter={formatBps} />
                <Tooltip
                  contentStyle={{ backgroundColor: "#0b0f19", border: "1px solid #1f293d", borderRadius: 8, fontSize: 10 }}
                  formatter={(val) => [formatBps(val), "Bandwidth"]}
                />
                <Area type="monotone" dataKey="bps" stroke="#00f0ff" strokeWidth={1.5} fillOpacity={1} fill="url(#gradBps)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>
        <div className="glass-card rounded-xl border border-slate-800/50 p-4">
          <div className="flex items-center gap-2 mb-3">
            <Globe className="h-4 w-4 text-indigo-400" />
            <h3 className="text-xs font-bold uppercase tracking-wider font-mono-tech">Protocol Split</h3>
          </div>
          <div className="h-[180px]">
            {protoDist.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={protoDist} margin={{ top: 5, right: 10, left: -20, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.02)" />
                  <XAxis dataKey="name" tick={{ fontSize: 10, fill: "#94a3b8" }} />
                  <YAxis tick={{ fontSize: 9, fill: "#64748b" }} />
                  <Tooltip contentStyle={{ backgroundColor: "#0b0f19", border: "1px solid #1f293d", borderRadius: 8, fontSize: 10 }} />
                  <Bar dataKey="count" fill="#00f0ff" radius={[4, 4, 0, 0]} name="Flows" />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="flex items-center justify-center h-full text-slate-600 text-[10px] font-mono-tech">
                Start capture to see protocol distribution
              </div>
            )}
          </div>
        </div>
      </section>

      {/* Topology + Alerts side-by-side */}
      <section className="grid grid-cols-1 lg:grid-cols-5 gap-4">
        {/* Minimized Force-Directed Topology (3/5 width) */}
        <div className="lg:col-span-3 glass-card rounded-xl border border-slate-800/50 p-4">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2">
              <Network className="h-4 w-4 text-purple-400" />
              <h3 className="text-xs font-bold uppercase tracking-wider font-mono-tech">Live Network Topology</h3>
              <span className="text-[9px] font-mono-tech text-slate-500 bg-slate-900 px-2 py-0.5 rounded">
                {topoNodeList.length} nodes · {topoLinks.length} links
              </span>
            </div>
            <div className="flex items-center gap-2 text-[8px] font-mono-tech">
              {[
                { label: "Critical", color: SEV_COLORS.critical },
                { label: "High", color: SEV_COLORS.high },
                { label: "Medium", color: SEV_COLORS.medium },
                { label: "Low", color: SEV_COLORS.low },
              ].map(l => (
                <div key={l.label} className="flex items-center gap-1">
                  <div className="w-2 h-2 rounded-full" style={{ backgroundColor: l.color }}></div>
                  <span className="text-slate-500">{l.label}</span>
                </div>
              ))}
            </div>
          </div>
          <div className="relative bg-[#060a12] rounded-lg overflow-hidden scan-overlay" style={{ height: 280 }}>
            {topoNodeList.length === 0 ? (
              <div className="flex flex-col items-center justify-center h-full text-slate-600 gap-2">
                <Network className="h-8 w-8 opacity-20" />
                <span className="text-[10px] font-mono-tech">Start a capture to see topology</span>
              </div>
            ) : (
              <ForceDirectedTopology
                nodes={topoNodeList}
                links={topoLinks}
                onNodeClick={(node) => {
                  const atkFlow = attackFlows.find(f => f.src_ip === node.ip || f.dst_ip === node.ip);
                  if (atkFlow && onFlowClick) onFlowClick(atkFlow);
                }}
              />
            )}
          </div>
        </div>

        {/* Attack Alerts Card (2/5 width) — only shows when attacks detected */}
        <div className="lg:col-span-2 glass-card rounded-xl border border-rose-900/30 p-4 flex flex-col">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2">
              <ShieldAlert className="h-4 w-4 text-rose-400 animate-pulse" />
              <h3 className="text-xs font-bold uppercase tracking-wider font-mono-tech text-rose-400">Attack Alerts</h3>
            </div>
            {attackFlows.length > 0 && (
              <span className="text-[8px] font-mono-tech text-rose-400 bg-rose-950/30 px-1.5 py-0.5 rounded border border-rose-900/50">
                {attackFlows.length} threats
              </span>
            )}
          </div>
          {attackFlows.length === 0 ? (
            <div className="flex-1 flex flex-col items-center justify-center text-slate-600 gap-2 py-6">
              <CheckCircle2 className="h-6 w-6 opacity-20 text-emerald-400" />
              <span className="text-[10px] font-mono-tech">No attacks detected — all clear</span>
            </div>
          ) : (
            <div className="space-y-1.5 flex-1 overflow-y-auto max-h-[320px] pr-1">
              {attackFlows.slice(0, 15).map((flow, idx) => {
                const aKey = `${flow.src_ip}-${flow.dst_ip}-${flow.dst_port}-${idx}`;
                const isExpanded = expandedAlertKey === aKey;
                const ifaceD = localDefenseState[selectedIface] || {};
                return (
                  <div key={idx}>
                    <button
                      onClick={() => setExpandedAlertKey(isExpanded ? null : aKey)}
                      className={`w-full text-left flex items-center justify-between p-2 rounded-lg border transition-all ${
                        isExpanded ? "bg-slate-900/60" : "hover:bg-slate-900/40"
                      } ${
                        flow.severity === "critical"
                          ? "border-rose-800/40 bg-rose-950/10"
                          : flow.severity === "high"
                          ? "border-amber-800/40 bg-amber-950/10"
                          : "border-slate-800/40 bg-slate-950/20"
                      }`}
                    >
                      <div className="flex items-center gap-2 min-w-0">
                        <span className={`px-1 py-0.5 rounded text-[7px] font-bold uppercase shrink-0 ${
                          flow.severity === "critical" ? "bg-rose-950/50 text-rose-400 border border-rose-900/50 pulse-red" :
                          flow.severity === "high" ? "bg-amber-950/50 text-amber-400 border border-amber-900/50" :
                          flow.severity === "medium" ? "bg-yellow-950/50 text-yellow-400 border border-yellow-900/50" :
                          "bg-cyan-950/50 text-cyan-400 border border-cyan-900/50"
                        }`}>
                          {flow.severity?.toUpperCase()?.slice(0, 4)}
                        </span>
                        <div className="font-mono-tech text-[9px] min-w-0">
                          <span className="text-cyan-400 font-bold">{flow.src_ip}</span>
                          <span className="text-slate-600 mx-0.5">→</span>
                          <span className="text-white font-bold">{flow.dst_ip}</span>
                        </div>
                      </div>
                      <div className="flex items-center gap-1.5 shrink-0 ml-2">
                        <span className="text-[8px] text-amber-400 font-mono-tech">{flow.ml_label && flow.ml_label !== 'benign' ? flow.ml_label.replace(/_/g, ' ') : flow.attack_type}</span>
                        {flow.ml_confidence && flow.ml_label && flow.ml_label !== 'benign' && (
                          <span className="text-[7px] text-slate-500 font-mono-tech">{Math.round(flow.ml_confidence * 100)}%</span>
                        )}
                        <ChevronRight className={`h-3 w-3 text-slate-600 transition-transform ${isExpanded ? "rotate-90" : ""}`} />
                      </div>
                    </button>
                    {/* Expanded defense actions */}
                    {isExpanded && (
                      <div className="mt-1 p-2.5 rounded-lg bg-[#0a0e18] border border-slate-800/60 space-y-2 animate-fade-in">
                        <div className="flex items-center gap-2 text-[8px] font-mono-tech text-slate-500 mb-1">
                          <ShieldAlert className="h-3 w-3 text-amber-400" />
                          <span>DEFEND: {flow.src_ip} → {flow.dst_ip}:{flow.dst_port} ({flow.protocol})</span>
                        </div>
                        <div className="grid grid-cols-2 gap-1.5">
                          <button
                            onClick={async (e) => { e.stopPropagation(); await callDefenseApi("rate-limit", { ip: flow.src_ip, interface: selectedIface }, `alert-rl-${aKey}`); }}
                            disabled={defenseLoading[`alert-rl-${aKey}`]}
                            className={`flex items-center justify-center gap-1 px-2 py-1.5 rounded border text-[8px] font-mono-tech uppercase transition-all ${
                              ifaceD.rate_limited_ips?.includes(flow.src_ip)
                                ? "bg-amber-600/25 border-amber-500 text-amber-300"
                                : "bg-amber-950/10 border-amber-800 text-amber-400 hover:bg-amber-600/20"
                            }`}
                          >
                            {defenseLoading[`alert-rl-${aKey}`] ? <RefreshCw className="h-2.5 w-2.5 animate-spin" /> : <Gauge className="h-2.5 w-2.5" />}
                            <span>{ifaceD.rate_limited_ips?.includes(flow.src_ip) ? "Unlimit" : "Rate Limit"}</span>
                          </button>
                          <button
                            onClick={async (e) => { e.stopPropagation(); await callDefenseApi("block-ip", { ip: flow.src_ip, interface: selectedIface }, `alert-bi-${aKey}`); }}
                            disabled={defenseLoading[`alert-bi-${aKey}`]}
                            className={`flex items-center justify-center gap-1 px-2 py-1.5 rounded border text-[8px] font-mono-tech uppercase transition-all ${
                              ifaceD.blocked_ips?.includes(flow.src_ip)
                                ? "bg-rose-600/25 border-rose-500 text-rose-300"
                                : "bg-rose-950/10 border-rose-800 text-rose-400 hover:bg-rose-600/20"
                            }`}
                          >
                            {defenseLoading[`alert-bi-${aKey}`] ? <RefreshCw className="h-2.5 w-2.5 animate-spin" /> : <Ban className="h-2.5 w-2.5" />}
                            <span>{ifaceD.blocked_ips?.includes(flow.src_ip) ? "Unblock" : "Block IP"}</span>
                          </button>
                          <button
                            onClick={async (e) => { e.stopPropagation(); await callDefenseApi("isolate-port", { port: flow.dst_port, interface: selectedIface }, `alert-ip-${aKey}`); }}
                            disabled={defenseLoading[`alert-ip-${aKey}`]}
                            className={`flex items-center justify-center gap-1 px-2 py-1.5 rounded border text-[8px] font-mono-tech uppercase transition-all ${
                              ifaceD.isolated_ports?.includes(flow.dst_port)
                                ? "bg-purple-600/25 border-purple-500 text-purple-300"
                                : "bg-purple-950/10 border-purple-800 text-purple-400 hover:bg-purple-600/20"
                            }`}
                          >
                            {defenseLoading[`alert-ip-${aKey}`] ? <RefreshCw className="h-2.5 w-2.5 animate-spin" /> : <Lock className="h-2.5 w-2.5" />}
                            <span>{ifaceD.isolated_ports?.includes(flow.dst_port) ? "Unisolate" : "Isolate Port"}</span>
                          </button>
                          <button
                            onClick={async (e) => { e.stopPropagation(); await callDefenseApi("firewall/raise", { interface: selectedIface }, `alert-fw-${aKey}`); }}
                            disabled={defenseLoading[`alert-fw-${aKey}`]}
                            className={`flex items-center justify-center gap-1 px-2 py-1.5 rounded border text-[8px] font-mono-tech uppercase transition-all ${
                              ifaceD.firewall_raised
                                ? "bg-cyan-600/25 border-cyan-500 text-cyan-300"
                                : "bg-cyan-950/10 border-cyan-800 text-cyan-400 hover:bg-cyan-600/20"
                            }`}
                          >
                            {defenseLoading[`alert-fw-${aKey}`] ? <RefreshCw className="h-2.5 w-2.5 animate-spin" /> : <ShieldAlert className="h-2.5 w-2.5" />}
                            <span>{ifaceD.firewall_raised ? "Drop Fw" : "Raise Fw"}</span>
                          </button>
                        </div>
                        <button
                          onClick={(e) => { e.stopPropagation(); onFlowClick && onFlowClick(flow); }}
                          className="w-full flex items-center justify-center gap-1 px-2 py-1 rounded bg-slate-900 border border-slate-700 text-[8px] font-mono-tech text-slate-400 hover:text-white hover:border-slate-500 transition-all"
                        >
                          <Target className="h-2.5 w-2.5" />
                          <span>View Full Forecast →</span>
                        </button>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </section>

      {/* Filter + Attack toggle */}
      <section className="flex items-center gap-3">
        <div className="flex items-center gap-2 bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 flex-1 max-w-md">
          <Search className="h-4 w-4 text-slate-500" />
          <input
            type="text"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            placeholder="Filter by IP, protocol, attack type..."
            className="bg-transparent text-xs text-white placeholder:text-slate-600 outline-none flex-1 font-mono-tech"
          />
        </div>
        <button
          onClick={() => setShowAttackOnly(!showAttackOnly)}
          className={`flex items-center gap-1.5 px-3 py-2 rounded-lg border text-[10px] font-mono-tech uppercase transition-all ${
            showAttackOnly
              ? "bg-rose-950/30 border-rose-800/50 text-rose-400"
              : "bg-slate-900 border-slate-800 text-slate-400 hover:text-slate-300"
          }`}
        >
          <ShieldAlert className="h-3.5 w-3.5" />
          <span>Attacks Only</span>
        </button>
      </section>

      {/* Flow Table */}
      <section className="glass-card rounded-xl border border-slate-800/50 overflow-hidden">
        <div className="p-4 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Activity className="h-4 w-4 text-indigo-400" />
            <h3 className="text-xs font-bold uppercase tracking-wider font-mono-tech">Captured Flows</h3>
            <span className="text-[9px] font-mono-tech text-slate-500 bg-slate-900 px-2 py-0.5 rounded">
              {flowList.length} flows
            </span>
          </div>
          {isCapturing && (
            <span className="text-[9px] text-cyan-400 font-mono-tech animate-pulse flex items-center gap-1">
              <RefreshCw className="h-3 w-3" /> Streaming
            </span>
          )}
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left font-mono-tech text-[10px]">
            <thead>
              <tr className="border-b border-slate-800 text-slate-500 uppercase tracking-widest">
                <th className="px-4 py-2.5">Source IP</th>
                <th>Src Port</th>
                <th>Destination IP</th>
                <th>Dst Port</th>
                <th>Proto</th>
                <th>Packets</th>
                <th>Bytes</th>
                <th>Attack</th>
                <th>Severity</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-900/50">
              {!isCapturing && flowList.length === 0 ? (
                <tr>
                  <td colSpan="9" className="py-16 text-center text-slate-600">
                    <Radio className="h-8 w-8 mx-auto mb-2 opacity-20" />
                    <p className="font-mono-tech text-xs">Select an interface and click Start Capture to begin</p>
                  </td>
                </tr>
              ) : flowList.length === 0 ? (
                <tr>
                  <td colSpan="9" className="py-16 text-center text-slate-600">
                    <Activity className="h-8 w-8 mx-auto mb-2 opacity-20 animate-spin" />
                    <p className="font-mono-tech text-xs">Capturing... waiting for packets</p>
                  </td>
                </tr>
              ) : (
                flowList.map((flow, idx) => {
                  const fKey = `${flow.src_ip}:${flow.src_port}-${flow.dst_ip}:${flow.dst_port}-${flow.protocol}`;
                  const isAttack = flow.severity && flow.severity !== "none";
                  const isExpanded = expandedFlowKey === fKey;
                  const ifaceD = localDefenseState[selectedIface] || {};
                  return (
                    <React.Fragment key={idx}>
                      <tr
                        onClick={() => isAttack && setExpandedFlowKey(isExpanded ? null : fKey)}
                        className={`transition-colors ${
                          isAttack
                            ? `bg-rose-950/5 hover:bg-rose-950/15 cursor-pointer ${isExpanded ? "bg-slate-900/30" : ""}`
                            : "hover:bg-slate-900/20"
                        }`}
                      >
                        <td className="px-4 py-2 text-cyan-400 font-bold">{flow.src_ip}</td>
                        <td className="text-slate-400">{flow.src_port}</td>
                        <td className="text-white font-bold">{flow.dst_ip}</td>
                        <td className="text-slate-400">{flow.dst_port}</td>
                        <td>
                          <span className={`px-1.5 py-0.5 rounded text-[8px] font-bold ${
                            flow.protocol === "TCP" ? "bg-cyan-950/50 text-cyan-400" :
                            flow.protocol === "UDP" ? "bg-indigo-950/50 text-indigo-400" :
                            flow.protocol === "ICMP" ? "bg-amber-950/50 text-amber-400" :
                            "bg-slate-800 text-slate-400"
                          }`}>{flow.protocol}</span>
                        </td>
                        <td className="text-slate-300">{flow.packet_count}</td>
                        <td className="text-slate-300">{formatBytes(flow.byte_count)}</td>
                        <td className={isAttack ? "text-amber-400 font-bold" : "text-slate-600"}>
                          <span>{flow.ml_label && flow.ml_label !== 'benign' ? flow.ml_label.replace(/_/g, ' ') : flow.attack_type || '—'}</span>
                          {flow.ml_confidence && flow.ml_label && flow.ml_label !== 'benign' && (
                            <span className="ml-1 text-[7px] text-slate-500">{Math.round(flow.ml_confidence * 100)}%</span>
                          )}
                        </td>
                        <td>
                          <span className={`px-1.5 py-0.5 rounded text-[8px] font-bold uppercase ${
                            flow.severity === "critical" ? "bg-rose-950/50 text-rose-400 border border-rose-900/50 pulse-red" :
                            flow.severity === "high" ? "bg-amber-950/50 text-amber-400 border border-amber-900/50" :
                            flow.severity === "medium" ? "bg-yellow-950/50 text-yellow-400 border border-yellow-900/50" :
                            flow.severity === "low" ? "bg-cyan-950/50 text-cyan-400 border border-cyan-900/50" :
                            "text-slate-600"
                          }`}>
                            {flow.severity === "none" ? "—" : flow.severity?.toUpperCase()}
                          </span>
                        </td>
                        <td className="text-right pr-4">
                          {isAttack && (
                            <ChevronRight className={`h-3 w-3 text-slate-500 inline transition-transform ${isExpanded ? "rotate-90" : ""}`} />
                          )}
                        </td>
                      </tr>
                      {/* Expanded defense panel for attack flows */}
                      {isAttack && isExpanded && (
                        <tr>
                          <td colSpan="9" className="p-0">
                            <div className="px-4 py-3 bg-[#0a0e18] border-t border-slate-800/40 animate-fade-in">
                              <div className="flex items-center gap-2 mb-2">
                                <ShieldAlert className="h-3 w-3 text-amber-400" />
                                <span className="text-[9px] font-mono-tech text-slate-400">
                                  DEFENSIVE INTERVENTIONS for <span className="text-cyan-400 font-bold">{flow.src_ip}</span> → <span className="text-white font-bold">{flow.dst_ip}:{flow.dst_port}</span>
                                </span>
                              </div>
                              <div className="flex items-center gap-2 flex-wrap">
                                <button
                                  onClick={async (e) => { e.stopPropagation(); await callDefenseApi("rate-limit", { ip: flow.src_ip, interface: selectedIface }, `tbl-rl-${fKey}`); }}
                                  disabled={defenseLoading[`tbl-rl-${fKey}`]}
                                  className={`flex items-center gap-1 px-2.5 py-1.5 rounded border text-[8px] font-mono-tech uppercase transition-all ${
                                    ifaceD.rate_limited_ips?.includes(flow.src_ip)
                                      ? "bg-amber-600/25 border-amber-500 text-amber-300"
                                      : "bg-amber-950/10 border-amber-800 text-amber-400 hover:bg-amber-600/20"
                                  }`}
                                >
                                  {defenseLoading[`tbl-rl-${fKey}`] ? <RefreshCw className="h-2.5 w-2.5 animate-spin" /> : <Gauge className="h-2.5 w-2.5" />}
                                  <span>{ifaceD.rate_limited_ips?.includes(flow.src_ip) ? "Unlimit" : "Rate Limit"}</span>
                                </button>
                                <button
                                  onClick={async (e) => { e.stopPropagation(); await callDefenseApi("block-ip", { ip: flow.src_ip, interface: selectedIface }, `tbl-bi-${fKey}`); }}
                                  disabled={defenseLoading[`tbl-bi-${fKey}`]}
                                  className={`flex items-center gap-1 px-2.5 py-1.5 rounded border text-[8px] font-mono-tech uppercase transition-all ${
                                    ifaceD.blocked_ips?.includes(flow.src_ip)
                                      ? "bg-rose-600/25 border-rose-500 text-rose-300"
                                      : "bg-rose-950/10 border-rose-800 text-rose-400 hover:bg-rose-600/20"
                                  }`}
                                >
                                  {defenseLoading[`tbl-bi-${fKey}`] ? <RefreshCw className="h-2.5 w-2.5 animate-spin" /> : <Ban className="h-2.5 w-2.5" />}
                                  <span>{ifaceD.blocked_ips?.includes(flow.src_ip) ? "Unblock" : "Block IP"}</span>
                                </button>
                                <button
                                  onClick={async (e) => { e.stopPropagation(); await callDefenseApi("isolate-port", { port: flow.dst_port, interface: selectedIface }, `tbl-ip-${fKey}`); }}
                                  disabled={defenseLoading[`tbl-ip-${fKey}`]}
                                  className={`flex items-center gap-1 px-2.5 py-1.5 rounded border text-[8px] font-mono-tech uppercase transition-all ${
                                    ifaceD.isolated_ports?.includes(flow.dst_port)
                                      ? "bg-purple-600/25 border-purple-500 text-purple-300"
                                      : "bg-purple-950/10 border-purple-800 text-purple-400 hover:bg-purple-600/20"
                                  }`}
                                >
                                  {defenseLoading[`tbl-ip-${fKey}`] ? <RefreshCw className="h-2.5 w-2.5 animate-spin" /> : <Lock className="h-2.5 w-2.5" />}
                                  <span>{ifaceD.isolated_ports?.includes(flow.dst_port) ? "Unisolate" : "Isolate Port"}</span>
                                </button>
                                <button
                                  onClick={async (e) => { e.stopPropagation(); await callDefenseApi("firewall/raise", { interface: selectedIface }, `tbl-fw-${fKey}`); }}
                                  disabled={defenseLoading[`tbl-fw-${fKey}`]}
                                  className={`flex items-center gap-1 px-2.5 py-1.5 rounded border text-[8px] font-mono-tech uppercase transition-all ${
                                    ifaceD.firewall_raised
                                      ? "bg-cyan-600/25 border-cyan-500 text-cyan-300"
                                      : "bg-cyan-950/10 border-cyan-800 text-cyan-400 hover:bg-cyan-600/20"
                                  }`}
                                >
                                  {defenseLoading[`tbl-fw-${fKey}`] ? <RefreshCw className="h-2.5 w-2.5 animate-spin" /> : <ShieldAlert className="h-2.5 w-2.5" />}
                                  <span>{ifaceD.firewall_raised ? "Drop Fw" : "Raise Fw"}</span>
                                </button>
                                <button
                                  onClick={(e) => { e.stopPropagation(); onFlowClick && onFlowClick(flow); }}
                                  className="flex items-center gap-1 px-2.5 py-1.5 rounded border border-slate-700 text-[8px] font-mono-tech text-slate-400 hover:text-white hover:border-slate-500 transition-all ml-auto"
                                >
                                  <Target className="h-2.5 w-2.5" />
                                  <span>Full Forecast →</span>
                                </button>
                              </div>
                            </div>
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  );
                }))
              }
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
