import React, { useState, useEffect, useRef, useMemo, useCallback } from "react";
import {
  Activity, Search, ShieldAlert, Wifi, Globe, Clock, Filter,
  AlertTriangle, Server, Zap, ArrowUpDown, RefreshCw, Radio,
  Play, Square, Network, ChevronDown, Signal, Usb, MonitorSmartphone,
  Link2, WifiOff, Target, Crosshair, CheckCircle2, Gauge, Ban, Lock, ChevronRight, Download
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

// Protocol colors for chart
const PROTO_COLORS = {
  TCP: "#3E63C7",
  UDP: "#22386E",
  ICMP: "#CBA135",
  OTHER: "#9BA6B4",
  HTTP: "#3E63C7",
  HTTPS: "#3E63C7",
  DNS: "#22386E",
  SSH: "#CBA135",
};

// Severity color
const SEV_COLORS = {
  none: "#262E3A",
  low: "#3E63C7",
  medium: "#3E63C7",
  high: "#CBA135",
  critical: "#CBA135",
};

// ── Force-Directed Topology Component ───────────────────────────────────────

function isPrivateIp(ip) {
  if (!ip) return false;
  if (ip === "127.0.0.1" || ip === "localhost" || ip.startsWith("127.") || ip.startsWith("169.254.")) return true;
  if (ip.startsWith("10.") || ip.startsWith("192.168.")) return true;
  const parts = ip.split(".");
  if (parts.length === 4 && parts[0] === "172") {
    const secondOctet = parseInt(parts[1], 10);
    if (!isNaN(secondOctet) && secondOctet >= 16 && secondOctet <= 31) {
      return true;
    }
  }
  return false;
}

function getNodeCategory(node, localHostIp) {
  // 1. Threat (red) = actual attack / high-risk nodes
  if (node.severity && node.severity !== "none") {
    return {
      type: "attack",
      role: "Threat Node",
      fill: "#DC2626",
      stroke: "#EF4444",
      ring: "#F87171",
      textColor: "#FFFFFF",
      dotColor: "#DC2626",
    };
  }

  // 2. Local Host (gold) = ONLY the capture interface's own IP (EXACTLY ONE gold node)
  if (localHostIp && node.ip === localHostIp) {
    return {
      type: "local",
      role: "Local Host / Hub",
      fill: "#CBA135",
      stroke: "#DFB84C",
      ring: "#F3D079",
      textColor: "#0B0F14",
      dotColor: "#CBA135",
    };
  }

  // 3. Internal (blue) = any RFC1918 private IP that is not the local host
  if (isPrivateIp(node.ip)) {
    return {
      type: "internal",
      role: "Internal IP",
      fill: "#3E63C7",
      stroke: "#527CEB",
      ring: "#789BF2",
      textColor: "#FFFFFF",
      dotColor: "#3E63C7",
    };
  }

  // 4. External (grey/slate) = public IPs (everything else)
  return {
    type: "external",
    role: "External IP",
    fill: "#2C3A57",
    stroke: "#4A5568",
    ring: "#64748B",
    textColor: "#FFFFFF",
    dotColor: "#4A5568",
  };
}

function ForceDirectedTopology({ nodes, links, localIp, onNodeClick }) {
  const svgRef = useRef(null);
  const positionsRef = useRef({});
  const velocitiesRef = useRef({});
  const nodesRef = useRef(nodes);
  const linksRef = useRef(links);
  const [hoverNode, setHoverNode] = useState(null);
  const [tick, setTick] = useState(0);

  nodesRef.current = nodes;
  linksRef.current = links;

  // Determine connection degree map
  const degreeMap = useMemo(() => {
    const map = {};
    links.forEach(l => {
      map[l.source] = (map[l.source] || 0) + 1;
      map[l.target] = (map[l.target] || 0) + 1;
    });
    return map;
  }, [links]);

  // Determine single local host IP (EXACTLY ONE gold node)
  const localHostIp = useMemo(() => {
    if (localIp && nodes.some(n => n.ip === localIp)) {
      return localIp;
    }
    const explicitLocal = nodes.find(n => n.isLocal);
    if (explicitLocal) {
      return explicitLocal.ip;
    }
    let bestIp = null, maxD = -1;
    Object.entries(degreeMap).forEach(([ip, d]) => {
      if (d > maxD) { maxD = d; bestIp = ip; }
    });
    return bestIp || (nodes[0] ? nodes[0].ip : null);
  }, [localIp, nodes, degreeMap]);

  // Throttled physics simulation
  useEffect(() => {
    let frameId;
    let lastRender = 0;
    const startTime = Date.now();

    const step = (ts) => {
      frameId = requestAnimationFrame(step);
      if (ts - lastRender < 80) return;
      lastRender = ts;

      const curNodes = nodesRef.current;
      const curLinks = linksRef.current;
      const nodeIps = curNodes.map(n => n.ip);
      const pos = positionsRef.current;
      const vel = velocitiesRef.current;
      const elapsed = (Date.now() - startTime) / 1000;

      // Init new nodes
      nodeIps.forEach((ip, idx) => {
        if (!pos[ip]) {
          const angle = (idx / Math.max(1, nodeIps.length)) * Math.PI * 2;
          const r = 80 + Math.random() * 40;
          pos[ip] = { x: 400 + Math.cos(angle) * r, y: 130 + Math.sin(angle) * (r * 0.6) };
          vel[ip] = { x: 0, y: 0 };
        }
      });

      // Prune old
      Object.keys(pos).forEach(ip => { if (!nodeIps.includes(ip)) { delete pos[ip]; delete vel[ip]; } });

      const ALPHA = Math.max(0.01, 0.35 - elapsed * 0.003);
      const WIDTH = 800, HEIGHT = 260;

      nodeIps.forEach(a => {
        let fx = 0, fy = 0;
        // Repulsion
        nodeIps.forEach(b => {
          if (a === b) return;
          const dx = pos[a].x - pos[b].x, dy = pos[a].y - pos[b].y;
          const d = Math.sqrt(dx * dx + dy * dy) + 1;
          const f = 6000 / (d * d);
          fx += (dx / d) * f; fy += (dy / d) * f;
        });

        // Attraction along links
        curLinks.forEach(lk => {
          let o = null;
          if (lk.source === a) o = lk.target;
          else if (lk.target === a) o = lk.source;
          if (!o || !pos[o]) return;
          fx += (pos[o].x - pos[a].x) * 0.008;
          fy += (pos[o].y - pos[a].y) * 0.008;
        });

        // Center gravity
        fx += (WIDTH / 2 - pos[a].x) * 0.002;
        fy += (HEIGHT / 2 - pos[a].y) * 0.002;

        vel[a].x = (vel[a].x + fx * ALPHA) * 0.82;
        vel[a].y = (vel[a].y + fy * ALPHA) * 0.82;

        // Keep inside bounds with comfortable margin
        pos[a].x = Math.max(45, Math.min(WIDTH - 45, pos[a].x + vel[a].x));
        pos[a].y = Math.max(35, Math.min(HEIGHT - 35, pos[a].y + vel[a].y));
      });

      setTick(n => n + 1);
    };
    frameId = requestAnimationFrame(step);
    return () => cancelAnimationFrame(frameId);
  }, []);

  const pos = positionsRef.current;
  const maxPackets = Math.max(1, ...nodes.map(n => n.packets || 1));

  // Neighbors of hovered node
  const hoverNeighbors = useMemo(() => {
    if (!hoverNode) return new Set();
    const set = new Set([hoverNode]);
    links.forEach(lk => {
      if (lk.source === hoverNode) set.add(lk.target);
      if (lk.target === hoverNode) set.add(lk.source);
    });
    return set;
  }, [hoverNode, links]);

  const activeHoverData = useMemo(() => {
    if (!hoverNode) return null;
    const n = nodes.find(item => item.ip === hoverNode);
    if (!n) return null;
    const cat = getNodeCategory(n, localHostIp);
    return { node: n, category: cat, pos: pos[hoverNode] };
  }, [hoverNode, nodes, localHostIp, pos]);

  return (
    <div className="relative w-full h-full bg-surface select-none">
      <svg ref={svgRef} viewBox="0 0 800 260" className="w-full h-full bg-surface">
        <defs>
          <pattern id="topoGrid" width="24" height="24" patternUnits="userSpaceOnUse">
            <path d="M 24 0 L 0 0 0 24" fill="none" stroke="#262E3A" strokeWidth="0.5" opacity="0.6" />
          </pattern>
          <marker id="arrowheadGold" markerWidth="6" markerHeight="4" refX="6" refY="2" orient="auto">
            <polygon points="0 0, 6 2, 0 4" fill="#CBA135" />
          </marker>
          <marker id="arrowheadRed" markerWidth="6" markerHeight="4" refX="6" refY="2" orient="auto">
            <polygon points="0 0, 6 2, 0 4" fill="#EF4444" />
          </marker>
        </defs>
        <rect width="800" height="260" fill="url(#topoGrid)" />

        {/* Links (edges) */}
        {links.map((link, i) => {
          const srcPos = pos[link.source];
          const dstPos = pos[link.target];
          if (!srcPos || !dstPos) return null;

          const isAttack = link.severity && link.severity !== "none";
          const isHighlighted = hoverNode && (link.source === hoverNode || link.target === hoverNode);
          const isDimmed = hoverNode && !isHighlighted;

          const midX = (srcPos.x + dstPos.x) / 2;
          const midY = (srcPos.y + dstPos.y) / 2;
          const dx = dstPos.x - srcPos.x;
          const dy = dstPos.y - srcPos.y;
          const dist = Math.sqrt(dx * dx + dy * dy) || 1;
          const curve = Math.min(dist * 0.12, 24);
          const nx = -dy / dist;
          const ny = dx / dist;
          const cx = midX + nx * curve;
          const cy = midY + ny * curve;

          const strokeColor = isAttack ? "#EF4444" : isHighlighted ? "#3E63C7" : "#262E3A";
          const opacity = isDimmed ? 0.08 : isHighlighted ? 0.85 : isAttack ? 0.75 : 0.35;
          const strokeWidth = isHighlighted ? 2.5 : isAttack ? 2 : 1.2;

          return (
            <path
              key={`link-${i}`}
              d={`M ${srcPos.x} ${srcPos.y} Q ${cx} ${cy} ${dstPos.x} ${dstPos.y}`}
              fill="none"
              stroke={strokeColor}
              strokeWidth={strokeWidth}
              strokeOpacity={opacity}
              markerEnd={isAttack ? "url(#arrowheadRed)" : undefined}
            />
          );
        })}

        {/* Nodes */}
        {nodes.map((node) => {
          const p = pos[node.ip];
          if (!p) return null;

          const cat = getNodeCategory(node, localHostIp);
          const volume = node.packets || 1;
          const radius = 12 + Math.min(14, Math.sqrt(volume / maxPackets) * 14);

          const isHovered = hoverNode === node.ip;
          const isNeighbor = hoverNeighbors.has(node.ip);
          const isDimmed = hoverNode && !isNeighbor;

          return (
            <g
              key={node.ip}
              className="cursor-pointer transition-opacity duration-200"
              opacity={isDimmed ? 0.25 : 1.0}
              onMouseEnter={() => setHoverNode(node.ip)}
              onMouseLeave={() => setHoverNode(null)}
              onClick={() => onNodeClick && onNodeClick(node)}
            >
              {/* Outer Ring */}
              <circle
                cx={p.x}
                cy={p.y}
                r={radius + 3}
                fill="none"
                stroke={cat.ring}
                strokeWidth={isHovered ? 2 : 1.2}
                strokeOpacity={isHovered ? 0.9 : 0.4}
              />

              {/* Node Body */}
              <circle
                cx={p.x}
                cy={p.y}
                r={radius}
                fill={cat.fill}
                stroke={cat.stroke}
                strokeWidth={1.5}
              />

              {/* Centered Packet Count */}
              <text
                x={p.x}
                y={p.y + (radius > 16 ? 4 : 3.5)}
                textAnchor="middle"
                fontSize={radius > 16 ? "11" : "10"}
                fontFamily="Inter, sans-serif"
                fontWeight="800"
                fill={cat.textColor}
              >
                {volume}
              </text>

              {/* IP Label BELOW node */}
              <text
                x={p.x}
                y={p.y + radius + 13}
                textAnchor="middle"
                fontSize="9.5"
                fontFamily="Consolas, monospace"
                fontWeight="600"
                fill="#9BA6B4"
              >
                {node.ip}
              </text>
            </g>
          );
        })}
      </svg>

      {/* Floating Hover Tooltip */}
      {activeHoverData && activeHoverData.pos && (
        <div
          className="absolute pointer-events-none bg-surface-2 border border-border px-3 py-2 rounded-lg shadow-xl text-xs z-30 transition-opacity duration-150"
          style={{
            left: Math.max(10, Math.min(640, activeHoverData.pos.x + 15)),
            top: Math.max(10, Math.min(180, activeHoverData.pos.y - 30)),
          }}
        >
          <div className="flex items-center gap-1.5 font-mono-tech font-bold text-white mb-0.5">
            <span className="w-2 h-2 rounded-full" style={{ backgroundColor: activeHoverData.category.dotColor }} />
            <span>{activeHoverData.node.ip}</span>
          </div>
          <div className="text-[11px] text-text-muted space-y-0.5">
            <div>Role: <span className="text-white font-semibold">{activeHoverData.category.role}</span></div>
            <div>Packets: <span className="text-gold font-bold">{activeHoverData.node.packets || 1}</span></div>
            {activeHoverData.node.severity && activeHoverData.node.severity !== "none" && (
              <div className="text-red-400 font-bold uppercase">Threat: {activeHoverData.node.severity}</div>
            )}
          </div>
        </div>
      )}

      {/* Category Legend Overlay (Bottom Left) */}
      <div className="absolute bottom-2 left-2 bg-surface-2/90 border border-border/80 px-2.5 py-1.5 rounded-lg flex items-center gap-3 text-[10px] font-mono-tech text-text-muted pointer-events-none">
        <div className="flex items-center gap-1">
          <span className="w-2 h-2 rounded-full bg-[#CBA135]" />
          <span>Local Host</span>
        </div>
        <div className="flex items-center gap-1">
          <span className="w-2 h-2 rounded-full bg-[#3E63C7]" />
          <span>Internal</span>
        </div>
        <div className="flex items-center gap-1">
          <span className="w-2 h-2 rounded-full bg-[#4A5568]" />
          <span>External</span>
        </div>
        <div className="flex items-center gap-1">
          <span className="w-2 h-2 rounded-full bg-[#DC2626]" />
          <span>Threat</span>
        </div>
      </div>
    </div>
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
  const [knownClean, setKnownClean] = useState(false);
  const [summaryInfo, setSummaryInfo] = useState({
    packets_captured: 0,
    flows_extracted: 0,
    forecastable_conversations: 0,
  });

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

  // --- Fetch capture summary info ---
  useEffect(() => {
    const fetchSummary = () => {
      fetch(`${CAPTURE_API}/api/capture/summary`)
        .then(r => r.json())
        .then(data => {
          if (data && typeof data.packets_captured === "number") {
            setSummaryInfo(data);
          }
        })
        .catch(() => {});
    };

    fetchSummary();
    const interval = setInterval(fetchSummary, 3000);
    return () => clearInterval(interval);
  }, []);

  // --- Initialize smooth BPS graph baseline ---
  useEffect(() => {
    const now = Date.now();
    const initialHistory = Array.from({ length: 30 }, (_, idx) => {
      const t = new Date(now - (30 - idx) * 1000).toLocaleTimeString("en", { hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit" });
      return { time: t, bps: 0 };
    });
    bpsRef.current = initialHistory;
    setBpsHistory(initialHistory);
  }, []);

  const packetQueueRef = useRef([]);

  // --- Reset / Refresh dashboard state ---
  const resetDashboardState = useCallback(() => {
    setPackets([]);
    setFlows({});
    setTopoNodes({});
    setTotalPkts(0);
    setTotalBytes(0);
    const now = Date.now();
    const initialHistory = Array.from({ length: 30 }, (_, idx) => {
      const t = new Date(now - (30 - idx) * 1000).toLocaleTimeString("en", { hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit" });
      return { time: t, bps: 0 };
    });
    bpsRef.current = initialHistory;
    setBpsHistory(initialHistory);
    bytesWindowRef.current = [];
    packetQueueRef.current = [];
    fetch(`${CAPTURE_API}/api/capture/reset`, { method: "POST" }).catch(() => {});
  }, []);

  // --- Fetch real interfaces & sync capture status from Python server ---
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

    fetch(`${CAPTURE_API}/api/capture/status`)
      .then(r => r.json())
      .then(status => {
        const activeIfaces = Object.keys(status || {}).filter(k => status[k]);
        if (activeIfaces.length > 0) {
          setIsCapturing(true);
          isCapturingRef.current = true;
          if (!activeIfaces.includes(selectedIfaceRef.current)) {
            setSelectedIface(activeIfaces[0]);
            selectedIfaceRef.current = activeIfaces[0];
          }
        } else {
          setIsCapturing(false);
          isCapturingRef.current = false;
        }
      })
      .catch(() => {});
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
            if (data.type === "connected") return;

            if (data.type === "capture_started" || data.type === "interface_switched") {
              setIsCapturing(true);
              isCapturingRef.current = true;
              return;
            }

            if (data.type === "capture_stopped" || data.type === "all_captures_stopped") {
              setIsCapturing(false);
              isCapturingRef.current = false;
              return;
            }

            if (data.type === "stage_forecasts" && data.data) {
              try { window.__mlStageForecasts = data.data; } catch (_) {}
              return;
            }

            if (data.type === "live_forecast_update" && data.data) {
              const f = data.data;
              try {
                window.__mlStageForecasts = {
                  ...(window.__mlStageForecasts || {}),
                  [`${f.sourceIp}>${f.targetIp}`]: f,
                };
              } catch (_) {}
              return;
            }

            if (data.type === "live_forecast_alert" && data.data) {
              try {
                window.__liveAlertQueue = [ ...(window.__liveAlertQueue || []), data.data ].slice(-25);
                window.dispatchEvent(new CustomEvent("live-forecast-alert"));
              } catch (_) {}
              return;
            }

            if (!isCapturingRef.current) return;

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
        const nowMs = Date.now();
        for (const data of queue) {
          const key = `${data.src_ip}:${data.src_port}-${data.dst_ip}:${data.dst_port}-${data.protocol}`;
          if (next[key]) {
            next[key] = {
              ...next[key],
              packet_count: next[key].packet_count + 1,
              byte_count: next[key].byte_count + (data.length || 0),
              last_seen: data.timestamp,
              last_updated_ms: nowMs,
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
              last_updated_ms: nowMs,
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
  const lastLiftTimeRef = useRef(0);
  useEffect(() => {
    const now = Date.now();
    if (now - lastLiftTimeRef.current >= 400 || !isCapturing) {
      lastLiftTimeRef.current = now;
      onFlowsUpdate && onFlowsUpdate(flows, packets, totalPkts);
    } else {
      const timer = setTimeout(() => {
        lastLiftTimeRef.current = Date.now();
        onFlowsUpdate && onFlowsUpdate(flows, packets, totalPkts);
      }, 400);
      return () => clearTimeout(timer);
    }
  }, [flows, packets, totalPkts, isCapturing, onFlowsUpdate]);

  // --- Compute BPS chart every second ---
  useEffect(() => {
    const interval = setInterval(() => {
      const now = Date.now();
      const windowMs = 3000;
      bytesWindowRef.current = bytesWindowRef.current.filter(e => now - e.time < windowMs);
      const totalB = bytesWindowRef.current.reduce((s, e) => s + e.bytes, 0);
      const bps = isCapturingRef.current ? Math.round((totalB * 8) / (windowMs / 1000)) : 0;
      const timeStr = new Date().toLocaleTimeString("en", { hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit" });
      bpsRef.current = [...bpsRef.current, { time: timeStr, bps }].slice(-30);
      setBpsHistory([...bpsRef.current]);
    }, 1000);
    return () => clearInterval(interval);
  }, []);

  // --- Defense state ---
  const [expandedAlertKey, setExpandedAlertKey] = useState(null);
  const [expandedFlowKey, setExpandedFlowKey] = useState(null);
  const [defenseLoading, setDefenseLoading] = useState({});
  const [localDefenseState, setLocalDefenseState] = useState({});

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
    setIsCapturing(true);
    isCapturingRef.current = true;
    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
      try {
        wsRef.current.send(JSON.stringify({ action: "start_capture", interface: selectedIface }));
      } catch (_) {}
    }
    fetch(`${CAPTURE_API}/api/capture/start/${encodeURIComponent(selectedIface)}`, { method: "POST" }).catch(() => {});
  }, [selectedIface]);

  const stopCapture = useCallback(() => {
    setIsCapturing(false);
    isCapturingRef.current = false;
    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
      try {
        wsRef.current.send(JSON.stringify({ action: "stop_capture", interface: selectedIface }));
      } catch (_) {}
    }
    if (selectedIface) {
      fetch(`${CAPTURE_API}/api/capture/stop/${encodeURIComponent(selectedIface)}`, { method: "POST" }).catch(() => {});
    }
  }, [selectedIface]);

  // Notifications
  const [pcapNotification, setPcapNotification] = useState(null);
  const [csvNotification, setCsvNotification] = useState(null);

  // Derived flow list
  const filteredFlows = useMemo(() => {
    let list = Object.values(flows);
    if (showAttackOnly) {
      list = list.filter(f => f.severity && f.severity !== "none");
    }
    if (filter) {
      const q = filter.toLowerCase();
      list = list.filter(f =>
        (f.src_ip || "").toLowerCase().includes(q) ||
        (f.dst_ip || "").toLowerCase().includes(q) ||
        (f.protocol || "").toLowerCase().includes(q) ||
        (f.attack_type || "").toLowerCase().includes(q)
      );
    }
    return list.sort((a, b) => (b.packet_count || 0) - (a.packet_count || 0));
  }, [flows, filter, showAttackOnly]);

  const flowList = useMemo(() => filteredFlows.slice(0, 100), [filteredFlows]);

  const protoDist = useMemo(() => {
    const counts = {};
    Object.values(flows).forEach(f => {
      const p = (f.protocol || "OTHER").toUpperCase();
      counts[p] = (counts[p] || 0) + (f.packet_count || 1);
    });
    return Object.entries(counts)
      .map(([name, count]) => ({ name, count }))
      .sort((a, b) => b.count - a.count);
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

  const consolidatedAlerts = useMemo(() => {
    const map = new Map();
    const bruteForcePairs = new Set();
    const portScanPairs = new Set();
    const sevOrder = { critical: 4, high: 3, medium: 2, low: 1 };

    attackFlows.forEach(flow => {
      if (flow.attack_type === 'Brute Force' || flow.ml_label === 'brute_force') {
        bruteForcePairs.add(`${flow.src_ip}|${flow.dst_ip}`);
      }
      if (flow.attack_type === 'Port Scan' || flow.ml_label === 'port_scan') {
        portScanPairs.add(`${flow.src_ip}|${flow.dst_ip}`);
      }
    });

    attackFlows.forEach(flow => {
      let displayType = flow.attack_type && flow.attack_type !== 'Benign'
        ? flow.attack_type
        : (flow.ml_label && flow.ml_label !== 'benign'
          ? flow.ml_label.replace(/_/g, ' ')
          : 'Unknown');

      if (flow.protocol === 'ICMP') {
        displayType = 'ICMP Flood';
      }

      if (displayType === 'Port Scan' && bruteForcePairs.has(`${flow.src_ip}|${flow.dst_ip}`)) {
        const allHostFlows = Object.values(flows).filter(f => f.src_ip === flow.src_ip && f.dst_ip === flow.dst_ip);
        const uniquePorts = new Set(allHostFlows.map(f => f.dst_port)).size;
        if (uniquePorts < 4) return;
      }

      if (displayType === 'Brute Force' && portScanPairs.has(`${flow.src_ip}|${flow.dst_ip}`)) {
        const samePortPkts = attackFlows
          .filter(f => f.src_ip === flow.src_ip && f.dst_ip === flow.dst_ip && f.dst_port === flow.dst_port)
          .reduce((sum, f) => sum + (f.packet_count || 1), 0);
        if (samePortPkts < 8) return;
      }

      const sev = flow.severity || 'low';
      const key = `${flow.src_ip}|${flow.dst_ip}|${displayType}`;

      if (!map.has(key)) {
        map.set(key, {
          key,
          src_ip: flow.src_ip,
          dst_ip: flow.dst_ip,
          dst_port: flow.dst_port,
          protocol: flow.protocol,
          attack_type: flow.attack_type,
          ml_label: flow.ml_label,
          ml_confidence: flow.ml_confidence,
          displayType,
          severity: sev,
          count: 1,
          last_seen: flow.last_seen || flow.timestamp,
          latestFlow: flow,
          allFlows: [flow],
        });
      } else {
        const existing = map.get(key);
        existing.count += 1;
        existing.allFlows.push(flow);
        if ((sevOrder[sev] || 0) > (sevOrder[existing.severity] || 0)) {
          existing.severity = sev;
        }
        if (flow.last_seen && flow.last_seen > existing.last_seen) {
          existing.last_seen = flow.last_seen;
          existing.latestFlow = flow;
        }
      }
    });
    return Array.from(map.values()).sort((a, b) => {
      if ((sevOrder[b.severity] || 0) !== (sevOrder[a.severity] || 0)) {
        return (sevOrder[b.severity] || 0) - (sevOrder[a.severity] || 0);
      }
      return b.count - a.count;
    });
  }, [attackFlows]);

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
    <div className="space-y-5 animate-fade-in bg-bg text-text">
      {/* Error banner */}
      {error && (
        <div className="bg-surface border border-gold/40 rounded-xl p-4 flex items-center gap-3 text-gold">
          <AlertTriangle className="h-5 w-5 shrink-0" />
          <div>
            <p className="text-sm font-bold text-gold">Capture Server Offline</p>
            <p className="text-xs mt-0.5 text-text-muted">{error}</p>
          </div>
        </div>
      )}

      {/* Interface Selector + Controls */}
      <section className="bg-surface rounded-xl border border-border p-4">
        <div className="flex items-center gap-4 flex-wrap justify-between w-full">
          {/* Left Side: Interface label + Dropdown + Download PCAP */}
          <div className="flex items-center gap-3 flex-wrap">
            <div className="flex items-center gap-2">
              <Radio className="h-4 w-4 text-gold" />
              <span className="text-sm font-bold uppercase tracking-wider text-white whitespace-nowrap">Network Interface</span>
            </div>
            <div className="relative">
              <select
                value={selectedIface}
                onChange={(e) => handleInterfaceChange(e.target.value)}
                className="appearance-none bg-surface-2 border border-border rounded-lg px-3 py-2 pr-8 text-sm text-text outline-none focus:border-gold cursor-pointer min-w-[220px] font-semibold"
              >
                <option value="">Select interface...</option>
                {interfaces.map(iface => (
                  <option key={iface.name} value={iface.name}>
                    {iface.name} ({iface.type}) - {iface.ip} {iface.is_up ? "●" : "○"}
                  </option>
                ))}
              </select>
              <ChevronDown className="absolute right-2 top-1/2 -translate-y-1/2 h-4 w-4 text-text-muted pointer-events-none" />
            </div>

            {/* DOWNLOAD PCAP Button to the right of dropdown */}
            <button
              onClick={() => window.open(`${CAPTURE_API}/api/capture/download?format=pcap`, "_blank")}
              title="Download raw packets captured during the telemetry session as a .pcap file"
              className="flex items-center gap-2 px-5 py-2.5 rounded-lg bg-blue hover:bg-blue-hi border border-border/80 text-white text-xs font-extrabold uppercase tracking-wider transition-all duration-200 shadow-md hover:scale-[1.03] hover:shadow-lg cursor-pointer whitespace-nowrap shrink-0"
            >
              <Download className="h-4 w-4" />
              <span>Download PCAP</span>
            </button>
          </div>

          {/* Right Side: Capture Server Online Indicator + Clear/Reset + Start Capture */}
          <div className="flex items-center gap-3 flex-wrap">
            {/* Capture Server Status with Green Flashy Glow Dot */}
            <div className={`flex items-center gap-2 px-3.5 py-1.5 rounded-full text-xs border transition-all ${
              connected 
                ? "bg-surface-2 border-border text-gold font-bold" 
                : "bg-surface-2 border-border text-text-muted font-medium"
            }`}>
              <div className={`h-2.5 w-2.5 rounded-full transition-all ${
                !connected
                  ? "bg-border"
                  : isCapturing
                  ? "bg-emerald-400 animate-pulse shadow-[0_0_12px_rgba(16,185,129,0.9)] ring-2 ring-emerald-500/50"
                  : "bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.7)]"
              }`} />
              <span className="font-bold tracking-wide whitespace-nowrap">
                {connected ? (isCapturing ? "LIVE CAPTURING ACTIVE" : "CAPTURE SERVER ONLINE") : "DISCONNECTED"}
              </span>
            </div>

            <button
              onClick={resetDashboardState}
              title="Reset dashboard metrics and start fresh"
              className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-surface-2 hover:bg-border border border-border text-text text-xs transition-all font-semibold cursor-pointer whitespace-nowrap"
            >
              <RefreshCw className="h-3.5 w-3.5 text-gold" />
              <span>Clear / Reset</span>
            </button>

            {!isCapturing ? (
              <button
                onClick={startCapture}
                disabled={!selectedIface || !connected}
                className="flex items-center gap-2 px-5 py-2 rounded-lg bg-gold hover:bg-gold-hi text-bg text-[11px] font-bold uppercase tracking-wider transition-all disabled:opacity-40 disabled:cursor-not-allowed cursor-pointer shadow-sm whitespace-nowrap"
              >
                <Play className="h-3.5 w-3.5 fill-current" />
                <span>Start Capture</span>
              </button>
            ) : (
              <button
                onClick={stopCapture}
                className="flex items-center gap-2 px-5 py-2 rounded-lg bg-gold hover:bg-gold-hi text-bg text-[11px] font-bold uppercase tracking-wider transition-all cursor-pointer shadow-sm whitespace-nowrap"
              >
                <Square className="h-3.5 w-3.5 fill-current" />
                <span>Stop Capture</span>
              </button>
            )}
          </div>
        </div>
      </section>

      {/* Stats Row — 3 Equal Cards Full Width */}
      <section className="grid grid-cols-1 md:grid-cols-3 gap-4 w-full">
        {[
          { label: "TOTAL PACKETS", value: totalPkts.toLocaleString() },
          { label: "TOTAL DATA", value: formatBytes(totalBytes) },
          { label: "UNIQUE FLOWS", value: Object.keys(flows).length.toLocaleString() },
        ].map((s, i) => (
          <div
            key={i}
            className="bg-surface rounded-xl border border-border px-5 py-3 flex items-center justify-between shadow-sm hover:border-border/80 transition-all w-full"
          >
            <div className="flex-1 min-w-0">
              <p className="text-[11px] font-bold uppercase tracking-wider text-text-muted mb-0.5 truncate">
                {s.label}
              </p>
              <p className="text-xl md:text-2xl font-black text-white leading-none tracking-tight truncate">
                {s.value}
              </p>
            </div>
          </div>
        ))}
      </section>

      {/* Charts Row: BPS + Protocol */}
      <section id="live-network-traffic" className="grid grid-cols-1 lg:grid-cols-3 gap-5 scroll-mt-6">
        <div className="lg:col-span-2 bg-surface rounded-xl border border-border p-4">
          <div className="flex items-center gap-2 mb-3">
            <h3 className="text-sm font-bold uppercase tracking-wider text-white">Live Network Traffic</h3>
            {isCapturing && <span className="text-xs text-gold font-bold ml-auto">LIVE</span>}
          </div>
          <div className="h-[260px]">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={bpsHistory} margin={{ top: 5, right: 10, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="liveTrafficGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#3E63C7" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#3E63C7" stopOpacity={0.0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#262E3A" />
                <XAxis dataKey="time" tick={{ fontSize: 10, fill: "#9BA6B4" }} interval={4} />
                <YAxis tick={{ fontSize: 10, fill: "#9BA6B4" }} tickFormatter={formatBps} />
                <Tooltip
                  contentStyle={{ backgroundColor: "#1B2430", border: "1px solid #262E3A", borderRadius: 8, fontSize: 12, color: "#F3F1EA" }}
                  formatter={(val) => [formatBps(val), "Bandwidth"]}
                />
                <Area
                  type="monotone"
                  dataKey="bps"
                  stroke="#3E63C7"
                  strokeWidth={2.5}
                  fillOpacity={1}
                  fill="url(#liveTrafficGrad)"
                  isAnimationActive={true}
                  animationDuration={850}
                  animationEasing="linear"
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="bg-surface rounded-xl border border-border p-4">
          <div className="flex items-center gap-2 mb-3">
            <h3 className="text-sm font-bold uppercase tracking-wider text-white">Protocol Split</h3>
          </div>
          <div className="h-[260px]">
            {protoDist.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={protoDist} margin={{ top: 5, right: 10, left: -20, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#262E3A" />
                  <XAxis dataKey="name" tick={{ fontSize: 11, fill: "#9BA6B4" }} />
                  <YAxis tick={{ fontSize: 10, fill: "#9BA6B4" }} />
                  <Tooltip contentStyle={{ backgroundColor: "#1B2430", border: "1px solid #262E3A", borderRadius: 8, fontSize: 12, color: "#F3F1EA" }} />
                  <Bar dataKey="count" radius={[4, 4, 0, 0]} fill="#3E63C7" name="Packets" isAnimationActive={true} animationDuration={300} />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="flex items-center justify-center h-full text-text-muted text-xs">
                Start capture to see protocol distribution
              </div>
            )}
          </div>
        </div>
      </section>

      {/* Topology + Alerts side-by-side — Symmetrical 2x2 Grid with Top Row */}
      <section id="live-network-topology" className="grid grid-cols-1 lg:grid-cols-3 gap-5 scroll-mt-6">
        {/* Live Network Topology (2/3 width — matches Live Network Traffic) */}
        <div className="lg:col-span-2 bg-surface rounded-xl border border-border p-4">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2">
              <h3 className="text-sm font-bold uppercase tracking-wider text-white">Live Network Topology</h3>
              <span className="text-xs text-text-muted bg-surface-2 px-2 py-0.5 rounded border border-border font-medium">
                {topoNodeList.length} nodes · {topoLinks.length} links
              </span>
            </div>
          </div>
          <div className="relative bg-surface rounded-lg overflow-hidden border border-border h-[260px]">
            {topoNodeList.length === 0 ? (
              <div className="flex flex-col items-center justify-center h-full text-text-muted gap-2">
                <span className="text-xs">Start a capture to see topology</span>
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

        {/* Attack Alerts Card (1/3 width — matches Protocol Split) */}
        <div className="lg:col-span-1 bg-surface rounded-xl border border-border p-4 flex flex-col justify-between">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2">
              <h3 className="text-sm font-bold uppercase tracking-wider text-white">Attack Alerts</h3>
            </div>
            {consolidatedAlerts.length > 0 && (
              <span className="text-xs text-bg bg-gold px-2 py-0.5 rounded font-bold">
                {consolidatedAlerts.length} {consolidatedAlerts.length === 1 ? "threat" : "threats"}
              </span>
            )}
          </div>
          {consolidatedAlerts.length === 0 ? (
            <div className="flex-1 flex flex-col items-center justify-center text-text-muted gap-2 h-[260px]">
              <CheckCircle2 className="h-6 w-6 text-gold opacity-80" />
              <span className="text-xs">No attacks detected — all clear</span>
            </div>
          ) : (
            <div className="space-y-2 h-[260px] max-h-[260px] overflow-y-auto pr-1">
              {consolidatedAlerts.map((alert) => {
                const aKey = alert.key;
                const flow = alert.latestFlow;
                return (
                  <div
                    key={aKey}
                    onClick={() => onFlowClick && onFlowClick(flow)}
                    className="w-full text-left p-3 rounded-lg border border-gold/30 bg-surface-2 text-text transition-all cursor-pointer hover:border-gold"
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2 min-w-0">
                        <span className="px-1.5 py-0.5 rounded text-xs font-bold uppercase bg-gold text-bg shrink-0">
                          {alert.severity?.toUpperCase()?.slice(0, 4)}
                        </span>
                        <div className="text-xs min-w-0">
                          <span className="text-white font-bold">{alert.src_ip}</span>
                          <span className="text-text-muted mx-1">→</span>
                          <span className="text-white font-bold">{alert.dst_ip}</span>
                        </div>
                      </div>
                      <div className="flex items-center gap-2 shrink-0 ml-2">
                        <span className="text-xs text-gold font-semibold">{alert.displayType}</span>
                        <span className="px-2 py-0.5 rounded bg-gold/20 text-gold text-xs font-semibold flex items-center gap-1 border border-gold/30">
                          <span>Forecast</span>
                        </span>
                      </div>
                    </div>

                    <div className="flex items-center justify-between mt-2 pt-1.5 border-t border-border text-xs text-text-muted">
                      <div className="flex items-center gap-1.5">
                        <span className="inline-block w-1.5 h-1.5 rounded-full bg-gold"></span>
                        <span>Ongoing · <strong className="text-white">{alert.count}</strong> {alert.count === 1 ? "event" : "events"}</span>
                      </div>
                      {alert.last_seen && (
                        <span className="text-xs text-text-muted opacity-80">{new Date(alert.last_seen).toLocaleTimeString()}</span>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </section>

      {/* Filter + Attack toggle + Export CSV */}
      <section className="flex items-center gap-3">
        <div className="flex items-center gap-2 bg-surface border border-border rounded-lg px-3 py-2 flex-1 max-w-md">
          <Search className="h-4 w-4 text-gold" />
          <input
            type="text"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            placeholder="Filter by IP, protocol, attack type..."
            className="bg-transparent text-sm text-text placeholder:text-text-muted outline-none flex-1 font-medium"
          />
        </div>
        <button
          onClick={() => setShowAttackOnly(!showAttackOnly)}
          className={`flex items-center gap-1.5 px-3.5 py-2 rounded-lg border text-xs font-bold uppercase transition-all cursor-pointer ${
            showAttackOnly
              ? "bg-gold text-bg border-gold"
              : "bg-surface-2 border-border text-text hover:bg-surface"
          }`}
        >
          <span>Attacks Only</span>
        </button>

        {/* Download CSV Button */}
        <button
          onClick={() => window.open(`${CAPTURE_API}/api/capture/download?format=csv${knownClean ? "&known_clean=1" : ""}`, "_blank")}
          className="flex items-center gap-2 px-5 py-2.5 rounded-lg bg-blue hover:bg-blue-hi border border-border/80 text-white text-xs font-extrabold uppercase tracking-wider transition-all duration-200 shadow-md hover:scale-[1.03] hover:shadow-lg cursor-pointer whitespace-nowrap shrink-0"
          title="Download flow feature dataset captured during the telemetry session as a .csv file"
        >
          <Download className="h-4 w-4 text-white" />
          <span>Download CSV</span>
        </button>
      </section>

      {/* Flow Table */}
      <section id="captured-flows" className="bg-surface rounded-xl border border-border overflow-hidden scroll-mt-6">
        <div className="p-4 border-b border-border flex items-center justify-between">
          <div className="flex items-center gap-2">
            <h3 className="text-sm font-bold uppercase tracking-wider text-white">Captured Flows</h3>
            <span className="text-xs text-text-muted bg-surface-2 px-2 py-0.5 rounded border border-border font-medium">
              {flowList.length} flows
            </span>
          </div>
          {isCapturing && (
            <span className="text-xs text-gold font-bold flex items-center gap-1">
              Streaming
            </span>
          )}
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-border text-text-muted uppercase tracking-wider bg-surface-2">
                <th className="px-4 py-2.5 font-bold">Source IP</th>
                <th className="font-bold">Src Port</th>
                <th className="font-bold">Destination IP</th>
                <th className="font-bold">Dst Port</th>
                <th className="font-bold">Proto</th>
                <th className="font-bold">Packets</th>
                <th className="font-bold">Bytes</th>
                <th className="font-bold">Attack</th>
                <th className="font-bold">Severity</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {!isCapturing && flowList.length === 0 ? (
                <tr>
                  <td colSpan="9" className="py-16 text-center text-text-muted">
                    <Radio className="h-8 w-8 mx-auto mb-2 text-gold opacity-80" />
                    <p className="text-sm font-bold text-text">Select an interface and click Start Capture to begin</p>
                  </td>
                </tr>
              ) : flowList.length === 0 ? (
                <tr>
                  <td colSpan="9" className="py-16 text-center text-text-muted">
                    <p className="text-sm font-bold text-text">Capturing... waiting for packets</p>
                  </td>
                </tr>
              ) : (
                flowList.map((flow, idx) => {
                  const fKey = `${flow.src_ip}:${flow.src_port}-${flow.dst_ip}:${flow.dst_port}-${flow.protocol}`;
                  const isAttack = flow.severity && flow.severity !== "none";
                  return (
                    <tr
                      key={idx}
                      onClick={() => isAttack && onFlowClick && onFlowClick(flow)}
                      className={`transition-colors ${
                        isAttack
                          ? "bg-surface-2 border-l-2 border-l-gold text-gold font-bold hover:bg-blue/30 cursor-pointer"
                          : "hover:bg-surface-2 text-text"
                      }`}
                    >
                      <td className={`px-4 py-2 font-bold ${isAttack ? "text-gold" : "text-text"}`}>{flow.src_ip}</td>
                      <td className={isAttack ? "text-gold" : "text-text-muted"}>{flow.src_port}</td>
                      <td className={`font-bold ${isAttack ? "text-gold" : "text-white"}`}>{flow.dst_ip}</td>
                      <td className={isAttack ? "text-gold" : "text-text-muted"}>{flow.dst_port}</td>
                      <td>
                        <span className={`px-1.5 py-0.5 rounded text-xs font-bold ${
                          isAttack ? "bg-gold text-bg" : "bg-surface-2 text-text-muted border border-border"
                        }`}>{flow.protocol}</span>
                      </td>
                      <td className={isAttack ? "text-gold font-bold" : "text-text-muted"}>{flow.packet_count}</td>
                      <td className={isAttack ? "text-gold font-bold" : "text-text-muted"}>{formatBytes(flow.byte_count)}</td>
                      <td className={isAttack ? "text-gold font-bold uppercase" : "text-text-muted"}>
                        <span>{flow.attack_type && flow.attack_type !== 'Benign' ? flow.attack_type : (flow.ml_label && flow.ml_label !== 'benign' ? flow.ml_label.replace(/_/g, ' ') : '—')}</span>
                      </td>
                      <td>
                        <span className={`px-1.5 py-0.5 rounded text-xs font-bold uppercase ${
                          isAttack ? "bg-gold text-bg" : "text-text-muted"
                        }`}>
                          {flow.severity === "none" ? "—" : flow.severity?.toUpperCase()}
                        </span>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
