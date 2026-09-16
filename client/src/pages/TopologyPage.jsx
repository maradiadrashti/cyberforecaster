import React, { useEffect, useRef, useMemo, useState, useCallback } from "react";
import {
  Network, Radio, RefreshCw, ZoomIn, ZoomOut, Play, Pause,
  Search, ShieldAlert, Activity, CheckCircle2, X, Eye, ChevronRight, Grid, Monitor
} from "lucide-react";

// ── Vibrant Cyber Color System ───────────────────────────────────────────────
const SEV_COLOR = {
  risk: "#ff0055",       // Electric Crimson / Critical
  anomaly: "#ffaa00",    // Cyber Amber / Anomaly
  elevated: "#f97316",   // Vibrant Orange / Elevated
  clean: "#00f0ff",      // Electric Cyan / Clean Monitored
  peer: "#a855f7",       // Amethyst Violet / External Peer
};

const SEV_GLOW = {
  risk: "rgba(255, 0, 85, 0.5)",
  anomaly: "rgba(255, 170, 0, 0.5)",
  elevated: "rgba(249, 115, 22, 0.45)",
  clean: "rgba(0, 240, 255, 0.4)",
  peer: "rgba(168, 85, 247, 0.35)",
};

const EDGE_MAL = "#ff0055";
const EDGE_NORM = "#1e293b";

function nodeSeverity(n) {
  if (!n) return "peer";
  if (!n.monitored) return "peer";
  if ((n.risk ?? 0) >= 0.5) return "risk";
  if (n.flag_reason === "anomaly" || n.anomaly) return "anomaly";
  if ((n.risk ?? 0) >= 0.25) return "elevated";
  return "clean";
}

// ── 3D Force Layout ──────────────────────────────────────────────────────────
function layoutGraph3D(data, prevPositions) {
  const nodes = data.nodes, edges = data.edges;
  if (!nodes || nodes.length === 0) return { P: [], E: [], nodes: [], posMap: {} };

  const idx = new Map(nodes.map((n, i) => [n.id, i]));
  const E = edges
    .map((e) => ({ s: idx.get(e.source), t: idx.get(e.target), m: e.malicious, flows: e.flows || 1, source: e.source, target: e.target }))
    .filter((e) => e.s != null && e.t != null);

  const P = nodes.map((n, i) => {
    if (prevPositions && prevPositions[n.id]) {
      const p = prevPositions[n.id];
      return { x: p.x, y: p.y, z: p.z, vx: 0, vy: 0, vz: 0, id: n.id };
    }
    const sev = nodeSeverity(n);
    const flagged = sev === "risk" || sev === "anomaly";
    const r = flagged ? 85 : 340;
    const phi = Math.acos(1 - (2 * (i + 0.5)) / nodes.length);
    const th = Math.PI * (1 + Math.sqrt(5)) * i;
    return {
      x: r * Math.sin(phi) * Math.cos(th),
      y: r * Math.sin(phi) * Math.sin(th),
      z: r * Math.cos(phi),
      vx: 0, vy: 0, vz: 0,
      id: n.id
    };
  });

  // Force simulation steps for spacious, larger 3D layout
  for (let step = 0; step < 40; step++) {
    for (let i = 0; i < P.length; i++) {
      for (let j = i + 1; j < P.length; j++) {
        const dx = P[j].x - P[i].x, dy = P[j].y - P[i].y, dz = P[j].z - P[i].z;
        const d2 = dx * dx + dy * dy + dz * dz + 0.01;
        const d = Math.sqrt(d2), rep = 24000 / d2;
        P[i].vx -= (dx / d) * rep; P[i].vy -= (dy / d) * rep; P[i].vz -= (dz / d) * rep;
        P[j].vx += (dx / d) * rep; P[j].vy += (dy / d) * rep; P[j].vz += (dz / d) * rep;
      }
    }
    E.forEach((e) => {
      const a = P[e.s], b = P[e.t];
      const dx = b.x - a.x, dy = b.y - a.y, dz = b.z - a.z;
      const d = Math.sqrt(dx * dx + dy * dy + dz * dz) + 0.01;
      const f = (d - 190) * 0.012;
      a.vx += (dx / d) * f; a.vy += (dy / d) * f; a.vz += (dz / d) * f;
      b.vx -= (dx / d) * f; b.vy -= (dy / d) * f; b.vz -= (dz / d) * f;
    });
    P.forEach((p) => {
      p.vx += -p.x * 0.001; p.vy += -p.y * 0.001; p.vz += -p.z * 0.001;
      p.vx *= 0.84; p.vy *= 0.84; p.vz *= 0.84;
      p.x += p.vx; p.y += p.vy; p.z += p.vz;
    });
  }

  const posMap = {};
  nodes.forEach((n, i) => { posMap[n.id] = { x: P[i].x, y: P[i].y, z: P[i].z }; });
  return { P, E, nodes, posMap };
}

function graphNeighbours(E, nodeIndex) {
  const peers = new Map();
  if (!E || nodeIndex == null) return peers;
  E.forEach((e) => {
    if (e.s === nodeIndex) peers.set(e.t, e);
    else if (e.t === nodeIndex) peers.set(e.s, e);
  });
  return peers;
}

// Generate static ambient background stars
function generateStarfield(count = 90) {
  const stars = [];
  for (let i = 0; i < count; i++) {
    stars.push({
      x: (Math.random() - 0.5) * 1400,
      y: (Math.random() - 0.5) * 1400,
      z: (Math.random() - 0.5) * 1400,
      size: Math.random() * 1.5 + 0.5,
      alpha: Math.random() * 0.35 + 0.1
    });
  }
  return stars;
}

// ── Main Component ──────────────────────────────────────────────────────────
export default function TopologyPage({ flows = {}, isCapturing = false, offlineAnalysisResult = null, selectedInterfaceInfo = null }) {
  const canvasRef = useRef(null);
  const animRef = useRef(null);
  const stateRef = useRef(null);
  const prevPosRef = useRef(null);
  const prevEdgeSetRef = useRef(null);
  const mouseRef = useRef({ x: 0, y: 0 });
  const starfieldRef = useRef(generateStarfield(90));

  // Selection & UI Filters
  const [selectedNodeId, setSelectedNodeId] = useState(null);
  const [searchFilter, setSearchFilter] = useState("");
  const [autoRotate, setAutoRotate] = useState(true);
  const [showGrid, setShowGrid] = useState(true);
  const [hoveredNodeId, setHoveredNodeId] = useState(null);

  // Sync state to refs for animation loop
  const autoRotateRef = useRef(autoRotate);
  useEffect(() => {
    autoRotateRef.current = autoRotate;
    if (stateRef.current) {
      stateRef.current.spin = autoRotate;
    }
  }, [autoRotate]);

  const showGridRef = useRef(showGrid);
  useEffect(() => {
    showGridRef.current = showGrid;
  }, [showGrid]);

  // Build 3D graph data from flows or offline analysis
  const graphData = useMemo(() => {
    let flowList = Object.values(flows);
    if (flowList.length === 0 && offlineAnalysisResult) {
      if (offlineAnalysisResult.threat_flows) {
        flowList = offlineAnalysisResult.threat_flows;
      } else if (offlineAnalysisResult.flows) {
        flowList = offlineAnalysisResult.flows;
      }
    }

    if (!flowList || flowList.length === 0) return { nodes: [], edges: [] };

    const nodeMap = {}, edgeMap = {};
    for (const f of flowList) {
      const src = f.src_ip || f.source_ip;
      const dst = f.dst_ip || f.destination_ip;
      if (!src || !dst) continue;

      const severity = (f.severity || f.stage || "none").toLowerCase();
      const risk =
        severity === "critical" ? 0.95 :
        severity === "high" ? 0.70 :
        severity === "medium" ? 0.45 :
        severity === "low" ? 0.20 : 0.02;

      const isAnomaly = (f.ml_label === "port_scan" || f.ml_label === "brute_force" || f.attack_type === "Port Scan") && risk < 0.5;

      if (!nodeMap[src]) {
        nodeMap[src] = {
          id: src, flows: 0, risk: 0, anomaly: false, monitored: true, isLocalSystem: false,
          stage: severity !== "none" ? severity.toUpperCase() : "BENIGN", flag_reason: ""
        };
      }
      nodeMap[src].flows += (f.packet_count || f.packets || 1);
      if (risk > nodeMap[src].risk) nodeMap[src].risk = risk;
      if (isAnomaly) { nodeMap[src].anomaly = true; nodeMap[src].flag_reason = "anomaly"; }

      if (!nodeMap[dst]) {
        nodeMap[dst] = {
          id: dst, flows: 0, risk: 0, anomaly: false, monitored: true, isLocalSystem: false,
          stage: severity !== "none" ? severity.toUpperCase() : "BENIGN", flag_reason: ""
        };
      }
      nodeMap[dst].flows += (f.packet_count || f.packets || 1);
      if (risk > nodeMap[dst].risk) nodeMap[dst].risk = risk;

      const key = `${src}>${dst}`;
      if (!edgeMap[key]) {
        edgeMap[key] = { source: src, target: dst, flows: 0, malicious: severity !== "none" ? 1 : 0 };
      }
      edgeMap[key].flows += (f.packet_count || f.packets || 1);
      if (severity !== "none") edgeMap[key].malicious = 1;
    }

    // Auto-detect and mark Current System / Local Host
    const localCandidateIp = selectedInterfaceInfo?.ip;
    let localFound = false;

    if (localCandidateIp && nodeMap[localCandidateIp]) {
      nodeMap[localCandidateIp].isLocalSystem = true;
      localFound = true;
    }

    if (!localFound) {
      const keys = Object.keys(nodeMap);
      const internalIp = keys.find(ip =>
        ip === "127.0.0.1" || ip === "localhost" ||
        ip.startsWith("10.") || ip.startsWith("192.168.") || ip.startsWith("172.")
      ) || keys[0];

      if (internalIp && nodeMap[internalIp]) {
        nodeMap[internalIp].isLocalSystem = true;
      }
    }

    const sorted = Object.values(nodeMap).sort((a, b) => b.risk - a.risk || b.flows - a.flows);
    const keep = new Set(sorted.slice(0, 75).map((n) => n.id));
    const allEdges = Object.values(edgeMap).filter((e) => keep.has(e.source) && keep.has(e.target));
    prevEdgeSetRef.current = new Set(allEdges.map((e) => `${e.source}>${e.target}`));

    return { nodes: sorted.filter((n) => keep.has(n.id)), edges: allEdges };
  }, [flows, offlineAnalysisResult, selectedInterfaceInfo]);

  const hasData = graphData.nodes.length > 0;
  const totalNodes = graphData.nodes.length;
  const totalEdges = graphData.edges.length;
  const malEdges = graphData.edges.filter((e) => e.malicious).length;

  // Crash-proof selected node info computation
  const selectedInfo = useMemo(() => {
    if (!selectedNodeId || !stateRef.current) return null;
    try {
      const s = stateRef.current;
      if (!s.nodes || s.nodes.length === 0) return null;

      const n = s.nodes.find((item) => item.id === selectedNodeId);
      if (!n) return null;

      const nodeIndex = s.nodes.findIndex((item) => item.id === selectedNodeId);
      if (nodeIndex === -1) return null;

      const nearMap = graphNeighbours(s.E, nodeIndex);
      const peers = [];
      nearMap.forEach((edge, peerIdx) => {
        const peerNode = s.nodes[peerIdx];
        if (peerNode && edge) {
          peers.push({ node: peerNode, edge });
        }
      });
      peers.sort((a, b) => (b.edge.m - a.edge.m) || (b.node.flows - a.node.flows));

      const mal = peers.filter((x) => x.edge.m).length;
      return { node: n, peers, mal };
    } catch (err) {
      console.warn("Topology selection error handled safely:", err);
      return null;
    }
  }, [selectedNodeId, graphData]);

  // Reset camera perspective (Bigger Default Zoom: 2.1)
  const handleResetView = useCallback(() => {
    if (stateRef.current) {
      stateRef.current.zoom = 2.1;
      stateRef.current.ax = -0.3;
      stateRef.current.ay = -0.4;
      stateRef.current.spin = true;
      stateRef.current.inertia = { vx: 0, vy: 0 };
      setAutoRotate(true);
    }
  }, []);

  const handleZoomIn = useCallback(() => {
    if (stateRef.current) {
      stateRef.current.zoom = Math.min(6, stateRef.current.zoom * 1.25);
    }
  }, []);

  const handleZoomOut = useCallback(() => {
    if (stateRef.current) {
      stateRef.current.zoom = Math.max(0.4, stateRef.current.zoom * 0.8);
    }
  }, []);

  // ── Canvas Render Loop & True 3D Model Orbit Controls ─────────────────────
  useEffect(() => {
    const cv = canvasRef.current;
    if (!cv) return;

    const FOCAL = 640;
    const dpr = window.devicePixelRatio || 1;

    if (animRef.current) { cancelAnimationFrame(animRef.current); animRef.current = null; }

    if (!hasData) {
      const w = cv.clientWidth, h = cv.clientHeight;
      if (w < 10) return;
      cv.width = w * dpr; cv.height = h * dpr;
      const g = cv.getContext("2d");
      g.setTransform(dpr, 0, 0, dpr, 0, 0);
      g.clearRect(0, 0, w, h);
      g.fillStyle = "#040715"; g.fillRect(0, 0, w, h);
      prevPosRef.current = null;
      return;
    }

    const laid = layoutGraph3D(graphData, prevPosRef.current);
    prevPosRef.current = laid.posMap;

    const state = (stateRef.current = {
      P: laid.P, E: laid.E, nodes: laid.nodes,
      zoom: stateRef.current?.zoom || 2.1, // Bigger default scale
      ax: stateRef.current?.ax || -0.3,
      ay: stateRef.current?.ay || -0.4,
      spin: autoRotateRef.current,
      selectedNodeId: selectedNodeId,
      proj: [], drag: null,
      inertia: { vx: 0, vy: 0 },
      _nodeAppearTime: stateRef.current?._nodeAppearTime || {},
    });

    const pos = (ev) => {
      const r = cv.getBoundingClientRect();
      return { x: ev.clientX - r.left, y: ev.clientY - r.top };
    };

    // ── Touchpad & Wheel 3D Orbit Interaction Handler ──
    const onWheel = (ev) => {
      ev.preventDefault();
      if (ev.ctrlKey || ev.shiftKey) {
        state.zoom = Math.min(6, Math.max(0.4, state.zoom * (ev.deltaY < 0 ? 1.08 : 0.92)));
      } else {
        const absX = Math.abs(ev.deltaX);
        const absY = Math.abs(ev.deltaY);

        if (absX > 2 || absY > 2) {
          state.spin = false;
          setAutoRotate(false);
          state.ay += ev.deltaX * 0.006;
          state.ax += ev.deltaY * 0.006;
        } else {
          state.zoom = Math.min(6, Math.max(0.4, state.zoom * (ev.deltaY < 0 ? 1.08 : 0.92)));
        }
      }
    };

    // ── Pointer / Mouse 3D Sphere Orbit Drag Handlers ──
    const onPointerDown = (ev) => {
      cv.setPointerCapture(ev.pointerId);
      const q = pos(ev);
      state.drag = {
        x: q.x, y: q.y,
        ax: state.ax, ay: state.ay,
        moved: 0,
        lastX: q.x, lastY: q.y,
        vx: 0, vy: 0
      };
      state.spin = false;
      setAutoRotate(false);
      state.inertia = { vx: 0, vy: 0 };
      cv.style.cursor = "grabbing";
    };

    const onPointerMove = (ev) => {
      const q = pos(ev);
      mouseRef.current = q;

      if (!state.drag) {
        let foundHover = null;
        for (const pt of state.proj) {
          if (Math.hypot(pt.sx - q.x, pt.sy - q.y) < pt.r + 4) {
            foundHover = pt.nodeId;
            break;
          }
        }
        cv.style.cursor = foundHover ? "pointer" : "grab";
        setHoveredNodeId(foundHover);
        return;
      }

      const dx = q.x - state.drag.x;
      const dy = q.y - state.drag.y;
      state.drag.moved = Math.max(state.drag.moved, Math.hypot(dx, dy));

      state.drag.vx = q.x - state.drag.lastX;
      state.drag.vy = q.y - state.drag.lastY;
      state.drag.lastX = q.x;
      state.drag.lastY = q.y;

      state.ay = state.drag.ay + dx * 0.007;
      state.ax = state.drag.ax + dy * 0.007;
    };

    const onPointerUp = (ev) => {
      const wasDrag = state.drag && state.drag.moved > 5;

      if (state.drag) {
        state.inertia = {
          vx: state.drag.vx * 0.005,
          vy: state.drag.vy * 0.005
        };
      }
      state.drag = null;
      cv.style.cursor = "grab";

      if (wasDrag) return;

      try {
        const q = pos(ev);
        let bestId = null;
        let bestD = 24;

        state.proj.forEach((pt) => {
          const d = Math.hypot(pt.sx - q.x, pt.sy - q.y);
          if (d < bestD) {
            bestD = d;
            bestId = pt.nodeId;
          }
        });

        const newSelId = (bestId && bestId === state.selectedNodeId) ? null : bestId;
        state.selectedNodeId = newSelId;
        setSelectedNodeId(newSelId);
      } catch (err) {
        console.warn("Topology click handled safely:", err);
      }
    };

    const onDblClick = () => {
      handleResetView();
      setSelectedNodeId(null);
    };

    cv.addEventListener("wheel", onWheel, { passive: false });
    cv.addEventListener("pointerdown", onPointerDown);
    cv.addEventListener("pointermove", onPointerMove);
    cv.addEventListener("pointerup", onPointerUp);
    cv.addEventListener("dblclick", onDblClick);
    cv.style.cursor = "grab";

    // ── 3D Model Render Loop ──────────────────────────────────────────────────
    function frame() {
      const w = cv.clientWidth, h = cv.clientHeight;
      if (w < 10) { animRef.current = requestAnimationFrame(frame); return; }

      cv.width = w * dpr;
      cv.height = h * dpr;
      const g = cv.getContext("2d");
      g.setTransform(dpr, 0, 0, dpr, 0, 0);

      // Apply Autorotation or Orbit Inertia Momentum
      if (state.spin) {
        state.ay += 0.0022;
      } else if (Math.abs(state.inertia.vx) > 0.0001 || Math.abs(state.inertia.vy) > 0.0001) {
        state.ay += state.inertia.vx;
        state.ax += state.inertia.vy;
        state.inertia.vx *= 0.94;
        state.inertia.vy *= 0.94;
      }

      const cy = Math.cos(state.ay), sy = Math.sin(state.ay);
      const cx = Math.cos(state.ax), sx = Math.sin(state.ax);

      // 3D Model Projection Function with Specular Lighting
      const project3D = (px, py, pz) => {
        let x1 = px * cy - pz * sy;
        let z1 = px * sy + pz * cy;

        let y2 = py * cx - z1 * sx;
        let z2 = py * sx + z1 * cx;

        const CAMERA_DIST = 460;
        const depth = CAMERA_DIST + z2;
        const scale = (FOCAL / Math.max(60, depth)) * state.zoom;

        const normLen = Math.hypot(x1, y2, z2) || 1;
        const dotLight = Math.max(0.15, (-x1 * 0.4 - y2 * 0.7 - z2 * 0.6) / normLen);

        return {
          sx: w / 2 + x1 * scale,
          sy: h / 2 + y2 * scale,
          s: scale,
          z: z2,
          light: dotLight
        };
      };

      // Project Nodes 3D -> 2D
      state.proj = state.P.map((p, i) => {
        const pt = project3D(p.x, p.y, p.z);
        const node = state.nodes[i];
        const baseR = node?.monitored ? 8.5 + Math.min(10, Math.log10((node.flows || 0) + 1) * 3.2) : 6.0;
        const r = baseR * Math.min(pt.s, 2.6);

        return {
          ...pt,
          i, r,
          nodeId: p.id,
          node
        };
      });

      const selId = state.selectedNodeId;
      const selIndex = selId ? state.nodes.findIndex(n => n.id === selId) : -1;
      const nearMap = selIndex !== -1 ? graphNeighbours(state.E, selIndex) : null;
      const isLit = (nodeIdx, nodeId) => selId == null || nodeId === selId || (nearMap && nearMap.has(nodeIdx));

      const filterQ = searchFilter.toLowerCase().trim();
      const matchesFilter = (nodeId) => !filterQ || nodeId.toLowerCase().includes(filterQ);

      // ── Render Static Background & Static 2D Cyber Grid ────────────────────
      g.clearRect(0, 0, w, h);
      g.fillStyle = "#040715";
      g.fillRect(0, 0, w, h);

      // Static 2D Cyber Checkerboard / Grid Overlay
      if (showGridRef.current) {
        const cellSize = 38;
        for (let y = 0; y < h; y += cellSize) {
          for (let x = 0; x < w; x += cellSize) {
            if ((Math.floor(x / cellSize) + Math.floor(y / cellSize)) % 2 === 0) {
              g.fillStyle = "rgba(0, 240, 255, 0.015)";
              g.fillRect(x, y, cellSize, cellSize);
            }
          }
        }

        g.strokeStyle = "rgba(0, 240, 255, 0.04)";
        g.lineWidth = 0.5;
        for (let x = 0; x < w; x += cellSize) {
          g.beginPath(); g.moveTo(x, 0); g.lineTo(x, h); g.stroke();
        }
        for (let y = 0; y < h; y += cellSize) {
          g.beginPath(); g.moveTo(0, y); g.lineTo(w, y); g.stroke();
        }
      }

      // Render Ambient Starfield Background
      g.fillStyle = "rgba(0, 240, 255, 0.3)";
      starfieldRef.current.forEach(st => {
        const pt = project3D(st.x, st.y, st.z);
        if (pt.sx >= 0 && pt.sx <= w && pt.sy >= 0 && pt.sy <= h && pt.s > 0.1) {
          g.beginPath();
          g.arc(pt.sx, pt.sy, st.size * Math.min(pt.s, 1.5), 0, 6.283);
          g.globalAlpha = st.alpha * Math.min(pt.s, 1.2);
          g.fill();
        }
      });
      g.globalAlpha = 1;

      // ── Render 3D Edges (Depth Sorted Back to Front) ──────────────────────
      state.E.map((e) => {
        const a = state.proj[e.s];
        const b = state.proj[e.t];
        const avgZ = a && b ? (a.z + b.z) / 2 : 0;
        return { e, a, b, z: avgZ };
      })
        .filter(item => item.a && item.b)
        .sort((a, b) => b.z - a.z)
        .forEach(({ e, a, b }) => {
          const depth = Math.min(a.s, b.s);
          const on = isLit(e.s, e.source) || isLit(e.t, e.target);
          const filterMatch = matchesFilter(e.source) || matchesFilter(e.target);

          g.beginPath();
          g.moveTo(a.sx, a.sy);
          g.lineTo(b.sx, b.sy);
          g.strokeStyle = e.m ? EDGE_MAL : "rgba(56, 189, 248, 0.65)";
          g.lineWidth = (e.m ? 3.5 : 2.2) * Math.min(depth, 2.5);
          g.globalAlpha = (e.m ? 0.95 : 0.75) * Math.min(depth, 1.5) * (on && filterMatch ? 1 : 0.08);
          g.stroke();

          // Malicious Edge Arrowheads
          if (e.m && on && filterMatch && depth > 0.5) {
            const dx = b.sx - a.sx, dy = b.sy - a.sy;
            const L = Math.hypot(dx, dy) || 1;
            const ux = dx / L, uy = dy / L;
            const tipX = b.sx - ux * 8, tipY = b.sy - uy * 8;
            const ah = 6.0 * Math.min(depth, 1.6);
            g.beginPath(); g.moveTo(tipX, tipY);
            g.lineTo(tipX - ux * ah + uy * ah * 0.55, tipY - uy * ah - ux * ah * 0.55);
            g.lineTo(tipX - ux * ah - uy * ah * 0.55, tipY - uy * ah + ux * ah * 0.55);
            g.closePath(); g.fillStyle = EDGE_MAL; g.globalAlpha = 0.95; g.fill();
          }
          g.globalAlpha = 1;
        });

      // ── Render 3D Model Nodes (Depth Sorted Back to Front) ────────────────
      state.proj.slice().sort((a, b) => b.z - a.z).forEach((pt) => {
        const n = pt.node;
        if (!n) return;

        const sev = nodeSeverity(n);
        const r = pt.r;
        const flagged = sev === "risk" || sev === "anomaly";
        const on = isLit(pt.i, pt.nodeId);
        const isSel = pt.nodeId === selId;
        const isHover = pt.nodeId === hoveredNodeId;
        const isFilterMatch = matchesFilter(pt.nodeId);

        g.globalAlpha = on && isFilterMatch ? 1 : 0.08;

        // Outer Corona Glow Aura
        if ((flagged || isSel || isHover) && on && isFilterMatch) {
          const glowR = r + (isSel ? 18 : isHover ? 14 : 10) * Math.min(pt.s, 2.0);
          const radGlow = g.createRadialGradient(pt.sx, pt.sy, r * 0.4, pt.sx, pt.sy, glowR);
          radGlow.addColorStop(0, SEV_GLOW[sev] || "rgba(0, 240, 255, 0.4)");
          radGlow.addColorStop(1, "rgba(0, 0, 0, 0)");

          g.beginPath();
          g.arc(pt.sx, pt.sy, glowR, 0, 6.283);
          g.fillStyle = radGlow;
          g.fill();
        }

        // 3D Sphere Model Shading
        const lightOffX = pt.sx - r * 0.35;
        const lightOffY = pt.sy - r * 0.35;
        const grad = g.createRadialGradient(
          lightOffX, lightOffY, r * 0.05,
          pt.sx, pt.sy, r
        );
        grad.addColorStop(0, "#ffffff");
        grad.addColorStop(0.35, SEV_COLOR[sev] || "#00f0ff");
        grad.addColorStop(1, "#040715");

        g.beginPath();
        g.arc(pt.sx, pt.sy, r, 0, 6.283);
        g.fillStyle = grad;
        g.fill();

        // Border Ring
        g.strokeStyle = isSel ? "#00f0ff" : isHover ? "#ffffff" : "#080b12";
        g.lineWidth = (isSel ? 3 : isHover ? 2 : 1.2) * Math.min(pt.s, 2);
        g.stroke();

        // Node ID Label
        if ((flagged || isSel || isHover || (filterQ && isFilterMatch)) && on && isFilterMatch && pt.s > 0.35) {
          const tag = n.id;
          const fs = Math.min(11 * pt.s, 14);
          g.font = "600 " + fs.toFixed(1) + "px 'Share Tech Mono', ui-monospace, monospace";
          g.textAlign = "center";
          g.textBaseline = "bottom";
          const tw = g.measureText(tag).width;
          const bgX = pt.sx - tw / 2 - 6, bgY = pt.sy - r - 12 - fs;

          g.fillStyle = "#080b15"; g.globalAlpha = 0.92;
          g.beginPath();
          g.roundRect(bgX, bgY, tw + 12, fs + 6, 4);
          g.fill();
          g.strokeStyle = isSel ? "#00f0ff" : SEV_COLOR[sev];
          g.lineWidth = 1;
          g.stroke();

          g.globalAlpha = 1;
          g.fillStyle = isSel ? "#00f0ff" : "#ffffff";
          g.fillText(tag, pt.sx, pt.sy - r - 9);
        }

        g.globalAlpha = 1;
      });

      animRef.current = requestAnimationFrame(frame);
    }

    animRef.current = requestAnimationFrame(frame);

    return () => {
      cancelAnimationFrame(animRef.current);
      animRef.current = null;
      cv.removeEventListener("wheel", onWheel);
      cv.removeEventListener("pointerdown", onPointerDown);
      cv.removeEventListener("pointermove", onPointerMove);
      cv.removeEventListener("pointerup", onPointerUp);
      cv.removeEventListener("dblclick", onDblClick);
    };
  }, [graphData, hasData, searchFilter, hoveredNodeId, handleResetView]);

  return (
    <div className="space-y-0 animate-fade-in relative overflow-hidden" style={{ margin: "-24px", minHeight: "calc(100vh - 52px)" }}>
      {/* Empty State */}
      {!hasData && (
        <div className="flex flex-col items-center justify-center gap-4 py-24">
          <div className="p-5 bg-purple-950/30 border border-purple-800/50 rounded-2xl shadow-xl backdrop-blur-md">
            <Network className="h-14 w-14 text-purple-400 animate-pulse" />
          </div>
          <div className="text-center max-w-md mx-auto">
            <h3 className="text-base font-bold font-mono-tech text-white uppercase tracking-wider">3D Network Topology Model</h3>
            <p className="text-xs text-slate-400 mt-2 leading-relaxed font-mono-tech">
              Start a live capture on <strong className="text-cyan-400">Live Telemetry</strong> or upload a file on <strong className="text-cyan-400">File Upload</strong> to render the interactive 3D network model.
            </p>
          </div>
          <div className="flex items-center gap-2 mt-2 text-[10px] font-mono-tech text-slate-500 bg-slate-900/80 px-3 py-1.5 rounded-full border border-slate-800">
            <Radio className="h-3.5 w-3.5 text-cyan-400" />
            <span>Waiting for network flow events...</span>
          </div>
        </div>
      )}

      {/* 3D Canvas Viewport */}
      {hasData && (
        <div className="relative w-full" style={{ height: "calc(100vh - 52px)", touchAction: "none" }}>
          <canvas
            ref={canvasRef}
            className="w-full h-full block"
            style={{ touchAction: "none" }}
          />

          {/* Top-Left Overlay: Stats & Severity Legend */}
          <div className="absolute top-4 left-4 z-10 space-y-2 pointer-events-auto">
            <div className="bg-[#040715]/90 border border-cyan-900/40 rounded-xl px-3.5 py-2.5 backdrop-blur-md shadow-2xl">
              <div className="flex items-center gap-2.5 mb-1.5">
                <Network className="h-4 w-4 text-cyan-400" />
                <span className="text-xs font-bold font-mono-tech text-white uppercase tracking-wider">3D Topology Model</span>
                {isCapturing && (
                  <span className="text-[9px] font-mono-tech text-emerald-400 bg-emerald-950/50 px-2 py-0.5 rounded border border-emerald-900/50 animate-pulse flex items-center gap-1">
                    <span className="inline-block w-1.5 h-1.5 rounded-full bg-emerald-400"></span>LIVE
                  </span>
                )}
              </div>
              <div className="text-[10px] font-mono-tech text-slate-400 flex items-center gap-2">
                <span><strong className="text-cyan-400">{totalNodes}</strong> hosts</span>
                <span>·</span>
                <span><strong className="text-slate-200">{totalEdges}</strong> edges</span>
                {malEdges > 0 && (
                  <>
                    <span>·</span>
                    <span className="text-rose-400 font-bold">{malEdges} malicious</span>
                  </>
                )}
              </div>
            </div>

            {/* Severity Colors Legend */}
            <div className="bg-[#040715]/90 border border-slate-800/60 rounded-xl px-3 py-2 backdrop-blur-md flex items-center gap-3 text-[9px] font-mono-tech">
              {[
                { label: "Critical", color: SEV_COLOR.risk },
                { label: "Anomaly", color: SEV_COLOR.anomaly },
                { label: "Elevated", color: SEV_COLOR.elevated },
                { label: "Clean", color: SEV_COLOR.clean },
                { label: "Peer", color: SEV_COLOR.peer },
              ].map((l) => (
                <div key={l.label} className="flex items-center gap-1.5">
                  <div className="w-2 h-2 rounded-full shadow-sm" style={{ backgroundColor: l.color, boxShadow: `0 0 6px ${l.color}` }} />
                  <span className="text-slate-400 font-medium">{l.label}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Top-Right Control Toolbar */}
          <div className="absolute top-4 right-4 z-10 flex items-center gap-2 pointer-events-auto">
            {/* Search Input */}
            <div className="flex items-center gap-2 bg-[#040715]/90 border border-slate-800 rounded-xl px-3 py-1.5 backdrop-blur-md">
              <Search className="h-3.5 w-3.5 text-slate-400" />
              <input
                type="text"
                value={searchFilter}
                onChange={(e) => setSearchFilter(e.target.value)}
                placeholder="Search IP address..."
                className="bg-transparent text-xs text-white placeholder:text-slate-600 outline-none w-36 font-mono-tech"
              />
              {searchFilter && (
                <button onClick={() => setSearchFilter("")} className="text-slate-500 hover:text-white text-xs">
                  <X className="h-3 w-3" />
                </button>
              )}
            </div>

            {/* Static Grid Overlay Toggle Button */}
            <button
              onClick={() => setShowGrid(!showGrid)}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-xl border text-[10px] font-mono-tech uppercase transition-all backdrop-blur-md shadow-lg ${
                showGrid
                  ? "bg-purple-950/50 border-purple-800/60 text-purple-300"
                  : "bg-slate-900/80 border-slate-800 text-slate-400 hover:text-white"
              }`}
              title="Toggle Static Background Grid"
            >
              <Grid className="h-3.5 w-3.5 text-purple-400" />
              <span>{showGrid ? "Grid On" : "Grid Off"}</span>
            </button>

            {/* Auto Rotate Toggle Button */}
            <button
              onClick={() => setAutoRotate(!autoRotate)}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-xl border text-[10px] font-mono-tech uppercase transition-all backdrop-blur-md shadow-lg ${
                autoRotate
                  ? "bg-cyan-950/50 border-cyan-800/60 text-cyan-400"
                  : "bg-slate-900/80 border-slate-800 text-slate-400 hover:text-white"
              }`}
              title="Toggle 3D Orbit Auto-Rotation"
            >
              {autoRotate ? <Pause className="h-3.5 w-3.5" /> : <Play className="h-3.5 w-3.5" />}
              <span>{autoRotate ? "Auto Spin On" : "Auto Spin Off"}</span>
            </button>

            {/* Reset View Button */}
            <button
              onClick={handleResetView}
              className="p-2 rounded-xl bg-slate-900/80 hover:bg-slate-800 border border-slate-800 text-slate-300 hover:text-white transition-all backdrop-blur-md"
              title="Reset 3D Model Perspective"
            >
              <RefreshCw className="h-3.5 w-3.5 text-cyan-400" />
            </button>

            {/* Zoom In/Out */}
            <div className="flex items-center bg-slate-900/80 border border-slate-800 rounded-xl overflow-hidden backdrop-blur-md">
              <button onClick={handleZoomIn} className="p-2 hover:bg-slate-800 text-slate-300 hover:text-white border-r border-slate-800" title="Zoom In">
                <ZoomIn className="h-3.5 w-3.5" />
              </button>
              <button onClick={handleZoomOut} className="p-2 hover:bg-slate-800 text-slate-300 hover:text-white" title="Zoom Out">
                <ZoomOut className="h-3.5 w-3.5" />
              </button>
            </div>
          </div>

          {/* Bottom Center Navigation Hint */}
          <div className="absolute bottom-4 left-1/2 -translate-x-1/2 z-10 pointer-events-none">
            <div className="bg-[#040715]/85 border border-slate-800/60 rounded-full px-4 py-1.5 backdrop-blur-md text-[10px] font-mono-tech text-slate-400 shadow-xl flex items-center gap-2">
              <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse"></span>
              <span>Drag touchpad / mouse in any direction to orbit 3D model · Scroll to zoom · Click node to inspect</span>
            </div>
          </div>

          {/* Bottom-Right Crash-Proof Node Details Panel */}
          {selectedInfo && selectedInfo.node && (
            <div className="absolute bottom-4 right-4 w-[350px] max-h-[48vh] bg-[#040715]/95 border border-cyan-800/60 rounded-2xl p-4 backdrop-blur-xl z-20 overflow-hidden flex flex-col shadow-2xl animate-fade-in pointer-events-auto">
              {/* Card Header */}
              <div className="flex items-center justify-between mb-3 shrink-0 pb-2 border-b border-slate-800/80">
                <div className="flex items-center gap-2 min-w-0">
                  <div className="p-1.5 rounded-lg bg-cyan-950/60 border border-cyan-800/50">
                    <Network className="h-4 w-4 text-cyan-400 shrink-0" />
                  </div>
                  <div className="min-w-0">
                    <h4 className="text-xs font-bold font-mono-tech text-white truncate">{selectedInfo.node.id}</h4>
                    <span className="text-[9px] font-mono-tech text-slate-500 uppercase">{selectedInfo.node.monitored ? "Monitored Host" : "External Peer"}</span>
                  </div>
                </div>

                <div className="flex items-center gap-2 shrink-0">
                  {(() => {
                    const sev = nodeSeverity(selectedInfo.node);
                    if (sev === "risk") return <span className="text-[9px] font-mono-tech font-bold px-2 py-0.5 rounded bg-rose-950/60 text-rose-400 border border-rose-900/60">CRITICAL</span>;
                    if (sev === "anomaly") return <span className="text-[9px] font-mono-tech font-bold px-2 py-0.5 rounded bg-amber-950/60 text-amber-400 border border-amber-900/60">ANOMALY</span>;
                    if (sev === "elevated") return <span className="text-[9px] font-mono-tech font-bold px-2 py-0.5 rounded bg-orange-950/60 text-orange-400 border border-orange-900/60">ELEVATED</span>;
                    return <span className="text-[9px] font-mono-tech font-bold px-2 py-0.5 rounded bg-cyan-950/60 text-cyan-400 border border-cyan-900/60">CLEAN</span>;
                  })()}

                  <button
                    onClick={() => setSelectedNodeId(null)}
                    className="p-1 text-slate-500 hover:text-white font-mono-tech rounded-lg hover:bg-slate-800 transition-colors"
                  >
                    <X className="h-4 w-4" />
                  </button>
                </div>
              </div>

              {/* Stats Bar */}
              <div className="grid grid-cols-2 gap-2 mb-3 text-[10px] font-mono-tech shrink-0">
                <div className="p-2 rounded-xl bg-slate-900/60 border border-slate-800">
                  <span className="text-slate-500 text-[8px] uppercase block">Total Flows</span>
                  <strong className="text-white text-xs">{Math.round(selectedInfo.node.flows || 0).toLocaleString()}</strong>
                </div>
                <div className="p-2 rounded-xl bg-slate-900/60 border border-slate-800">
                  <span className="text-slate-500 text-[8px] uppercase block">Connections</span>
                  <strong className="text-white text-xs">{selectedInfo.peers.length} peers</strong>
                  {selectedInfo.mal > 0 && <span className="text-rose-400 ml-1 text-[9px]">({selectedInfo.mal} mal)</span>}
                </div>
              </div>

              {/* Peer Connections Header */}
              <div className="text-[9px] font-mono-tech uppercase font-bold text-slate-400 mb-1.5 flex items-center justify-between shrink-0">
                <span>Active Network Peers</span>
                <span>Packets</span>
              </div>

              {/* Peer Connections List */}
              <div className="flex-1 overflow-y-auto space-y-1 pr-1">
                {selectedInfo.peers.map((p, i) => {
                  if (!p || !p.node) return null;
                  const isMalicious = p.edge && p.edge.m;
                  return (
                    <div
                      key={p.node.id || i}
                      className={`flex items-center justify-between px-2.5 py-1.5 rounded-lg text-[10px] font-mono-tech transition-all ${
                        isMalicious
                          ? "bg-rose-950/40 border border-rose-900/40 text-rose-300"
                          : "bg-slate-900/50 border border-slate-800/40 text-slate-300"
                      }`}
                    >
                      <div className="flex items-center gap-1.5 truncate">
                        <div className={`w-1.5 h-1.5 rounded-full ${isMalicious ? "bg-rose-500 animate-pulse" : "bg-cyan-400"}`} />
                        <span className="font-bold truncate">{p.node.id}</span>
                      </div>
                      <span className="text-slate-400 shrink-0 font-mono-tech">{(p.edge.flows || 0).toLocaleString()} pkts</span>
                    </div>
                  );
                })}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
