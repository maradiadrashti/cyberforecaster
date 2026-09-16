import React, { useEffect, useRef, useCallback, useState } from "react";
import { Network, X } from "lucide-react";

// Severity thresholds and colors
const RISK_THRESHOLD = 0.5;
const ELEVATED_THRESHOLD = 0.25;
const SEV_COLOR = {
  risk: "#ff0055",
  anomaly: "#ffaa00",
  elevated: "#f97316",
  clean: "#00f0ff",
  peer: "#a855f7",
};
const EDGE_COLOR_MAL = "#ff0055";
const EDGE_COLOR_NORMAL = "#1e293b";

function nodeSeverity(n) {
  if (!n) return "peer";
  if ((n.risk ?? 0) >= RISK_THRESHOLD) return "risk";
  if (n.anomaly) return "anomaly";
  if ((n.risk ?? 0) >= ELEVATED_THRESHOLD) return "elevated";
  return "clean";
}

// ── Pre-computed 3D Force Layout ────────────────────────────────────────────

function computeLayout3D(nodes, edges) {
  if (!nodes || nodes.length === 0) return { P: [], E: [], nodes: [] };

  const idx = new Map(nodes.map((n, i) => [n.id, i]));
  const E = edges
    .map((e) => ({
      s: idx.get(e.source),
      t: idx.get(e.target),
      m: e.malicious,
      flows: e.flows || 1,
      source: e.source,
      target: e.target
    }))
    .filter((e) => e.s != null && e.t != null);

  const P = nodes.map((n, i) => {
    const sev = nodeSeverity(n);
    const flagged = sev === "risk" || sev === "anomaly";
    const r = flagged ? 40 : 170;
    const phi = Math.acos(1 - (2 * (i + 0.5)) / nodes.length);
    const th = Math.PI * (1 + Math.sqrt(5)) * i;
    return {
      x: r * Math.sin(phi) * Math.cos(th),
      y: r * Math.sin(phi) * Math.sin(th),
      z: r * Math.cos(phi),
      vx: 0,
      vy: 0,
      vz: 0,
      id: n.id
    };
  });

  for (let step = 0; step < 120; step++) {
    for (let i = 0; i < P.length; i++) {
      for (let j = i + 1; j < P.length; j++) {
        const dx = P[j].x - P[i].x;
        const dy = P[j].y - P[i].y;
        const dz = P[j].z - P[i].z;
        const d2 = dx * dx + dy * dy + dz * dz + 0.01;
        const d = Math.sqrt(d2);
        const rep = 8500 / d2;
        P[i].vx -= (dx / d) * rep;
        P[i].vy -= (dy / d) * rep;
        P[i].vz -= (dz / d) * rep;
        P[j].vx += (dx / d) * rep;
        P[j].vy += (dy / d) * rep;
        P[j].vz += (dz / d) * rep;
      }
    }

    E.forEach((e) => {
      const a = P[e.s], b = P[e.t];
      const dx = b.x - a.x;
      const dy = b.y - a.y;
      const dz = b.z - a.z;
      const d = Math.sqrt(dx * dx + dy * dy + dz * dz) + 0.01;
      const f = (d - 90) * 0.012;
      a.vx += (dx / d) * f;
      a.vy += (dy / d) * f;
      a.vz += (dz / d) * f;
      b.vx -= (dx / d) * f;
      b.vy -= (dy / d) * f;
      b.vz -= (dz / d) * f;
    });

    P.forEach((p) => {
      p.vx += -p.x * 0.0018;
      p.vy += -p.y * 0.0018;
      p.vz += -p.z * 0.0018;
      p.vx *= 0.84;
      p.vy *= 0.84;
      p.vz *= 0.84;
      p.x += p.vx;
      p.y += p.vy;
      p.z += p.vz;
    });
  }

  return { P, E, nodes };
}

// ── Main Component ──────────────────────────────────────────────────────────

export default function SidebarTopology({ flows = {}, offlineAnalysisResult = null }) {
  const canvasRef = useRef(null);
  const stateRef = useRef(null);
  const animRef = useRef(null);
  const [selectedNodeId, setSelectedNodeId] = useState(null);

  // Convert flows data into graph nodes + edges
  const { graphNodes, graphEdges } = React.useMemo(() => {
    let flowList = Object.values(flows);
    if (flowList.length === 0 && offlineAnalysisResult) {
      if (offlineAnalysisResult.threat_flows) {
        flowList = offlineAnalysisResult.threat_flows;
      } else if (offlineAnalysisResult.flows) {
        flowList = offlineAnalysisResult.flows;
      }
    }

    if (!flowList || flowList.length === 0) return { graphNodes: [], graphEdges: [] };

    const nodeMap = {};
    const edgeMap = {};

    for (const f of flowList) {
      const src = f.src_ip || f.source_ip;
      const dst = f.dst_ip || f.destination_ip;
      if (!src || !dst) continue;

      const severity = (f.severity || f.stage || "none").toLowerCase();
      const risk =
        severity === "critical"
          ? 0.9
          : severity === "high"
          ? 0.65
          : severity === "medium"
          ? 0.4
          : severity === "low"
          ? 0.15
          : 0.02;
      const anomaly =
        (f.ml_label === "port_scan" || f.ml_label === "brute_force" || f.attack_type === "Port Scan") &&
        risk < RISK_THRESHOLD;

      if (!nodeMap[src]) {
        nodeMap[src] = {
          id: src,
          flows: 0,
          risk: 0,
          anomaly: false,
          stage: severity !== "none" ? severity.toUpperCase() : "BENIGN",
        };
      }
      nodeMap[src].flows += (f.packet_count || f.packets || 1);
      if (risk > nodeMap[src].risk) nodeMap[src].risk = risk;
      if (anomaly) nodeMap[src].anomaly = true;

      if (!nodeMap[dst]) {
        nodeMap[dst] = {
          id: dst,
          flows: 0,
          risk: 0,
          anomaly: false,
          stage: severity !== "none" ? severity.toUpperCase() : "BENIGN",
        };
      }
      nodeMap[dst].flows += (f.packet_count || f.packets || 1);
      if (risk > nodeMap[dst].risk) nodeMap[dst].risk = risk;

      const key = `${src}>${dst}`;
      if (!edgeMap[key]) {
        edgeMap[key] = {
          source: src,
          target: dst,
          flows: 0,
          malicious: severity !== "none" ? 1 : 0,
        };
      }
      edgeMap[key].flows += (f.packet_count || f.packets || 1);
      if (severity !== "none") edgeMap[key].malicious = 1;
    }

    const sorted = Object.values(nodeMap).sort((a, b) => b.risk - a.risk || b.flows - a.flows);
    const keep = new Set(sorted.slice(0, 35).map((n) => n.id));

    const nodes = sorted.filter((n) => keep.has(n.id));
    const edges = Object.values(edgeMap).filter(
      (e) => keep.has(e.source) && keep.has(e.target)
    );

    return { graphNodes: nodes, graphEdges: edges };
  }, [flows, offlineAnalysisResult]);

  // Compute 3D layout
  const layout = React.useMemo(
    () => computeLayout3D(graphNodes, graphEdges),
    [graphNodes, graphEdges]
  );

  // Crash-proof node selection data
  const selectedInfo = React.useMemo(() => {
    if (!selectedNodeId || !layout || !layout.nodes) return null;
    const n = layout.nodes.find(item => item.id === selectedNodeId);
    if (!n) return null;

    const nodeIdx = layout.nodes.findIndex(item => item.id === selectedNodeId);
    if (nodeIdx === -1) return null;

    const peersMap = new Map();
    layout.E.forEach((e) => {
      if (e.s === nodeIdx) peersMap.set(e.t, e);
      else if (e.t === nodeIdx) peersMap.set(e.s, e);
    });

    const peers = [];
    peersMap.forEach((e, peerIdx) => {
      const peerNode = layout.nodes[peerIdx];
      if (peerNode && e) {
        peers.push({ node: peerNode, edge: e });
      }
    });

    peers.sort((a, b) => (b.edge.m - a.edge.m) || (b.node.flows - a.node.flows));
    const mal = peers.filter((x) => x.edge.m).length;

    return {
      ip: n.id,
      severity: nodeSeverity(n),
      risk: n.risk,
      anomaly: n.anomaly,
      flows: n.flows,
      peerCount: peers.length,
      malCount: mal,
      peers: peers.slice(0, 20),
    };
  }, [selectedNodeId, layout]);

  // Canvas rendering + Touchpad 2-finger Orbit controls
  useEffect(() => {
    const cv = canvasRef.current;
    if (!cv || layout.P.length === 0) {
      if (animRef.current) cancelAnimationFrame(animRef.current);
      return;
    }

    const FOCAL = 620;

    const getState = () => {
      if (!stateRef.current || stateRef.current.nodes !== layout.nodes) {
        stateRef.current = {
          P: layout.P,
          E: layout.E,
          nodes: layout.nodes,
          cv,
          zoom: 1,
          ax: -0.25,
          ay: -0.35,
          spin: true,
          selectedNodeId,
          proj: [],
          drag: null,
        };
      }
      return stateRef.current;
    };

    const state = getState();
    state.cv = cv;

    const pos = (ev) => {
      const r = cv.getBoundingClientRect();
      return { x: ev.clientX - r.left, y: ev.clientY - r.top };
    };

    // Touchpad 2-finger rotation + Mouse Wheel Zoom
    const onWheel = (ev) => {
      ev.preventDefault();
      if (ev.ctrlKey || ev.shiftKey) {
        state.zoom = Math.min(5, Math.max(0.5, state.zoom * (ev.deltaY < 0 ? 1.12 : 0.89)));
      } else {
        const absX = Math.abs(ev.deltaX);
        const absY = Math.abs(ev.deltaY);

        if (absX > 2 || absY > 2) {
          state.spin = false;
          state.ay += ev.deltaX * 0.005;
          state.ax = Math.max(-1.2, Math.min(1.2, state.ax + ev.deltaY * 0.005));
        } else {
          state.zoom = Math.min(5, Math.max(0.5, state.zoom * (ev.deltaY < 0 ? 1.12 : 0.89)));
        }
      }
    };

    const onPointerDown = (ev) => {
      cv.setPointerCapture(ev.pointerId);
      const q = pos(ev);
      state.drag = {
        x: q.x,
        y: q.y,
        ax: state.ax,
        ay: state.ay,
        moved: 0,
      };
      state.spin = false;
    };

    const onPointerMove = (ev) => {
      if (!state.drag) return;
      const q = pos(ev);
      const dx = q.x - state.drag.x;
      const dy = q.y - state.drag.y;
      state.drag.moved = Math.max(state.drag.moved, Math.hypot(dx, dy));
      state.ay = state.drag.ay + dx * 0.006;
      state.ax = Math.max(-1.2, Math.min(1.2, state.drag.ax + dy * 0.006));
    };

    const onPointerUp = (ev) => {
      const wasDrag = state.drag && state.drag.moved > 4;
      state.drag = null;
      if (wasDrag) return;

      const q = pos(ev);
      let bestId = null;
      let bestD = 20;
      state.proj.forEach((pt) => {
        const d = Math.hypot(pt.sx - q.x, pt.sy - q.y);
        if (d < bestD) {
          bestD = d;
          bestId = pt.nodeId;
        }
      });
      const newSel = bestId != null && bestId === state.selectedNodeId ? null : bestId;
      state.selectedNodeId = newSel;
      setSelectedNodeId(newSel);
    };

    const onDblClick = () => {
      state.zoom = 1;
      state.ax = -0.25;
      state.ay = -0.35;
      state.spin = true;
      state.selectedNodeId = null;
      setSelectedNodeId(null);
    };

    cv.addEventListener("wheel", onWheel, { passive: false });
    cv.addEventListener("pointerdown", onPointerDown);
    cv.addEventListener("pointermove", onPointerMove);
    cv.addEventListener("pointerup", onPointerUp);
    cv.addEventListener("dblclick", onDblClick);
    cv.style.cursor = "grab";

    const dpr = window.devicePixelRatio || 1;

    function frame() {
      const w = cv.clientWidth;
      const h = cv.clientHeight || 220;
      if (w < 10) {
        animRef.current = requestAnimationFrame(frame);
        return;
      }

      cv.width = w * dpr;
      cv.height = h * dpr;
      cv.style.height = h + "px";
      const g = cv.getContext("2d");
      g.setTransform(dpr, 0, 0, dpr, 0, 0);

      if (state.spin) state.ay += 0.0025;

      const cy = Math.cos(state.ay), sy = Math.sin(state.ay);
      const cx = Math.cos(state.ax), sx = Math.sin(state.ax);

      state.proj = state.P.map((p, i) => {
        let x = p.x * cy + p.z * sy;
        let z = -p.x * sy + p.z * cy;
        const y = p.y * cx - z * sx;
        z = p.y * sx + z * cx;
        const s = (FOCAL / (FOCAL + z + 260)) * state.zoom;
        return { sx: w / 2 + x * s, sy: h / 2 + y * s, s, z, i, nodeId: p.id };
      });

      const selId = state.selectedNodeId;
      const selIndex = selId ? state.nodes.findIndex(n => n.id === selId) : -1;
      const nearMap = selIndex !== -1 ? graphNeighbours(state.E, selIndex) : null;
      const isLit = (j, nodeId) => selId == null || nodeId === selId || (nearMap && nearMap.has(j));

      g.clearRect(0, 0, w, h);

      // Edges
      state.E.map((e) => ({
        e,
        z: (state.proj[e.s].z + state.proj[e.t].z) / 2,
      }))
        .sort((a, b) => b.z - a.z)
        .forEach(({ e }) => {
          const a = state.proj[e.s], b = state.proj[e.t];
          if (!a || !b) return;
          const depth = Math.min(a.s, b.s);
          const on = isLit(e.s, e.source) || isLit(e.t, e.target);

          g.beginPath();
          g.moveTo(a.sx, a.sy);
          g.lineTo(b.sx, b.sy);
          g.strokeStyle = e.m ? EDGE_COLOR_MAL : EDGE_COLOR_NORMAL;
          g.lineWidth = (e.m ? 1.4 : 0.6) * Math.min(depth, 2);
          g.globalAlpha = (e.m ? 0.85 : 0.3) * Math.min(depth, 1.4) * (on ? 1 : 0.06);
          g.stroke();
          g.globalAlpha = 1;
        });

      // Nodes
      state.proj
        .slice()
        .sort((a, b) => b.z - a.z)
        .forEach((pt) => {
          const n = state.nodes[pt.i];
          if (!n) return;
          const sev = nodeSeverity(n);
          const base = 4 + Math.min(6, Math.log10((n.flows || 0) + 1) * 2.2);
          const r = base * Math.min(pt.s, 2.2);
          const flagged = sev === "risk" || sev === "anomaly";
          const on = isLit(pt.i, pt.nodeId);
          const isSel = pt.nodeId === selId;

          g.globalAlpha = on ? 1 : 0.1;

          if (flagged || isSel) {
            const glowR = r + (isSel ? 12 : 8) * Math.min(pt.s, 2);
            g.beginPath();
            g.arc(pt.sx, pt.sy, glowR, 0, 6.283);
            g.fillStyle = isSel ? "rgba(0, 240, 255, 0.22)" : (SEV_COLOR[sev] || "rgba(255,0,85,0.2)");
            g.fill();
          }

          g.beginPath();
          g.arc(pt.sx, pt.sy, r, 0, 6.283);
          g.fillStyle = SEV_COLOR[sev] || "#00f0ff";
          g.fill();

          g.strokeStyle = isSel ? "#00f0ff" : "#080b12";
          g.lineWidth = (isSel ? 2.5 : 1) * Math.min(pt.s, 2);
          g.stroke();
          g.globalAlpha = 1;
        });

      animRef.current = requestAnimationFrame(frame);
    }

    animRef.current = requestAnimationFrame(frame);

    return () => {
      cancelAnimationFrame(animRef.current);
      cv.removeEventListener("wheel", onWheel);
      cv.removeEventListener("pointerdown", onPointerDown);
      cv.removeEventListener("pointermove", onPointerMove);
      cv.removeEventListener("pointerup", onPointerUp);
      cv.removeEventListener("dblclick", onDblClick);
    };
  }, [layout]);

  const nodeCount = graphNodes.length;
  const edgeCount = graphEdges.length;
  const hasData = nodeCount > 0;

  return (
    <div className="p-3 border-t border-cyber-border">
      <div className="flex items-center gap-2 mb-2">
        <Network className="h-3.5 w-3.5 text-purple-400 shrink-0" />
        <span className="text-[9px] font-bold font-mono-tech tracking-wider text-slate-400 uppercase">
          Network Topology
        </span>
        {hasData && (
          <span className="ml-auto text-[8px] font-mono-tech text-slate-600 bg-slate-900 px-1.5 py-0.5 rounded">
            {nodeCount}n · {edgeCount}e
          </span>
        )}
      </div>

      <div
        className="relative bg-[#040710] rounded-lg overflow-hidden border border-slate-800/50"
        style={{ height: 220, touchAction: "none" }}
      >
        {!hasData ? (
          <div className="flex flex-col items-center justify-center h-full text-slate-600 gap-1.5 px-3">
            <Network className="h-6 w-6 opacity-20" />
            <span className="text-[9px] font-mono-tech text-center leading-relaxed">
              Start live capturing or upload a file to see network topology
            </span>
          </div>
        ) : (
          <canvas
            ref={canvasRef}
            className="w-full"
            style={{ height: 220, touchAction: "none" }}
          />
        )}
      </div>

      {selectedInfo && selectedInfo.ip && (
        <div className="mt-2 p-2 bg-[#080b12]/90 border border-slate-800/50 rounded-lg">
          <div className="flex items-center gap-1.5">
            <span className="text-[9px] font-mono-tech font-bold text-cyan-400 truncate">
              {selectedInfo.ip}
            </span>
            <button
              onClick={() => setSelectedNodeId(null)}
              className="ml-auto text-[8px] text-slate-600 hover:text-slate-300 font-mono-tech"
            >
              ✕
            </button>
          </div>
          <div className="flex items-center gap-1 mt-1 text-[8px] font-mono-tech text-slate-500">
            <span>{selectedInfo.flows.toLocaleString()} flows</span>
            <span>·</span>
            <span>{selectedInfo.peerCount} connections</span>
          </div>
        </div>
      )}
    </div>
  );
}
