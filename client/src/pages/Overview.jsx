import React, { useState, useEffect, useMemo } from "react";
import {
  ShieldAlert, Shield, Server, Activity, Database, Cpu,
  TrendingUp, AlertTriangle, Globe, Zap, Radio, Wifi,
  Link2, MonitorSmartphone, WifiOff, ArrowUpDown, CheckCircle2
} from "lucide-react";
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  BarChart, Bar, PieChart, Pie, Cell
} from "recharts";

const _HOST = import.meta.env.VITE_CAPTURE_HOST ?? "127.0.0.1";
const _PORT = import.meta.env.VITE_CAPTURE_PORT ?? "8080";
const CAPTURE_API = `http://${_HOST}:${_PORT}`;
const WS_URL = `ws://${_HOST}:${_PORT}/ws/live`;

const IFACE_ICONS = {
  WiFi: Wifi,
  Ethernet: Link2,
  Bluetooth: MonitorSmartphone,
  VPN: ShieldAlert,
  Virtual: Server,
  Docker: Server,
  Unknown: Globe,
};

const SEV_COLORS = {
  none: "#334155",
  low: "#38bdf8",
  medium: "#f59e0b",
  high: "#f97316",
  critical: "#ff0055",
};

const STAGE_COLORS = {
  Normal: "#22c55e",
  Reconnaissance: "#38bdf8",
  "Initial Access": "#f59e0b",
  "Lateral Movement": "#f97316",
  "Command & Control": "#ef4444",
  Exfiltration: "#ff0055",
};

export default function Overview() {
  const [interfaces, setInterfaces] = useState([]);
  const [captureStats, setCaptureStats] = useState({ total_packets: 0, flow_count: 0, start_time: null });
  const [flows, setFlows] = useState({});
  const [packets, setPackets] = useState([]);
  const [wsConnected, setWsConnected] = useState(false);
  const [ifaceStats, setIfaceStats] = useState([]);

  // Fetch interfaces
  useEffect(() => {
    const fetchIfaces = () => {
      fetch(`${CAPTURE_API}/api/interfaces`)
        .then(r => r.json())
        .then(data => setInterfaces(data))
        .catch(() => {});
    };
    fetchIfaces();
    const iv = setInterval(fetchIfaces, 5000);
    return () => clearInterval(iv);
  }, []);

  // Poll stats
  useEffect(() => {
    const fetchStats = () => {
      fetch(`${CAPTURE_API}/api/stats`)
        .then(r => r.json())
        .then(data => setCaptureStats(data))
        .catch(() => {});
    };
    fetchStats();
    const iv = setInterval(fetchStats, 2000);
    return () => clearInterval(iv);
  }, []);

  // Poll per-interface attack stats
  useEffect(() => {
    const fetchIfaceStats = () => {
      fetch(`${CAPTURE_API}/api/interface-stats`)
        .then(r => r.json())
        .then(data => setIfaceStats(data))
        .catch(() => {});
    };
    fetchIfaceStats();
    const iv = setInterval(fetchIfaceStats, 3000);
    return () => clearInterval(iv);
  }, []);

  // WebSocket for live packet stream
  useEffect(() => {
    let ws;
    let reconnectTimer;
    const connect = () => {
      try {
        ws = new WebSocket(WS_URL);
        ws.onopen = () => setWsConnected(true);
        ws.onclose = () => {
          setWsConnected(false);
          reconnectTimer = setTimeout(connect, 2000);
        };
        ws.onerror = () => { try { ws.close(); } catch (_) {} };
        ws.onmessage = (event) => {
          try {
            const data = JSON.parse(event.data);
            if (data.type === "connected") return;
            if (data.src_ip && data.dst_ip) {
              setPackets(prev => [data, ...prev].slice(0, 200));
              setFlows(prev => {
                const key = `${data.src_ip}:${data.src_port}-${data.dst_ip}:${data.dst_port}-${data.protocol}`;
                const next = { ...prev };
                if (next[key]) {
                  next[key] = { ...next[key], packet_count: next[key].packet_count + 1, byte_count: next[key].byte_count + (data.length || 0), last_seen: data.timestamp };
                } else {
                  next[key] = {
                    src_ip: data.src_ip, dst_ip: data.dst_ip, src_port: data.src_port, dst_port: data.dst_port,
                    protocol: data.protocol, packet_count: 1, byte_count: data.length || 0,
                    first_seen: data.timestamp, last_seen: data.timestamp,
                    severity: data.severity, attack_type: data.attack_type,
                  };
                }
                return next;
              });
            }
          } catch (_) {}
        };
      } catch (_) {}
    };
    connect();
    return () => { clearTimeout(reconnectTimer); if (ws) try { ws.close(); } catch (_) {} };
  }, []);

  // --- Derived data ---
  const flowList = Object.values(flows);
  const totalInterfaces = interfaces.length;
  const activeInterfaces = interfaces.filter(i => i.is_up).length;
  const attackFlows = flowList.filter(f => f.severity && f.severity !== "none");
  const totalBytes = packets.reduce((s, p) => s + (p.length || 0), 0);

  // Severity breakdown
  const severityBreakdown = useMemo(() => {
    const counts = { critical: 0, high: 0, medium: 0, low: 0 };
    attackFlows.forEach(f => {
      const sev = f.severity;
      if (counts[sev] !== undefined) counts[sev]++;
    });
    return Object.entries(counts)
      .map(([name, count]) => ({ name: name.toUpperCase(), count, color: SEV_COLORS[name] }))
      .filter(s => s.count > 0);
  }, [attackFlows]);

  // Protocol distribution
  const protoDist = useMemo(() => {
    const counts = {};
    flowList.forEach(f => { counts[f.protocol] = (counts[f.protocol] || 0) + 1; });
    return Object.entries(counts).map(([name, count]) => ({ name, count }));
  }, [flowList]);

  // Attack type breakdown
  const attackTypes = useMemo(() => {
    const counts = {};
    attackFlows.forEach(f => { counts[f.attack_type || "Unknown"] = (counts[f.attack_type || "Unknown"] || 0) + 1; });
    return Object.entries(counts).map(([name, count]) => ({ name, count })).sort((a, b) => b.count - a.count);
  }, [attackFlows]);

  // Top talkers (most packets)
  const topTalkers = useMemo(() => {
    const ipPackets = {};
    packets.forEach(p => {
      ipPackets[p.src_ip] = (ipPackets[p.src_ip] || 0) + 1;
    });
    return Object.entries(ipPackets)
      .map(([ip, count]) => ({ ip, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 8);
  }, [packets]);

  // Top destinations
  const topDests = useMemo(() => {
    const ipPackets = {};
    packets.forEach(p => {
      ipPackets[p.dst_ip] = (ipPackets[p.dst_ip] || 0) + 1;
    });
    return Object.entries(ipPackets)
      .map(([ip, count]) => ({ ip, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 8);
  }, [packets]);

  const formatBytes = (b) => {
    if (b >= 1000000) return `${(b / 1000000).toFixed(1)} MB`;
    if (b >= 1000) return `${(b / 1000).toFixed(1)} KB`;
    return `${b} B`;
  };

  // Determine highest threat level across all flows
  const highestThreat = useMemo(() => {
    if (attackFlows.some(f => f.severity === "critical")) return "CRITICAL";
    if (attackFlows.some(f => f.severity === "high")) return "HIGH";
    if (attackFlows.some(f => f.severity === "medium")) return "MEDIUM";
    if (attackFlows.some(f => f.severity === "low")) return "LOW";
    return "NONE";
  }, [attackFlows]);

  const threatColor = {
    NONE: "text-emerald-400",
    LOW: "text-cyan-400",
    MEDIUM: "text-amber-400",
    HIGH: "text-orange-400",
    CRITICAL: "text-rose-400",
  }[highestThreat];

  return (
    <div className="space-y-6 animate-fade-in">
      {/* KPI Row */}
      <section className="grid grid-cols-2 lg:grid-cols-5 gap-4">
        {[
          { title: "Network Interfaces", value: totalInterfaces, sub: `${activeInterfaces} active`, icon: Wifi, color: "text-cyan-400", border: "border-cyan-900/40" },
          { title: "Captured Flows", value: flowList.length, sub: `${captureStats.total_packets.toLocaleString()} packets`, icon: Activity, color: "text-indigo-400", border: "border-indigo-900/40" },
          { title: "Attack Flows Detected", value: attackFlows.length, sub: `${severityBreakdown.length} severity levels`, icon: ShieldAlert, color: "text-rose-400", border: "border-rose-900/40" },
          { title: "Total Data Captured", value: formatBytes(totalBytes), sub: "across all interfaces", icon: Globe, color: "text-purple-400", border: "border-purple-900/40" },
          { title: "Network Threat Level", value: highestThreat, sub: highestThreat !== "NONE" ? "Action recommended" : "Network healthy", icon: highestThreat !== "NONE" ? AlertTriangle : CheckCircle2, color: threatColor, border: "border-slate-800" },
        ].map((kpi, idx) => (
          <div key={idx} className={`glass-card rounded-xl border ${kpi.border} p-4 flex items-center justify-between`}>
            <div>
              <p className="text-[10px] uppercase tracking-wider text-slate-500 font-mono-tech">{kpi.title}</p>
              <h2 className={`text-2xl font-black mt-1 ${kpi.color} font-mono-tech`}>{kpi.value}</h2>
              <p className="text-[10px] text-slate-600 mt-0.5">{kpi.sub}</p>
            </div>
            <kpi.icon className={`h-8 w-8 ${kpi.color} opacity-30`} />
          </div>
        ))}
      </section>

      {/* Interface Status Cards */}
      <section className="glass-card rounded-xl border border-slate-800/50 p-5">
        <div className="flex items-center gap-2 mb-4">
          <Server className="h-4 w-4 text-cyan-400" />
          <h3 className="text-xs font-bold uppercase tracking-wider font-mono-tech">Detected Network Interfaces</h3>
          <span className="text-[9px] font-mono-tech text-slate-500 bg-slate-900 px-2 py-0.5 rounded">{totalInterfaces} total</span>
        </div>
        <div className="grid grid-cols-2 lg:grid-cols-3 gap-3">
          {interfaces.map((iface, idx) => {
            const Icon = IFACE_ICONS[iface.type] || Globe;
            const isUp = iface.is_up;
            const stats = ifaceStats.find(s => s.interface === iface.name);
            const attackCount = stats?.attack_flows || 0;
            const criticalCount = stats?.critical || 0;
            const highCount = stats?.high || 0;
            const isUnderAttack = attackCount > 0;
            const isCritical = criticalCount > 0;
            const borderColor = isCritical ? "border-rose-600" : isUnderAttack ? "border-amber-600" : isUp ? "border-slate-800" : "border-slate-900";
            const glowClass = isCritical ? "glow-red" : isUnderAttack ? "glow-amber" : "";

            return (
              <div key={idx} className={`p-3 rounded-lg border transition-all ${glowClass} ${
                isUp ? `bg-slate-950/50 ${borderColor} hover:border-slate-700` : "bg-slate-950/20 border-slate-900 opacity-50"
              }`}>
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-2">
                    <Icon className={`h-4 w-4 ${isUnderAttack ? (isCritical ? "text-rose-400" : "text-amber-400") : isUp ? "text-cyan-400" : "text-slate-600"}`} />
                    <span className="text-xs font-bold text-white truncate">{iface.name}</span>
                  </div>
                  {isUnderAttack && (
                    <span className={`text-[7px] font-mono-tech font-bold px-1.5 py-0.5 rounded ${
                      isCritical ? "bg-rose-950/50 text-rose-400 border border-rose-900/50 animate-pulse" :
                      highCount > 0 ? "bg-amber-950/50 text-amber-400 border border-amber-900/50" :
                      "bg-yellow-950/50 text-yellow-400 border border-yellow-900/50"
                    }`}>
                      {isCritical ? "CRITICAL" : "UNDER ATTACK"}
                    </span>
                  )}
                </div>
                <div className="space-y-1 text-[9px] font-mono-tech">
                  <div className="flex justify-between">
                    <span className="text-slate-500">Type</span>
                    <span className="text-slate-300">{iface.type}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-500">IP</span>
                    <span className="text-slate-300">{iface.ip}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-500">Status</span>
                    <span className={isUp ? "text-emerald-400" : "text-slate-600"}>{isUp ? "ACTIVE" : "INACTIVE"}</span>
                  </div>
                  {stats && (
                    <>
                      <div className="flex justify-between">
                        <span className="text-slate-500">Flows</span>
                        <span className="text-slate-300">{stats.total_flows}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-slate-500">Packets</span>
                        <span className="text-slate-300">{stats.total_packets.toLocaleString()}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-slate-500">Data</span>
                        <span className="text-slate-300">{formatBytes(stats.total_bytes)}</span>
                      </div>
                      {attackCount > 0 && (
                        <div className="flex justify-between">
                          <span className="text-slate-500">Attacks</span>
                          <span className="text-rose-400 font-bold">{attackCount}</span>
                        </div>
                      )}
                    </>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </section>

      {/* Charts Row */}
      <section className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Severity Breakdown */}
        <div className="glass-card rounded-xl border border-slate-800/50 p-5">
          <div className="flex items-center gap-2 mb-4">
            <ShieldAlert className="h-4 w-4 text-rose-400" />
            <h3 className="text-xs font-bold uppercase tracking-wider font-mono-tech">Threat Severity Breakdown</h3>
          </div>
          <div className="h-[200px]">
            {severityBreakdown.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={severityBreakdown}
                    cx="50%"
                    cy="50%"
                    innerRadius={45}
                    outerRadius={75}
                    paddingAngle={3}
                    dataKey="count"
                    label={({ name, count }) => `${name}: ${count}`}
                  >
                    {severityBreakdown.map((entry, idx) => (
                      <Cell key={idx} fill={entry.color} stroke="none" />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{ backgroundColor: "#0b0f19", border: "1px solid #1f293d", borderRadius: 8, fontSize: 11 }}
                  />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div className="flex items-center justify-center h-full text-slate-600 text-xs font-mono-tech">
                No attack flows detected yet
              </div>
            )}
          </div>
        </div>

        {/* Protocol Distribution */}
        <div className="glass-card rounded-xl border border-slate-800/50 p-5">
          <div className="flex items-center gap-2 mb-4">
            <Globe className="h-4 w-4 text-indigo-400" />
            <h3 className="text-xs font-bold uppercase tracking-wider font-mono-tech">Protocol Distribution</h3>
          </div>
          <div className="h-[200px]">
            {protoDist.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={protoDist} margin={{ top: 5, right: 10, left: -20, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.02)" />
                  <XAxis dataKey="name" tick={{ fontSize: 10, fill: "#94a3b8" }} />
                  <YAxis tick={{ fontSize: 9, fill: "#64748b" }} />
                  <Tooltip contentStyle={{ backgroundColor: "#0b0f19", border: "1px solid #1f293d", borderRadius: 8, fontSize: 11 }} />
                  <Bar dataKey="count" fill="#00f0ff" radius={[4, 4, 0, 0]} name="Flows" />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="flex items-center justify-center h-full text-slate-600 text-xs font-mono-tech">
                Start a capture to see protocol data
              </div>
            )}
          </div>
        </div>

        {/* Attack Types */}
        <div className="glass-card rounded-xl border border-slate-800/50 p-5">
          <div className="flex items-center gap-2 mb-4">
            <AlertTriangle className="h-4 w-4 text-amber-400" />
            <h3 className="text-xs font-bold uppercase tracking-wider font-mono-tech">Detected Attack Types</h3>
          </div>
          <div className="space-y-2">
            {attackTypes.length > 0 ? (
              attackTypes.map((at, i) => (
                <div key={i} className="flex items-center justify-between p-2 rounded bg-slate-950/50 border border-slate-900">
                  <span className="text-[10px] font-mono-tech text-white">{at.name}</span>
                  <div className="flex items-center gap-2">
                    <div className="w-20 h-1.5 bg-slate-900 rounded-full overflow-hidden">
                      <div
                        className="h-full bg-amber-400 rounded-full"
                        style={{ width: `${(at.count / Math.max(...attackTypes.map(a => a.count))) * 100}%` }}
                      ></div>
                    </div>
                    <span className="text-[10px] font-mono-tech text-amber-400 font-bold w-6 text-right">{at.count}</span>
                  </div>
                </div>
              ))
            ) : (
              <div className="flex items-center justify-center py-8 text-slate-600 text-xs font-mono-tech">
                No attacks detected
              </div>
            )}
          </div>
        </div>
      </section>

      {/* Top Talkers + Top Destinations */}
      <section className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="glass-card rounded-xl border border-slate-800/50 p-5">
          <div className="flex items-center gap-2 mb-4">
            <ArrowUpDown className="h-4 w-4 text-cyan-400" />
            <h3 className="text-xs font-bold uppercase tracking-wider font-mono-tech">Top Source IPs (Talkers)</h3>
          </div>
          <div className="space-y-1.5">
            {topTalkers.length > 0 ? topTalkers.map((t, i) => (
              <div key={i} className="flex items-center justify-between p-2 rounded bg-slate-950/40 border border-slate-900 text-[10px] font-mono-tech">
                <div className="flex items-center gap-2">
                  <span className="text-slate-600 w-4">{i + 1}.</span>
                  <span className="text-cyan-400 font-bold">{t.ip}</span>
                </div>
                <span className="text-slate-400">{t.count} pkts</span>
              </div>
            )) : (
              <div className="text-center py-8 text-slate-600 text-xs font-mono-tech">No data yet</div>
            )}
          </div>
        </div>

        <div className="glass-card rounded-xl border border-slate-800/50 p-5">
          <div className="flex items-center gap-2 mb-4">
            <ArrowUpDown className="h-4 w-4 text-purple-400" />
            <h3 className="text-xs font-bold uppercase tracking-wider font-mono-tech">Top Destination IPs (Targets)</h3>
          </div>
          <div className="space-y-1.5">
            {topDests.length > 0 ? topDests.map((t, i) => (
              <div key={i} className="flex items-center justify-between p-2 rounded bg-slate-950/40 border border-slate-900 text-[10px] font-mono-tech">
                <div className="flex items-center gap-2">
                  <span className="text-slate-600 w-4">{i + 1}.</span>
                  <span className="text-purple-400 font-bold">{t.ip}</span>
                </div>
                <span className="text-slate-400">{t.count} pkts</span>
              </div>
            )) : (
              <div className="text-center py-8 text-slate-600 text-xs font-mono-tech">No data yet</div>
            )}
          </div>
        </div>
      </section>

      {/* Recent Attack Flows */}
      <section className="glass-card rounded-xl border border-slate-800/50 p-5">
        <div className="flex items-center gap-2 mb-4">
          <ShieldAlert className="h-4 w-4 text-rose-400" />
          <h3 className="text-xs font-bold uppercase tracking-wider font-mono-tech">Recent Suspicious Flows</h3>
          <span className="text-[9px] font-mono-tech text-slate-500 bg-slate-900 px-2 py-0.5 rounded">{attackFlows.length} total</span>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left font-mono-tech text-[10px]">
            <thead>
              <tr className="border-b border-slate-800 text-slate-500 uppercase tracking-widest text-[9px]">
                <th className="py-2.5">Time</th>
                <th>Source</th>
                <th>Destination</th>
                <th>Protocol</th>
                <th>Type</th>
                <th>Severity</th>
                <th>Packets</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-900">
              {attackFlows.length === 0 ? (
                <tr>
                  <td colSpan="7" className="py-12 text-center text-slate-500">
                    <CheckCircle2 className="h-8 w-8 mx-auto mb-2 opacity-20 text-emerald-400" />
                    <p className="font-mono-tech text-xs">No suspicious flows detected. Network is clean.</p>
                  </td>
                </tr>
              ) : (
                attackFlows.slice(0, 15).map((f, idx) => (
                  <tr key={idx} className="hover:bg-slate-900/20 transition-colors">
                    <td className="py-2 text-slate-500">{new Date(f.last_seen).toLocaleTimeString()}</td>
                    <td className="text-cyan-400 font-bold">{f.src_ip}</td>
                    <td className="text-white font-bold">{f.dst_ip}</td>
                    <td>
                      <span className={`px-1.5 py-0.5 rounded text-[8px] font-bold ${
                        f.protocol === "TCP" ? "bg-cyan-950/50 text-cyan-400" :
                        f.protocol === "UDP" ? "bg-indigo-950/50 text-indigo-400" :
                        "bg-slate-800 text-slate-400"
                      }`}>{f.protocol}</span>
                    </td>
                    <td className="text-amber-400">{f.attack_type || "Unknown"}</td>
                    <td>
                      <span className={`px-1.5 py-0.5 rounded text-[8px] font-bold uppercase ${
                        f.severity === "critical" ? "bg-rose-950/50 text-rose-400 border border-rose-900/50" :
                        f.severity === "high" ? "bg-amber-950/50 text-amber-400 border border-amber-900/50" :
                        f.severity === "medium" ? "bg-yellow-950/50 text-yellow-400 border border-yellow-900/50" :
                        "bg-cyan-950/50 text-cyan-400 border border-cyan-900/50"
                      }`}>
                        {f.severity?.toUpperCase()}
                      </span>
                    </td>
                    <td className="text-slate-400">{f.packet_count}</td>
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
