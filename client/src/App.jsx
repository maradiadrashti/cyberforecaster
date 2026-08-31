import React, { useState, useEffect, useRef, useCallback } from "react";
import {
  ShieldAlert, Shield, Activity, Server, Cpu, Database,
  AlertTriangle, Layers, Clock, Eye, BarChart3, Brain, FileText,
  ChevronLeft, ChevronRight, Radio, Zap, Target, Network,
  TrendingUp, Globe
} from "lucide-react";
import LiveTraffic from "./pages/LiveTraffic";
import Overview from "./pages/Overview";
import AttackForecast from "./pages/AttackForecast";
import Explainability from "./pages/Explainability";
import ModelPerformance from "./pages/ModelPerformance";
import AuditTrail from "./pages/AuditTrail";
import {
  HOSTS, generateTrafficEvent, generateForecast, generateAlert
} from "./demoData";

// Reordered: Live Traffic first, then Attack Forecast, then Overview, etc.
const NAV_ITEMS = [
  { id: "live", label: "Live Traffic", icon: Activity },
  { id: "forecast", label: "Attack Forecast", icon: Target },
  { id: "overview", label: "Overview", icon: Layers },
  { id: "explain", label: "Explainability", icon: Brain },
  { id: "model", label: "Model Performance", icon: BarChart3 },
  { id: "audit", label: "Audit Trail", icon: Database },
];

const _HOST = import.meta.env.VITE_CAPTURE_HOST ?? "127.0.0.1";
const _PORT = import.meta.env.VITE_CAPTURE_PORT ?? "8080";
const CAPTURE_API = `http://${_HOST}:${_PORT}`;

export default function App() {
  const [activePage, setActivePage] = useState("live");
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [trafficEvents, setTrafficEvents] = useState([]);
  const [forecasts, setForecasts] = useState({});
  const [alerts, setAlerts] = useState([]);
  const [hosts, setHosts] = useState(HOSTS.map(h => ({ ...h, status: "ONLINE" })));
  const [tick, setTick] = useState(0);
  const tickRef = useRef(0);
  const [realInterfaces, setRealInterfaces] = useState([]);
  const [captureStats, setCaptureStats] = useState({ total_packets: 0, flow_count: 0 });

  // Shared state for interface communication between LiveTraffic and AttackForecast
  const [selectedInterface, setSelectedInterface] = useState("");
  const [selectedInterfaceInfo, setSelectedInterfaceInfo] = useState(null);
  const [liveFlows, setLiveFlows] = useState({});
  const [livePackets, setLivePackets] = useState([]);
  const [attackFlows, setAttackFlows] = useState([]);
  const [selectedFlow, setSelectedFlow] = useState(null);
  const [totalPacketsLive, setTotalPacketsLive] = useState(0);

  // Fetch real interfaces from capture server
  useEffect(() => {
    const fetchInterfaces = () => {
      fetch(`${CAPTURE_API}/api/interfaces`)
        .then(r => r.json())
        .then(data => setRealInterfaces(data))
        .catch(() => {});
    };
    fetchInterfaces();
    const interval = setInterval(fetchInterfaces, 5000);
    return () => clearInterval(interval);
  }, []);

  // Poll capture stats
  useEffect(() => {
    const fetchStats = () => {
      fetch(`${CAPTURE_API}/api/stats`)
        .then(r => r.json())
        .then(data => setCaptureStats(data))
        .catch(() => {});
    };
    fetchStats();
    const interval = setInterval(fetchStats, 2000);
    return () => clearInterval(interval);
  }, []);

  // Simulate live traffic for demo pages
  useEffect(() => {
    const interval = setInterval(() => {
      tickRef.current++;
      setTick(tickRef.current);

      const evt = generateTrafficEvent(HOSTS);
      setTrafficEvents(prev => [evt, ...prev].slice(0, 100));

      const fc = generateForecast(evt.dstIp);
      setForecasts(prev => ({ ...prev, [evt.dstIp]: fc }));

      if (evt.severity !== "none") {
        const alert = generateAlert(evt.dstIp, fc);
        if (alert) {
          setAlerts(prev => [alert, ...prev].slice(0, 50));
        }
      }
    }, 1800);

    return () => clearInterval(interval);
  }, []);

  // Callbacks for LiveTraffic to lift state up
  const handleInterfaceChange = useCallback((iface, ifaceInfo) => {
    setSelectedInterface(iface);
    setSelectedInterfaceInfo(ifaceInfo);
  }, []);

  const handleFlowsUpdate = useCallback((flows, packets, totalPkts) => {
    setLiveFlows(flows);
    setLivePackets(packets);
    setTotalPacketsLive(totalPkts || 0);
    const atkFlows = Object.values(flows).filter(f => f.severity && f.severity !== "none");
    setAttackFlows(atkFlows);
  }, []);

  // Navigate to attack forecast for a specific flow
  const navigateToForecast = useCallback((flow) => {
    setSelectedFlow(flow);
    setActivePage("forecast");
  }, []);

  const totalInterfaces = realInterfaces.length;
  const highThreatAlerts = Object.keys(liveFlows).length;

  return (
    <div className="min-h-screen flex cyber-grid font-sans select-none">
      {/* ===== SIDEBAR ===== */}
      <aside
        className={`flex flex-col border-r border-cyber-border bg-[#080b12]/95 backdrop-blur-xl transition-all duration-300 ${
          sidebarCollapsed ? "w-[60px]" : "w-[220px]"
        }`}
      >
        {/* Brand */}
        <div className="p-4 border-b border-cyber-border flex items-center gap-2 min-h-[60px]">
          <div className="relative shrink-0">
            <ShieldAlert className="h-6 w-6 text-cyber-accent" />
            <div className="absolute inset-0 bg-cyber-accent rounded blur-md opacity-20"></div>
          </div>
          {!sidebarCollapsed && (
            <div className="overflow-hidden">
              <h1 className="text-sm font-extrabold tracking-wider text-transparent bg-clip-text bg-gradient-to-r from-white via-cyan-300 to-indigo-400 font-mono-tech whitespace-nowrap">
                CYBERFORECASTER
              </h1>
              <p className="text-[8px] text-slate-600 uppercase tracking-widest font-mono-tech whitespace-nowrap">
                AI Network Attack Forecasting
              </p>
            </div>
          )}
        </div>

        {/* Nav items */}
        <nav className="flex-1 py-3 px-2 flex flex-col gap-0.5 overflow-y-auto">
          {NAV_ITEMS.map((item) => {
            const Icon = item.icon;
            const isActive = activePage === item.id;
            return (
              <button
                key={item.id}
                onClick={() => setActivePage(item.id)}
                className={`nav-item ${isActive ? "active" : "text-slate-400"} ${
                  sidebarCollapsed ? "justify-center px-0" : ""
                }`}
                title={item.label}
              >
                <Icon className="h-4 w-4 shrink-0" />
                {!sidebarCollapsed && <span className="font-mono-tech text-xs">{item.label}</span>}
              </button>
            );
          })}
        </nav>

        {/* Status indicators */}
        {!sidebarCollapsed && (
          <div className="p-3 border-t border-cyber-border space-y-2">
            <div className="flex items-center gap-2 text-[9px] font-mono-tech text-emerald-400">
              <div className="status-dot status-dot-online pulse-cyan"></div>
              <span>ON-CHAIN AUDIT ACTIVE</span>
            </div>
            <div className="flex items-center gap-2 text-[9px] font-mono-tech text-cyan-400">
              <div className="status-dot status-dot-online pulse-cyan"></div>
              <span>WORLD MODEL ONLINE</span>
            </div>
          </div>
        )}

        {/* Collapse toggle */}
        <button
          onClick={() => setSidebarCollapsed(!sidebarCollapsed)}
          className="p-2 border-t border-cyber-border text-slate-500 hover:text-cyber-accent transition-colors flex justify-center"
        >
          {sidebarCollapsed ? <ChevronRight className="h-4 w-4" /> : <ChevronLeft className="h-4 w-4" />}
        </button>
      </aside>

      {/* ===== MAIN CONTENT ===== */}
      <div className="flex-1 flex flex-col min-h-screen overflow-hidden">
        {/* Top Header Bar */}
        <header className="border-b border-cyber-border bg-[#080b12]/90 backdrop-blur-md px-6 py-3 flex justify-between items-center sticky top-0 z-40">
          <div className="flex items-center gap-4">
            <h2 className="text-sm font-bold tracking-wider font-mono-tech text-white uppercase">
              {NAV_ITEMS.find(n => n.id === activePage)?.label}
            </h2>
          </div>
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-1.5 bg-slate-900/80 border border-slate-800 px-2.5 py-1 rounded-full text-[9px] font-mono-tech">
              <Server className="h-3 w-3 text-cyan-400" />
              <span className="text-slate-400">{totalInterfaces} Interfaces</span>
            </div>
            <div className="flex items-center gap-1.5 bg-slate-900/80 border border-slate-800 px-2.5 py-1 rounded-full text-[9px] font-mono-tech">
              <ShieldAlert className={`h-3 w-3 ${highThreatAlerts > 0 ? "text-rose-400 animate-pulse" : "text-slate-500"}`} />
              <span className="text-slate-400">
                {highThreatAlerts} Flows
              </span>
            </div>
            <div className="flex items-center gap-1.5 bg-slate-900/80 border border-slate-800 px-2.5 py-1 rounded-full text-[9px] font-mono-tech">
              <Activity className="h-3 w-3 text-indigo-400" />
              <span className="text-slate-400">{totalPacketsLive.toLocaleString()} Pkts</span>
            </div>
            <div className="flex items-center gap-1.5 bg-emerald-950/30 border border-emerald-900/50 px-2.5 py-1 rounded-full text-[9px] font-mono-tech text-emerald-400">
              <Radio className="h-3 w-3 animate-pulse" />
              <span>LIVE</span>
            </div>
          </div>
        </header>

        {/* Page Content */}
        <main className="flex-1 overflow-y-auto p-6 animate-fade-in">
          {/* LiveTraffic stays mounted always so capture/WS/WebSocket are never killed */}
          <div style={{ display: activePage === "live" ? "block" : "none" }}>
            <LiveTraffic
              onInterfaceChange={handleInterfaceChange}
              onFlowsUpdate={handleFlowsUpdate}
              onFlowClick={navigateToForecast}
            />
          </div>
          {activePage === "forecast" && (
            <AttackForecast
              selectedInterface={selectedInterface}
              selectedInterfaceInfo={selectedInterfaceInfo}
              liveFlows={liveFlows}
              livePackets={livePackets}
              attackFlows={attackFlows}
              selectedFlow={selectedFlow}
              hosts={hosts}
              forecasts={forecasts}
              isCapturing={captureStats.active_captures && (selectedInterface ? !!captureStats.active_captures[selectedInterface] : Object.keys(captureStats.active_captures).length > 0)}
            />
          )}
          {activePage === "overview" && (
            <Overview />
          )}
          {activePage === "explain" && (
            <Explainability
              hosts={hosts}
              forecasts={forecasts}
            />
          )}
          {activePage === "model" && (
            <ModelPerformance />
          )}
          {activePage === "audit" && (
            <AuditTrail alerts={alerts} />
          )}
        </main>
      </div>
    </div>
  );
}
