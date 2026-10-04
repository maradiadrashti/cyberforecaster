import React, { useState, useEffect, useRef, useCallback } from "react";
import {
  Shield, Activity, Server,
  ChevronLeft, ChevronRight, Radio, Target, Home, UploadCloud, Gamepad2, Menu, Network
} from "lucide-react";
import LiveTraffic from "./pages/LiveTraffic";
import AttackForecast from "./pages/AttackForecast";
import UploadAnalysis from "./pages/UploadAnalysis";
import LandingPage from "./pages/LandingPage";

// Sidebar Navigation Groups
const NAV_GROUPS = [
  {
    title: "INPUT",
    items: [
      { id: "live", label: "Live Telemetry", icon: Radio },
      { id: "upload", label: "File Upload", icon: UploadCloud },
    ],
  },
  {
    title: "ANALYSIS",
    items: [
      { id: "forecast", label: "Attack Forecast", icon: Target },
    ],
  },
];

const LIVE_SUB_ITEMS = [
  { id: "live-network-traffic", label: "Live Network Traffic" },
  { id: "live-network-topology", label: "Live Network Topology" },
  { id: "captured-flows", label: "Captured Flows" },
];

const FORECAST_SUB_ITEMS = [
  { id: "risk-forecast", label: "Risk Forecast" },
  { id: "mitre-attack-progression", label: "Stage Progression Tree" },
  { id: "mitre-attack-analysis", label: "MITRE ATT&CK Mapping" },
  { id: "shap-explanation", label: "Feature Attribution" },
  { id: "observed-network-evidence", label: "Observed Network Evidence" },
];

const ALL_NAV_ITEMS = NAV_GROUPS.flatMap(g => g.items);

const _HOST = import.meta.env.VITE_CAPTURE_HOST ?? "127.0.0.1";
const _PORT = import.meta.env.VITE_CAPTURE_PORT ?? "8080";
const CAPTURE_API = `http://${_HOST}:${_PORT}`;

export default function App() {
  const [view, setView] = useState(() => {
    if (typeof window !== "undefined") {
      const params = new URLSearchParams(window.location.search);
      if (params.get("view") === "dashboard" || window.location.hash === "#dashboard") {
        return "dashboard";
      }
    }
    return "landing";
  });
  const [activePage, setActivePage] = useState("live");
  const [activeSubsection, setActiveSubsection] = useState("live-network-traffic");
  const [expandedMenus, setExpandedMenus] = useState({
    live: false,
    forecast: false,
  });
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [alerts, setAlerts] = useState([]);
  const mainScrollRef = useRef(null);
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

  // Shared state for offline file analysis results (PCAP/CSV)
  const [offlineAnalysisResult, setOfflineAnalysisResult] = useState(null);

  const handleAnalysisComplete = useCallback((result) => {
    setOfflineAnalysisResult(result);
    setActivePage("forecast");
  }, []);

  const handleClearOfflineAnalysis = useCallback(() => {
    setOfflineAnalysisResult(null);
  }, []);

  const scrollToSection = useCallback((sectionId, targetPage = "live") => {
    setActivePage(targetPage);
    setTimeout(() => {
      const el = document.getElementById(sectionId);
      if (el) {
        el.scrollIntoView({ behavior: "smooth", block: "start" });
      }
    }, 0);
  }, []);

  // Fetch real interfaces from capture server (active on dashboard)
  useEffect(() => {
    if (view !== "dashboard") return;
    const fetchInterfaces = () => {
      fetch(`${CAPTURE_API}/api/interfaces`)
        .then(r => r.json())
        .then(data => setRealInterfaces(data))
        .catch(() => {});
    };
    fetchInterfaces();
    const interval = setInterval(fetchInterfaces, 5000);
    return () => clearInterval(interval);
  }, [view]);

  // Poll capture stats (active on dashboard)
  useEffect(() => {
    if (view !== "dashboard") return;
    const fetchStats = () => {
      fetch(`${CAPTURE_API}/api/stats`)
        .then(r => r.json())
        .then(data => setCaptureStats(data))
        .catch(() => {});
    };
    fetchStats();
    const interval = setInterval(fetchStats, 2000);
    return () => clearInterval(interval);
  }, [view]);

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
  const activeNavItem = ALL_NAV_ITEMS.find(n => n.id === activePage);

  if (view === "landing") {
    return (
      <LandingPage
        onGetStarted={() => {
          const dashboardUrl = `${window.location.origin}${window.location.pathname}?view=dashboard`;
          window.open(dashboardUrl, "_blank");
        }}
      />
    );
  }

  return (
    <div className="min-h-screen flex bg-bg font-sans select-none text-text">
      {/* ===== SIDEBAR ===== */}
      <aside
        className={`flex flex-col border-r border-border bg-surface transition-all duration-300 overflow-hidden ${
          !sidebarOpen ? "w-0 border-r-0 opacity-0" : sidebarCollapsed ? "w-[60px]" : "w-[235px]"
        }`}
      >
        {/* Brand - Clickable to return to Landing */}
        <button
          onClick={() => setView("landing")}
          className="p-4 border-b border-border flex items-center gap-2.5 min-h-[60px] text-left hover:bg-surface-2 transition-colors w-full cursor-pointer overflow-hidden"
          title="Back to Landing Page"
        >
          <div className="shrink-0">
            <Shield className="h-6 w-6 text-gold stroke-[2.2]" />
          </div>
          {!sidebarCollapsed && (
            <div className="min-w-0 flex-1">
              <h1 className="text-sm font-black tracking-wider leading-tight uppercase whitespace-nowrap">
                <span className="text-white">CYBER</span>
                <span className="text-gold">FORECASTER</span>
              </h1>
            </div>
          )}
        </button>

        {/* Grouped Nav items (INPUT & ANALYSIS) */}
        <nav className="flex-1 py-4 px-2.5 flex flex-col gap-4 overflow-y-auto">
          {NAV_GROUPS.map((group) => (
            <div key={group.title} className="space-y-1.5">
              {!sidebarCollapsed && (
                <div className="px-3.5 py-1 text-[11px] font-mono-tech font-bold tracking-widest text-text-muted/70 uppercase">
                  {group.title}
                </div>
              )}
              {group.items.map((item) => {
                const Icon = item.icon;
                const isActive = activePage === item.id;
                const isLiveItem = item.id === "live";
                const isForecastItem = item.id === "forecast";
                const isExpandable = isLiveItem || isForecastItem;
                const isExpanded = isExpandable ? Boolean(expandedMenus[item.id]) : false;

                return (
                  <div key={item.id} className="space-y-1">
                    {/* Primary Navigation Item */}
                    <button
                      onClick={() => {
                        setActivePage(item.id);
                        if (isExpandable) {
                          setExpandedMenus(prev => ({ ...prev, [item.id]: !prev[item.id] }));
                        }
                      }}
                      className={`w-full flex items-center justify-between gap-2.5 px-3 py-2 rounded-lg font-mono-tech text-[13px] transition-all relative cursor-pointer ${
                        isActive
                          ? "bg-gold text-bg font-bold shadow-sm"
                          : "text-text-muted hover:text-white hover:bg-surface-2"
                      } ${sidebarCollapsed ? "justify-center px-0" : ""}`}
                      title={item.label}
                    >
                      <div className="flex items-center gap-2.5 min-w-0">
                        <Icon className={`h-4 w-4 shrink-0 ${isActive ? "text-bg" : "text-gold"}`} />
                        {!sidebarCollapsed && <span className="tracking-wide font-medium truncate">{item.label}</span>}
                      </div>

                      {/* Dropdown Chevron Indicator */}
                      {isExpandable && !sidebarCollapsed && (
                        <ChevronRight
                          className={`h-3.5 w-3.5 shrink-0 transition-transform duration-200 ${
                            isExpanded ? "rotate-90" : "rotate-0"
                          } ${isActive ? "text-bg" : "text-gold/80"}`}
                        />
                      )}
                    </button>

                    {/* Sub-navigation Tree under LIVE TELEMETRY */}
                    {isLiveItem && !sidebarCollapsed && isExpanded && (
                      <div className="ml-3.5 pl-2.5 border-l border-border flex flex-col gap-1 my-1">
                        {LIVE_SUB_ITEMS.map((sub) => (
                          <button
                            key={sub.id}
                            onClick={(e) => {
                              e.stopPropagation();
                              scrollToSection(sub.id, "live");
                            }}
                            className="w-full flex items-center px-2.5 py-1.5 rounded-md font-mono-tech text-xs transition-all cursor-pointer text-left text-text-muted hover:text-white hover:bg-surface-2"
                            title={sub.label}
                          >
                            <span className="truncate">{sub.label}</span>
                          </button>
                        ))}
                      </div>
                    )}

                    {/* Sub-navigation Tree under ATTACK FORECAST */}
                    {isForecastItem && !sidebarCollapsed && isExpanded && (
                      <div className="ml-3.5 pl-2.5 border-l border-border flex flex-col gap-1 my-1">
                        {FORECAST_SUB_ITEMS.map((sub) => (
                          <button
                            key={sub.id}
                            onClick={(e) => {
                              e.stopPropagation();
                              scrollToSection(sub.id, "forecast");
                            }}
                            className="w-full flex items-center px-2.5 py-1.5 rounded-md font-mono-tech text-xs transition-all cursor-pointer text-left text-text-muted hover:text-white hover:bg-surface-2"
                            title={sub.label}
                          >
                            <span className="truncate">{sub.label}</span>
                          </button>
                        ))}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          ))}
        </nav>

      </aside>

      {/* ===== MAIN CONTENT ===== */}
      <div className="flex-1 flex flex-col min-h-screen overflow-hidden bg-bg">
        {/* Page Content */}
        <main ref={mainScrollRef} className="flex-1 overflow-y-auto p-6 animate-fade-in bg-bg">
          <div style={{ display: activePage === "live" ? "block" : "none" }}>
            <LiveTraffic
              onInterfaceChange={handleInterfaceChange}
              onFlowsUpdate={handleFlowsUpdate}
              onToggleSidebar={() => setSidebarOpen(!sidebarOpen)}
            />
          </div>
          <div style={{ display: activePage === "forecast" ? "block" : "none" }}>
            <AttackForecast
              isActive={activePage === "forecast"}
              onToggleSidebar={() => setSidebarOpen(!sidebarOpen)}
              onNavigateToUpload={() => setActivePage("upload")}
            />
          </div>
          <div style={{ display: activePage === "upload" ? "block" : "none" }}>
            <UploadAnalysis
              onAnalysisComplete={handleAnalysisComplete}
              onToggleSidebar={() => setSidebarOpen(!sidebarOpen)}
              onNavigateToLive={() => setActivePage("live")}
            />
          </div>
        </main>
      </div>
    </div>
  );
}
