import React, { useState, useEffect, useMemo, useCallback } from "react";
import {
  Database, ShieldCheck, ShieldAlert, ExternalLink, CheckCircle2,
  XCircle, RefreshCw, Search, Clock, AlertTriangle, Lock, Hash,
  Cpu, Filter, Server, ArrowRight, Layers, FileText, Check, Copy
} from "lucide-react";
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend
} from "recharts";
import io from "socket.io-client";

const API_BASE = "http://127.0.0.1:5050";

// Real Cryptographic Verification Modal
function VerifyModal({ eventId, onClose }) {
  const [loading, setLoading] = useState(true);
  const [verificationData, setVerificationData] = useState(null);
  const [error, setError] = useState(null);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    let isMounted = true;
    async function fetchVerification() {
      try {
        setLoading(true);
        const res = await fetch(`${API_BASE}/api/blockchain/verify/${eventId}`);
        if (!res.ok) {
          throw new Error(`HTTP ${res.status}: Failed to verify audit record`);
        }
        const data = await res.json();
        if (isMounted) {
          setVerificationData(data);
          setError(null);
        }
      } catch (err) {
        if (isMounted) {
          setError(err.message || "Failed to connect to verification server");
        }
      } finally {
        if (isMounted) setLoading(false);
      }
    }

    if (eventId) {
      fetchVerification();
    }
    return () => { isMounted = false; };
  }, [eventId]);

  const handleCopyHash = (text) => {
    if (text) {
      navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const record = verificationData?.record;
  const isAuthentic = verificationData?.isAuthentic;
  const onChain = verificationData?.onChainVerified;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-md px-4" onClick={onClose}>
      <div
        className="w-full max-w-2xl bg-[#0b0f19] border border-slate-800 rounded-2xl p-6 shadow-2xl relative animate-slide-up"
        onClick={(e) => e.stopPropagation()}
      >
        <button
          onClick={onClose}
          className="absolute top-4 right-4 text-slate-500 hover:text-white transition-colors"
        >
          <XCircle className="h-6 w-6" />
        </button>

        <div className="flex items-center gap-2 border-b border-slate-800 pb-3 mb-5">
          <Database className="h-5 w-5 text-cyber-accent" />
          <div>
            <h3 className="font-extrabold uppercase text-sm tracking-wider font-mono-tech text-white">
              Cryptographic Audit Verification
            </h3>
            <p className="text-[10px] text-slate-500 font-mono-tech">
              Zero-knowledge proof & SHA-256 data integrity check against immutable storage
            </p>
          </div>
        </div>

        {loading ? (
          <div className="py-16 flex flex-col items-center justify-center gap-3 text-slate-400">
            <RefreshCw className="h-8 w-8 animate-spin text-cyber-accent" />
            <span className="text-xs font-mono-tech">Querying MongoDB and Hardhat EVM node...</span>
          </div>
        ) : error ? (
          <div className="py-8 font-mono-tech text-xs space-y-4">
            <div className="flex items-center gap-3 bg-rose-950/30 border border-rose-900/50 p-4 rounded-xl text-rose-400">
              <AlertTriangle className="h-6 w-6 shrink-0" />
              <div>
                <h4 className="font-bold text-sm uppercase">Verification Query Failed</h4>
                <p className="text-[11px] text-rose-300 mt-0.5">{error}</p>
              </div>
            </div>
            <div className="flex justify-end pt-4 border-t border-slate-900">
              <button
                onClick={onClose}
                className="px-4 py-2 bg-slate-900 border border-slate-700 hover:bg-slate-800 text-xs text-slate-300 font-bold rounded"
              >
                CLOSE
              </button>
            </div>
          </div>
        ) : (
          <div className="font-mono-tech text-xs space-y-4">
            {isAuthentic ? (
              <div className="flex items-center gap-3 bg-emerald-950/30 border border-emerald-900/60 p-4 rounded-xl text-emerald-400">
                <CheckCircle2 className="h-6 w-6 shrink-0 text-emerald-400" />
                <div>
                  <h4 className="font-black text-sm uppercase flex items-center gap-2">
                    {onChain ? "Cryptographic Ledger Verified (On-Chain)" : "Audit Record Authenticated (MongoDB)"}
                  </h4>
                  <p className="text-[11px] text-emerald-500/90 mt-0.5">
                    {onChain
                      ? "SHA-256 state matches the Solidity smart contract on Hardhat EVM. Prediction record is authentic and tamper-proof."
                      : "Document integrity verified from MongoDB primary store. SHA-256 data hash computed and validated."}
                  </p>
                </div>
              </div>
            ) : (
              <div className="flex items-center gap-3 bg-rose-950/30 border border-rose-900/50 p-4 rounded-xl text-rose-400">
                <AlertTriangle className="h-6 w-6 shrink-0" />
                <div>
                  <h4 className="font-bold text-sm uppercase">Integrity Mismatch / Unverified</h4>
                  <p className="text-[11px] text-rose-300 mt-0.5">
                    The audit record hash could not be verified against the ledger.
                  </p>
                </div>
              </div>
            )}

            <div className="space-y-2 bg-slate-950/60 p-4 rounded-xl border border-slate-900 max-h-[320px] overflow-y-auto">
              {[
                { label: "Audit Event ID", value: record?.id || eventId, bold: true },
                { label: "Event Type", value: record?.eventType, color: record?.eventType === "CONFIRMED_ATTACK" ? "text-rose-400" : "text-cyan-400" },
                { label: "Attacker IP", value: record?.attackerIp || "N/A", color: "text-rose-400 font-bold" },
                { label: "Target / Host IP", value: record?.targetIp || record?.hostIp || "N/A", color: "text-white font-bold" },
                { label: "Classification", value: record?.classification || "None" },
                { label: "Evidence MITRE Stage", value: record?.mitreStage || "None", color: "text-amber-400 font-bold" },
                { label: "GRU Forecast Stage", value: record?.gruPredictedStage || "None", color: "text-cyan-400" },
                { label: "GRU Confidence", value: record?.gruConfidence != null ? `${(record.gruConfidence * 100).toFixed(1)}%` : "N/A" },
                { label: "Severity Level", value: record?.severity || "INFO", color: record?.severity === "CRITICAL" ? "text-rose-400 font-bold" : "text-slate-300" },
                { label: "Timestamp", value: record?.timestamp ? new Date(record.timestamp).toLocaleString() : "N/A" },
                { label: "On-Chain Block Number", value: record?.blockchainBlockNumber != null ? `#${record.blockchainBlockNumber}` : "Not Anchored (Non-Attack)", bold: true },
                { label: "Contract Address", value: verificationData?.contract?.address || "N/A" },
                { label: "Network", value: verificationData?.contract?.network || "Localhost" },
              ].map((row, i) => (
                <div key={i} className="flex justify-between items-center border-b border-slate-900/80 pb-1.5 text-[11px]">
                  <span className="text-slate-500">{row.label}</span>
                  <span className={`text-slate-300 ${row.color || ""} ${row.bold ? "font-bold text-white" : ""}`}>
                    {row.value}
                  </span>
                </div>
              ))}

              {record?.blockchainTxHash && (
                <div className="flex flex-col pt-1">
                  <div className="flex items-center justify-between text-slate-500 text-[10px]">
                    <span>Ethereum Transaction Hash</span>
                    <button
                      onClick={() => handleCopyHash(record.blockchainTxHash)}
                      className="text-cyber-accent hover:underline flex items-center gap-1 text-[10px]"
                    >
                      {copied ? <Check className="h-3 w-3" /> : <Copy className="h-3 w-3" />}
                      {copied ? "Copied" : "Copy"}
                    </button>
                  </div>
                  <span className="text-emerald-400 mt-1 select-all break-all bg-emerald-950/20 p-2 rounded border border-emerald-950/60 text-[10px]">
                    {record.blockchainTxHash}
                  </span>
                </div>
              )}

              {record?.blockchainDataHash && (
                <div className="flex flex-col pt-1">
                  <div className="flex items-center justify-between text-slate-500 text-[10px]">
                    <span>SHA-256 Document Fingerprint</span>
                  </div>
                  <span className="text-cyan-400 mt-1 select-all break-all bg-cyan-950/20 p-2 rounded border border-cyan-950/60 text-[10px]">
                    {record.blockchainDataHash}
                  </span>
                </div>
              )}
            </div>

            <div className="flex justify-end gap-2 mt-4 pt-4 border-t border-slate-900">
              <button
                onClick={onClose}
                className="px-5 py-2 bg-cyber-accent hover:bg-cyan-400 text-slate-950 font-bold text-xs rounded transition-colors"
              >
                CLOSE
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

export default function AuditTrail() {
  const [events, setEvents] = useState([]);
  const [summary, setSummary] = useState({
    totalEvents: 0,
    confirmedAttacks: 0,
    modelForecasts: 0,
    modelDisagreements: 0,
    systemEvents: 0,
    verifiedOnChain: 0,
    lastEvent: null,
  });
  const [hourlyActivity, setHourlyActivity] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Filters
  const [eventTypeFilter, setEventTypeFilter] = useState("ALL");
  const [mitreStageFilter, setMitreStageFilter] = useState("ALL");
  const [timeRangeFilter, setTimeRangeFilter] = useState("all");
  const [searchQuery, setSearchQuery] = useState("");
  const [verifyEventId, setVerifyEventId] = useState(null);

  // Fetch real audit data from Express backend
  const fetchAuditData = useCallback(async () => {
    try {
      setLoading(true);
      const params = new URLSearchParams();
      if (eventTypeFilter !== "ALL") params.append("eventType", eventTypeFilter);
      if (mitreStageFilter !== "ALL") params.append("mitreStage", mitreStageFilter);
      if (timeRangeFilter) params.append("timeRange", timeRangeFilter);
      if (searchQuery.trim()) params.append("search", searchQuery.trim());
      params.append("limit", "150");

      const res = await fetch(`${API_BASE}/api/audit?${params.toString()}`);
      if (!res.ok) {
        throw new Error(`HTTP ${res.status}: Failed to load audit trail`);
      }
      const data = await res.json();
      setEvents(data.events || []);
      setSummary(data.summary || {
        totalEvents: 0,
        confirmedAttacks: 0,
        modelForecasts: 0,
        modelDisagreements: 0,
        systemEvents: 0,
        verifiedOnChain: 0,
        lastEvent: null,
      });
      setHourlyActivity(data.hourlyActivity || []);
      setError(null);
    } catch (err) {
      console.error("Failed to fetch audit data:", err);
      setError(err.message || "Failed to connect to backend audit API");
    } finally {
      setLoading(false);
    }
  }, [eventTypeFilter, mitreStageFilter, timeRangeFilter, searchQuery]);

  // Initial load and filter change trigger
  useEffect(() => {
    fetchAuditData();
  }, [fetchAuditData]);

  // Listen for real-time audit event socket updates
  useEffect(() => {
    let socket;
    try {
      socket = io(API_BASE, { transports: ["websocket", "polling"] });
      socket.on("audit_event", (newEvent) => {
        setEvents((prev) => [newEvent, ...prev.slice(0, 149)]);
        setSummary((prev) => ({
          ...prev,
          totalEvents: prev.totalEvents + 1,
          confirmedAttacks: newEvent.eventType === "CONFIRMED_ATTACK" ? prev.confirmedAttacks + 1 : prev.confirmedAttacks,
          modelForecasts: newEvent.eventType === "MODEL_FORECAST" ? prev.modelForecasts + 1 : prev.modelForecasts,
          modelDisagreements: newEvent.eventType === "MODEL_EVIDENCE_DISAGREEMENT" ? prev.modelDisagreements + 1 : prev.modelDisagreements,
          systemEvents: newEvent.eventType === "SYSTEM_EVENT" ? prev.systemEvents + 1 : prev.systemEvents,
          verifiedOnChain: newEvent.chainStatus === "VERIFIED_ON_CHAIN" ? prev.verifiedOnChain + 1 : prev.verifiedOnChain,
          lastEvent: newEvent.timestamp,
        }));
      });
    } catch (err) {
      console.warn("Socket.io audit listener failed:", err);
    }

    return () => {
      if (socket) socket.disconnect();
    };
  }, []);

  const clearFilters = () => {
    setEventTypeFilter("ALL");
    setMitreStageFilter("ALL");
    setTimeRangeFilter("all");
    setSearchQuery("");
  };

  return (
    <div className="space-y-6 animate-fade-in font-mono-tech pb-12">
      {/* Header */}
      <section className="glass-card rounded-xl border border-slate-800/60 p-5 bg-gradient-to-r from-slate-950 via-[#0b0f19] to-slate-950">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="p-3 bg-emerald-950/40 border border-emerald-800/60 rounded-xl">
              <Database className="h-6 w-6 text-emerald-400" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-base font-extrabold uppercase tracking-wider text-white">
                  Security Event Audit Trail & Ledger
                </h2>
                <span className="text-[10px] bg-emerald-950/60 border border-emerald-800/60 text-emerald-400 px-2 py-0.5 rounded-full font-bold">
                  PERSISTENT
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-0.5">
                Real-time security telemetry persisted in MongoDB with cryptographic Hardhat smart contract verification
              </p>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={fetchAuditData}
              disabled={loading}
              className="flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-slate-900 border border-slate-700 hover:bg-slate-800 text-xs text-slate-200 transition-all active:scale-95 disabled:opacity-50"
            >
              <RefreshCw className={`h-3.5 w-3.5 text-cyber-accent ${loading ? "animate-spin" : ""}`} />
              <span>Refresh Ledger</span>
            </button>
            <div className="flex items-center gap-2 bg-emerald-950/30 border border-emerald-900/60 px-3.5 py-2 rounded-lg text-xs text-emerald-400">
              <Lock className="h-3.5 w-3.5" />
              <span className="font-bold">MONGODB & HARDHAT SYNCED</span>
            </div>
          </div>
        </div>
      </section>

      {/* Summary KPI Cards */}
      <section className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
        <div className="glass-card rounded-xl border border-slate-800/60 p-4 bg-slate-950/60">
          <div className="flex items-center justify-between">
            <p className="text-[10px] uppercase tracking-wider text-slate-400 font-bold">Total Events</p>
            <Database className="h-4 w-4 text-slate-400 opacity-60" />
          </div>
          <p className="text-2xl font-black mt-2 text-white">{summary.totalEvents}</p>
          <span className="text-[9px] text-slate-500">Persisted in MongoDB</span>
        </div>

        <div className="glass-card rounded-xl border border-rose-900/40 p-4 bg-rose-950/10">
          <div className="flex items-center justify-between">
            <p className="text-[10px] uppercase tracking-wider text-rose-400 font-bold">Confirmed Attacks</p>
            <ShieldAlert className="h-4 w-4 text-rose-400 opacity-80" />
          </div>
          <p className="text-2xl font-black mt-2 text-rose-400">{summary.confirmedAttacks}</p>
          <span className="text-[9px] text-rose-500/70">Verified Heuristics</span>
        </div>

        <div className="glass-card rounded-xl border border-cyan-900/40 p-4 bg-cyan-950/10">
          <div className="flex items-center justify-between">
            <p className="text-[10px] uppercase tracking-wider text-cyan-400 font-bold">Model Forecasts</p>
            <Cpu className="h-4 w-4 text-cyan-400 opacity-80" />
          </div>
          <p className="text-2xl font-black mt-2 text-cyan-400">{summary.modelForecasts}</p>
          <span className="text-[9px] text-cyan-500/70">GRU Stage Predictions</span>
        </div>

        <div className="glass-card rounded-xl border border-amber-900/40 p-4 bg-amber-950/10">
          <div className="flex items-center justify-between">
            <p className="text-[10px] uppercase tracking-wider text-amber-400 font-bold">Model Disagreements</p>
            <AlertTriangle className="h-4 w-4 text-amber-400 opacity-80" />
          </div>
          <p className="text-2xl font-black mt-2 text-amber-400">{summary.modelDisagreements}</p>
          <span className="text-[9px] text-amber-500/70">Evidence Overrides</span>
        </div>

        <div className="glass-card rounded-xl border border-emerald-900/40 p-4 bg-emerald-950/10">
          <div className="flex items-center justify-between">
            <p className="text-[10px] uppercase tracking-wider text-emerald-400 font-bold">On-Chain Verified</p>
            <ShieldCheck className="h-4 w-4 text-emerald-400 opacity-80" />
          </div>
          <p className="text-2xl font-black mt-2 text-emerald-400">{summary.verifiedOnChain}</p>
          <span className="text-[9px] text-emerald-500/70">Hardhat EVM Anchored</span>
        </div>

        <div className="glass-card rounded-xl border border-slate-800/60 p-4 bg-slate-950/60">
          <div className="flex items-center justify-between">
            <p className="text-[10px] uppercase tracking-wider text-slate-400 font-bold">Last Event</p>
            <Clock className="h-4 w-4 text-slate-400 opacity-60" />
          </div>
          <p className="text-xs font-bold mt-3 text-slate-200 truncate">
            {summary.lastEvent
              ? new Date(typeof summary.lastEvent === "object" ? summary.lastEvent.timestamp : summary.lastEvent).toLocaleTimeString()
              : "No events yet"}
          </p>
          <span className="text-[9px] text-slate-500">
            {summary.lastEvent
              ? new Date(typeof summary.lastEvent === "object" ? summary.lastEvent.timestamp : summary.lastEvent).toLocaleDateString()
              : "System initialized"}
          </span>
        </div>
      </section>

      {/* Real Chart + Architecture Overview */}
      <section className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left: Real Event Frequency Chart */}
        <div className="lg:col-span-7 glass-card rounded-xl border border-slate-800/60 p-5 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-2">
                <Clock className="h-4 w-4 text-indigo-400" />
                <h3 className="text-xs font-bold uppercase tracking-wider text-white">
                  6-Hour Security Event Timeline
                </h3>
              </div>
              <span className="text-[10px] text-slate-500">Aggregated from MongoDB</span>
            </div>

            <div className="h-[220px] w-full mt-2">
              {summary.totalEvents === 0 ? (
                <div className="h-full flex flex-col items-center justify-center border border-dashed border-slate-800 rounded-xl bg-slate-950/30 text-slate-500 text-center px-4">
                  <Database className="h-8 w-8 mb-2 opacity-30 text-cyan-400" />
                  <p className="text-xs font-bold text-slate-400">No Historical Security Events in this Period</p>
                  <p className="text-[10px] text-slate-600 mt-1 max-w-sm">
                    Events are automatically recorded when packet capture observes traffic and generates confirmed attacks or GRU forecasts.
                  </p>
                </div>
              ) : (
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={hourlyActivity} margin={{ top: 10, right: 10, left: -15, bottom: 0 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.03)" />
                    <XAxis dataKey="hour" tick={{ fontSize: 10, fill: "#94a3b8" }} />
                    <YAxis tick={{ fontSize: 9, fill: "#64748b" }} allowDecimals={false} />
                    <Tooltip
                      contentStyle={{
                        backgroundColor: "#0b0f19",
                        border: "1px solid #1e293b",
                        borderRadius: 8,
                        fontSize: 11,
                        color: "#fff"
                      }}
                    />
                    <Legend wrapperStyle={{ fontSize: "10px", paddingTop: "8px" }} />
                    <Bar dataKey="attacks" fill="#f43f5e" name="Confirmed Attacks" radius={[3, 3, 0, 0]} />
                    <Bar dataKey="forecasts" fill="#06b6d4" name="Model Forecasts" radius={[3, 3, 0, 0]} />
                    <Bar dataKey="disagreements" fill="#f59e0b" name="Disagreements" radius={[3, 3, 0, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              )}
            </div>
          </div>
        </div>

        {/* Right: Architecture & Cryptographic Integrity Card */}
        <div className="lg:col-span-5 glass-card rounded-xl border border-slate-800/60 p-5 flex flex-col justify-between">
          <div>
            <div className="flex items-center gap-2 mb-3">
              <ShieldCheck className="h-4 w-4 text-emerald-400" />
              <h3 className="text-xs font-bold uppercase tracking-wider text-white">
                Cryptographic Audit Architecture
              </h3>
            </div>
            <div className="space-y-2.5">
              {[
                {
                  step: "01",
                  title: "Telemetry & Flow Extraction",
                  desc: "Live packet capture extracts 14 real-time flow features across 5-second sliding windows.",
                  color: "text-cyan-400",
                  bg: "border-cyan-950/60 bg-cyan-950/20"
                },
                {
                  step: "02",
                  title: "GRU Inference & Heuristic Verification",
                  desc: "GRU model predicts MITRE stage; active attack engine confirms genuine anomalies.",
                  color: "text-indigo-400",
                  bg: "border-indigo-950/60 bg-indigo-950/20"
                },
                {
                  step: "03",
                  title: "Immutable MongoDB Document Store",
                  desc: "Every security event is logged with SHA-256 fingerprint, capture session ID, and telemetry.",
                  color: "text-amber-400",
                  bg: "border-amber-950/60 bg-amber-950/20"
                },
                {
                  step: "04",
                  title: "Ethereum Smart Contract Anchoring",
                  desc: "Confirmed attacks are automatically committed to ForecastRegistry.sol on Hardhat node.",
                  color: "text-emerald-400",
                  bg: "border-emerald-950/60 bg-emerald-950/20"
                },
              ].map((item, i) => (
                <div key={i} className={`flex items-start gap-3 p-2.5 rounded-lg border ${item.bg}`}>
                  <span className={`text-base font-black ${item.color}`}>{item.step}</span>
                  <div>
                    <p className="text-xs font-bold text-white">{item.title}</p>
                    <p className="text-[10px] text-slate-400 mt-0.5 leading-relaxed">{item.desc}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </section>

      {/* Filter and Search Bar */}
      <section className="glass-card rounded-xl border border-slate-800/60 p-4 space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex flex-wrap items-center gap-3">
            {/* Event Type Dropdown */}
            <div className="flex items-center gap-1.5 bg-slate-900 border border-slate-800 rounded-lg px-3 py-1.5">
              <Filter className="h-3.5 w-3.5 text-slate-400" />
              <label className="text-[10px] uppercase text-slate-400 font-bold">Event Type:</label>
              <select
                value={eventTypeFilter}
                onChange={(e) => setEventTypeFilter(e.target.value)}
                className="bg-transparent text-xs text-white outline-none cursor-pointer"
              >
                <option value="ALL" className="bg-slate-900">All Events</option>
                <option value="CONFIRMED_ATTACK" className="bg-slate-900 text-rose-400">Confirmed Attack</option>
                <option value="MODEL_FORECAST" className="bg-slate-900 text-cyan-400">Model Forecast</option>
                <option value="MODEL_EVIDENCE_DISAGREEMENT" className="bg-slate-900 text-amber-400">Model Disagreement</option>
                <option value="SYSTEM_EVENT" className="bg-slate-900 text-slate-300">System Event</option>
              </select>
            </div>

            {/* MITRE Stage Dropdown */}
            <div className="flex items-center gap-1.5 bg-slate-900 border border-slate-800 rounded-lg px-3 py-1.5">
              <Layers className="h-3.5 w-3.5 text-slate-400" />
              <label className="text-[10px] uppercase text-slate-400 font-bold">MITRE Stage:</label>
              <select
                value={mitreStageFilter}
                onChange={(e) => setMitreStageFilter(e.target.value)}
                className="bg-transparent text-xs text-white outline-none cursor-pointer"
              >
                <option value="ALL" className="bg-slate-900">All Stages</option>
                <option value="Reconnaissance" className="bg-slate-900">Reconnaissance</option>
                <option value="Initial Access" className="bg-slate-900">Initial Access</option>
                <option value="Execution" className="bg-slate-900">Execution</option>
                <option value="Persistence" className="bg-slate-900">Persistence</option>
                <option value="Lateral Movement" className="bg-slate-900">Lateral Movement</option>
                <option value="Command and Control" className="bg-slate-900">Command and Control</option>
                <option value="Exfiltration" className="bg-slate-900">Exfiltration</option>
                <option value="Impact" className="bg-slate-900">Impact</option>
              </select>
            </div>

            {/* Time Range Filter Buttons */}
            <div className="flex items-center bg-slate-900 border border-slate-800 rounded-lg p-0.5">
              {[
                { id: "1h", label: "1h" },
                { id: "6h", label: "6h" },
                { id: "24h", label: "24h" },
                { id: "7d", label: "7d" },
                { id: "all", label: "All Time" },
              ].map((t) => (
                <button
                  key={t.id}
                  onClick={() => setTimeRangeFilter(t.id)}
                  className={`px-2.5 py-1 text-[10px] font-bold rounded transition-colors ${
                    timeRangeFilter === t.id
                      ? "bg-cyber-accent text-slate-950"
                      : "text-slate-400 hover:text-white"
                  }`}
                >
                  {t.label}
                </button>
              ))}
            </div>

            {(eventTypeFilter !== "ALL" || mitreStageFilter !== "ALL" || timeRangeFilter !== "all" || searchQuery) && (
              <button
                onClick={clearFilters}
                className="text-[10px] text-slate-400 hover:text-white underline cursor-pointer"
              >
                Reset Filters
              </button>
            )}
          </div>

          {/* Search Input */}
          <div className="flex items-center gap-2 bg-slate-900 border border-slate-800 rounded-lg px-3 py-1.5 w-full md:w-64">
            <Search className="h-3.5 w-3.5 text-slate-400 shrink-0" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search IP, Stage, Tx Hash..."
              className="bg-transparent text-xs text-white placeholder:text-slate-600 outline-none w-full"
            />
            {searchQuery && (
              <button onClick={() => setSearchQuery("")} className="text-slate-500 hover:text-white text-[10px]">
                ✕
              </button>
            )}
          </div>
        </div>
      </section>

      {/* Audit Log Table */}
      <section className="glass-card rounded-xl border border-slate-800/60 p-5">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <ShieldAlert className="h-4 w-4 text-cyber-accent" />
            <h3 className="text-xs font-bold uppercase tracking-wider text-white">
              Historical Audit Log
            </h3>
            <span className="text-[10px] text-slate-400 bg-slate-900 border border-slate-800 px-2 py-0.5 rounded font-bold">
              {events.length} records returned
            </span>
          </div>
          {events.length > 0 && (
            <span className="text-[10px] text-slate-500">
              Showing latest {events.length} immutable events
            </span>
          )}
        </div>

        {loading ? (
          <div className="py-16 flex flex-col items-center justify-center gap-2 text-slate-500">
            <RefreshCw className="h-6 w-6 animate-spin text-cyber-accent" />
            <span className="text-xs">Querying historical records from MongoDB...</span>
          </div>
        ) : error ? (
          <div className="py-8 text-center text-rose-400">
            <AlertTriangle className="h-6 w-6 mx-auto mb-2 opacity-80" />
            <p className="text-xs font-bold">{error}</p>
          </div>
        ) : events.length === 0 ? (
          <div className="py-16 text-center text-slate-500 border border-dashed border-slate-800 rounded-xl bg-slate-950/20">
            <Database className="h-8 w-8 mx-auto mb-2 opacity-30 text-slate-400" />
            <p className="text-xs font-bold text-slate-400">No Audit Trail Records Found</p>
            <p className="text-[10px] text-slate-600 mt-1 max-w-sm mx-auto">
              No events matched the selected filters. Start a live packet capture or trigger security actions to generate persistent records.
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-[11px]">
              <thead>
                <tr className="border-b border-slate-800 text-slate-500 uppercase tracking-widest text-[9px]">
                  <th className="py-3 px-2">Timestamp</th>
                  <th className="px-2">Event Type</th>
                  <th className="px-2">Attacker / Src</th>
                  <th className="px-2">Target / Host</th>
                  <th className="px-2">Classification</th>
                  <th className="px-2">MITRE Stage</th>
                  <th className="px-2">GRU Forecast</th>
                  <th className="px-2">Severity</th>
                  <th className="px-2">Chain Status</th>
                  <th className="text-right py-3 px-2">Verification</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-900/80">
                {events.map((evt, idx) => {
                  const isConfirmed = evt.eventType === "CONFIRMED_ATTACK";
                  const isForecast = evt.eventType === "MODEL_FORECAST";
                  const isDisagreement = evt.eventType === "MODEL_EVIDENCE_DISAGREEMENT";
                  const isSystem = evt.eventType === "SYSTEM_EVENT";
                  const isOnChain = evt.chainStatus === "VERIFIED_ON_CHAIN" || !!evt.blockchainTxHash;

                  return (
                    <tr key={evt._id || idx} className="hover:bg-slate-900/40 transition-colors">
                      {/* Timestamp */}
                      <td className="py-3 px-2 text-slate-400 whitespace-nowrap text-[10px]">
                        {new Date(evt.timestamp).toLocaleString()}
                      </td>

                      {/* Event Type */}
                      <td className="px-2 whitespace-nowrap">
                        <span className={`px-2 py-0.5 rounded text-[9px] font-extrabold uppercase border ${
                          isConfirmed ? "bg-rose-950/60 border-rose-800/80 text-rose-400" :
                          isForecast ? "bg-cyan-950/60 border-cyan-800/80 text-cyan-400" :
                          isDisagreement ? "bg-amber-950/60 border-amber-800/80 text-amber-400" :
                          "bg-slate-900 border-slate-700 text-slate-300"
                        }`}>
                          {evt.eventType ? evt.eventType.replace(/_/g, " ") : "UNKNOWN"}
                        </span>
                      </td>

                      {/* Attacker / Source */}
                      <td className="px-2 font-mono-tech whitespace-nowrap">
                        {evt.attackerIp ? (
                          <span className="text-rose-400 font-bold">{evt.attackerIp}</span>
                        ) : evt.sourceIp ? (
                          <span className="text-slate-300">{evt.sourceIp}</span>
                        ) : (
                          <span className="text-slate-600">N/A</span>
                        )}
                      </td>

                      {/* Target / Host */}
                      <td className="px-2 font-mono-tech whitespace-nowrap">
                        {evt.targetIp ? (
                          <span className="text-white font-bold">{evt.targetIp}</span>
                        ) : evt.hostIp ? (
                          <span className="text-slate-300">{evt.hostIp}</span>
                        ) : (
                          <span className="text-slate-600">N/A</span>
                        )}
                      </td>

                      {/* Classification */}
                      <td className="px-2 whitespace-nowrap">
                        <span className="text-slate-200 font-semibold">{evt.classification || "Normal Telemetry"}</span>
                      </td>

                      {/* MITRE Stage */}
                      <td className="px-2 whitespace-nowrap">
                        <span className={`px-2 py-0.5 rounded text-[9px] font-bold ${
                          evt.mitreStage === "Exfiltration" || evt.mitreStage === "Impact"
                            ? "bg-rose-950/50 border border-rose-900/50 text-rose-400" :
                          evt.mitreStage === "Lateral Movement" || evt.mitreStage === "Command and Control" || evt.mitreStage === "Command & Control"
                            ? "bg-amber-950/50 border border-amber-900/50 text-amber-400" :
                          evt.mitreStage === "Execution" || evt.mitreStage === "Initial Access" || evt.mitreStage === "Reconnaissance"
                            ? "bg-cyan-950/50 border border-cyan-900/50 text-cyan-400" :
                          "bg-slate-900 border border-slate-800 text-slate-400"
                        }`}>
                          {evt.mitreStage || "None"}
                        </span>
                      </td>

                      {/* GRU Forecast */}
                      <td className="px-2 whitespace-nowrap">
                        {evt.gruPredictedStage ? (
                          <div className="flex items-center gap-1.5">
                            <span className="text-cyan-400 font-semibold">{evt.gruPredictedStage}</span>
                            {evt.gruConfidence != null && (
                              <span className="text-[10px] text-slate-400">
                                ({(evt.gruConfidence * 100).toFixed(0)}%)
                              </span>
                            )}
                          </div>
                        ) : (
                          <span className="text-slate-600">N/A</span>
                        )}
                      </td>

                      {/* Severity */}
                      <td className="px-2 whitespace-nowrap">
                        <span className={`px-2 py-0.5 rounded text-[9px] font-extrabold uppercase border ${
                          evt.severity === "CRITICAL" ? "bg-rose-950/50 text-rose-400 border-rose-900/50" :
                          evt.severity === "HIGH" ? "bg-amber-950/50 text-amber-400 border-amber-900/50" :
                          evt.severity === "MEDIUM" ? "bg-cyan-950/50 text-cyan-400 border-cyan-900/50" :
                          "bg-slate-900 text-slate-400 border-slate-800"
                        }`}>
                          {evt.severity || "INFO"}
                        </span>
                      </td>

                      {/* Chain Status */}
                      <td className="px-2 whitespace-nowrap">
                        {isOnChain ? (
                          <div className="flex items-center gap-1 text-emerald-400 font-bold" title={evt.blockchainTxHash}>
                            <CheckCircle2 className="h-3 w-3 shrink-0" />
                            <span className="text-[10px]">
                              {evt.blockchainTxHash ? `${evt.blockchainTxHash.slice(0, 10)}...` : "ON-CHAIN"}
                            </span>
                          </div>
                        ) : isSystem ? (
                          <span className="text-slate-500 text-[10px]">SYSTEM LOG</span>
                        ) : (
                          <span className="text-slate-500 text-[10px]">MONGODB</span>
                        )}
                      </td>

                      {/* Action */}
                      <td className="text-right py-3 px-2 whitespace-nowrap">
                        <button
                          onClick={() => setVerifyEventId(evt._id)}
                          className="px-2.5 py-1 rounded bg-slate-900 border border-slate-700 hover:bg-slate-800 text-[10px] text-slate-200 transition-colors flex items-center gap-1.5 ml-auto font-mono-tech active:scale-95"
                        >
                          <Database className="h-3 w-3 text-emerald-400" />
                          <span>Verify Audit</span>
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {/* Verification Modal */}
      {verifyEventId && (
        <VerifyModal
          eventId={verifyEventId}
          onClose={() => setVerifyEventId(null)}
        />
      )}
    </div>
  );
}
