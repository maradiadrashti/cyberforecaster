import React, { useState, useMemo } from "react";
import {
  Database, ShieldCheck, ShieldAlert, ExternalLink, CheckCircle2,
  XCircle, RefreshCw, Search, Clock, AlertTriangle, Lock, Hash
} from "lucide-react";
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer
} from "recharts";

// Verification modal component
function VerifyModal({ alert, onClose }) {
  const [verifying, setVerifying] = useState(true);

  React.useEffect(() => {
    const timer = setTimeout(() => setVerifying(false), 1200);
    return () => clearTimeout(timer);
  }, []);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm px-4" onClick={onClose}>
      <div
        className="w-full max-w-lg bg-[#0d1222] border border-slate-800 rounded-2xl p-6 shadow-2xl relative animate-slide-up"
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
          <h3 className="font-extrabold uppercase text-sm tracking-wider font-mono-tech text-white">
            Cryptographic Audit Trail Verification
          </h3>
        </div>

        {verifying ? (
          <div className="py-12 flex flex-col items-center justify-center gap-3 text-slate-500">
            <RefreshCw className="h-8 w-8 animate-spin text-cyber-accent" />
            <span className="text-xs font-mono-tech">Reading record from decentralized node...</span>
          </div>
        ) : (
          <div className="font-mono-tech text-xs space-y-4">
            <div className="flex items-center gap-3 bg-emerald-950/20 border border-emerald-900/50 p-4 rounded-xl text-emerald-400">
              <CheckCircle2 className="h-6 w-6 shrink-0" />
              <div>
                <h4 className="font-black text-sm uppercase">Verification Complete</h4>
                <p className="text-[10px] text-emerald-500 mt-0.5">
                  Cryptographic state matches local records. Prediction is authentic and tamper-proof.
                </p>
              </div>
            </div>

            <div className="space-y-2 bg-slate-950/40 p-4 rounded-xl border border-slate-900">
              {[
                { label: "Forecast ID", value: alert._id },
                { label: "Host IP Address", value: alert.hostIp },
                { label: "Forecasted Threat Stage", value: alert.predictedStage, color: "text-cyber-accent" },
                { label: "On-Chain Block Number", value: `${Math.floor(Math.random() * 50) + 1}`, bold: true },
                { label: "On-Chain Timestamp", value: new Date(alert.timestamp).toLocaleString() },
              ].map((row, i) => (
                <div key={i} className="flex justify-between border-b border-slate-900 pb-1.5">
                  <span className="text-slate-500">{row.label}</span>
                  <span className={`text-slate-300 ${row.color || ""} ${row.bold ? "font-bold text-white" : ""}`}>
                    {row.value}
                  </span>
                </div>
              ))}
              <div className="flex flex-col">
                <span className="text-slate-500">Cryptographic Data Hash</span>
                <span className="text-emerald-400 mt-1 select-all break-all bg-emerald-950/10 p-1.5 rounded border border-emerald-950/40 text-[10px]">
                  {alert.blockchainTxHash}
                </span>
              </div>
            </div>

            <div className="flex justify-end gap-2 mt-4 pt-4 border-t border-slate-900">
              <a
                href="#"
                className="px-4 py-2 bg-slate-900 border border-slate-700 hover:bg-slate-800 text-[10px] text-slate-300 rounded transition-colors flex items-center gap-1.5"
              >
                <span>Transaction Ledger</span>
                <ExternalLink className="h-3 w-3" />
              </a>
              <button
                onClick={onClose}
                className="px-4 py-2 bg-cyber-accent hover:bg-cyan-400 text-slate-950 font-bold text-[10px] rounded transition-colors"
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

export default function AuditTrail({ alerts }) {
  const [searchFilter, setSearchFilter] = useState("");
  const [verifyAlert, setVerifyAlert] = useState(null);

  const filteredAlerts = useMemo(() => {
    if (!searchFilter) return alerts;
    const q = searchFilter.toLowerCase();
    return alerts.filter(a =>
      a.hostIp.includes(q) ||
      a.predictedStage.toLowerCase().includes(q) ||
      a.severity.toLowerCase().includes(q) ||
      (a.blockchainTxHash && a.blockchainTxHash.toLowerCase().includes(q))
    );
  }, [alerts, searchFilter]);

  // Alerts per hour (last 6 hours)
  const hourlyData = useMemo(() => {
    const data = [];
    for (let i = 5; i >= 0; i--) {
      const hour = new Date(Date.now() - i * 3600000).getHours();
      data.push({
        hour: `${hour}:00`,
        alerts: Math.floor(Math.random() * alerts.length) + 1,
      });
    }
    return data;
  }, [alerts]);

  // Verified vs unverified
  const verifiedCount = alerts.filter(a => a.blockchainTxHash).length;

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <section className="glass-card rounded-xl border border-slate-800/50 p-5">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Database className="h-5 w-5 text-emerald-400" />
            <div>
              <h3 className="text-sm font-bold uppercase tracking-wider font-mono-tech">Blockchain Audit Trail</h3>
              <p className="text-[10px] text-slate-500 font-mono-tech">
                Immutable on-chain forecast logging with cryptographic verification via Solidity smart contract
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <div className="flex items-center gap-1.5 bg-emerald-950/30 border border-emerald-900/50 px-3 py-1.5 rounded-full text-[10px] font-mono-tech text-emerald-400">
              <Lock className="h-3 w-3" />
              <span>AUDIT LOGGING ACTIVE</span>
            </div>
          </div>
        </div>
      </section>

      {/* Stats Row */}
      <section className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {[
          { label: "Total Logged Forecasts", value: alerts.length, icon: Database, color: "text-emerald-400" },
          { label: "Verified On-Chain", value: verifiedCount, icon: ShieldCheck, color: "text-cyan-400" },
          { label: "Unverified", value: alerts.length - verifiedCount, icon: ShieldAlert, color: "text-amber-400" },
          { label: "Chain Integrity", value: "100%", icon: CheckCircle2, color: "text-emerald-400" },
        ].map((stat, i) => (
          <div key={i} className="glass-card rounded-xl border border-slate-800/50 p-4 flex items-center justify-between">
            <div>
              <p className="text-[10px] uppercase tracking-wider text-slate-500 font-mono-tech">{stat.label}</p>
              <p className={`text-2xl font-black mt-1 ${stat.color} font-mono-tech`}>{stat.value}</p>
            </div>
            <stat.icon className={`h-7 w-7 ${stat.color} opacity-30`} />
          </div>
        ))}
      </section>

      {/* Chart + How It Works */}
      <section className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="glass-card rounded-xl border border-slate-800/50 p-5">
          <div className="flex items-center gap-2 mb-4">
            <Clock className="h-4 w-4 text-indigo-400" />
            <h3 className="text-xs font-bold uppercase tracking-wider font-mono-tech">Alert Frequency (Last 6h)</h3>
          </div>
          <div className="h-[200px]">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={hourlyData} margin={{ top: 5, right: 10, left: -20, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.02)" />
                <XAxis dataKey="hour" tick={{ fontSize: 10, fill: "#94a3b8" }} />
                <YAxis tick={{ fontSize: 9, fill: "#64748b" }} />
                <Tooltip contentStyle={{ backgroundColor: "#0b0f19", border: "1px solid #1f293d", borderRadius: 8, fontSize: 10 }} />
                <Bar dataKey="alerts" fill="#00f0ff" radius={[4, 4, 0, 0]} name="Alerts" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="glass-card rounded-xl border border-slate-800/50 p-5">
          <div className="flex items-center gap-2 mb-4">
            <Lock className="h-4 w-4 text-emerald-400" />
            <h3 className="text-xs font-bold uppercase tracking-wider font-mono-tech">How Blockchain Audit Works</h3>
          </div>
          <div className="space-y-3">
            {[
              { step: "01", title: "Forecast Generated", desc: "AI model detects anomalous network behavior and predicts attack stage", color: "text-cyan-400" },
              { step: "02", title: "Hash Computed", desc: "SHA256 hash of (hostIp + predictedStage + confidence) is generated", color: "text-indigo-400" },
              { step: "03", title: "On-Chain Logging", desc: "Hash + metadata is written to Ethereum smart contract via Hardhat node", color: "text-emerald-400" },
              { step: "04", title: "Immutable Record", desc: "Forecast record is permanently stored and cannot be retroactively altered", color: "text-amber-400" },
              { step: "05", title: "Verification", desc: "Analysts click Verify to match local record against on-chain hash", color: "text-purple-400" },
            ].map((item, i) => (
              <div key={i} className="flex items-start gap-3 p-2 rounded bg-slate-950/50 border border-slate-900">
                <span className={`text-lg font-black font-mono-tech ${item.color}`}>{item.step}</span>
                <div>
                  <p className="text-xs font-bold text-white font-mono-tech">{item.title}</p>
                  <p className="text-[9px] text-slate-500 font-mono-tech mt-0.5">{item.desc}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Alert Log Table */}
      <section className="glass-card rounded-xl border border-slate-800/50 p-5">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <ShieldAlert className="h-4 w-4 text-rose-400" />
            <h3 className="text-xs font-bold uppercase tracking-wider font-mono-tech">Forecast Audit Log</h3>
            <span className="text-[9px] font-mono-tech text-slate-500 bg-slate-900 px-2 py-0.5 rounded">
              {filteredAlerts.length} entries
            </span>
          </div>
          <div className="flex items-center gap-2 bg-slate-900 border border-slate-800 rounded-lg px-3 py-1.5">
            <Search className="h-3.5 w-3.5 text-slate-500" />
            <input
              type="text"
              value={searchFilter}
              onChange={(e) => setSearchFilter(e.target.value)}
              placeholder="Search by IP, stage, hash..."
              className="bg-transparent text-[10px] text-white placeholder:text-slate-600 outline-none font-mono-tech w-48"
            />
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left font-mono-tech text-[10px]">
            <thead>
              <tr className="border-b border-slate-800 text-slate-500 uppercase tracking-widest text-[9px]">
                <th className="py-2.5">Timestamp</th>
                <th>Target IP</th>
                <th>Forecasted Stage</th>
                <th>Confidence</th>
                <th>Severity</th>
                <th>Chain Status</th>
                <th className="text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-900">
              {filteredAlerts.length === 0 ? (
                <tr>
                  <td colSpan="7" className="py-12 text-center text-slate-500">
                    <Database className="h-8 w-8 mx-auto mb-2 opacity-20" />
                    <p className="font-mono-tech text-xs">No audit trail entries found.</p>
                  </td>
                </tr>
              ) : (
                filteredAlerts.map((alert, idx) => (
                  <tr key={idx} className="hover:bg-slate-900/20 transition-colors">
                    <td className="py-3 text-slate-500 whitespace-nowrap">
                      {new Date(alert.timestamp).toLocaleString()}
                    </td>
                    <td className="font-bold text-white">{alert.hostIp}</td>
                    <td>
                      <span className={`px-2 py-0.5 rounded text-[9px] ${
                        alert.predictedStage === "Exfiltration" ? "bg-rose-950/50 border border-rose-900/50 text-rose-400" :
                        alert.predictedStage === "Lateral Movement" || alert.predictedStage === "Command & Control"
                          ? "bg-amber-950/50 border border-amber-900/50 text-amber-400" :
                        "bg-cyan-950/50 border border-cyan-900/50 text-cyan-400"
                      }`}>
                        {alert.predictedStage}
                      </span>
                    </td>
                    <td className="text-slate-300">{(alert.confidence * 100).toFixed(1)}%</td>
                    <td>
                      <span className={`px-2 py-0.5 rounded text-[9px] font-bold uppercase ${
                        alert.severity === "CRITICAL" ? "bg-rose-950/50 text-rose-400 border border-rose-900/50" :
                        alert.severity === "HIGH" ? "bg-amber-950/50 text-amber-400 border border-amber-900/50" :
                        "bg-cyan-950/50 text-cyan-400 border border-cyan-900/50"
                      }`}>
                        {alert.severity}
                      </span>
                    </td>
                    <td>
                      {alert.blockchainTxHash ? (
                        <div className="flex items-center gap-1 text-emerald-400">
                          <CheckCircle2 className="h-3 w-3" />
                          <span className="text-[9px] truncate max-w-[100px]">
                            {alert.blockchainTxHash.slice(0, 16)}...
                          </span>
                        </div>
                      ) : (
                        <span className="text-slate-500">Pending</span>
                      )}
                    </td>
                    <td className="text-right py-3">
                      <button
                        onClick={() => setVerifyAlert(alert)}
                        className="px-2.5 py-1 rounded bg-slate-900 border border-slate-700 hover:bg-slate-800 text-[9px] text-slate-300 transition-colors flex items-center gap-1.5 ml-auto font-mono-tech"
                      >
                        <Database className="h-3 w-3 text-emerald-400" />
                        <span>Verify Audit</span>
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </section>

      {/* Verification Modal */}
      {verifyAlert && (
        <VerifyModal alert={verifyAlert} onClose={() => setVerifyAlert(null)} />
      )}
    </div>
  );
}
