import React, { useState, useMemo } from "react";
import {
  Brain, BarChart3, Info, Zap, ArrowRight, Target,
  TrendingUp, AlertTriangle, ChevronRight
} from "lucide-react";
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  RadarChart, Radar, PolarGrid, PolarAngleAxis, PolarRadiusAxis
} from "recharts";
import {
  FEATURE_IMPORTANCE, STATE_FEATURES, STATE_FEATURES as SF,
  generateStateVector, STAGE_COLORS, MITRE_TECHNIQUES
} from "../demoData";

// Feature importance bar component
function FeatureBar({ name, value, description, index }) {
  const color = value > 0.8 ? "#ff0055" : value > 0.6 ? "#f59e0b" : value > 0.4 ? "#00f0ff" : "#22c55e";
  return (
    <div className="space-y-1">
      <div className="flex items-center justify-between">
        <span className="text-[10px] font-mono-tech text-slate-300">{name}</span>
        <span className="text-[10px] font-mono-tech font-bold" style={{ color }}>{(value * 100).toFixed(1)}%</span>
      </div>
      <div className="relative h-2 bg-slate-900 rounded-full overflow-hidden">
        <div
          className="h-full rounded-full transition-all duration-1000 ease-out"
          style={{ width: `${value * 100}%`, backgroundColor: color }}
        ></div>
        {/* Glow effect */}
        <div
          className="absolute top-0 left-0 h-full rounded-full opacity-40 blur-sm transition-all duration-1000"
          style={{ width: `${value * 100}%`, backgroundColor: color }}
        ></div>
      </div>
      <p className="text-[9px] text-slate-600 font-mono-tech">{description}</p>
    </div>
  );
}

// Network state vector display
function StateVectorDisplay({ features }) {
  return (
    <div className="grid grid-cols-2 gap-2">
      {features.map((f, i) => {
        const delta = f.value - f.previousValue;
        const isIncrease = delta > 0;
        return (
          <div key={i} className="flex items-center justify-between p-2 rounded bg-slate-950/50 border border-slate-900 text-[9px] font-mono-tech">
            <span className="text-slate-400 truncate">{f.name}</span>
            <div className="flex items-center gap-2">
              <span className="text-white font-bold">{f.value.toFixed(3)}</span>
              <span className={`font-bold ${isIncrease ? "text-rose-400" : "text-emerald-400"}`}>
                {isIncrease ? "▲" : "▼"}
              </span>
            </div>
          </div>
        );
      })}
    </div>
  );
}

export default function Explainability({ hosts, forecasts }) {
  const [selectedHost, setSelectedHost] = useState("");
  const internalHosts = hosts.filter(h => h.role !== "attacker");

  React.useEffect(() => {
    if (internalHosts.length > 0 && !selectedHost) {
      setSelectedHost(internalHosts[0].ip);
    }
  }, [internalHosts]);

  const stateVector = useMemo(() => generateStateVector(), [selectedHost]);
  const selectedForecast = forecasts[selectedHost] || { predictedStage: "Normal", confidence: 0.9 };
  const stage = selectedForecast.predictedStage;

  // Radar chart data from state vector
  const radarData = useMemo(() => {
    const important = ["syn_ratio", "port_entropy", "failed_connection_rate", "IAT_variance",
      "unique_dst_ports", "connection_rate", "rst_ratio", "mean_IAT"];
    return important.map(name => {
      const f = stateVector.find(s => s.name === name);
      return {
        feature: name.replace(/_/g, " ").replace(/\b\w/g, c => c.toUpperCase()),
        value: f ? f.value : 0,
        fullMark: 1,
      };
    });
  }, [stateVector]);

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Explainability Header */}
      <section className="glass-card rounded-xl border border-slate-800/50 p-5">
        <div className="flex items-center gap-3">
          <Brain className="h-5 w-5 text-purple-400" />
          <div>
            <h3 className="text-sm font-bold uppercase tracking-wider font-mono-tech">Model Explainability Engine</h3>
            <p className="text-[10px] text-slate-500 font-mono-tech">
              SHAP-style feature attribution and gradient saliency analysis for transparent AI decisions
            </p>
          </div>
        </div>
      </section>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Feature Importance Panel */}
        <div className="lg:col-span-5 glass-card rounded-xl border border-slate-800/50 p-5">
          <div className="flex items-center gap-2 mb-5">
            <BarChart3 className="h-4 w-4 text-cyan-400" />
            <h3 className="text-xs font-bold uppercase tracking-wider font-mono-tech">Feature Attribution (SHAP)</h3>
          </div>

          <div className="space-y-4">
            {FEATURE_IMPORTANCE.map((f, i) => (
              <FeatureBar key={i} index={i} {...f} />
            ))}
          </div>

          <div className="mt-5 p-3 rounded-lg bg-purple-950/15 border border-purple-900/30">
            <div className="flex items-center gap-2 mb-1">
              <Info className="h-3 w-3 text-purple-400" />
              <span className="text-[9px] text-purple-400 font-mono-tech uppercase font-bold">Method: Gradient Saliency</span>
            </div>
            <p className="text-[9px] text-slate-500 font-mono-tech">
              Uses PyTorch integrated gradients to attribute model output to input features. Higher values indicate features that most influenced the model's prediction.
            </p>
          </div>
        </div>

        {/* Right Column */}
        <div className="lg:col-span-7 space-y-6">
          {/* Current Prediction Explanation */}
          <div className="glass-card rounded-xl border border-slate-800/50 p-5">
            <div className="flex items-center gap-2 mb-4">
              <Target className="h-4 w-4 text-amber-400" />
              <h3 className="text-xs font-bold uppercase tracking-wider font-mono-tech">Why This Prediction?</h3>
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div className="p-4 rounded-lg bg-slate-950/50 border border-slate-900">
                <p className="text-[9px] text-slate-500 uppercase font-mono-tech mb-1">Predicted Stage</p>
                <p className="text-xl font-black font-mono-tech" style={{ color: STAGE_COLORS[stage] }}>
                  {stage}
                </p>
                <p className="text-[10px] text-slate-400 font-mono-tech mt-1">
                  Confidence: {(selectedForecast.confidence * 100).toFixed(1)}%
                </p>
              </div>
              <div className="p-4 rounded-lg bg-slate-950/50 border border-slate-900">
                <p className="text-[9px] text-slate-500 uppercase font-mono-tech mb-1">Key Contributing Features</p>
                <div className="space-y-1.5 mt-2">
                  {FEATURE_IMPORTANCE.slice(0, 3).map((f, i) => (
                    <div key={i} className="flex items-center gap-2 text-[9px] font-mono-tech">
                      <Zap className="h-3 w-3 text-amber-400" />
                      <span className="text-slate-300">{f.name}</span>
                      <span className="text-cyan-400 font-bold ml-auto">{(f.value * 100).toFixed(0)}%</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* Explanation text */}
            <div className="mt-4 p-3 rounded-lg bg-slate-950/50 border border-slate-900">
              <p className="text-[10px] text-slate-300 font-mono-tech leading-relaxed">
                {stage === "Reconnaissance" &&
                  "The model detected elevated port entropy and SYN ratio patterns consistent with network service discovery. The inter-arrival time variance dropped below normal thresholds, suggesting automated scanning tooling. These features collectively contributed to a Reconnaissance classification with high confidence."}
                {stage === "Initial Access" &&
                  "Failed connection rates spiked alongside elevated connection rates to non-standard ports. The packet size variance patterns and TCP flag distributions indicate potential exploitation attempts against public-facing services. Initial Access stage detected with significant confidence."}
                {stage === "Lateral Movement" &&
                  "The model identified unusual internal connection patterns with elevated RST ratios and abnormal TTL distributions. Multiple unique destination IPs from a single source suggest credential harvesting or pass-the-hash activity. Lateral Movement patterns detected with elevated risk."}
                {stage === "Command & Control" &&
                  "Sustained encrypted channel indicators and consistent connection intervals to external IPs suggest command and control communication. The IAT patterns are highly regular (automated), and port entropy is elevated. High confidence C2 channel classification."}
                {stage === "Exfiltration" &&
                  "Outbound data volumes are significantly elevated relative to baseline. The inbound/outbound ratio has inverted, and the model detects patterns consistent with data exfiltration over an established C2 channel. Critical threat level — immediate isolation recommended."}
                {stage === "Normal" &&
                  "All monitored network features are within normal operating parameters. Traffic patterns match baseline behavior. No anomalous indicators detected. The model maintains high confidence that current network state is benign."}
              </p>
            </div>
          </div>

          {/* Radar Chart + State Vector */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Radar chart */}
            <div className="glass-card rounded-xl border border-slate-800/50 p-5">
              <div className="flex items-center gap-2 mb-4">
                <TrendingUp className="h-4 w-4 text-cyan-400" />
                <h3 className="text-xs font-bold uppercase tracking-wider font-mono-tech">Feature Radar</h3>
              </div>
              <div className="h-[260px]">
                <ResponsiveContainer width="100%" height="100%">
                  <RadarChart data={radarData}>
                    <PolarGrid stroke="rgba(255,255,255,0.05)" />
                    <PolarAngleAxis
                      dataKey="feature"
                      tick={{ fontSize: 7, fill: "#64748b" }}
                    />
                    <PolarRadiusAxis tick={false} domain={[0, 1]} />
                    <Radar
                      dataKey="value"
                      stroke="#00f0ff"
                      fill="#00f0ff"
                      fillOpacity={0.15}
                      strokeWidth={1.5}
                    />
                  </RadarChart>
                </ResponsiveContainer>
              </div>
            </div>

            {/* Current State Vector */}
            <div className="glass-card rounded-xl border border-slate-800/50 p-5">
              <div className="flex items-center gap-2 mb-4">
                <Zap className="h-4 w-4 text-amber-400" />
                <h3 className="text-xs font-bold uppercase tracking-wider font-mono-tech">Current Network State S(t)</h3>
              </div>
              <div className="max-h-[280px] overflow-y-auto">
                <StateVectorDisplay features={stateVector.slice(0, 12)} />
              </div>
              <p className="text-[8px] text-slate-600 font-mono-tech mt-2">
                23-dimensional state vector aggregated from 5-second time windows
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* MITRE ATT&CK Mapping for current stage */}
      <section className="glass-card rounded-xl border border-slate-800/50 p-5">
        <div className="flex items-center gap-2 mb-4">
          <AlertTriangle className="h-4 w-4 text-amber-400" />
          <h3 className="text-xs font-bold uppercase tracking-wider font-mono-tech">MITRE ATT&CK Technique Mapping</h3>
        </div>
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          {ATTACK_STAGES.filter(s => s !== "Normal").map(s => (
            <div key={s} className={`p-4 rounded-lg border ${
              s === stage
                ? "bg-slate-900/50 border-slate-700"
                : "bg-slate-950/30 border-slate-900"
            }`}>
              <div className="flex items-center gap-2 mb-2">
                <div className="w-2 h-2 rounded-full" style={{ backgroundColor: STAGE_COLORS[s] }}></div>
                <span className="text-[10px] font-bold font-mono-tech" style={{ color: STAGE_COLORS[s] }}>{s}</span>
                {s === stage && (
                  <span className="text-[8px] bg-cyan-950/50 text-cyan-400 px-1.5 py-0.5 rounded border border-cyan-900/50 font-mono-tech">ACTIVE</span>
                )}
              </div>
              <div className="space-y-1">
                {MITRE_TECHNIQUES[s].map((t, i) => (
                  <div key={i} className="flex items-center gap-1.5 text-[9px] font-mono-tech text-slate-400">
                    <ChevronRight className="h-2.5 w-2.5 shrink-0" style={{ color: STAGE_COLORS[s] }} />
                    <span>{t}</span>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}
