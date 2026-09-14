import React, { useState, useRef } from "react";
import {
  UploadCloud, FileText, AlertTriangle, CheckCircle2, RefreshCw,
  Activity, Server, Clock, Database, Layers, ArrowUpRight,
  Cpu, Filter, Eye, ChevronRight, FileUp, Play, Shield, Info
} from "lucide-react";

const _HOST = import.meta.env.VITE_CAPTURE_HOST ?? "127.0.0.1";
const _PORT = import.meta.env.VITE_CAPTURE_PORT ?? "8080";
const CAPTURE_API = `http://${_HOST}:${_PORT}`;

function formatFileSize(bytes) {
  if (!bytes || bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${(bytes / Math.pow(k, i)).toFixed(1)} ${sizes[i]}`;
}

export default function UploadAnalysis({ onAnalysisComplete }) {
  const [isDragging, setIsDragging] = useState(false);
  const [file, setFile] = useState(null);
  const [filePreview, setFilePreview] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const fileInputRef = useRef(null);

  const handleDragOver = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(true);
  };

  const handleDragLeave = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);
  };

  const validateAndSelectFile = (selectedFile) => {
    setError(null);
    if (!selectedFile) return;

    const ext = selectedFile.name.split(".").pop().toLowerCase();
    if (!["pcap", "pcapng", "csv"].includes(ext)) {
      setError(`Unsupported file format (.${ext}). CyberForecaster accepts .pcap, .pcapng, and .csv files only.`);
      setFile(null);
      setFilePreview(null);
      return;
    }

    setFile(selectedFile);

    // Detect format preview
    let formatLabel = "Standard Flow Format";
    if (ext === "pcap" || ext === "pcapng") {
      formatLabel = "Raw Packet Capture (PCAP)";
    } else if (selectedFile.name.toLowerCase().includes("cic")) {
      formatLabel = "CIC-IDS-2018 / CIC-IDS-2017 Dataset";
    } else if (selectedFile.name.toLowerCase().includes("ctu") || selectedFile.name.toLowerCase().includes("unsw")) {
      formatLabel = "CTU-13 / UNSW-NB15 Dataset";
    } else {
      formatLabel = "CSV Network Flow Dataset";
    }

    setFilePreview({
      name: selectedFile.name,
      size: formatFileSize(selectedFile.size),
      ext: ext.toUpperCase(),
      format: formatLabel,
      featureSchema: "14-Dimensional Temporal Network State Vector",
      labelStatus: "Ground-Truth Labels Excluded from Inference Input",
    });
  };

  const handleDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);

    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      validateAndSelectFile(e.dataTransfer.files[0]);
    }
  };

  const handleFileInputChange = (e) => {
    if (e.target.files && e.target.files[0]) {
      validateAndSelectFile(e.target.files[0]);
    }
  };

  const runWorldModelAnalysis = async () => {
    if (!file) return;
    setLoading(true);
    setError(null);

    const formData = new FormData();
    formData.append("file", file);

    try {
      const response = await fetch(`${CAPTURE_API}/api/analyze_file`, {
        method: "POST",
        body: formData,
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.detail || data.error || "File analysis failed.");
      }

      // Automatically pass analysis results and navigate to Attack Forecast page
      if (onAnalysisComplete) {
        onAnalysisComplete(data);
      }
    } catch (err) {
      console.error("[Upload error]:", err);
      setError(err.message || "Failed to analyze file. Ensure the capture server is running.");
    } finally {
      setLoading(false);
    }
  };

  const resetState = () => {
    setFile(null);
    setFilePreview(null);
    setError(null);
    setLoading(false);
    if (fileInputRef.current) {
      fileInputRef.current.value = "";
    }
  };

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="bg-slate-900/60 border border-cyber-border p-6 rounded-2xl backdrop-blur-xl">
        <div className="flex items-center gap-3">
          <div className="p-2.5 bg-cyan-500/10 border border-cyan-500/30 rounded-xl text-cyan-400">
            <UploadCloud className="h-6 w-6 animate-pulse" />
          </div>
          <div>
            <h1 className="text-base font-extrabold tracking-wider font-mono-tech text-white uppercase">
              OFFLINE FILE ANALYSIS
            </h1>
            <p className="text-xs text-slate-400 mt-0.5">
              Analyze previously captured network traffic using the trained World Model.
            </p>
          </div>
        </div>
      </div>

      {/* Error Banner */}
      {error && (
        <div className="bg-rose-950/40 border border-rose-800/80 p-4 rounded-xl flex items-start gap-3 text-rose-300 text-xs font-mono-tech animate-fade-in">
          <AlertTriangle className="h-5 w-5 text-rose-400 shrink-0 mt-0.5" />
          <div className="flex-1">
            <h4 className="font-bold text-rose-200">Analysis Error</h4>
            <p className="mt-1">{error}</p>
          </div>
          <button
            onClick={() => setError(null)}
            className="text-rose-400 hover:text-white text-xs underline cursor-pointer"
          >
            Dismiss
          </button>
        </div>
      )}

      {/* Dropzone (when no file preview selected) */}
      {!filePreview && !loading && (
        <div
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          onDrop={handleDrop}
          onClick={() => fileInputRef.current?.click()}
          className={`border-2 border-dashed rounded-2xl p-12 text-center transition-all cursor-pointer flex flex-col items-center justify-center min-h-[320px] ${
            isDragging
              ? "border-cyan-400 bg-cyan-950/20 shadow-lg shadow-cyan-500/10 scale-[1.01]"
              : "border-cyber-border bg-[#080b12]/80 hover:border-slate-700 hover:bg-slate-900/40"
          }`}
        >
          <input
            type="file"
            ref={fileInputRef}
            onChange={handleFileInputChange}
            accept=".pcap,.pcapng,.csv"
            className="hidden"
          />

          <div className="p-4 bg-slate-900/80 rounded-full border border-slate-800 text-cyan-400 mb-4">
            <FileUp className="h-8 w-8" />
          </div>

          <h3 className="text-sm font-bold font-mono-tech text-white uppercase tracking-wider">
            Drag & Drop PCAP or CSV File
          </h3>
          <p className="text-xs text-slate-400 mt-2 max-w-md">
            Supports raw network captures (<code className="text-cyan-400">.pcap</code>, <code className="text-cyan-400">.pcapng</code>) and flow dataset CSVs (<code className="text-cyan-400">.csv</code> CIC-IDS-2018 / CTU-13 formatted).
          </p>

          <div className="mt-6">
            <span className="bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 text-xs px-5 py-2.5 rounded-xl font-mono-tech font-bold hover:bg-cyan-500/20 transition-all shadow-lg shadow-cyan-500/5">
              Browse Files
            </span>
          </div>

          <p className="text-[10px] text-slate-600 mt-6 uppercase tracking-widest font-mono-tech">
            100% Offline Processing — Uses Pre-Trained PyTorch GRU Artifacts
          </p>
        </div>
      )}

      {/* Pre-Analysis File Summary Preview Card */}
      {filePreview && !loading && (
        <div className="bg-slate-900/80 border border-cyber-border rounded-2xl p-6 space-y-6 backdrop-blur-xl animate-fade-in">
          <div className="flex items-center justify-between border-b border-slate-800 pb-4">
            <div className="flex items-center gap-3">
              <div className="p-3 bg-cyan-500/10 border border-cyan-500/30 rounded-xl text-cyan-400 font-mono-tech text-xs font-bold">
                {filePreview.ext}
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <h3 className="text-sm font-bold font-mono-tech text-white truncate max-w-md">
                    {filePreview.name}
                  </h3>
                  <span className="px-2 py-0.5 rounded text-[9px] font-mono-tech font-bold bg-emerald-950/70 text-emerald-400 border border-emerald-500/40 uppercase">
                    FILE READY
                  </span>
                </div>
                <p className="text-xs text-slate-400 mt-0.5">
                  Size: {filePreview.size} | Format: {filePreview.ext}
                </p>
              </div>
            </div>
            <button
              onClick={resetState}
              className="text-xs text-slate-400 hover:text-white font-mono-tech underline cursor-pointer"
            >
              Select Different File
            </button>
          </div>

          {/* Metadata Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono-tech">
            <div className="bg-slate-950/60 p-4 rounded-xl border border-slate-800/80 space-y-1">
              <span className="text-slate-500 text-[10px] uppercase tracking-wider block">Detected Format</span>
              <span className="text-cyan-300 font-bold block">{filePreview.format}</span>
            </div>

            <div className="bg-slate-950/60 p-4 rounded-xl border border-slate-800/80 space-y-1">
              <span className="text-slate-500 text-[10px] uppercase tracking-wider block">Feature Schema</span>
              <span className="text-indigo-300 font-bold block">{filePreview.featureSchema}</span>
            </div>

            <div className="bg-slate-950/60 p-4 rounded-xl border border-slate-800/80 space-y-1 md:col-span-2">
              <span className="text-slate-500 text-[10px] uppercase tracking-wider block">Ground-Truth Label Handling</span>
              <span className="text-emerald-400 font-bold flex items-center gap-2">
                <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />
                {filePreview.labelStatus}
              </span>
            </div>
          </div>

          {/* Action Trigger */}
          <div className="pt-2 flex flex-col sm:flex-row items-center gap-4 justify-between border-t border-slate-800">
            <div className="flex items-center gap-2 text-[11px] text-slate-400 font-mono-tech">
              <Info className="h-4 w-4 text-cyan-400 shrink-0" />
              <span>Inference executes offline via pre-trained PyTorch GRU model (<code className="text-slate-300">models/stage_forecaster_v1.pth</code>).</span>
            </div>

            <button
              onClick={runWorldModelAnalysis}
              className="w-full sm:w-auto bg-gradient-to-r from-cyan-500 to-indigo-600 hover:from-cyan-400 hover:to-indigo-500 text-white font-mono-tech font-bold text-xs px-8 py-3 rounded-xl shadow-lg shadow-cyan-500/20 hover:shadow-cyan-500/40 transition-all flex items-center justify-center gap-2 cursor-pointer shrink-0 uppercase tracking-wider"
            >
              <Play className="h-4 w-4 fill-white" />
              <span>ANALYZE WITH WORLD MODEL</span>
            </button>
          </div>
        </div>
      )}

      {/* Loading State */}
      {loading && (
        <div className="border border-cyber-border bg-[#080b12]/90 rounded-2xl p-12 text-center flex flex-col items-center justify-center min-h-[320px] backdrop-blur-xl">
          <div className="relative mb-6">
            <div className="h-16 w-16 rounded-full border-4 border-cyan-500/20 border-t-cyan-400 animate-spin" />
            <Activity className="h-6 w-6 text-cyan-400 absolute inset-0 m-auto animate-pulse" />
          </div>
          <h3 className="text-sm font-bold font-mono-tech text-white uppercase tracking-wider">
            Running PyTorch GRU World Model Inference...
          </h3>
          <p className="text-xs text-slate-400 mt-2 max-w-md">
            Extracting flow features, preprocessing temporal network state vectors, and computing multi-step attack forecasts...
          </p>
        </div>
      )}
    </div>
  );
}
