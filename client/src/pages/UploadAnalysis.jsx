import React, { useState, useRef } from "react";
import {
  FileText, AlertTriangle, RefreshCw,
  Activity, Database, ArrowRight,
  Cpu, Play, Menu, Upload, Network, BarChart3, X, FileUp
} from "lucide-react";
import DinoGame from "../components/DinoGame";

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

// Stylized document icon matching the reference design (blue outline sheet with folded corner & yellow format badge)
function DocumentBadgeIcon({ ext = "CSV" }) {
  return (
    <div className="relative w-10 h-12 shrink-0 flex items-center justify-center">
      <svg
        className="w-full h-full text-blue-400 drop-shadow-[0_2px_8px_rgba(59,130,246,0.25)]"
        viewBox="0 0 40 48"
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
      >
        <path
          d="M6 3H26L34 11V43C34 44.1046 33.1046 45 32 45H6C4.89543 45 4 44.1046 4 43V5C4 3.89543 4.89543 3 6 3Z"
          fill="#101B2E"
          stroke="#3B82F6"
          strokeWidth="2"
          strokeLinejoin="round"
        />
        <path
          d="M26 3V11H34"
          stroke="#3B82F6"
          strokeWidth="2"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
      </svg>
      {/* Yellow / Gold badge in bottom-left */}
      <span className="absolute -bottom-1 -left-1 px-1.5 py-0.5 bg-[#CBA135] text-[#0B0F14] font-black text-[9px] font-mono-tech rounded uppercase tracking-tighter leading-none shadow-sm">
        {ext}
      </span>
    </div>
  );
}

export default function UploadAnalysis({
  onAnalysisComplete,
  onToggleSidebar,
}) {
  const [isDragging, setIsDragging] = useState(false);
  const [file, setFile] = useState(null);
  const [filePreview, setFilePreview] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [uploadStage, setUploadStage] = useState("");
  const fileInputRef = useRef(null);
  const abortControllerRef = useRef(null);

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

  const validateAndSelectFile = async (selectedFile) => {
    setError(null);
    if (!selectedFile) return;

    const ext = selectedFile.name.split(".").pop().toLowerCase();
    if (!["pcap", "pcapng", "csv"].includes(ext)) {
      setError(
        `Unsupported file format (.${ext}). CyberForecaster accepts .pcap, .pcapng, and .csv files only.`
      );
      return;
    }

    setFile(selectedFile);

    // Format label based on the actual uploaded file
    let formatLabel = "CSV Flow Dataset (.csv)";
    if (ext === "pcap") {
      formatLabel = "Raw Packet Capture (.pcap)";
    } else if (ext === "pcapng") {
      formatLabel = "Next-Gen Packet Capture (.pcapng)";
    } else if (selectedFile.name.toLowerCase().includes("cic")) {
      formatLabel = "CIC-IDS Dataset Flow CSV (.csv)";
    } else if (
      selectedFile.name.toLowerCase().includes("ctu") ||
      selectedFile.name.toLowerCase().includes("unsw")
    ) {
      formatLabel = "CTU-13 / UNSW-NB15 Flow CSV (.csv)";
    }

    let featureSchemaLabel =
      ext === "csv"
        ? "Extracting column headers..."
        : "Network Packet Header Attributes (IP, TCP/UDP Ports, Payload & Flow Rates)";

    // Parse CSV header to dynamically extract real columns and feature schema
    if (ext === "csv") {
      try {
        const textChunk = await selectedFile.slice(0, 16384).text();
        const firstLine = textChunk.split(/\r?\n/)[0];
        if (firstLine) {
          const cols = firstLine
            .split(",")
            .map((c) => c.trim().replace(/^["']|["']$/g, ""))
            .filter(Boolean);
          if (cols.length > 0) {
            const previewCols = cols.slice(0, 3).join(", ");
            featureSchemaLabel = `${cols.length} Features Extracted (${previewCols}${
              cols.length > 3 ? ", ..." : ""
            })`;
          }
        }
      } catch (e) {
        console.warn("Could not read CSV header:", e);
        featureSchemaLabel = "Tabular Network Flow Features";
      }
    }

    setFilePreview({
      name: selectedFile.name,
      size: formatFileSize(selectedFile.size),
      ext: ext.toUpperCase(),
      format: formatLabel,
      featureSchema: featureSchemaLabel,
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


  const cancelProcessing = () => {
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
      abortControllerRef.current = null;
    }
    setLoading(false);
    setUploadStage("");
    setError("File processing was cancelled.");
  };

  const runWorldModelAnalysis = async () => {
    if (!file) {
      fileInputRef.current?.click();
      return;
    }

    setLoading(true);
    setError(null);
    setUploadStage("Uploading file to server...");

    const controller = new AbortController();
    abortControllerRef.current = controller;

    const formData = new FormData();
    formData.append("file", file);

    try {
      setUploadStage("Processing... (converting PCAP / running LSTM World Model)");
      const response = await fetch(`${CAPTURE_API}/api/upload`, {
        method: "POST",
        body: formData,
        signal: controller.signal,
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.detail || data.error || "File analysis failed.");
      }

      // Navigate to Attack Forecast page after successful upload
      if (onAnalysisComplete) {
        onAnalysisComplete(data);
      }
    } catch (err) {
      if (err.name === "AbortError") {
        setError("File processing was cancelled.");
      } else {
        console.error("[Upload error]:", err);
        setError(
          err.message ||
            "Failed to analyze file. Ensure the capture server is running."
        );
      }
    } finally {
      abortControllerRef.current = null;
      setLoading(false);
      setUploadStage("");
    }
  };

  const resetState = () => {
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
      abortControllerRef.current = null;
    }
    setFile(null);
    setFilePreview(null);
    setError(null);
    setLoading(false);
    setUploadStage("");
    if (fileInputRef.current) {
      fileInputRef.current.value = "";
    }
  };

  return (
    <div className="relative min-h-screen flex-1 flex flex-col bg-[#070C18] text-[#F3F1EA] -m-6 p-6 sm:p-8 font-sans select-none overflow-x-hidden">
      {/* Subtle cosmic background glow & grid */}
      <div className="absolute inset-0 pointer-events-none opacity-40 bg-[radial-gradient(ellipse_at_top,_var(--tw-gradient-stops))] from-blue-900/20 via-transparent to-transparent" />
      <div className="absolute inset-0 pointer-events-none opacity-15 bg-[radial-gradient(#3B82F6_1px,transparent_1px)] [background-size:32px_32px]" />

      {/* Hidden file input */}
      <input
        type="file"
        ref={fileInputRef}
        onChange={handleFileInputChange}
        accept=".pcap,.pcapng,.csv"
        className="hidden"
      />

      {/* Top Header Bar */}
      <header className="relative z-10 flex items-center gap-4 pb-6 border-b border-white/10 w-full">
        {/* Left: Sidebar Toggle Menu Icon */}
        <button
          onClick={onToggleSidebar}
          className="p-2.5 rounded-lg bg-[#141E30]/70 hover:bg-[#1C2A44] border border-white/10 text-gold hover:text-white transition-all cursor-pointer shadow-sm shrink-0"
          title="Toggle Navigation Sidebar"
        >
          <Menu className="h-5 w-5" />
        </button>

        {/* Title Section */}
        <div>
          <h1 className="text-2xl sm:text-3xl font-black tracking-wider uppercase leading-none">
            <span className="text-white">OFFLINE </span>
            <span className="text-[#CBA135]">FILE ANALYSIS</span>
          </h1>
          <p className="text-xs sm:text-sm text-[#8E9CAE] mt-1.5 font-normal">
            Analyze previously captured network traffic using the trained World Model.
          </p>
        </div>
      </header>

      {/* Main Content Container */}
      <main className="relative z-10 flex-1 w-full flex flex-col justify-start space-y-8 animate-fade-in pt-6">

        {/* Error Alert */}
        {error && (
          <div className="border border-[#CBA135]/50 bg-[#161F2E] p-4 rounded-xl flex items-start gap-3 text-[#CBA135] shadow-lg">
            <AlertTriangle className="h-5 w-5 shrink-0 mt-0.5" />
            <div className="flex-1 text-xs">
              <span className="font-bold block text-sm">Analysis Notice</span>
              <p className="mt-0.5 text-[#8E9CAE]">{error}</p>
            </div>
            <button
              onClick={() => setError(null)}
              className="text-xs font-bold hover:underline cursor-pointer"
            >
              Dismiss
            </button>
          </div>
        )}

        {/* 1. INITIAL BROWSE / DROPZONE STATE (When no file selected and not loading) */}
        {!filePreview && !loading && (
          <section className="flex-1 flex flex-col justify-center space-y-6 pt-4">
            <div
              onDragOver={handleDragOver}
              onDragLeave={handleDragLeave}
              onDrop={handleDrop}
              onClick={() => fileInputRef.current?.click()}
              className={`border-2 border-dashed rounded-2xl p-12 text-center transition-all cursor-pointer flex flex-col items-center justify-center min-h-[380px] bg-[#0E1728]/40 ${
                isDragging
                  ? "border-[#CBA135] bg-[#CBA135]/5 scale-[1.01]"
                  : "border-white/15 hover:border-[#CBA135]/60 hover:bg-[#0E1728]/70"
              }`}
            >
              <div className="p-4 bg-[#142036] rounded-full border border-white/10 text-[#CBA135] mb-4 shadow-lg">
                <FileUp className="h-8 w-8" />
              </div>

              <h3 className="text-base sm:text-lg font-extrabold font-mono-tech text-white uppercase tracking-wider">
                Drag &amp; Drop PCAP or CSV File
              </h3>
              <p className="text-xs sm:text-sm text-[#8E9CAE] mt-2 max-w-md">
                Supports raw captures (<code className="bg-[#142036] text-[#CBA135] px-1.5 py-0.5 rounded text-[11px] font-mono-jb">.pcap</code>, <code className="bg-[#142036] text-[#CBA135] px-1.5 py-0.5 rounded text-[11px] font-mono-jb">.pcapng</code>) and flow dataset CSVs (<code className="bg-[#142036] text-[#CBA135] px-1.5 py-0.5 rounded text-[11px] font-mono-jb">.csv</code>).
              </p>

              <div className="mt-6 flex items-center justify-center">
                <button
                  type="button"
                  onClick={(e) => {
                    e.stopPropagation();
                    fileInputRef.current?.click();
                  }}
                  className="px-6 py-2.5 rounded-lg bg-[#CBA135] hover:bg-[#DDB54B] text-[#0B0F14] font-bold text-xs uppercase tracking-wider font-mono-tech shadow-md transition-all cursor-pointer"
                >
                  Browse Files
                </button>
              </div>
            </div>
          </section>
        )}

        {/* 2. FILE UPLOADED & READY STATE (Shows Summary, Pipeline & Analyze Button) */}
        {filePreview && !loading && (
          <div className="space-y-8 animate-fade-in">
            {/* Selected File Details Row */}
            <div className="flex flex-col space-y-4">
              <div className="flex items-center justify-between flex-wrap gap-4 py-2">
                <div className="flex items-center gap-4 min-w-0">
                  <DocumentBadgeIcon ext={filePreview.ext} />
                  <div className="min-w-0">
                    <h3 className="text-base sm:text-lg font-bold text-white tracking-wide truncate">
                      {filePreview.name}
                    </h3>
                    <p className="text-xs text-[#8E9CAE] font-mono-tech mt-0.5">
                      Size: {filePreview.size} <span className="mx-1 text-white/20">|</span> Format: {filePreview.ext}
                    </p>
                  </div>
                </div>

                {/* Select Different File */}
                <button
                  onClick={resetState}
                  className="flex items-center gap-2 text-xs font-mono-tech font-bold text-[#CBA135] hover:text-[#E0C36A] hover:underline cursor-pointer transition-colors shrink-0"
                >
                  <RefreshCw className="h-4 w-4 text-[#CBA135]" />
                  <span>Select Different File</span>
                </button>
              </div>

              <div className="w-full h-px bg-white/10" />
            </div>

            {/* INPUT SUMMARY (Clean format without diagram icons or inference mode / model input) */}
            <section className="space-y-4">
              <h2 className="text-sm sm:text-base font-extrabold uppercase tracking-widest text-white">
                INPUT SUMMARY
              </h2>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {/* Detected Format Card */}
                <div className="bg-[#0E1728]/70 border border-white/10 rounded-xl p-4 sm:p-5 flex flex-col justify-center space-y-1.5 transition-colors hover:border-white/20">
                  <span className="text-[11px] font-semibold text-[#8E9CAE] uppercase tracking-wider">
                    Detected Format
                  </span>
                  <span className="text-sm sm:text-base font-bold text-white tracking-wide">
                    {filePreview.format}
                  </span>
                </div>

                {/* Feature Schema Card */}
                <div className="bg-[#0E1728]/70 border border-white/10 rounded-xl p-4 sm:p-5 flex flex-col justify-center space-y-1.5 transition-colors hover:border-white/20">
                  <span className="text-[11px] font-semibold text-[#8E9CAE] uppercase tracking-wider">
                    Feature Schema
                  </span>
                  <span className="text-sm sm:text-base font-bold text-white tracking-wide">
                    {filePreview.featureSchema}
                  </span>
                </div>
              </div>
            </section>

            {/* ANALYSIS PIPELINE (5-step horizontal pipeline with connecting arrows) */}
            <section className="space-y-4">
              <div className="inline-block">
                <h2 className="text-sm sm:text-base font-extrabold uppercase tracking-widest text-white">
                  ANALYSIS PIPELINE
                </h2>
                <div className="h-0.5 w-full bg-blue-500/80 mt-1 rounded-full" />
              </div>

              <div className="w-full flex items-center justify-between py-4 px-1 gap-1 sm:gap-2">
                {/* Step 1: File */}
                <div className="flex flex-col items-center text-center flex-1 min-w-[70px] max-w-[130px] space-y-2">
                  <div className="w-11 h-11 sm:w-12 sm:h-12 rounded-full bg-[#13223A] border border-[#2B4673] flex items-center justify-center text-blue-400 shadow-[0_0_12px_rgba(59,130,246,0.15)]">
                    <FileText className="h-4 w-4 sm:h-5 sm:w-5" />
                  </div>
                  <div>
                    <span className="block text-[11px] sm:text-xs font-bold text-white tracking-wider">
                      1. FILE
                    </span>
                    <span className="block text-[10px] sm:text-[11px] text-[#8E9CAE] mt-0.5 leading-tight">
                      Uploaded PCAP/CSV
                    </span>
                  </div>
                </div>

                {/* Flow Arrow 1 */}
                <div className="flex items-center justify-center flex-1 max-w-[40px] sm:max-w-[60px] px-1 shrink-0 self-center">
                  <svg
                    className="w-full h-4 text-blue-400 drop-shadow-[0_0_6px_rgba(59,130,246,0.3)]"
                    viewBox="0 0 40 14"
                    fill="none"
                    xmlns="http://www.w3.org/2000/svg"
                  >
                    <line
                      x1="2"
                      y1="7"
                      x2="33"
                      y2="7"
                      stroke="currentColor"
                      strokeWidth="2"
                      strokeLinecap="round"
                    />
                    <polyline
                      points="27,3 34,7 27,11"
                      fill="none"
                      stroke="currentColor"
                      strokeWidth="2"
                      strokeLinecap="round"
                      strokeLinejoin="round"
                    />
                  </svg>
                </div>

                {/* Step 2: Feature Extraction */}
                <div className="flex flex-col items-center text-center flex-1 min-w-[75px] max-w-[140px] space-y-2">
                  <div className="w-11 h-11 sm:w-12 sm:h-12 rounded-full bg-[#13223A] border border-[#2B4673] flex items-center justify-center text-blue-400 shadow-[0_0_12px_rgba(59,130,246,0.15)]">
                    <Cpu className="h-4 w-4 sm:h-5 sm:w-5" />
                  </div>
                  <div>
                    <span className="block text-[11px] sm:text-xs font-bold text-white tracking-wider">
                      2. FEATURE EXTRACTION
                    </span>
                    <span className="block text-[10px] sm:text-[11px] text-[#8E9CAE] mt-0.5 leading-tight">
                      Extract network features
                    </span>
                  </div>
                </div>

                {/* Flow Arrow 2 */}
                <div className="flex items-center justify-center flex-1 max-w-[40px] sm:max-w-[60px] px-1 shrink-0 self-center">
                  <svg
                    className="w-full h-4 text-blue-400 drop-shadow-[0_0_6px_rgba(59,130,246,0.3)]"
                    viewBox="0 0 40 14"
                    fill="none"
                    xmlns="http://www.w3.org/2000/svg"
                  >
                    <line
                      x1="2"
                      y1="7"
                      x2="33"
                      y2="7"
                      stroke="currentColor"
                      strokeWidth="2"
                      strokeLinecap="round"
                    />
                    <polyline
                      points="27,3 34,7 27,11"
                      fill="none"
                      stroke="currentColor"
                      strokeWidth="2"
                      strokeLinecap="round"
                      strokeLinejoin="round"
                    />
                  </svg>
                </div>

                {/* Step 3: Temporal Network States */}
                <div className="flex flex-col items-center text-center flex-1 min-w-[80px] max-w-[150px] space-y-2">
                  <div className="w-11 h-11 sm:w-12 sm:h-12 rounded-full bg-[#13223A] border border-[#2B4673] flex items-center justify-center text-blue-400 shadow-[0_0_12px_rgba(59,130,246,0.15)]">
                    <Database className="h-4 w-4 sm:h-5 sm:w-5" />
                  </div>
                  <div>
                    <span className="block text-[11px] sm:text-xs font-bold text-white tracking-wider">
                      3. TEMPORAL NETWORK STATES
                    </span>
                    <span className="block text-[10px] sm:text-[11px] text-[#8E9CAE] mt-0.5 leading-tight">
                      Build time-series sequences
                    </span>
                  </div>
                </div>

                {/* Flow Arrow 3 */}
                <div className="flex items-center justify-center flex-1 max-w-[40px] sm:max-w-[60px] px-1 shrink-0 self-center">
                  <svg
                    className="w-full h-4 text-blue-400 drop-shadow-[0_0_6px_rgba(59,130,246,0.3)]"
                    viewBox="0 0 40 14"
                    fill="none"
                    xmlns="http://www.w3.org/2000/svg"
                  >
                    <line
                      x1="2"
                      y1="7"
                      x2="33"
                      y2="7"
                      stroke="currentColor"
                      strokeWidth="2"
                      strokeLinecap="round"
                    />
                    <polyline
                      points="27,3 34,7 27,11"
                      fill="none"
                      stroke="currentColor"
                      strokeWidth="2"
                      strokeLinecap="round"
                      strokeLinejoin="round"
                    />
                  </svg>
                </div>

                {/* Step 4: LSTM World Model */}
                <div className="flex flex-col items-center text-center flex-1 min-w-[75px] max-w-[140px] space-y-2">
                  <div className="w-11 h-11 sm:w-12 sm:h-12 rounded-full bg-[#13223A] border border-[#2B4673] flex items-center justify-center text-blue-400 shadow-[0_0_12px_rgba(59,130,246,0.15)]">
                    <Network className="h-4 w-4 sm:h-5 sm:w-5" />
                  </div>
                  <div>
                    <span className="block text-[11px] sm:text-xs font-bold text-white tracking-wider">
                      4. LSTM WORLD MODEL
                    </span>
                    <span className="block text-[10px] sm:text-[11px] text-[#8E9CAE] mt-0.5 leading-tight">
                      Predict future behavior
                    </span>
                  </div>
                </div>

                {/* Flow Arrow 4 */}
                <div className="flex items-center justify-center flex-1 max-w-[40px] sm:max-w-[60px] px-1 shrink-0 self-center">
                  <svg
                    className="w-full h-4 text-blue-400 drop-shadow-[0_0_6px_rgba(59,130,246,0.3)]"
                    viewBox="0 0 40 14"
                    fill="none"
                    xmlns="http://www.w3.org/2000/svg"
                  >
                    <line
                      x1="2"
                      y1="7"
                      x2="33"
                      y2="7"
                      stroke="currentColor"
                      strokeWidth="2"
                      strokeLinecap="round"
                    />
                    <polyline
                      points="27,3 34,7 27,11"
                      fill="none"
                      stroke="currentColor"
                      strokeWidth="2"
                      strokeLinecap="round"
                      strokeLinejoin="round"
                    />
                  </svg>
                </div>

                {/* Step 5: Attack Forecast */}
                <div className="flex flex-col items-center text-center flex-1 min-w-[75px] max-w-[140px] space-y-2">
                  <div className="w-11 h-11 sm:w-12 sm:h-12 rounded-full bg-[#13223A] border border-[#2B4673] flex items-center justify-center text-blue-400 shadow-[0_0_12px_rgba(59,130,246,0.15)]">
                    <BarChart3 className="h-4 w-4 sm:h-5 sm:w-5" />
                  </div>
                  <div>
                    <span className="block text-[11px] sm:text-xs font-bold text-white tracking-wider">
                      5. ATTACK FORECAST
                    </span>
                    <span className="block text-[10px] sm:text-[11px] text-[#8E9CAE] mt-0.5 leading-tight">
                      Generate risk predictions
                    </span>
                  </div>
                </div>
              </div>
            </section>

            {/* Bottom Actions Row (Centered CTA Button) */}
            <section className="pt-4 pb-2 flex items-center justify-center">
              <button
                onClick={runWorldModelAnalysis}
                disabled={loading}
                className="bg-[#CBA135] hover:bg-[#DDB54B] active:bg-[#BA922A] text-[#0B0F14] font-black font-mono-tech text-xs sm:text-sm px-8 py-3.5 rounded-lg flex items-center justify-center gap-2.5 uppercase tracking-wider transition-all duration-200 cursor-pointer shadow-[0_4px_20px_rgba(203,161,53,0.3)] hover:scale-[1.02] active:scale-[0.98] disabled:opacity-50 disabled:cursor-not-allowed"
              >
                <Play className="h-4 w-4 fill-current" />
                <span>ANALYZE WITH WORLD MODEL</span>
              </button>
            </section>
          </div>
        )}

        {/* 3. LOADING STATE & CYBER DINO GAME (Active while LSTM analysis runs) */}
        {loading && (
          <section className="mt-2 p-6 border border-white/10 bg-[#0A1120]/95 backdrop-blur-md rounded-2xl text-center flex flex-col items-center justify-center animate-fade-in space-y-6">
            <div className="flex flex-wrap items-center justify-center gap-4">
              <div className="flex items-center gap-2.5 bg-[#142036] border border-blue-500/30 px-5 py-2.5 rounded-xl text-white font-mono-tech text-xs font-bold shadow-md">
                <Activity className="h-4 w-4 text-[#CBA135] animate-spin" />
                <span>{uploadStage || "Running PyTorch LSTM World Model Inference..."}</span>
              </div>

              <button
                onClick={cancelProcessing}
                className="px-4 py-2.5 rounded-xl bg-red-500/20 border border-red-500/40 text-red-400 hover:bg-red-500 hover:text-white font-mono-tech font-bold text-xs uppercase tracking-wider transition-all cursor-pointer flex items-center gap-1.5"
                title="Cancel file processing"
              >
                <X className="w-4 h-4" />
                <span>CANCEL</span>
              </button>
            </div>

            <div className="w-full max-w-4xl">
              <DinoGame />
            </div>
          </section>
        )}

      </main>
    </div>
  );
}
