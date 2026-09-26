import React, { useState, useRef } from "react";
import {
  UploadCloud, FileText, AlertTriangle, CheckCircle2, RefreshCw,
  Activity, Server, Clock, Database, Layers, ArrowUpRight,
  Cpu, Filter, Eye, ChevronRight, FileUp, Play, Shield, Info, X
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

export default function UploadAnalysis({ onAnalysisComplete }) {
  const [isDragging, setIsDragging] = useState(false);
  const [file, setFile] = useState(null);
  const [filePreview, setFilePreview] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
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

  const [uploadStage, setUploadStage] = useState("");
  const [successInfo, setSuccessInfo] = useState(null);

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
    if (!file) return;
    setLoading(true);
    setError(null);
    setSuccessInfo(null);
    setUploadStage("Uploading file to server...");

    const controller = new AbortController();
    abortControllerRef.current = controller;

    const formData = new FormData();
    formData.append("file", file);

    try {
      setUploadStage("Processing... (converting PCAP / running model)");
      const response = await fetch(`${CAPTURE_API}/api/upload`, {
        method: "POST",
        body: formData,
        signal: controller.signal,
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.detail || data.error || "File analysis failed.");
      }

      setSuccessInfo({
        filename: data.filename,
        total_flows: data.total_flows,
        total_conversations: data.total_conversations,
      });

      // Navigate to Attack Forecast page after successful upload
      if (onAnalysisComplete) {
        onAnalysisComplete(data);
      }
    } catch (err) {
      if (err.name === "AbortError") {
        setError("File processing was cancelled.");
      } else {
        console.error("[Upload error]:", err);
        setError(err.message || "Failed to analyze file. Ensure the capture server is running.");
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
    setSuccessInfo(null);
    setLoading(false);
    setUploadStage("");
    if (fileInputRef.current) {
      fileInputRef.current.value = "";
    }
  };

  return (
    <div className="space-y-6 bg-bg text-text">
      {/* Header Banner */}
      <div className="bg-surface border border-border p-6 rounded-2xl">
        <div className="flex items-center gap-3">
          <div className="p-2.5 bg-surface-2 border border-border rounded-xl text-gold">
            <UploadCloud className="h-6 w-6" />
          </div>
          <div>
            <h1 className="text-lg font-extrabold tracking-wider font-mono-tech text-white uppercase">
              OFFLINE FILE ANALYSIS
            </h1>
            <p className="text-sm text-text-muted mt-0.5">
              Analyze previously captured network traffic using the trained World Model.
            </p>
          </div>
        </div>
      </div>

      {/* Error Banner */}
      {error && (
        <div className="bg-surface-2 border border-gold p-4 rounded-xl flex items-start gap-3 text-sm font-mono-tech animate-fade-in text-text">
          <AlertTriangle className="h-5 w-5 text-gold shrink-0 mt-0.5" />
          <div className="flex-1">
            <h4 className="font-bold text-gold">Analysis Status</h4>
            <p className="mt-1 opacity-90">{error}</p>
          </div>
          <button
            onClick={() => setError(null)}
            className="text-gold hover:underline text-sm cursor-pointer font-bold"
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
              ? "border-gold bg-surface-2 scale-[1.01]"
              : "border-border bg-surface hover:bg-surface-2"
          }`}
        >
          <input
            type="file"
            ref={fileInputRef}
            onChange={handleFileInputChange}
            accept=".pcap,.pcapng,.csv"
            className="hidden"
          />

          <div className="p-4 bg-surface-2 rounded-full border border-border text-gold mb-4">
            <FileUp className="h-8 w-8" />
          </div>

          <h3 className="text-base font-bold font-mono-tech text-white uppercase tracking-wider">
            Drag & Drop PCAP or CSV File
          </h3>
          <p className="text-sm text-text-muted mt-2 max-w-md">
            Supports raw network captures (<code className="bg-surface-2 text-gold px-1.5 py-0.5 rounded font-mono-jb">.pcap</code>, <code className="bg-surface-2 text-gold px-1.5 py-0.5 rounded font-mono-jb">.pcapng</code>) and flow dataset CSVs (<code className="bg-surface-2 text-gold px-1.5 py-0.5 rounded font-mono-jb">.csv</code>).
          </p>

          <div className="mt-6">
            <span className="bg-gold text-bg border border-gold text-sm px-6 py-3 rounded-xl font-mono-tech font-bold hover:bg-gold-hi transition-all">
              Browse Files
            </span>
          </div>

          <p className="text-xs text-text-muted mt-6 uppercase tracking-widest font-mono-tech">
            100% Offline Processing — Uses Pre-Trained PyTorch LSTM Artifacts
          </p>
        </div>
      )}

      {/* Pre-Analysis File Summary Preview Card */}
      {filePreview && !loading && (
        <div className="bg-surface border border-border rounded-2xl p-6 space-y-6 animate-fade-in">
          <div className="flex items-center justify-between border-b border-border pb-4">
            <div className="flex items-center gap-3">
              <div className="p-3 bg-gold text-bg rounded-xl font-mono-tech text-sm font-bold">
                {filePreview.ext}
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <h3 className="text-base font-bold font-mono-tech text-white truncate max-w-md">
                    {filePreview.name}
                  </h3>
                </div>
                <p className="text-sm text-text-muted mt-0.5">
                  Size: {filePreview.size} | Format: {filePreview.ext}
                </p>
              </div>
            </div>
            <button
              onClick={resetState}
              className="text-sm text-gold hover:underline font-mono-tech font-bold cursor-pointer"
            >
              Select Different File
            </button>
          </div>

          {/* Metadata Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm font-mono-tech">
            <div className="bg-surface-2 p-4 rounded-xl border border-border space-y-1">
              <span className="text-text-muted text-xs uppercase tracking-wider block font-bold">Detected Format</span>
              <span className="text-white font-bold block">{filePreview.format}</span>
            </div>

            <div className="bg-surface-2 p-4 rounded-xl border border-border space-y-1">
              <span className="text-text-muted text-xs uppercase tracking-wider block font-bold">Feature Schema</span>
              <span className="text-white font-bold block">{filePreview.featureSchema}</span>
            </div>

            <div className="bg-surface-2 p-4 rounded-xl border border-border space-y-1 md:col-span-2">
              <span className="text-text-muted text-xs uppercase tracking-wider block font-bold">Ground-Truth Label Handling</span>
              <span className="text-gold font-bold flex items-center gap-2">
                <CheckCircle2 className="h-4 w-4 text-gold" />
                {filePreview.labelStatus}
              </span>
            </div>
          </div>

          {/* Action Trigger */}
          <div className="pt-2 flex justify-end border-t border-border">
            <button
              onClick={runWorldModelAnalysis}
              className="w-full sm:w-auto bg-gold hover:bg-gold-hi text-bg font-mono-tech font-bold text-sm px-8 py-3 rounded-xl transition-all flex items-center justify-center gap-2 cursor-pointer shrink-0 uppercase tracking-wider border border-gold"
            >
              <Play className="h-4 w-4 fill-bg" />
              <span>ANALYZE WITH WORLD MODEL</span>
            </button>
          </div>
        </div>
      )}

      {/* Loading State with Cyber Dino Game & Cancel Button */}
      {loading && (
        <div className="border border-border bg-surface rounded-2xl p-6 text-center flex flex-col items-center justify-center animate-fade-in space-y-6">
          <div className="flex flex-wrap items-center justify-center gap-4">
            <div className="flex items-center gap-3 bg-surface-2 border border-border px-5 py-2.5 rounded-xl text-white font-mono-tech text-sm font-bold">
              <Activity className="h-4 w-4 text-gold animate-spin" />
              <span>{uploadStage || "Running PyTorch LSTM World Model Inference..."}</span>
            </div>

            <button
              onClick={cancelProcessing}
              className="px-4 py-2.5 rounded-xl bg-red-500/20 border border-red-500/50 text-red-400 hover:bg-red-500 hover:text-white font-mono-tech font-bold text-xs uppercase tracking-wider transition-all cursor-pointer flex items-center gap-2 shadow-sm"
              title="Cancel file processing"
            >
              <X className="w-4 h-4" />
              <span>CANCEL PROCESSING</span>
            </button>
          </div>

          <div className="w-full max-w-5xl">
            <DinoGame />
          </div>
        </div>
      )}
    </div>
  );
}

