import mongoose from "mongoose";

// Host Schema
const hostSchema = new mongoose.Schema({
  ip: { type: String, required: true, unique: true },
  name: { type: String, required: true },
  department: { type: String, default: "IT" },
  criticality: { type: String, enum: ["LOW", "MEDIUM", "HIGH", "CRITICAL"], default: "MEDIUM" },
  status: { type: String, enum: ["ONLINE", "RATE_LIMITED", "PORTS_BLOCKED", "ISOLATED"], default: "ONLINE" },
  lastSeen: { type: Date, default: Date.now }
});

// Traffic Event Schema
const trafficEventSchema = new mongoose.Schema({
  hostIp: { type: String, required: true },
  duration: Number,
  src_pkts: Number,
  dst_pkts: Number,
  total_bytes: Number,
  port_danger: Number,
  protocol: Number, // 1 for TCP, 0.5 for UDP, etc.
  action: { type: Number, default: 0 }, // 0=None, 1=Rate Limit, 2=Block Port, 3=Isolate
  timestamp: { type: Date, default: Date.now }
});

// Forecast Schema
const forecastSchema = new mongoose.Schema({
  hostIp: { type: String, required: true },
  predictedStage: { type: String, required: true },
  confidence: { type: Number, required: true },
  mitreTechniques: [String],
  timestamp: { type: Date, default: Date.now },
  flowFeatures: Object
});

// Alert Schema
const alertSchema = new mongoose.Schema({
  hostIp: { type: String, required: true },
  severity: { type: String, enum: ["LOW", "MEDIUM", "HIGH", "CRITICAL"], default: "MEDIUM" },
  predictedStage: String,
  confidence: Number,
  status: { type: String, enum: ["ACTIVE", "ACKNOWLEDGED", "RESOLVED"], default: "ACTIVE" },
  mitreTechniques: [String],
  blockchainTxHash: String,
  actionTaken: { type: String, default: "PENDING" }, // PENDING, ISOLATE, BLOCK_PORTS, RATE_LIMIT, IGNORED
  timestamp: { type: Date, default: Date.now }
});

// Blockchain Log Schema
const blockchainLogSchema = new mongoose.Schema({
  forecastId: String,
  hostIp: String,
  predictedStage: String,
  dataHash: String,
  txHash: String,
  blockNumber: Number,
  timestamp: { type: Date, default: Date.now }
});

export const Host = mongoose.model("Host", hostSchema);
export const TrafficEvent = mongoose.model("TrafficEvent", trafficEventSchema);
export const Forecast = mongoose.model("Forecast", forecastSchema);
export const Alert = mongoose.model("Alert", alertSchema);
export const BlockchainLog = mongoose.model("BlockchainLog", blockchainLogSchema);
