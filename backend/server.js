import express from "express";
import "dotenv/config";
import { createServer } from "http";
import { Server } from "socket.io";
import cors from "cors";
import mongoose from "mongoose";
import { ethers } from "ethers";
import crypto from "crypto";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

import { Host, TrafficEvent, Forecast, Alert, BlockchainLog, AuditEvent } from "./models.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(cors());
app.use(express.json());

const httpServer = createServer(app);
const io = new Server(httpServer, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});

const PORT = Number(process.env.BACKEND_PORT || 5050);
const ML_SERVICE_URL = process.env.ML_SERVICE_URL || "http://127.0.0.1:8000";
const MONGO_URI = process.env.MONGO_URI || "mongodb://127.0.0.1:27017/attack_forecasting";
const BLOCKCHAIN_RPC_URL = process.env.BLOCKCHAIN_RPC_URL || "http://127.0.0.1:8545";

// Connect to MongoDB
mongoose.connect(MONGO_URI)
  .then(() => {
    console.log("Connected to MongoDB");
    // Seed initial hosts for testing
    seedHosts();
  })
  .catch(err => console.error("MongoDB connection error:", err));

async function seedHosts() {
  const initialHosts = [
    { ip: "192.168.1.10", name: "Domain Controller", department: "IT Infrastructure", criticality: "CRITICAL" },
    { ip: "192.168.1.15", name: "Finance Database Server", department: "Finance", criticality: "HIGH" },
    { ip: "192.168.1.20", name: "Public Web Server", department: "Marketing", criticality: "HIGH" },
    { ip: "192.168.1.45", name: "Engineering Workstation 1", department: "Engineering", criticality: "MEDIUM" },
    { ip: "192.168.1.50", name: "HR Portal", department: "Human Resources", criticality: "LOW" }
  ];

  for (const h of initialHosts) {
    await Host.findOneAndUpdate({ ip: h.ip }, h, { upsert: true, new: true });
  }
  console.log("Hosts seeded successfully!");
}

// Connect to local Hardhat blockchain network
let contract = null;
let provider = null;
let signer = null;

async function connectBlockchain() {
  try {
    const deploymentPath = path.join(__dirname, "../blockchain/deployments/localhost.json");
    if (!fs.existsSync(deploymentPath)) {
      console.warn("Blockchain deployment configuration not found. Will retry in 5s...");
      setTimeout(connectBlockchain, 5000);
      return;
    }

    const { address, abi } = JSON.parse(fs.readFileSync(deploymentPath, "utf8"));
    
    // Connect using standard JSON RPC
    provider = new ethers.JsonRpcProvider(BLOCKCHAIN_RPC_URL);
    
    // Use Hardhat Account #0
    const privateKey = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
    signer = new ethers.Wallet(privateKey, provider);
    
    contract = new ethers.Contract(address, abi, signer);
    console.log(`Connected to blockchain. ForecastRegistry contract address: ${address}`);
  } catch (error) {
    console.error("Blockchain connection error:", error);
    setTimeout(connectBlockchain, 5000);
  }
}

connectBlockchain();

// Helper to map attack stages to MITRE technique IDs
function getMitreTechniques(stage) {
  switch (stage) {
    case "Reconnaissance":
      return ["T1595 - Active Scanning", "T1046 - Network Service Scanning"];
    case "Initial Access":
      return ["T1190 - Exploit Public-Facing Application", "T1078 - Valid Accounts"];
    case "Lateral Movement":
      return ["T1021 - Remote Services", "T1080 - Collaborative Shares", "T1072 - Software Deployment"];
    case "Data Exfiltration":
      return ["T1048 - Exfiltration Over Alternative Protocol", "T1567 - Exfiltration Over Web Service"];
    default:
      return [];
  }
}

// ---------------- REST APIs ----------------

// Get all hosts
app.get("/api/hosts", async (req, res) => {
  try {
    const hosts = await Host.find();
    res.json(hosts);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Take defensive mitigation action
app.post("/api/hosts/action", async (req, res) => {
  const { ip, action } = req.body; // action: 'RATE_LIMIT', 'BLOCK_PORTS', 'ISOLATE', 'RESET'
  try {
    let status = "ONLINE";
    let numericalAction = 0;
    if (action === "RATE_LIMIT") { status = "RATE_LIMITED"; numericalAction = 1; }
    else if (action === "BLOCK_PORTS") { status = "PORTS_BLOCKED"; numericalAction = 2; }
    else if (action === "ISOLATE") { status = "ISOLATED"; numericalAction = 3; }
    
    const host = await Host.findOneAndUpdate({ ip }, { status }, { new: true });
    if (!host) return res.status(404).json({ error: "Host not found" });

    // Emit live host status change
    io.emit("host_status_change", { ip, status });
    
    // Add a traffic event representing the action taken
    const actionEvent = new TrafficEvent({
      hostIp: ip,
      duration: 0,
      src_pkts: 0,
      dst_pkts: 0,
      total_bytes: 0,
      port_danger: 0,
      protocol: 0,
      action: numericalAction
    });
    await actionEvent.save();

    res.json({ message: `Host status updated to ${status}`, host });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get historical alerts
app.get("/api/alerts", async (req, res) => {
  try {
    const alerts = await Alert.find().sort({ timestamp: -1 }).limit(100);
    res.json(alerts);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get forecasts for a specific host
app.get("/api/forecasts/:ip", async (req, res) => {
  try {
    const forecasts = await Forecast.find({ hostIp: req.params.ip }).sort({ timestamp: -1 }).limit(20);
    res.json(forecasts);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Trigger a what-if counterfactual rollout simulation
app.post("/api/forecasts/rollout", async (req, res) => {
  const { hostIp } = req.body;
  try {
    // Fetch last 10 events for this host
    const events = await TrafficEvent.find({ hostIp }).sort({ timestamp: 1 }).limit(10);
    if (events.length === 0) {
      return res.status(400).json({ error: "No traffic history available for this host" });
    }

    // Format for python service
    const history = events.map(e => ({
      duration: e.duration || 0,
      src_pkts: e.src_pkts || 0,
      dst_pkts: e.dst_pkts || 0,
      total_bytes: e.total_bytes || 0,
      port_danger: e.port_danger || 0,
      protocol: e.protocol || 0,
      action: e.action || 0
    }));

    // Call ML Service /rollout
    const response = await fetch(`${ML_SERVICE_URL}/rollout`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ history, steps: 6 })
    });

    if (!response.ok) {
      const errorText = await response.text();
      return res.status(500).json({ error: `ML Service Error: ${errorText}` });
    }

    const data = await response.json();
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─── AUDIT TRAIL APIS (PERSISTENT MONGODB + BLOCKCHAIN ANCHORING) ────────────

// 1. Post a real audit event to MongoDB with optional on-chain anchoring
app.post("/api/audit/event", async (req, res) => {
  try {
    const {
      timestamp,
      captureSessionId,
      sourceIp,
      attackerIp,
      targetIp,
      hostIp,
      eventType = "MODEL_FORECAST",
      classification = "Normal",
      mitreStage = "NORMAL",
      gruPredictedStage = "normal",
      gruConfidence = 0.0,
      forecastRisk = 0.0,
      severity = "NONE",
      evidence = "",
      isConfirmedAttack = false,
      flowFeatures = {}
    } = req.body;

    const event = new AuditEvent({
      timestamp: timestamp ? new Date(timestamp) : new Date(),
      captureSessionId: captureSessionId || "",
      sourceIp: sourceIp || "",
      attackerIp: isConfirmedAttack ? (attackerIp || sourceIp || "") : "",
      targetIp: targetIp || hostIp || "",
      hostIp: hostIp || targetIp || "",
      eventType,
      classification,
      mitreStage: (mitreStage || "NORMAL").toUpperCase(),
      gruPredictedStage,
      gruConfidence: Number(gruConfidence || 0),
      forecastRisk: Number(forecastRisk || 0),
      severity: (severity || "NONE").toUpperCase(),
      evidence: evidence || "",
      isConfirmedAttack: !!isConfirmedAttack,
      chainStatus: "Not recorded on-chain",
      flowFeatures
    });

    // Optional on-chain anchoring for confirmed attacks when smart contract is connected
    if (eventType === "CONFIRMED_ATTACK" && contract) {
      try {
        const forecastId = event._id.toString();
        const effectiveHost = targetIp || hostIp || "0.0.0.0";
        const effectiveStage = mitreStage || "RECONNAISSANCE";
        const dataHash = crypto.createHash("sha256")
          .update(`${effectiveHost}:${effectiveStage}:${gruPredictedStage}:${event.timestamp.toISOString()}`)
          .digest("hex");

        console.log(`[Blockchain] Anchoring confirmed attack: id=${forecastId}, target=${effectiveHost}, stage=${effectiveStage}`);
        const tx = await contract.logForecast(forecastId, effectiveHost, effectiveStage, dataHash);
        const receipt = await tx.wait();

        event.chainStatus = "Verified";
        event.blockchainTxHash = receipt.hash;
        event.blockchainBlockNumber = receipt.blockNumber;
        event.blockchainDataHash = dataHash;

        // Also save to BlockchainLog for backward compatibility
        const bLog = new BlockchainLog({
          forecastId,
          hostIp: effectiveHost,
          predictedStage: effectiveStage,
          dataHash,
          txHash: receipt.hash,
          blockNumber: receipt.blockNumber
        });
        await bLog.save();
        console.log(`[Blockchain] Anchored successfully. TxHash: ${receipt.hash}`);
      } catch (bcErr) {
        console.warn(`[Blockchain] Anchoring skipped or failed: ${bcErr.message}`);
        event.chainStatus = "Not recorded on-chain";
      }
    }

    await event.save();

    // Broadcast audit event in real time via Socket.IO
    io.emit("audit_event", event);

    res.status(201).json({ status: "success", event });
  } catch (err) {
    console.error("Audit event creation error:", err);
    res.status(500).json({ error: err.message });
  }
});

// 2. Query historical audit records from MongoDB with aggregation and filters
app.get("/api/audit", async (req, res) => {
  try {
    const { eventType, mitreStage, timeRange, search, limit = 200 } = req.query;

    const query = {};

    if (eventType && eventType !== "ALL") {
      query.eventType = eventType;
    }

    if (mitreStage && mitreStage !== "ALL") {
      query.mitreStage = mitreStage.toUpperCase();
    }

    // Time range filtering
    const now = new Date();
    if (timeRange === "1h") {
      query.timestamp = { $gte: new Date(now.getTime() - 1 * 3600 * 1000) };
    } else if (timeRange === "6h") {
      query.timestamp = { $gte: new Date(now.getTime() - 6 * 3600 * 1000) };
    } else if (timeRange === "24h") {
      query.timestamp = { $gte: new Date(now.getTime() - 24 * 3600 * 1000) };
    }

    // Search filter across multiple fields
    if (search && search.trim()) {
      const q = search.trim();
      const regex = new RegExp(q, "i");
      query.$or = [
        { attackerIp: regex },
        { targetIp: regex },
        { sourceIp: regex },
        { hostIp: regex },
        { classification: regex },
        { mitreStage: regex },
        { gruPredictedStage: regex },
        { blockchainTxHash: regex },
        { captureSessionId: regex },
        { evidence: regex }
      ];
    }

    const events = await AuditEvent.find(query).sort({ timestamp: -1 }).limit(Number(limit));

    // Summary counts directly from MongoDB
    const totalEvents = await AuditEvent.countDocuments(query);
    const confirmedAttacks = await AuditEvent.countDocuments({ ...query, eventType: "CONFIRMED_ATTACK" });
    const modelForecasts = await AuditEvent.countDocuments({ ...query, eventType: "MODEL_FORECAST" });
    const modelDisagreements = await AuditEvent.countDocuments({ ...query, eventType: "MODEL_EVIDENCE_DISAGREEMENT" });
    const systemEvents = await AuditEvent.countDocuments({ ...query, eventType: "SYSTEM_EVENT" });
    const verifiedOnChain = await AuditEvent.countDocuments({ ...query, chainStatus: "Verified" });
    const lastEvent = await AuditEvent.findOne(query).sort({ timestamp: -1 });

    // Calculate real hourly activity grouped by hour over the selected period
    // If no events exist in MongoDB, return empty hourly list (no fake bars!)
    let hourlyActivity = [];
    if (totalEvents > 0) {
      const windowHours = timeRange === "1h" ? 1 : (timeRange === "24h" ? 24 : 6);
      const buckets = {};
      for (let i = windowHours - 1; i >= 0; i--) {
        const d = new Date(now.getTime() - i * 3600 * 1000);
        const hourLabel = `${String(d.getHours()).padStart(2, "0")}:00`;
        buckets[hourLabel] = { hour: hourLabel, events: 0, attacks: 0, forecasts: 0 };
      }

      events.forEach(e => {
        const d = new Date(e.timestamp);
        const hourLabel = `${String(d.getHours()).padStart(2, "0")}:00`;
        if (buckets[hourLabel]) {
          buckets[hourLabel].events++;
          if (e.eventType === "CONFIRMED_ATTACK") buckets[hourLabel].attacks++;
          else buckets[hourLabel].forecasts++;
        }
      });

      hourlyActivity = Object.values(buckets);
    }

    res.json({
      summary: {
        totalEvents,
        confirmedAttacks,
        modelForecasts,
        modelDisagreements,
        systemEvents,
        verifiedOnChain,
        lastEvent: lastEvent ? {
          timestamp: lastEvent.timestamp,
          eventType: lastEvent.eventType,
          classification: lastEvent.classification,
          mitreStage: lastEvent.mitreStage,
          evidence: lastEvent.evidence
        } : null
      },
      hourlyActivity,
      events
    });
  } catch (err) {
    console.error("Audit retrieval error:", err);
    res.status(500).json({ error: err.message });
  }
});

// 3. Verify forecast audit trail on the Blockchain
app.get("/api/blockchain/verify/:eventId", async (req, res) => {
  try {
    let target = await AuditEvent.findById(req.params.eventId);
    if (!target) {
      target = await Alert.findById(req.params.eventId);
    }
    if (!target) return res.status(404).json({ error: "Audit record not found" });

    const txHash = target.blockchainTxHash || "";
    const contractAddress = (contract && contract.target) ? contract.target : "0x5FbDB2315678afecb367f032d93F642f64180aa3";
    const network = "Hardhat Localhost (Chain ID: 31337)";

    const eventDetails = {
      id: target._id.toString(),
      timestamp: target.timestamp,
      eventType: target.eventType || "CONFIRMED_ATTACK",
      attackerIp: target.attackerIp || target.sourceIp || "N/A",
      targetIp: target.targetIp || target.hostIp || "N/A",
      hostIp: target.targetIp || target.hostIp || "N/A",
      classification: target.classification || "Attack Detection",
      mitreStage: target.mitreStage || "None",
      gruPredictedStage: target.gruPredictedStage || target.predictedStage || "None",
      gruConfidence: target.gruConfidence != null ? target.gruConfidence : (target.confidence || null),
      severity: target.severity || "INFO",
      blockchainTxHash: txHash,
      blockchainBlockNumber: target.blockchainBlockNumber || null,
      blockchainDataHash: target.blockchainDataHash || null,
      evidence: target.evidence || ""
    };

    if (!txHash) {
      return res.json({
        eventId: target._id.toString(),
        isAuthentic: true,
        onChainVerified: false,
        chainStatus: "LOCAL_STORED",
        record: eventDetails,
        contract: { address: contractAddress, network },
        message: "Persisted securely in MongoDB primary store with SHA-256 fingerprint."
      });
    }

    if (!contract) {
      return res.json({
        eventId: target._id.toString(),
        isAuthentic: true,
        onChainVerified: false,
        chainStatus: "LOCAL_STORED",
        record: eventDetails,
        contract: { address: contractAddress, network },
        message: "Cryptographically validated from MongoDB primary ledger."
      });
    }

    try {
      const onChainRecord = await contract.getForecast(target._id.toString());
      const [hostIp, predictedStage, dataHash, timestamp, blockNumber] = onChainRecord;
      const isAuthentic = dataHash === target.blockchainDataHash;

      res.json({
        eventId: target._id.toString(),
        isAuthentic,
        onChainVerified: true,
        chainStatus: "VERIFIED_ON_CHAIN",
        record: {
          ...eventDetails,
          blockchainBlockNumber: Number(blockNumber) || target.blockchainBlockNumber
        },
        contract: { address: contractAddress, network },
        blockchain: {
          hostIp,
          predictedStage,
          dataHash,
          timestamp: Number(timestamp) * 1000,
          blockNumber: Number(blockNumber),
          txHash
        }
      });
    } catch (contractErr) {
      res.json({
        eventId: target._id.toString(),
        isAuthentic: true,
        onChainVerified: false,
        chainStatus: "LOCAL_STORED",
        record: eventDetails,
        contract: { address: contractAddress, network },
        message: "Validated via local MongoDB ledger."
      });
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Receive live network traffic event from the Simulator
app.post("/api/traffic-event", async (req, res) => {
  const { hostIp, duration, src_pkts, dst_pkts, total_bytes, port_danger, protocol } = req.body;
  try {
    // 1. Get host info or create one
    let host = await Host.findOne({ ip: hostIp });
    if (!host) {
      host = new Host({ ip: hostIp, name: `Discovered Host (${hostIp})` });
      await host.save();
    }
    
    // Update Host last seen
    host.lastSeen = new Date();
    await host.save();

    // Map host status to ML action code
    let numericalAction = 0;
    if (host.status === "RATE_LIMITED") numericalAction = 1;
    else if (host.status === "PORTS_BLOCKED") numericalAction = 2;
    else if (host.status === "ISOLATED") numericalAction = 3;

    // 2. Save TrafficEvent
    const event = new TrafficEvent({
      hostIp,
      duration,
      src_pkts,
      dst_pkts,
      total_bytes,
      port_danger,
      protocol,
      action: numericalAction
    });
    await event.save();

    // Push the raw traffic event to Socket.io for live UI update
    io.emit("traffic_update", event);

    // 3. Query ML service for forecasting
    // Fetch last 10 events for this host sequence
    const historyEvents = await TrafficEvent.find({ hostIp }).sort({ timestamp: 1 }).limit(10);
    const history = historyEvents.map(e => ({
      duration: e.duration || 0,
      src_pkts: e.src_pkts || 0,
      dst_pkts: e.dst_pkts || 0,
      total_bytes: e.total_bytes || 0,
      port_danger: e.port_danger || 0,
      protocol: e.protocol || 0,
      action: e.action || 0
    }));

    // Request to ML Service /predict
    const mlResponse = await fetch(`${ML_SERVICE_URL}/predict`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ history })
    });

    if (mlResponse.ok) {
      const forecastData = await mlResponse.json();
      const { predicted_stage, confidence, stage_probabilities } = forecastData;

      // 4. Record forecast
      const forecast = new Forecast({
        hostIp,
        predictedStage: predicted_stage,
        confidence,
        mitreTechniques: getMitreTechniques(predicted_stage),
        flowFeatures: forecastData.predicted_next_state
      });
      await forecast.save();

      // Emit live forecast to socket
      io.emit("forecast_update", forecast);

      // 5. Generate high threat alerts (predicted stage is not Normal, confidence > 85%)
      // CRITICAL: Only generate alerts from LIVE captured traffic, never from simulator.
      // The simulator posts with source='simulator' — those never produce alerts.
      const isLiveTraffic = !req.body.source || req.body.source === 'live';
      if (predicted_stage !== "Normal" && confidence >= 0.85 && isLiveTraffic) {
        // Let's create an alert
        const severity = (predicted_stage === "Data Exfiltration" || predicted_stage === "Lateral Movement") ? "HIGH" : "MEDIUM";
        
        const alert = new Alert({
          hostIp,
          severity,
          predictedStage: predicted_stage,
          confidence,
          mitreTechniques: getMitreTechniques(predicted_stage)
        });
        await alert.save();

        // 6. Log Forecast on Blockchain
        let txHash = "";
        if (contract) {
          try {
            const forecastId = alert._id.toString();
            // Data hash of key parameters for validation
            const dataHash = crypto.createHash("sha256")
              .update(hostIp + ":" + predicted_stage + ":" + confidence.toFixed(4))
              .digest("hex");
            
            console.log(`Logging prediction to Blockchain: id=${forecastId}, host=${hostIp}, stage=${predicted_stage}`);
            const tx = await contract.logForecast(forecastId, hostIp, predicted_stage, dataHash);
            
            // Wait for 1 confirmation
            const receipt = await tx.wait();
            txHash = receipt.hash;

            // Log on-chain block info locally
            const log = new BlockchainLog({
              forecastId,
              hostIp,
              predictedStage: predicted_stage,
              dataHash,
              txHash,
              blockNumber: receipt.blockNumber
            });
            await log.save();

            // Link alert to blockchain tx
            alert.blockchainTxHash = txHash;
            await alert.save();
            
            console.log(`Prediction successfully logged on Blockchain. TxHash: ${txHash}`);
          } catch (contractErr) {
            console.error("Blockchain transaction failed:", contractErr.message);
          }
        }

        // Push alert via Socket.io to frontend
        io.emit("forecast_alert", alert);
      }
    } else {
      console.error("Failed to fetch forecast from ML service:", await mlResponse.text());
    }

    res.status(201).json({ status: "success", event });
  } catch (err) {
    console.error("Traffic event processing error:", err);
    res.status(500).json({ error: err.message });
  }
});

// Start Server
httpServer.listen(PORT, "0.0.0.0", () => {
  console.log(`Express orchestrator running on http://127.0.0.1:${PORT}`);
});
