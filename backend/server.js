import express from "express";
import { createServer } from "http";
import { Server } from "socket.io";
import cors from "cors";
import mongoose from "mongoose";
import { ethers } from "ethers";
import crypto from "crypto";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

import { Host, TrafficEvent, Forecast, Alert, BlockchainLog } from "./models.js";

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

const PORT = 5050;
const ML_SERVICE_URL = "http://127.0.0.1:8000";
const MONGO_URI = "mongodb://127.0.0.1:27017/attack_forecasting";

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
    provider = new ethers.JsonRpcProvider("http://127.0.0.1:8545");
    
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

// Verify forecast audit trail on the Blockchain
app.get("/api/blockchain/verify/:alertId", async (req, res) => {
  try {
    const alert = await Alert.findById(req.params.alertId);
    if (!alert) return res.status(404).json({ error: "Alert not found" });

    const log = await BlockchainLog.findOne({ forecastId: alert._id.toString() });
    if (!log) return res.status(404).json({ error: "Blockchain verification log not found locally" });

    if (!contract) {
      return res.status(503).json({ error: "Blockchain contract not ready" });
    }

    // Query the smart contract
    const onChainRecord = await contract.getForecast(alert._id.toString());
    const [hostIp, predictedStage, dataHash, timestamp, blockNumber] = onChainRecord;

    // Check matching
    const isAuthentic = dataHash === log.dataHash;

    res.json({
      alertId: alert._id.toString(),
      isAuthentic,
      blockchain: {
        hostIp,
        predictedStage,
        dataHash,
        timestamp: Number(timestamp) * 1000,
        blockNumber: Number(blockNumber)
      },
      local: {
        hostIp: log.hostIp,
        predictedStage: log.predictedStage,
        dataHash: log.dataHash,
        txHash: log.txHash
      }
    });
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

      // 5. Generate high threat alerts (predicted stage is not Normal, confidence > 50%)
      if (predicted_stage !== "Normal" && confidence >= 0.50) {
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
