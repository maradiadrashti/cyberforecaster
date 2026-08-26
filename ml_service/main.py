from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Dict, Any
import torch
import numpy as np
import os
from model import AttackWorldModel
from train_simulator import train_model

app = FastAPI(title="SIH 2026 Cybersecurity Forecasting ML Service")

# Allow CORS for backend communication
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global variables for model
model = None
feature_min = None
feature_max = None

class FlowRecord(BaseModel):
    duration: float
    src_pkts: float
    dst_pkts: float
    total_bytes: float
    port_danger: float
    protocol: float
    action: float # 0=None, 1=Rate Limit, 2=Block Port, 3=Isolate Host

class PredictRequest(BaseModel):
    history: List[FlowRecord]

class RolloutRequest(BaseModel):
    history: List[FlowRecord]
    steps: int = 5

STAGE_NAMES = [
    "Normal",
    "Reconnaissance",
    "Initial Access",
    "Lateral Movement",
    "Data Exfiltration"
]

def load_model():
    global model, feature_min, feature_max
    model_path = "world_model.pth"
    if not os.path.exists(model_path):
        print("Model file not found. Running training first...")
        train_model()
    
    checkpoint = torch.load(model_path, map_location=torch.device('cpu'))
    model = AttackWorldModel(feature_dim=6, action_dim=1, hidden_dim=32, num_classes=5)
    model.load_state_dict(checkpoint['model_state_dict'])
    model.eval()
    
    feature_min = np.array(checkpoint['feature_min'], dtype=np.float32)
    feature_max = np.array(checkpoint['feature_max'], dtype=np.float32)
    print("Model loaded successfully!")

@app.on_event("startup")
def startup_event():
    load_model()

@app.post("/predict")
def predict(request: PredictRequest):
    global model, feature_min, feature_max
    if model is None:
        load_model()
        
    if not request.history:
        raise HTTPException(status_code=400, detail="History cannot be empty")
        
    try:
        # 1. Parse request history
        raw_states = []
        raw_actions = []
        for record in request.history:
            raw_states.append([
                record.duration,
                record.src_pkts,
                record.dst_pkts,
                record.total_bytes,
                record.port_danger,
                record.protocol
            ])
            raw_actions.append([record.action])
            
        # Convert to numpy arrays
        states_np = np.array(raw_states, dtype=np.float32)
        actions_np = np.array(raw_actions, dtype=np.float32)
        
        # Add batch dimension (1, seq_len, dim)
        states_np = np.expand_dims(states_np, axis=0)
        actions_np = np.expand_dims(actions_np, axis=0)
        
        # 2. Normalize
        states_scaled = (states_np - feature_min) / (feature_max - feature_min + 1e-8)
        
        # 3. Convert to torch tensors
        states_tensor = torch.tensor(states_scaled, dtype=torch.float32)
        actions_tensor = torch.tensor(actions_np, dtype=torch.float32)
        
        # 4. Predict
        model.eval()
        with torch.no_grad():
            next_states_scaled, stage_logits, _ = model(states_tensor, actions_tensor)
            
            # Extract last predictions in sequence
            last_state_scaled = next_states_scaled[0, -1, :].numpy()
            last_stage_logits = stage_logits[0, -1, :]
            
            # Apply softmax for probabilities
            stage_probs = torch.softmax(last_stage_logits, dim=-1).tolist()
            
            # De-normalize predicted next state
            predicted_next_state = (last_state_scaled * (feature_max - feature_min) + feature_min).tolist()
            
        predicted_stage_idx = int(np.argmax(stage_probs))
        
        return {
            "predicted_next_state": {
                "duration": predicted_next_state[0],
                "src_pkts": predicted_next_state[1],
                "dst_pkts": predicted_next_state[2],
                "total_bytes": predicted_next_state[3],
                "port_danger": predicted_next_state[4],
                "protocol": predicted_next_state[5]
            },
            "stage_probabilities": {STAGE_NAMES[i]: stage_probs[i] for i in range(5)},
            "predicted_stage": STAGE_NAMES[predicted_stage_idx],
            "confidence": stage_probs[predicted_stage_idx]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/rollout")
def rollout(request: RolloutRequest):
    global model, feature_min, feature_max
    if model is None:
        load_model()
        
    if not request.history:
        raise HTTPException(status_code=400, detail="History cannot be empty")
        
    try:
        # Extract history
        raw_states = []
        raw_actions = []
        for record in request.history:
            raw_states.append([
                record.duration,
                record.src_pkts,
                record.dst_pkts,
                record.total_bytes,
                record.port_danger,
                record.protocol
            ])
            raw_actions.append([record.action])
            
        states_np = np.array(raw_states, dtype=np.float32)
        actions_np = np.array(raw_actions, dtype=np.float32)
        
        states_np = np.expand_dims(states_np, axis=0)
        actions_np = np.expand_dims(actions_np, axis=0)
        
        states_scaled = (states_np - feature_min) / (feature_max - feature_min + 1e-8)
        
        state_history_tensor = torch.tensor(states_scaled, dtype=torch.float32)
        action_history_tensor = torch.tensor(actions_np, dtype=torch.float32)
        
        # Scenarios to simulate
        scenarios = {
            "do_nothing": [0.0] * request.steps,
            "rate_limit": [1.0] * request.steps,
            "block_port": [2.0] * request.steps,
            "isolate_host": [3.0] * request.steps
        }
        
        rollout_results = {}
        
        for name, fut_actions in scenarios.items():
            pred_states_scaled, pred_stages_probs = model.rollout(
                state_history_tensor, action_history_tensor, fut_actions
            )
            
            # Map predictions to timeline
            timeline = []
            for t in range(request.steps):
                probs = pred_stages_probs[t]
                # De-normalize predicted state at time t
                scaled_state = np.array(pred_states_scaled[t], dtype=np.float32)
                state_features = (scaled_state * (feature_max - feature_min) + feature_min).tolist()
                
                # Identify stage name with max probability
                max_stage_idx = int(np.argmax(probs))
                
                timeline.append({
                    "step": t + 1,
                    "stage_probabilities": {STAGE_NAMES[i]: probs[i] for i in range(5)},
                    "predicted_stage": STAGE_NAMES[max_stage_idx],
                    "threat_level": float(sum(i * probs[i] for i in range(5)) / 4.0), # weighted threat score [0, 1]
                    "flow_features": {
                        "duration": state_features[0],
                        "src_pkts": state_features[1],
                        "dst_pkts": state_features[2],
                        "total_bytes": state_features[3],
                        "port_danger": state_features[4],
                        "protocol": state_features[5]
                    }
                })
            rollout_results[name] = timeline
            
        return {
            "history_length": len(request.history),
            "rollout_steps": request.steps,
            "scenarios": rollout_results
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/train")
def trigger_training():
    try:
        train_model()
        load_model()
        return {"status": "success", "message": "Model trained and loaded successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
