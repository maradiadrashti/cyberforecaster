import torch
import torch.nn as nn
import torch.optim as optim
import numpy as np
from model import AttackWorldModel

# Set seed for reproducibility
np.random.seed(42)
torch.manual_seed(42)

def generate_sequence(attack_type="recon", action_at_step=None, action_type=0):
    """
    Generates a sequence of 10 flow vectors representing a specific network scenario.
    Flow vector: [duration, src_pkts, dst_pkts, total_bytes, port_danger, protocol]
    Action: 0=None, 1=Rate Limit, 2=Block Port, 3=Isolate Host
    """
    seq_len = 10
    states = []
    actions = []
    labels = []
    
    # Starting state (Normal)
    current_state = [0.1, 2.0, 2.0, 150.0, 0.0, 0.8]  # normal web traffic
    
    for t in range(seq_len):
        # Determine current action
        curr_action = 0.0
        if action_at_step is not None and t >= action_at_step:
            curr_action = float(action_type)
            
        actions.append([curr_action])
        
        # Determine transition behavior based on action
        if curr_action == 3.0: # Isolate Host
            # Immediately drop all traffic features to near zero
            current_state = [0.0, 0.0, 0.0, 0.0, 0.0, 0.0]
            label = 0 # Normal
        elif curr_action == 2.0: # Block Port
            # Port danger goes to 0, traffic bytes/packets drop
            current_state[4] = 0.0
            current_state[1] = max(0.1, current_state[1] * 0.1)
            current_state[2] = max(0.1, current_state[2] * 0.1)
            current_state[3] = max(10.0, current_state[3] * 0.05)
            # Progression stops or reduces threat level
            label = max(0, labels[-1] - 1) if len(labels) > 0 else 0
        elif curr_action == 1.0: # Rate Limit
            # Bytes and packets halved, duration might increase
            current_state[0] = current_state[0] * 1.5
            current_state[1] = current_state[1] * 0.5
            current_state[2] = current_state[2] * 0.5
            current_state[3] = current_state[3] * 0.5
            # Progression slows down
            label = labels[-1] if len(labels) > 0 else 0
        else: # No Action (progression continues)
            if attack_type == "full_attack":
                # Progression: 0-1 Normal, 2-3 Recon, 4-5 Access, 6-7 Lateral, 8-9 Exfiltration
                if t < 2:
                    current_state = [0.2, 3.0, 3.0, 200.0, 0.0, 1.0] # Normal
                    label = 0
                elif t < 4:
                    current_state = [0.5, 20.0, 10.0, 500.0, 1.0, 1.0] # Recon (Scanning)
                    label = 1
                elif t < 6:
                    current_state = [1.2, 50.0, 45.0, 5000.0, 0.5, 1.0] # Initial Access (Exploit SSH/HTTP)
                    label = 2
                elif t < 8:
                    current_state = [2.5, 30.0, 20.0, 3000.0, 0.8, 1.0] # Lateral Movement (RDP/SMB)
                    label = 3
                else:
                    current_state = [10.0, 200.0, 100.0, 150000.0, 0.4, 1.0] # Exfiltration (High Bytes transfer)
                    label = 4
            elif attack_type == "recon_only":
                if t < 3:
                    current_state = [0.2, 3.0, 3.0, 200.0, 0.0, 1.0]
                    label = 0
                else:
                    current_state = [0.8, 45.0, 15.0, 800.0, 1.0, 1.0] # Recon scanning
                    label = 1
            else: # Normal only
                current_state = [0.15 + np.random.uniform(-0.05, 0.05), 
                                 2.0 + np.random.randint(-1, 2), 
                                 2.0 + np.random.randint(-1, 2), 
                                 150.0 + np.random.randint(-50, 50), 
                                 0.0, 0.8]
                label = 0
                
        states.append(list(current_state))
        labels.append(label)
        
    return states, actions, labels

def train_model():
    print("Generating simulated network attack dataset...")
    X_states = []
    X_actions = []
    y_next_states = []
    y_stages = []
    
    # Generate a dataset of 800 samples
    for _ in range(300):
        # 1. Full attacks
        states, actions, labels = generate_sequence("full_attack")
        X_states.append(states)
        X_actions.append(actions)
        y_stages.append(labels)
        
        # 2. Attacks mitigated by Isolation
        states, actions, labels = generate_sequence("full_attack", action_at_step=6, action_type=3)
        X_states.append(states)
        X_actions.append(actions)
        y_stages.append(labels)
        
        # 3. Attacks mitigated by Block Port
        states, actions, labels = generate_sequence("full_attack", action_at_step=5, action_type=2)
        X_states.append(states)
        X_actions.append(actions)
        y_stages.append(labels)

    for _ in range(250):
        # Normal traffic
        states, actions, labels = generate_sequence("normal")
        X_states.append(states)
        X_actions.append(actions)
        y_stages.append(labels)

    for _ in range(250):
        # Recon only
        states, actions, labels = generate_sequence("recon_only")
        X_states.append(states)
        X_actions.append(actions)
        y_stages.append(labels)

    X_states = np.array(X_states, dtype=np.float32)
    X_actions = np.array(X_actions, dtype=np.float32)
    y_stages = np.array(y_stages, dtype=np.int64)
    
    # We need to scale the data: normalise features
    # Min-max values for scaling flow features:
    # duration (0 to 15), src_pkts (0 to 250), dst_pkts (0 to 150), total_bytes (0 to 200,000), port_danger (0 to 1), protocol (0 to 1)
    feature_max = np.array([15.0, 250.0, 150.0, 200000.0, 1.0, 1.0], dtype=np.float32)
    feature_min = np.array([0.0, 0.0, 0.0, 0.0, 0.0, 0.0], dtype=np.float32)
    
    # Normalize X_states
    X_states_scaled = (X_states - feature_min) / (feature_max - feature_min + 1e-8)
    
    # Create target next states: shifted by 1 step in sequence
    # For index t, the target is t+1 state. The last step can target a replica of itself or zero
    y_next_states_scaled = np.zeros_like(X_states_scaled)
    y_next_states_scaled[:, :-1, :] = X_states_scaled[:, 1:, :]
    y_next_states_scaled[:, -1, :] = X_states_scaled[:, -1, :]
    
    # Convert to Tensors
    X_states_t = torch.tensor(X_states_scaled, dtype=torch.float32)
    X_actions_t = torch.tensor(X_actions, dtype=torch.float32)
    y_next_states_t = torch.tensor(y_next_states_scaled, dtype=torch.float32)
    y_stages_t = torch.tensor(y_stages, dtype=torch.int64)
    
    # Initialize Model
    model = AttackWorldModel(feature_dim=6, action_dim=1, hidden_dim=32, num_classes=5)
    
    # Loss functions & Optimizer
    criterion_state = nn.MSELoss()
    criterion_stage = nn.CrossEntropyLoss()
    optimizer = optim.Adam(model.parameters(), lr=0.005)
    
    epochs = 25
    batch_size = 64
    num_samples = len(X_states_t)
    
    print("Training GRU World Model...")
    model.train()
    for epoch in range(epochs):
        epoch_loss = 0
        state_loss_val = 0
        stage_loss_val = 0
        
        # Shuffle batch indices
        indices = np.arange(num_samples)
        np.random.shuffle(indices)
        
        for i in range(0, num_samples, batch_size):
            batch_idx = indices[i:i+batch_size]
            b_states = X_states_t[batch_idx]
            b_actions = X_actions_t[batch_idx]
            b_next_states = y_next_states_t[batch_idx]
            b_stages = y_stages_t[batch_idx]
            
            optimizer.zero_grad()
            
            # Forward pass
            pred_next_states, pred_stage_logits, _ = model(b_states, b_actions)
            
            # Loss calculations
            loss_state = criterion_state(pred_next_states, b_next_states)
            # Stage prediction is done at each step in the sequence, so flatten the tensors
            loss_stage = criterion_stage(pred_stage_logits.view(-1, 5), b_stages.view(-1))
            
            # Total Loss (weighted)
            loss = loss_state * 2.0 + loss_stage * 1.0
            
            loss.backward()
            optimizer.step()
            
            epoch_loss += loss.item() * len(batch_idx)
            state_loss_val += loss_state.item() * len(batch_idx)
            stage_loss_val += loss_stage.item() * len(batch_idx)
            
        epoch_loss /= num_samples
        state_loss_val /= num_samples
        stage_loss_val /= num_samples
        
        if (epoch + 1) % 5 == 0:
            print(f"Epoch {epoch+1}/{epochs} - Total Loss: {epoch_loss:.4f} | State MSE: {state_loss_val:.4f} | Stage CrossEntropy: {stage_loss_val:.4f}")
            
    # Save model and configuration
    save_path = "world_model.pth"
    torch.save({
        'model_state_dict': model.state_dict(),
        'feature_min': feature_min.tolist(),
        'feature_max': feature_max.tolist()
    }, save_path)
    print(f"Model saved to {save_path}!")

if __name__ == "__main__":
    train_model()
