import torch
import torch.nn as nn
import torch.optim as optim
import numpy as np
import os
import csv
from model import AttackWorldModel

# Set seed for reproducibility
np.random.seed(42)
torch.manual_seed(42)

# ── Realistic feature ranges based on actual network captures ────────────────
# These ranges are derived from real captured traffic, not generic datasets.
# [duration, src_pkts, dst_pkts, total_bytes, port_danger, protocol]
FEATURE_MAX = np.array([30.0, 500.0, 500.0, 2_000_000.0, 1.0, 1.0], dtype=np.float32)
FEATURE_MIN = np.array([0.0, 0.0, 0.0, 0.0, 0.0, 0.0], dtype=np.float32)

STAGE_NAMES = [
    "Normal",          # 0
    "Reconnaissance",  # 1
    "Initial Access",  # 2
    "Lateral Movement",# 3
    "Data Exfiltration"# 4
]


def _add_noise(state, scale=0.05):
    """Add small realistic noise to a state vector."""
    noise = np.random.uniform(-scale, scale, size=len(state)).astype(np.float32)
    noisy = np.array(state, dtype=np.float32) + noise * np.array(state, dtype=np.float32)
    return np.clip(noisy, 0, None).tolist()


def generate_normal_traffic(seq_len=10):
    """Generate a sequence of normal benign network traffic.
    Simulates typical web browsing, DNS, SSH, file transfers.
    """
    states = []
    actions = []
    labels = []

    # Normal traffic varies by service type
    normal_profiles = [
        # Web browsing: short flows, moderate packets
        {"dur_range": (0.05, 5.0), "src_range": (1, 50), "dst_range": (1, 50),
         "bytes_range": (100, 50000), "port_danger": 0.0, "proto": 1.0},
        # DNS queries: very short, few packets
        {"dur_range": (0.01, 0.5), "src_range": (1, 5), "dst_range": (1, 5),
         "bytes_range": (40, 500), "port_danger": 0.0, "proto": 1.0},
        # SSH session: longer duration, moderate data
        {"dur_range": (2.0, 20.0), "src_range": (5, 100), "dst_range": (3, 80),
         "bytes_range": (500, 100000), "port_danger": 0.0, "proto": 1.0},
        # File download: long duration, high bytes
        {"dur_range": (5.0, 25.0), "src_range": (10, 200), "dst_range": (10, 200),
         "bytes_range": (50000, 500000), "port_danger": 0.0, "proto": 1.0},
        # Video streaming: sustained moderate traffic
        {"dur_range": (10.0, 30.0), "src_range": (50, 300), "dst_range": (50, 300),
         "bytes_range": (100000, 800000), "port_danger": 0.0, "proto": 1.0},
    ]

    for t in range(seq_len):
        profile = np.random.choice(normal_profiles)
        state = [
            np.random.uniform(*profile["dur_range"]),
            np.random.uniform(*profile["src_range"]),
            np.random.uniform(*profile["dst_range"]),
            np.random.uniform(*profile["bytes_range"]),
            profile["port_danger"],
            profile["proto"],
        ]
        state = _add_noise(state, scale=0.03)
        states.append(state)
        actions.append([0.0])  # No action on normal traffic
        labels.append(0)       # Normal stage

    return states, actions, labels


def generate_recon_sequence(seq_len=10):
    """Generate a reconnaissance/scanning sequence.
    Attacker performs port scanning, service enumeration.
    """
    states = []
    actions = []
    labels = []

    for t in range(seq_len):
        if t < 3:
            # Pre-attack: normal traffic
            state = [
                np.random.uniform(0.05, 2.0),
                np.random.uniform(1, 10),
                np.random.uniform(1, 10),
                np.random.uniform(100, 5000),
                0.0,
                1.0,
            ]
            label = 0  # Normal
        else:
            # Scanning phase: many short connections to different ports
            scan_intensity = min(1.0, (t - 3) / 4.0)  # Ramp up
            state = [
                np.random.uniform(0.001, 0.1),  # Very short flows (SYN scans)
                np.random.uniform(1 + scan_intensity * 50, 3 + scan_intensity * 100),  # Low src packets
                np.random.uniform(0, 2),  # Few or no responses
                np.random.uniform(40 + scan_intensity * 200, 80 + scan_intensity * 500),  # Small packets
                min(1.0, 0.3 + scan_intensity * 0.7),  # Port danger increases
                1.0,
            ]
            label = 1  # Reconnaissance

        state = _add_noise(state, scale=0.04)
        states.append(state)
        actions.append([0.0])
        labels.append(label)

    return states, actions, labels


def generate_initial_access_sequence(seq_len=10):
    """Generate an initial access / exploitation sequence.
    Attacker exploits a vulnerability to gain access.
    """
    states = []
    actions = []
    labels = []

    for t in range(seq_len):
        if t < 2:
            # Pre-exploitation: normal or late recon
            state = [
                np.random.uniform(0.5, 3.0),
                np.random.uniform(5, 30),
                np.random.uniform(5, 30),
                np.random.uniform(500, 20000),
                0.2,
                1.0,
            ]
            label = 1  # Late reconnaissance
        elif t < 5:
            # Exploitation: targeted attack on specific service
            exploit_intensity = (t - 2) / 3.0
            state = [
                np.random.uniform(0.5, 2.0),  # Moderate duration
                np.random.uniform(20 + exploit_intensity * 80, 40 + exploit_intensity * 150),
                np.random.uniform(15 + exploit_intensity * 60, 30 + exploit_intensity * 120),
                np.random.uniform(2000 + exploit_intensity * 20000, 5000 + exploit_intensity * 50000),
                min(1.0, 0.4 + exploit_intensity * 0.4),  # High port danger
                1.0,
            ]
            label = 2  # Initial Access
        else:
            # Post-exploitation: establishing foothold
            state = [
                np.random.uniform(1.0, 5.0),
                np.random.uniform(30, 80),
                np.random.uniform(20, 60),
                np.random.uniform(5000, 80000),
                0.5,
                1.0,
            ]
            label = 2  # Still Initial Access stage

        state = _add_noise(state, scale=0.04)
        states.append(state)
        actions.append([0.0])
        labels.append(label)

    return states, actions, labels


def generate_lateral_movement_sequence(seq_len=10):
    """Generate lateral movement sequence.
    Attacker moves between hosts using stolen credentials.
    """
    states = []
    actions = []
    labels = []

    for t in range(seq_len):
        if t < 2:
            # Late initial access
            state = [
                np.random.uniform(1.0, 3.0),
                np.random.uniform(20, 60),
                np.random.uniform(15, 50),
                np.random.uniform(5000, 50000),
                0.5,
                1.0,
            ]
            label = 2
        else:
            # Lateral movement: SMB, RDP, WMI traffic to multiple hosts
            lat_intensity = (t - 2) / (seq_len - 2)
            state = [
                np.random.uniform(2.0, 15.0),  # Longer sessions (RDP/SMB)
                np.random.uniform(30 + lat_intensity * 50, 80 + lat_intensity * 100),
                np.random.uniform(20 + lat_intensity * 40, 60 + lat_intensity * 80),
                np.random.uniform(10000 + lat_intensity * 50000, 50000 + lat_intensity * 200000),
                min(1.0, 0.5 + lat_intensity * 0.3),
                1.0,
            ]
            label = 3  # Lateral Movement

        state = _add_noise(state, scale=0.04)
        states.append(state)
        actions.append([0.0])
        labels.append(label)

    return states, actions, labels


def generate_exfiltration_sequence(seq_len=10):
    """Generate data exfiltration sequence.
    Attacker siphons data out of the network.
    """
    states = []
    actions = []
    labels = []

    for t in range(seq_len):
        if t < 2:
            # Late lateral movement
            state = [
                np.random.uniform(3.0, 10.0),
                np.random.uniform(40, 80),
                np.random.uniform(30, 70),
                np.random.uniform(20000, 100000),
                0.6,
                1.0,
            ]
            label = 3
        else:
            # Exfiltration: large data transfers over long connections
            exfil_intensity = (t - 2) / (seq_len - 2)
            state = [
                np.random.uniform(5.0, 30.0),  # Long duration
                np.random.uniform(100 + exfil_intensity * 300, 200 + exfil_intensity * 400),
                np.random.uniform(80 + exfil_intensity * 250, 150 + exfil_intensity * 350),
                np.random.uniform(100000 + exfil_intensity * 500000, 300000 + exfil_intensity * 1000000),
                min(1.0, 0.4 + exfil_intensity * 0.4),
                1.0,
            ]
            label = 4  # Data Exfiltration

        state = _add_noise(state, scale=0.04)
        states.append(state)
        actions.append([0.0])
        labels.append(label)

    return states, actions, labels


def generate_mitigated_sequence(attack_type, action_at_step, action_type):
    """Generate a sequence where an attack is mitigated by a defensive action."""
    # Generate the base attack sequence
    generators = {
        "recon": generate_recon_sequence,
        "initial_access": generate_initial_access_sequence,
        "lateral_movement": generate_lateral_movement_sequence,
        "exfiltration": generate_exfiltration_sequence,
    }
    states, actions, labels = generators[attack_type](10)

    # Apply mitigation action from action_at_step onwards
    for t in range(action_at_step, 10):
        actions[t] = [float(action_type)]

        if action_type == 3:  # Isolate Host
            states[t] = [0.0, 0.0, 0.0, 0.0, 0.0, 0.0]
            labels[t] = 0  # Back to Normal
        elif action_type == 2:  # Block Port
            states[t][4] = 0.0  # Port danger zeroed
            states[t][1] *= 0.1
            states[t][2] *= 0.1
            states[t][3] *= 0.05
            labels[t] = max(0, labels[t] - 1)  # Regression in threat
        elif action_type == 1:  # Rate Limit
            states[t][1] *= 0.5
            states[t][2] *= 0.5
            states[t][3] *= 0.5

    return states, actions, labels


def load_live_data(csv_path):
    """Load live captured flow data from CSV for retraining."""
    if not os.path.exists(csv_path):
        return []

    sequences = []
    current_seq = []
    current_label = 0

    try:
        with open(csv_path, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                try:
                    duration = max(float(row.get('duration', 0.001)), 0.001)
                    packet_count = max(int(float(row.get('packet_count', 1))), 1)
                    byte_count = int(float(row.get('byte_count', 0)))

                    state = [
                        duration,
                        packet_count * 0.5,  # Approximate src_pkts
                        packet_count * 0.5,  # Approximate dst_pkts
                        byte_count,
                        0.0,  # port_danger from heuristic
                        1.0 if str(row.get('protocol', 'TCP')).upper() == 'TCP' else 0.8,
                    ]

                    # Map label to stage
                    label_map = {
                        'benign': 0, 'normal': 0,
                        'port_scan': 1, 'reconnaissance': 1,
                        'brute_force': 2, 'dos_ddos': 2,
                        'exfiltration': 4, 'data_exfiltration': 4,
                        'arp_spoof': 1, 'large_transfer': 3,
                    }
                    stage = label_map.get(row.get('label', 'benign'), 0)

                    current_seq.append(state)
                    current_label = stage

                    if len(current_seq) == 10:
                        sequences.append((current_seq[:], [0.0] * 10, [current_label] * 10))
                        current_seq = current_seq[5:]  # 50% overlap
                except (ValueError, KeyError):
                    continue
    except Exception as e:
        print(f"  Warning: Could not load live data: {e}")

    return sequences


def train_model():
    print("=" * 60)
    print("  GRU WORLD MODEL TRAINING (Enhanced)")
    print("=" * 60)

    X_states = []
    X_actions = []
    y_stages = []

    # 1. Load live captured data first (if available)
    live_csv = os.path.join(os.path.dirname(__file__), '..', 'logs', 'live_flows_for_training.csv')
    live_sequences = load_live_data(live_csv)
    if live_sequences:
        print(f"\n[+] Loaded {len(live_sequences)} sequences from live capture data")
        for states, actions, labels in live_sequences:
            X_states.append(states)
            X_actions.append(actions)
            y_stages.append(labels)

    # 2. Generate diverse synthetic training data
    print("\n[*] Generating realistic synthetic training sequences...")

    # Generate many normal traffic sequences
    for _ in range(400):
        states, actions, labels = generate_normal_traffic(10)
        X_states.append(states)
        X_actions.append(actions)
        y_stages.append(labels)

    # Full attack progression sequences
    for _ in range(150):
        states, actions, labels = generate_recon_sequence(10)
        X_states.append(states)
        X_actions.append(actions)
        y_stages.append(labels)

    for _ in range(150):
        states, actions, labels = generate_initial_access_sequence(10)
        X_states.append(states)
        X_actions.append(actions)
        y_stages.append(labels)

    for _ in range(100):
        states, actions, labels = generate_lateral_movement_sequence(10)
        X_states.append(states)
        X_actions.append(actions)
        y_stages.append(labels)

    for _ in range(100):
        states, actions, labels = generate_exfiltration_sequence(10)
        X_states.append(states)
        X_actions.append(actions)
        y_stages.append(labels)

    # Mitigated attack sequences (defensive actions)
    for attack in ["recon", "initial_access", "lateral_movement", "exfiltration"]:
        for action_type in [1, 2, 3]:  # Rate limit, Block, Isolate
            for step in [3, 5, 7]:
                for _ in range(30):
                    states, actions, labels = generate_mitigated_sequence(attack, step, action_type)
                    X_states.append(states)
                    X_actions.append(actions)
                    y_stages.append(labels)

    X_states = np.array(X_states, dtype=np.float32)
    X_actions = np.array(X_actions, dtype=np.float32)
    y_stages = np.array(y_stages, dtype=np.int64)

    # Normalize
    X_states_scaled = (X_states - FEATURE_MIN) / (FEATURE_MAX - FEATURE_MIN + 1e-8)

    # Create target next states: shifted by 1 step
    y_next_states_scaled = np.zeros_like(X_states_scaled)
    y_next_states_scaled[:, :-1, :] = X_states_scaled[:, 1:, :]
    y_next_states_scaled[:, -1, :] = X_states_scaled[:, -1, :]

    # Convert to Tensors
    X_states_t = torch.tensor(X_states_scaled, dtype=torch.float32)
    X_actions_t = torch.tensor(X_actions, dtype=torch.float32)
    y_next_states_t = torch.tensor(y_next_states_scaled, dtype=torch.float32)
    y_stages_t = torch.tensor(y_stages, dtype=torch.int64)

    print(f"    Total sequences: {len(X_states_t)}")
    print(f"    Stage distribution:")
    for i, name in enumerate(STAGE_NAMES):
        count = (y_stages == i).sum()
        print(f"      {name}: {count} ({count/len(y_stages)*100:.1f}%)")

    # Initialize Model
    model = AttackWorldModel(feature_dim=6, action_dim=1, hidden_dim=32, num_classes=5)

    # Loss functions & Optimizer
    criterion_state = nn.MSELoss()
    criterion_stage = nn.CrossEntropyLoss()
    optimizer = optim.Adam(model.parameters(), lr=0.003, weight_decay=1e-5)

    epochs = 40
    batch_size = 64
    num_samples = len(X_states_t)

    print(f"\n[*] Training GRU World Model for {epochs} epochs...")
    best_loss = float('inf')
    model.train()

    for epoch in range(epochs):
        epoch_loss = 0
        state_loss_val = 0
        stage_loss_val = 0

        indices = np.arange(num_samples)
        np.random.shuffle(indices)

        for i in range(0, num_samples, batch_size):
            batch_idx = indices[i:i+batch_size]
            b_states = X_states_t[batch_idx]
            b_actions = X_actions_t[batch_idx]
            b_next_states = y_next_states_t[batch_idx]
            b_stages = y_stages_t[batch_idx]

            optimizer.zero_grad()

            pred_next_states, pred_stage_logits, _ = model(b_states, b_actions)

            loss_state = criterion_state(pred_next_states, b_next_states)
            loss_stage = criterion_stage(pred_stage_logits.view(-1, 5), b_stages.view(-1))

            loss = loss_state * 2.0 + loss_stage * 1.0

            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
            optimizer.step()

            epoch_loss += loss.item() * len(batch_idx)
            state_loss_val += loss_state.item() * len(batch_idx)
            stage_loss_val += loss_stage.item() * len(batch_idx)

        epoch_loss /= num_samples
        state_loss_val /= num_samples
        stage_loss_val /= num_samples

        if epoch_loss < best_loss:
            best_loss = epoch_loss

        if (epoch + 1) % 5 == 0:
            print(f"  Epoch {epoch+1:3d}/{epochs} - Total: {epoch_loss:.4f} | State MSE: {state_loss_val:.4f} | Stage CE: {stage_loss_val:.4f}")

    # Save model and configuration
    save_path = os.path.join(os.path.dirname(__file__), "world_model.pth")
    torch.save({
        'model_state_dict': model.state_dict(),
        'feature_min': FEATURE_MIN.tolist(),
        'feature_max': FEATURE_MAX.tolist()
    }, save_path)
    print(f"\n[+] Model saved to {save_path}")

    # Quick validation
    model.eval()
    with torch.no_grad():
        # Test normal traffic prediction
        normal_state = np.array([[[0.5, 5.0, 5.0, 2000.0, 0.0, 1.0]]], dtype=np.float32)
        normal_scaled = (normal_state - FEATURE_MIN) / (FEATURE_MAX - FEATURE_MIN + 1e-8)
        normal_tensor = torch.tensor(normal_scaled, dtype=torch.float32)
        normal_action = torch.tensor([[[0.0]]], dtype=torch.float32)

        _, stage_logits, _ = model(normal_tensor, normal_action)
        probs = torch.softmax(stage_logits, dim=-1)
        pred_stage = STAGE_NAMES[probs.argmax(dim=-1).item()]
        confidence = probs.max().item()
        print(f"\n  Validation - Normal traffic prediction: {pred_stage} ({confidence:.1%})")

        # Test attack traffic prediction
        attack_state = np.array([[[0.01, 80.0, 1.0, 100.0, 0.9, 1.0]]], dtype=np.float32)
        attack_scaled = (attack_state - FEATURE_MIN) / (FEATURE_MAX - FEATURE_MIN + 1e-8)
        attack_tensor = torch.tensor(attack_scaled, dtype=torch.float32)

        _, stage_logits, _ = model(attack_tensor, normal_action)
        probs = torch.softmax(stage_logits, dim=-1)
        pred_stage = STAGE_NAMES[probs.argmax(dim=-1).item()]
        confidence = probs.max().item()
        print(f"  Validation - Attack traffic prediction: {pred_stage} ({confidence:.1%})")

    print("\n" + "=" * 60)
    print("  TRAINING COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    train_model()
