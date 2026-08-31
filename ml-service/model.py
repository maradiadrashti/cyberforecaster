import torch
import torch.nn as nn

class AttackWorldModel(nn.Module):
    def __init__(self, feature_dim=6, action_dim=1, hidden_dim=32, num_classes=5):
        super().__init__()
        self.feature_dim = feature_dim
        self.action_dim = action_dim
        self.hidden_dim = hidden_dim
        self.num_classes = num_classes
        
        # Inputs: concatenated state vector (feature_dim) and action vector (action_dim)
        self.gru = nn.GRU(
            input_size=feature_dim + action_dim,
            hidden_size=hidden_dim,
            num_layers=1,
            batch_first=True
        )
        # Head 1: Predicts the next state features (regression)
        self.state_head = nn.Linear(hidden_dim, feature_dim)
        # Head 2: Predicts the attack stage classification (logits)
        self.stage_head = nn.Linear(hidden_dim, num_classes)
        
    def forward(self, state_sequence, actions, hidden=None):
        # state_sequence: (batch, seq_len, feature_dim)
        # actions: (batch, seq_len, action_dim)
        # Concatenate states and actions along the feature dimension
        x = torch.cat([state_sequence, actions], dim=-1)
        
        # Pass through GRU
        out, hidden = self.gru(x, hidden)
        
        # Out shape: (batch, seq_len, hidden_dim)
        next_states = self.state_head(out)
        stage_logits = self.stage_head(out)
        
        return next_states, stage_logits, hidden

    def rollout(self, state_history, action_history, future_actions):
        """
        Runs a counterfactual rollout for a sequence of future actions.
        Args:
            state_history: Tensor of shape (1, seq_len, feature_dim)
            action_history: Tensor of shape (1, seq_len, action_dim)
            future_actions: List of integers representing future intervention actions
        Returns:
            predicted_states: List of state vectors (each length feature_dim)
            predicted_stages: List of class probability distributions (each length num_classes)
        """
        self.eval()
        with torch.no_grad():
            # 1. Warm up the GRU with the history to get the current hidden state
            _, _, hidden = self.forward(state_history, action_history)
            
            last_state = state_history[:, -1:, :] # Shape: (1, 1, feature_dim)
            
            predicted_states = []
            predicted_stages = []
            
            # 2. Rollout future actions step-by-step
            for action_val in future_actions:
                # Format current action as tensor (1, 1, 1)
                action_tensor = torch.tensor([[[float(action_val)]]], dtype=torch.float32)
                
                # Predict next step
                x = torch.cat([last_state, action_tensor], dim=-1)
                out, hidden = self.gru(x, hidden)
                
                next_state = self.state_head(out)
                stage_logits = self.stage_head(out)
                
                # Apply softmax to get probabilities
                probs = torch.softmax(stage_logits, dim=-1).squeeze(0).squeeze(0).tolist()
                
                predicted_states.append(next_state.squeeze(0).squeeze(0).tolist())
                predicted_stages.append(probs)
                
                # Update last state to be the predicted state for the next step of recursion
                last_state = next_state
                
        return predicted_states, predicted_stages
