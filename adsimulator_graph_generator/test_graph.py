import torch
import torch.nn.functional as F
from torch.nn import Linear
from torch_geometric.nn import RGCNConv
import torch.optim as optim
import numpy as np
import sys
import os

class BudgetAllocationRGNN(torch.nn.Module):
    def __init__(self, num_node_features, hidden_dim, num_relations):
        super(BudgetAllocationRGNN, self).__init__()
        
        # 1. Relational Graph Convolutions (RGCN)
        self.conv1 = RGCNConv(num_node_features, hidden_dim, num_relations)
        self.conv2 = RGCNConv(hidden_dim, hidden_dim // 2, num_relations)
        
        # 2. Final Scoring Layer
        self.scorer = Linear(hidden_dim // 2, 1)

    def forward(self, x, edge_index, edge_type):
        # --- Message Passing ---
        h = self.conv1(x, edge_index, edge_type)
        h = F.relu(h)
        
        h = self.conv2(h, edge_index, edge_type)
        h = F.relu(h)
        
        # --- Raw Scoring ---
        raw_scores = self.scorer(h)  # Shape: [num_nodes, 1]
        
        # --- Constraint 1: All values must be between 0 and 1 ---
        allocations = torch.sigmoid(raw_scores)
        
        return allocations.squeeze() # Return as a 1D tensor [num_nodes]

def compute_loss(allocations, target_risk_reduction, target_budget, penalty_weight=10.0):
    task_loss = F.mse_loss(allocations, target_risk_reduction)
    
    current_sum = allocations.sum()
    budget_penalty = torch.abs(current_sum - target_budget)
    
    return task_loss + (penalty_weight * budget_penalty)


if __name__ == "__main__":
    # Specify the prefix you used when running the processing script
    # e.g., if you ran: python process_graph.py graph.json ad_graph
    # then the prefix is 'ad_graph'
    PREFIX = "ad_graph" if len(sys.argv) < 2 else sys.argv[1]
    
    if not os.path.exists(f"{PREFIX}_node_features.npy"):
        print(f"Error: Could not find '{PREFIX}_node_features.npy'.")
        print("Please run the data processing script first to generate the .npy files.")
        sys.exit(1)

    print(f"Loading data from prefix: '{PREFIX}'...")

    # --- 1. Load Data from .npy Files ---
    # Convert numpy arrays directly into PyTorch tensors
    x = torch.tensor(np.load(f"{PREFIX}_node_features.npy"), dtype=torch.float)
    edge_index = torch.tensor(np.load(f"{PREFIX}_edge_index.npy"), dtype=torch.long)
    edge_type = torch.tensor(np.load(f"{PREFIX}_edge_types.npy"), dtype=torch.long)

    # Automatically determine dimensions from the loaded data
    num_nodes = x.shape[0]
    num_features = x.shape[1]
    # num_relations is the maximum edge type index + 1
    num_relations = int(edge_type.max().item() + 1)

    print(f"Graph Loaded -> Nodes: {num_nodes} | Features: {num_features} | Edge Types: {num_relations} | Edges: {edge_index.shape[1]}")

    # --- 2. Initialize Model & Optimizer ---
    model = BudgetAllocationRGNN(num_node_features=num_features, hidden_dim=32, num_relations=num_relations)
    optimizer = optim.Adam(model.parameters(), lr=0.01)

    # --- 3. Define our constraints ---
    TARGET_BUDGET = 5.0  # e.g., We have enough budget to fully harden 5 nodes total
    
    # Since this is a demo without a real "Risk Calculator Baseline", 
    # we will mock the target risk reduction priorities for the specific number of nodes loaded.
    # In reality, this would be computed by a traditional pathfinding/defense algorithm.
    target_risk_reduction = torch.rand(num_nodes) 

    # --- 4. Training Loop ---
    print("\nStarting Training...")
    for epoch in range(1, 201):
        optimizer.zero_grad()
        
        # Get allocations (all between 0 and 1 due to Sigmoid)
        allocations = model(x, edge_index, edge_type)
        
        # Calculate loss including the budget penalty
        loss = compute_loss(allocations, target_risk_reduction, TARGET_BUDGET, penalty_weight=2.0)
        
        # Backpropagation
        loss.backward()
        optimizer.step()
        
        if epoch % 20 == 0:
            current_sum = allocations.sum().item()
            print(f"Epoch {epoch:03d} | Loss: {loss.item():.4f} | Sum of Allocations: {current_sum:.4f} (Target: {TARGET_BUDGET})")

    # --- 5. Final Output ---
    print("\n--- Final Graph Defense Budget Allocation ---")
    final_allocations = model(x, edge_index, edge_type).detach()
    
    # To avoid printing 416 lines, let's just print the top 10 nodes to allocate budget to
    top_nodes = torch.argsort(final_allocations, descending=True)[:10]
    
    for idx in top_nodes:
        node_id = idx.item()
        b = final_allocations[node_id].item()
        print(f"Node {node_id:03d} Allocation: {b:.4f}")
        
    print(f"...\nFinal Budget Spent: {final_allocations.sum().item():.4f} / {TARGET_BUDGET}")