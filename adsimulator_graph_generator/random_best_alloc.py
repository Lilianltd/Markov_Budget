import numpy as np
import sys
import os

def build_transition_matrix(edges, num_nodes):
    """
    Converts the edge list into a probability transition matrix 'T'.
    If Node A has 3 outgoing edges, each edge gets 1/3 of Node A's 'attack flow'.
    """
    T = np.zeros((num_nodes, num_nodes))
    sources = edges[0]
    targets = edges[1]
    
    # Count how many outgoing edges each node has
    out_degrees = np.bincount(sources, minlength=num_nodes)
    
    # Avoid division by zero for nodes with no outgoing edges
    out_degrees[out_degrees == 0] = 1.0 
    
    # Populate the transition matrix
    T[sources, targets] = 1.0 / out_degrees[sources]
    
    return T

def generate_subgraph_allocation(subgraph_nodes, num_nodes, target_budget):
    """
    Generates a random budget, but ONLY allocates it to nodes that actually 
    exist in the attack subgraph. (Why waste money protecting safe nodes?)
    """
    num_sub_nodes = len(subgraph_nodes)
    
    # Dirichlet creates a spiky distribution summing exactly to 1.0
    alpha = np.ones(num_sub_nodes) * 0.1 
    raw_alloc = np.random.dirichlet(alpha) * target_budget
    
    # Enforce the rule that no single node can have > 1.0 budget
    raw_alloc = np.clip(raw_alloc, 0.0, 1.0)
    
    # Map the subgraph budget back to the global node indices
    full_alloc = np.zeros(num_nodes)
    full_alloc[subgraph_nodes] = raw_alloc
    
    return full_alloc

def evaluate_subgraph_risk(budget_allocation, T, source_nodes, target_nodes, max_hops=8):
    """
    Propagates the attack risk through the subgraph matrix.
    This is mathematically equivalent to a GNN Message Passing layer!
    """
    num_nodes = len(budget_allocation)
    
    # 1. Initialize the Attack State (Risk is 100% at the compromised source nodes)
    state = np.zeros(num_nodes)
    state[source_nodes] = 1.0
    
    # 2. Defense Layer: (1.0 - budget) is the percentage of attacks that slip through
    survival_rates = 1.0 - budget_allocation
    
    total_risk_reaching_targets = 0.0
    
    # 3. Flow the risk through the graph
    for _ in range(max_hops):
        # Move the risk across the edges to the next nodes
        state = state @ T
        
        # Apply the defense budget of those new nodes to reduce the risk
        state = state * survival_rates
        
        # Tally up any risk that successfully bled into our Domain Computers
        total_risk_reaching_targets += np.sum(state[target_nodes])
        
    return total_risk_reaching_targets

def run_subgraph_monte_carlo(prefix, iterations=10000, target_budget=5.0):
    nodes_file = f"{prefix}_subgraph_nodes.npy"
    edges_file = f"{prefix}_subgraph_edges.npy"
    feat_file = f"{prefix}_node_features.npy"
    
    if not os.path.exists(nodes_file) or not os.path.exists(edges_file):
        print(f"Error: Missing subgraph files for prefix '{prefix}'.")
        sys.exit(1)
        
    # 1. Load Data
    features = np.load(feat_file)
    subgraph_nodes = np.load(nodes_file)
    subgraph_edges = np.load(edges_file)
    
    num_nodes = features.shape[0]
    
    # 2. Identify Sources and Targets automatically from the subgraph's topology
    # Sources = nodes with NO incoming edges in the subgraph
    # Targets = nodes with NO outgoing edges in the subgraph
    in_degrees = np.bincount(subgraph_edges[1], minlength=num_nodes)
    out_degrees = np.bincount(subgraph_edges[0], minlength=num_nodes)
    
    source_nodes = [n for n in subgraph_nodes if in_degrees[n] == 0]
    target_nodes = [n for n in subgraph_nodes if out_degrees[n] == 0]
    
    print(f"[+] Global Graph Nodes: {num_nodes}")
    print(f"[+] Attack Subgraph: {len(subgraph_nodes)} nodes, {subgraph_edges.shape[1]} edges")
    print(f"[+] Identified {len(source_nodes)} logical source nodes and {len(target_nodes)} target computers.")
    
    # 3. Build the Transition Matrix
    T = build_transition_matrix(subgraph_edges, num_nodes)
    
    # 4. Baseline Risk (0 budget)
    baseline_risk = evaluate_subgraph_risk(np.zeros(num_nodes), T, source_nodes, target_nodes)
    print(f"[+] Baseline Risk (No Defense): {baseline_risk:.4f}")
    
    # 5. Monte Carlo Exploration Loop
    print(f"[+] Starting Matrix Monte Carlo Simulation ({iterations} iterations)...")
    best_allocation = None
    best_risk = float('inf')
    
    for i in range(1, iterations + 1):
        current_alloc = generate_subgraph_allocation(subgraph_nodes, num_nodes, target_budget)
        current_risk = evaluate_subgraph_risk(current_alloc, T, source_nodes, target_nodes)
        
        if current_risk < best_risk:
            best_risk = current_risk
            best_allocation = current_alloc
            
        if i % (iterations // 10) == 0:
            print(f"    Iteration {i:06d} | Current Best Risk: {best_risk:.4f} "
                  f"(-{(1 - best_risk/baseline_risk)*100:.1f}%)")
            
    # 6. Output Results
    top_indices = np.argsort(best_allocation)[::-1][:10]    
    for rank, idx in enumerate(top_indices, 1):
        alloc_val = best_allocation[idx]
        if alloc_val > 0.01:
            print(f" {rank}. Node {idx:03d} -> Allocate {alloc_val:.4f} budget")

if __name__ == "__main__":
    PREFIX = sys.argv[1] if len(sys.argv) > 1 else "ad_dataset_export/ad_dataset"
    run_subgraph_monte_carlo(PREFIX, iterations=50000, target_budget=3.0)