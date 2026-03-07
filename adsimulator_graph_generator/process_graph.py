import json
import networkx as nx
import numpy as np
import os
import sys
import random

REMEDIATION_EFFORT = {
    'HasSession': 1, 'CanRDP': 3, 'CanPSRemote': 3, 'ExecuteDCOM': 3,
    'AllowedToDelegate': 5, 'GenericWrite': 6, 'AddMember': 6, 
    'ForceChangePassword': 6, 'WriteDacl': 7, 'WriteOwner': 7, 
    'GenericAll': 8, 'AllExtendedRights': 8, 'MemberOf': 9, 'Trust': 10
}

def load_jsonl(filepath):
    nodes, edges = [], []
    with open(filepath, 'r') as f:
        for line in f:
            if not line.strip(): continue
            data = json.loads(line)
            if data['type'] == 'node':
                nodes.append(data)
            elif data['type'] == 'relationship':
                edges.append(data)
    return nodes, edges

def extract_attack_subgraph(G, source_nodes, target_nodes, max_hops=8):
    """
    Uses Bidirectional BFS to mathematically guarantee extraction of 
    EVERY node and edge that participates in a path from a source to a target 
    within the max_hops limit. 
    """
    valid_nodes = set()
    
    # 1. Forward BFS: Find shortest distances from ANY source to all nodes
    dist_from_sources = {}
    for s in source_nodes:
        # Get distances from this specific source (up to max_hops)
        lengths = nx.single_source_shortest_path_length(G, s, cutoff=max_hops)
        for node, d in lengths.items():
            # Keep the shortest distance found so far from any source
            if node not in dist_from_sources or d < dist_from_sources[node]:
                dist_from_sources[node] = d
                
    # 2. Backward BFS: Find shortest distances from all nodes to ANY target
    G_rev = G.reverse(copy=False)
    dist_to_targets = {}
    for t in target_nodes:
        # Get distances from this specific target backwards (up to max_hops)
        lengths = nx.single_source_shortest_path_length(G_rev, t, cutoff=max_hops)
        for node, d in lengths.items():
            # Keep the shortest distance found so far to any target
            if node not in dist_to_targets or d < dist_to_targets[node]:
                dist_to_targets[node] = d
                
    # 3. Intersection: If Distance(Source -> Node) + Distance(Node -> Target) <= max_hops, 
    # it is mathematically part of the attack path.
    for node, d_S in dist_from_sources.items():
        if node in dist_to_targets:
            d_T = dist_to_targets[node]
            if d_S + d_T <= max_hops:
                valid_nodes.add(node)
                
    # 4. Extract the perfect subgraph
    return G.subgraph(valid_nodes).copy()

def process_and_save(jsonl_path, out_prefix):
    nodes, edges = load_jsonl(jsonl_path)
    out_dir = f"{out_prefix}_export"
    os.makedirs(out_dir, exist_ok=True)
    base_name = os.path.basename(out_prefix)
    save_prefix = os.path.join(out_dir, base_name)
    
    # FIX: Must be a DiGraph for AD attack paths
    G = nx.DiGraph()
    for n in nodes:
        node_id = str(n['id'])
        props = n.get('properties', {})
        labels = n.get('labels', [])
        G.add_node(node_id, labels=labels, **props)
        
    for e in edges:
        G.add_edge(str(e['start']['id']), str(e['end']['id']), type=e['label'], **e.get('properties', {}))
    
    nodes_list = list(G.nodes())
    node_to_idx = {n: i for i, n in enumerate(nodes_list)}
    
    node_features = np.zeros((len(nodes_list), 7))
    for i, n in enumerate(nodes_list):
        d = G.nodes[n]
        lbls = d.get('labels', [])
        node_features[i, 0] = 1 if 'Computer' in lbls else 0
        node_features[i, 1] = 1 if 'User' in lbls else 0
        node_features[i, 2] = 1 if 'Group' in lbls else 0
        node_features[i, 3] = 1 if d.get('owned') == True else 0
        node_features[i, 4] = 1 if d.get('exploitable') == True else 0
        node_features[i, 5] = 1 if d.get('highvalue') == True else 0
        node_features[i, 6] = 1 if d.get('admincount') == True else 0

    edge_types_unique = list(set(e['label'] for e in edges))
    edge_type_to_id = {lbl: i for i, lbl in enumerate(edge_types_unique)}
    
    edge_index = np.zeros((2, len(edges)), dtype=np.int64)
    edge_types = np.zeros((len(edges),), dtype=np.int64)
    edge_efforts = np.zeros((len(edges),), dtype=np.float32)
    edge_is_acl = np.zeros((len(edges),), dtype=np.int64)
    
    for i, e in enumerate(edges):
        src_idx = node_to_idx[str(e['start']['id'])]
        dst_idx = node_to_idx[str(e['end']['id'])]
        lbl = e['label']
        props = e.get('properties', {})
        
        edge_index[0, i] = src_idx
        edge_index[1, i] = dst_idx
        edge_types[i] = edge_type_to_id[lbl]
        edge_efforts[i] = REMEDIATION_EFFORT.get(lbl, 5)
        edge_is_acl[i] = 1 if props.get('isacl') == True else 0

    corrupt_nodes = [n for n, d in G.nodes(data=True) if d.get('owned') == True or 'Compromised' in d.get('labels', [])]
    domain = [n for n, d in G.nodes(data=True) if 'Domain' in d.get('labels', [])]

    print(f"[*] Extracting mathematical attack surface between {len(corrupt_nodes)} sources and {len(domain)} targets (Max Depth: 8)...")
    
    attack_subgraph = extract_attack_subgraph(G, corrupt_nodes, domain, max_hops=8)
    
    if attack_subgraph.number_of_nodes() == 0:
        print("[!] No paths exist between sources and targets within 8 hops.")
    else:
        print(f"[+] Attack Subgraph extracted perfectly!")
        
    print(f"[+] Attack Subgraph size: {attack_subgraph.number_of_nodes()} nodes, {attack_subgraph.number_of_edges()} edges")
    print(f"[+] Attack Subgraph size: {attack_subgraph.number_of_nodes()} nodes, {attack_subgraph.number_of_edges()} edges")
    
    # FIX: Ensure subgraph files save to the correct subfolder (save_prefix)
    subgraph_nodes = np.array([node_to_idx[n] for n in attack_subgraph.nodes()], dtype=np.int64)
    np.save(f"{save_prefix}_subgraph_nodes.npy", subgraph_nodes)
    
    subgraph_edges = np.array([[node_to_idx[u], node_to_idx[v]] for u, v in attack_subgraph.edges()], dtype=np.int64).T
    if subgraph_edges.size == 0:
        subgraph_edges = np.empty((2, 0), dtype=np.int64) # Handle empty edge case cleanly
    np.save(f"{save_prefix}_subgraph_edges.npy", subgraph_edges)
    
    np.save(f"{save_prefix}_node_features.npy", node_features)
    np.save(f"{save_prefix}_edge_index.npy", edge_index)
    np.save(f"{save_prefix}_edge_types.npy", edge_types)
    np.save(f"{save_prefix}_edge_efforts.npy", edge_efforts)
    np.save(f"{save_prefix}_edge_isacl.npy", edge_is_acl)
    
    with open(f"{save_prefix}_edge_mapping.json", "w") as f:
        json.dump(edge_type_to_id, f, indent=4)
        
    return save_prefix

# =======================================================
# NEW: Matrix-based Subgraph Monte Carlo Logic
# =======================================================



def build_transition_matrix(edges, num_nodes):
    T = np.zeros((num_nodes, num_nodes))
    if edges.size == 0: return T
    
    sources, targets = edges[0], edges[1]
    out_degrees = np.bincount(sources, minlength=num_nodes)
    out_degrees[out_degrees == 0] = 1.0 
    T[sources, targets] = 1.0 / out_degrees[sources]
    return T

def generate_subgraph_allocation(subgraph_nodes, num_nodes, budget):
    num_sub_nodes = len(subgraph_nodes)
    alpha = np.ones(num_sub_nodes) * 0.1 
    raw_alloc = np.random.dirichlet(alpha) * budget
    raw_alloc = np.clip(raw_alloc, 0.0, 1.0)
    
    full_alloc = np.zeros(num_nodes)
    full_alloc[subgraph_nodes] = raw_alloc
    return full_alloc

def evaluate_subgraph_risk(budget_allocation, T, source_nodes, target_nodes, max_hops=8):
    num_nodes = len(budget_allocation)
    state = np.zeros(num_nodes)
    state[source_nodes] = 1.0
    survival_rates = 1.0 - budget_allocation
    
    total_risk_reaching_targets = 0.0
    for _ in range(max_hops):
        state = state @ T
        state = state * survival_rates
        total_risk_reaching_targets += np.sum(state[target_nodes])
        
    return total_risk_reaching_targets

def run_monte_carlo(prefix, iterations=5000, target_budget=3.0):
    nodes_file = f"{prefix}_subgraph_nodes.npy"
    edges_file = f"{prefix}_subgraph_edges.npy"
    feat_file = f"{prefix}_node_features.npy"
    
    if not os.path.exists(nodes_file) or not os.path.exists(edges_file):
        return "Subgraph files missing. Simulation aborted."
        
    features = np.load(feat_file)
    subgraph_nodes = np.load(nodes_file)
    subgraph_edges = np.load(edges_file)
    num_nodes = features.shape[0]
    
    if len(subgraph_nodes) == 0:
        return "No valid attack paths found in subgraph."

    # Identify sources and targets
    in_degrees = np.bincount(subgraph_edges[1], minlength=num_nodes) if subgraph_edges.size > 0 else np.zeros(num_nodes)
    out_degrees = np.bincount(subgraph_edges[0], minlength=num_nodes) if subgraph_edges.size > 0 else np.zeros(num_nodes)
    
    source_nodes = [n for n in subgraph_nodes if in_degrees[n] == 0]
    target_nodes = [n for n in subgraph_nodes if out_degrees[n] == 0]
    
    T = build_transition_matrix(subgraph_edges, num_nodes)
    baseline_risk = evaluate_subgraph_risk(np.zeros(num_nodes), T, source_nodes, target_nodes)
    
    best_allocation = None
    best_risk = float('inf')
    
    for i in range(1, iterations + 1):
        current_alloc = generate_subgraph_allocation(subgraph_nodes, num_nodes, target_budget)
        current_risk = evaluate_subgraph_risk(current_alloc, T, source_nodes, target_nodes)
        
        if current_risk < best_risk:
            best_risk = current_risk
            best_allocation = current_alloc
            
    result = f"Baseline Risk: {baseline_risk:.4f}\n"
    result += f"Final Risk Score: {best_risk:.4f}\n\nTop Nodes to Harden:\n"
    top_indices = np.argsort(best_allocation)[::-1][:10]
    for rank, idx in enumerate(top_indices, 1):
        if best_allocation[idx] > 0.01:
            result += f"{rank}. Node {idx:03d} -> Allocate {best_allocation[idx]:.4f}\n"
            
    return result

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python process_graph.py <input_jsonl> <output_prefix>")
        sys.exit(1)
        
    input_json = sys.argv[1]
    out_prefix = sys.argv[2]
    
    save_prefix = process_and_save(input_json, out_prefix)
    
    print("\n--- Running Subgraph Monte Carlo Simulation ---")
    res = run_monte_carlo(save_prefix, iterations=10000, target_budget=3.0)
    print(res)