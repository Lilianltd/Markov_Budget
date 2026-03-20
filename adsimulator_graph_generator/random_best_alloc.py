import numpy as np
import networkx as nx
import matplotlib.pyplot as plt

def build_transition_matrix(edges, num_nodes):
    """Builds the probabilistic transition matrix T."""
    T = np.zeros((num_nodes, num_nodes))
    if not edges: return T
    
    sources = [e[0] for e in edges]
    targets = [e[1] for e in edges]
    
    out_degrees = np.bincount(sources, minlength=num_nodes)
    out_degrees[out_degrees == 0] = 1.0 
    
    T[sources, targets] = 1.0 / out_degrees[sources]
    return T

def generate_subgraph_allocation(num_nodes, target_budget):
    """Generates a random allocation strictly respecting bounds and budget."""
    alpha = np.ones(num_nodes) * 0.5 
    raw_alloc = np.random.dirichlet(alpha) * target_budget
    return np.clip(raw_alloc, 0.0, 1.0)

def mutate_allocation(alloc, target_budget, mutation_rate=0.1):
    """
    Slightly mutates an existing allocation to search the local neighborhood.
    This behaves like a Hill Climbing / Simulated Annealing step.
    """
    noise = np.random.normal(0, mutation_rate, size=len(alloc))
    new_alloc = alloc + noise
    new_alloc = np.clip(new_alloc, 0.0, 1.0)
    
    # Re-normalize to ensure the budget constraint is respected
    current_sum = np.sum(new_alloc)
    if current_sum > 0:
        new_alloc = new_alloc * (target_budget / current_sum)
        
    return np.clip(new_alloc, 0.0, 1.0)

def evaluate_subgraph_risk(alloc, T, source_nodes, target_nodes, iterations=10):
    """Evaluates the probability of attackers reaching the target nodes."""
    state = np.zeros(len(alloc))
    state[source_nodes] = 1.0 / len(source_nodes) # Normalize initial state
    
    # The allocation reduces the probability of transitioning into defended nodes
    T_defended = T.copy()
    defense_multiplier = np.maximum(0, 1.0 - alloc)
    
    # Vectorized defense application
    T_defended = T_defended * defense_multiplier
        
    for _ in range(iterations):
        state = state @ T_defended
        
    return float(np.sum(state[target_nodes]))

def find_best_alloc(num_nodes, baseline_risk, mc_iterations, target_budget, T, sources, terminals):
    """
    Finds the best defensive allocation using an exploratory local search.
    Returns the best allocation, final risk, and the historical progression.
    """
    best_allocation = generate_subgraph_allocation(num_nodes, target_budget)
    best_risk = evaluate_subgraph_risk(best_allocation, T, sources, terminals)
        
    for i in range(1, mc_iterations + 1):
        # 20% of the time, try a completely new random state to escape local minima
        # 80% of the time, mutate the best known state to refine it
        if np.random.rand() < 0.2:
            current_alloc = generate_subgraph_allocation(num_nodes, target_budget)
        else:
            current_alloc = mutate_allocation(best_allocation, target_budget, mutation_rate=0.15)
            
        current_risk = evaluate_subgraph_risk(current_alloc, T, sources, terminals)
        
        # Accept if it's strictly better
        if current_risk < best_risk:
            best_risk = current_risk
            best_allocation = current_alloc
            
    return best_allocation, best_risk

import json
import numpy as np
import networkx as nx
import matplotlib.pyplot as plt
from matplotlib.patches import Patch

import networkx as nx
import matplotlib.pyplot as plt
from matplotlib.patches import Patch

def plot_single_attack_path(edges, num_nodes, source, target, allocation, node_registry=None, T=None):
    """
    Extracts and visualizes a single shortest path from a specific source to a target.
    """
    # 1. Build the full graph to find the path
    G = nx.DiGraph()
    G.add_nodes_from(range(num_nodes))
    G.add_edges_from(edges)
    
    # 2. Extract a single shortest path
    try:
        path_nodes = nx.shortest_path(G, source=source, target=target)
        print(f"Path found: {' -> '.join([str(n) for n in path_nodes])}")
    except nx.NetworkXNoPath:
        print(f"No valid path found between Source {source} and Target {target}.")
        return
        
    # 3. Create a smaller subgraph containing ONLY the nodes/edges in this path
    H = G.subgraph(path_nodes).copy()
    
    # 4. Assign layers strictly based on the node's index in the path (forces strict Left-to-Right)
    for index, node in enumerate(path_nodes):
        H.nodes[node]['layer'] = index
        
    # Use multipartite layout, but align horizontally for a clear timeline/flowchart look
    pos = nx.multipartite_layout(H, subset_key="layer", align="horizontal")
    
    # 5. Determine colors and sizes for the extracted subgraph
    node_colors = []
    node_sizes = []
    
    for node in H.nodes():
        if node == source:
            node_colors.append('limegreen')
            node_sizes.append(2500)
        elif node == target:
            node_colors.append('red')
            node_sizes.append(2500)
        else:
            budget = allocation[node]
            node_colors.append(plt.cm.Blues(0.2 + budget * 0.8)) 
            node_sizes.append(1500 + budget * 1500)
            
    plt.figure(figsize=(12, 4)) # Wide and short canvas for a single path
    
    # Draw Nodes and Edges
    nx.draw_networkx_nodes(H, pos, node_color=node_colors, node_size=node_sizes, edgecolors='black')
    nx.draw_networkx_edges(H, pos, alpha=0.6, arrowsize=20, edge_color='gray', width=2)
    
    # Extract Labels directly from JSON
    node_labels = {}
    for node in H.nodes():
        if node_registry is not None:
            node_data = node_registry[str(node)]
            raw_name = node_data['properties']['properties'].get('name', str(node))
            clean_name = raw_name.split('@')[0].split('.')[0]
            node_type = node_data['labels'][1] if len(node_data['labels']) > 1 else ""
            node_labels[node] = f"{clean_name}\n({node_type})"
        else:
            node_labels[node] = str(node)
            
    nx.draw_networkx_labels(H, pos, labels=node_labels, font_size=8, font_weight='bold', font_color='black')
    
    # Draw Edge Labels (Transition Probabilities)
    if T is not None:
        edge_labels = {}
        for u, v in H.edges(): # Only get labels for the edges currently in the subgraph
            prob = T[u, v]
            edge_labels[(u, v)] = f"{prob:.2f}"
            
        nx.draw_networkx_edge_labels(
            H, pos, 
            edge_labels=edge_labels, 
            font_size=9, 
            font_color='darkred',
            bbox=dict(facecolor='white', alpha=0.8, edgecolor='none', pad=1)
        )
        
    # Draw Legend
    legend_elements = [
        Patch(facecolor='limegreen', edgecolor='black', label='Attacker Source'),
        Patch(facecolor='red', edgecolor='black', label='Target Domain'),
        Patch(facecolor=plt.cm.Blues(0.8), edgecolor='black', label='Defended Point')
    ]
    
    # We put the legend outside the plot so it doesn't cover the path
    plt.legend(handles=legend_elements, loc='center left', bbox_to_anchor=(1, 0.5), fontsize=10)
    plt.title(f"Attack Path: Source {source} -> Target {target}", fontsize=14)
    plt.axis('off')
    plt.tight_layout()
    plt.show()


import json
import numpy as np
if __name__ == "__main__":

    # 1. Load the data
    with open('Dataset/graph_1_structured.json', 'r') as f:
        graph_data = json.load(f)

    num_nodes = graph_data['metadata']['nodes_count']
    edges = graph_data['subgraph_topology']['edge_index']
    node_registry = graph_data['node_registry']

    # Build the transition matrix
    T = build_transition_matrix(edges, num_nodes)

    # Extract best known allocation for colors (using the ones embedded in your JSON)
    actual_alloc = np.zeros(num_nodes)
    for i in range(num_nodes):
        actual_alloc[i] = node_registry[str(i)]['best_allocation_weight']

    # 2. Automatically find ALL Sources and ALL Targets from the JSON registry
    sources = [int(node_id) for node_id, data in node_registry.items() if data.get('is_source') == True]
    targets = [int(node_id) for node_id, data in node_registry.items() if data.get('is_terminal') == True]

    print(f"Detected {len(sources)} sources and {len(targets)} targets.")
    print(f"Total possible source-target combinations to check: {len(sources) * len(targets)}\n")

    # 3. Loop through all combinations and plot them
    for source in sources:
        for target in targets:
            print(f"\n--- Checking route from Source {source} to Target {target} ---")
            
            plot_single_attack_path(
                edges=edges, 
                num_nodes=num_nodes, 
                source=source, 
                target=target, 
                allocation=actual_alloc, 
                node_registry=node_registry, 
                T=T
            )