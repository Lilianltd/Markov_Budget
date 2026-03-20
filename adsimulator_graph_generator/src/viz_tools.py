import matplotlib.pyplot as plt
import networkx as nx
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