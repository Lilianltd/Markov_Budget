import matplotlib.pyplot as plt
import networkx as nx
from matplotlib.patches import Patch
import matplotlib.patches as mpatches
import json
import itertools
import numpy as np

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
    
def plot_ad_complete_graph(jsonl_path):
    """
    Affiche le graphe AD complet avec tous les nœuds et toutes les relations.
    """
    print(f"[*] Génération du graphe complet depuis {jsonl_path}...")

    nodes_data, edges_data = [], []
    with open(jsonl_path, 'r', encoding='utf-8') as f:
        for line in f:
            if not line.strip(): continue
            data = json.loads(line)
            if data['type'] == 'node': nodes_data.append(data)
            elif data['type'] == 'relationship': edges_data.append(data)

    G = nx.DiGraph()

    # 1. Ajout de TOUS les nœuds
    for n in nodes_data:
        node_id = n['id']
        # On garde les labels bruts pour la coloration
        labels = [l.upper() for l in n.get('labels', [])]
        name = n.get('properties', {}).get('name', 'Unknown')
        G.add_node(node_id, name=name, raw_labels=labels)

    # 2. Ajout de TOUTES les relations
    for e in edges_data:
        if e['start']['id'] in G and e['end']['id'] in G:
            G.add_edge(e['start']['id'], e['end']['id'], label=e['label'])

    # 3. Mapping des couleurs complet
    color_map = []
    for node_id, data in G.nodes(data=True):
        labels = data.get('raw_labels', [])
        if 'COMPUTER' in labels: color_map.append('lightblue')
        elif 'USER' in labels: color_map.append('lightgreen')
        elif 'GROUP' in labels: color_map.append('orange')
        elif 'DOMAIN' in labels: color_map.append('purple')
        elif any(l in labels for l in ['ORGANIZATIONALUNIT', 'OU']): color_map.append('gold')
        elif any(l in labels for l in ['GPO', 'GROUPPOLICYOBJECT']): color_map.append('lightcoral')
        elif 'CONTAINER' in labels: color_map.append('silver')
        else: color_map.append('gray')

    # 4. Rendu visuel
    fig, ax = plt.subplots(figsize=(16, 12))
    
    # Pour un graphe complet, on utilise un k plus petit pour serrer les noeuds 
    # ou on augmente la taille de la figure.
    pos = nx.spring_layout(G, k=0.15, iterations=50, seed=42)

    # Dessin des arêtes (fines et grises pour ne pas noyer le graphe)
    nx.draw_networkx_edges(G, pos, alpha=0.2, edge_color='gray', arrows=True, arrowsize=8, ax=ax)
    
    # Dessin des nœuds
    nx.draw_networkx_nodes(G, pos, node_size=100, node_color=color_map, edgecolors='black', linewidths=0.5, ax=ax)

    # Légende exhaustive
    legend_elements = [
        mpatches.Patch(color='lightblue', label='Ordinateurs'),
        mpatches.Patch(color='lightgreen', label='Utilisateurs'),
        mpatches.Patch(color='orange', label='Groupes'),
        mpatches.Patch(color='purple', label='Domaines'),
        mpatches.Patch(color='gold', label='OUs'),
        mpatches.Patch(color='lightcoral', label='GPOs'),
        mpatches.Patch(color='silver', label='Containers'),
        mpatches.Patch(color='gray', label='Autres')
    ]
    ax.legend(handles=legend_elements, loc='upper left', title="Composants AD")

    plt.title(f"Vue Globale de l'Infrastructure ({G.number_of_nodes()} nœuds, {G.number_of_edges()} relations)", fontsize=16)
    plt.axis('off')
    plt.show()

    print(f"✅ Graphe généré avec succès.")

def plot_attack_paths_from_json(json_path):
    """Charge un export ADSim (format JSONL), reconstruit les données et affiche les chemins."""
    raw_nodes = []
    raw_edges = []

    # 1. Lecture ligne par ligne (Correction de l'erreur Extra Data)
    try:
        with open(json_path, 'r') as f:
            for line in f:
                if not line.strip(): continue
                data = json.loads(line)
                if data.get('type') == 'node':
                    raw_nodes.append(data)
                elif data.get('type') == 'relationship':
                    raw_edges.append(data)
    except Exception as e:
        print(f"Error reading file: {e}")
        return

    # 2. Reconstruction du node_registry et mapping des IDs
    # On crée un mapping pour convertir les UUIDs complexes en indices 0, 1, 2...
    id_map = {str(node['id']): i for i, node in enumerate(raw_nodes)}
    num_nodes = len(raw_nodes)
    
    node_registry = {}
    for node in raw_nodes:
        idx = id_map[str(node['id'])]
        labels = node.get('labels', [])
        props = node.get('properties', {}).get('properties', {})
        name = str(props.get('name', '')).upper()

        # Logique de détection Source / Terminal corrigée
        # Source : Un utilisateur qui n'est pas Admin
        # Terminal : Le Domaine ou un groupe Admin
        is_src = 'User' in labels and 'ADMIN' not in name
        is_term = 'Domain' in labels or ('Group' in labels and 'ADMIN' in name)

        node_registry[str(idx)] = {
            'properties': {'properties': props},
            'labels': labels,
            'is_source': is_src,
            'is_terminal': is_term,
            'best_allocation_weight': 0.5  # Valeur par défaut
        }

    # 3. Reconstruction des edges avec les nouveaux indices
    edges = []
    for rel in raw_edges:
        u_id, v_id = str(rel['start']['id']), str(rel['end']['id'])
        if u_id in id_map and v_id in id_map:
            edges.append((id_map[u_id], id_map[v_id]))

    # 4. Préparation des variables pour le plot
    T = build_transition_matrix(edges, num_nodes)

    actual_alloc = np.zeros(num_nodes)
    for i in range(num_nodes):
        actual_alloc[i] = node_registry[str(i)]['best_allocation_weight']

    # Identification des sources et cibles par index
    sources = [int(idx) for idx, data in node_registry.items() if data['is_source']]
    targets = [int(idx) for idx, data in node_registry.items() if data['is_terminal']]

    print(f"Detected {len(sources)} sources and {len(targets)} targets.")

    # 5. Boucle de visualisation
    for source in sources:
        for target in targets:
            plot_single_attack_path(
                edges=edges, 
                num_nodes=num_nodes, 
                source=source, 
                target=target, 
                allocation=actual_alloc, 
                node_registry=node_registry, 
                T=T
            )
            
def plot_full_network(edges, num_nodes, sources, targets, allocation, node_registry=None):
    """
    Provides a hierarchical (depth-based) view of the entire network graph
    to show the progression from sources to targets.
    """
    G = nx.DiGraph()
    G.add_nodes_from(range(num_nodes))
    G.add_edges_from(edges)

    # 1. Calculate the 'depth' (layer) of each node
    # Depth is defined as the shortest path distance from any source node.
    layers = {n: float('inf') for n in G.nodes()}

    for s in sources:
        layers[s] = 0
        # Get shortest paths from this source to all reachable nodes
        lengths = nx.single_source_shortest_path_length(G, s)
        for node, dist in lengths.items():
            if dist < layers[node]:
                layers[node] = dist

    # Handle nodes that are completely isolated/unreachable from sources
    valid_depths = [d for d in layers.values() if d != float('inf')]
    max_depth = max(valid_depths) if valid_depths else 0

    for node in G.nodes():
        if layers[node] == float('inf'):
            # Group unreachable nodes on the far right
            G.nodes[node]['layer'] = max_depth + 1
        else:
            G.nodes[node]['layer'] = layers[node]

    # 2. Use a multipartite layout to arrange nodes by their calculated layer
    # This aligns nodes with the same depth vertically, flowing left to right
    pos = nx.multipartite_layout(G, subset_key='layer')

    # 3. Setup styling based on node type and defense allocation
    node_colors = []
    node_sizes = []

    for node in G.nodes():
        if node in sources:
            node_colors.append('limegreen')
            node_sizes.append(800)
        elif node in targets:
            node_colors.append('red')
            node_sizes.append(800)
        else:
            budget = allocation[node]
            node_colors.append(plt.cm.Blues(0.2 + budget * 0.8))
            node_sizes.append(300 + budget * 1000)

    # Use a wider canvas to accommodate the left-to-right flow nicely
    plt.figure(figsize=(18, 10))

    # Draw the graph (adding a slight curve to edges makes overlapping lines readable)
    nx.draw_networkx_nodes(G, pos, node_color=node_colors, node_size=node_sizes, edgecolors='black')
    nx.draw_networkx_edges(G, pos, alpha=0.4, arrowsize=15, edge_color='gray', connectionstyle='arc3,rad=0.05')

    # Add labels
    if node_registry:
        labels = {n: str(n) for n in G.nodes()}
        nx.draw_networkx_labels(G, pos, labels=labels, font_size=9, font_weight='bold', font_color='black')

    # Legend (moved outside the plot so it doesn't cover nodes)
    legend_elements = [
        Patch(facecolor='limegreen', edgecolor='black', label='Attacker Sources (Layer 0)'),
        Patch(facecolor='red', edgecolor='black', label='Target Domains'),
        Patch(facecolor=plt.cm.Blues(0.8), edgecolor='black', label='Heavily Defended Point'),
        Patch(facecolor=plt.cm.Blues(0.3), edgecolor='black', label='Lightly Defended Point')
    ]
    plt.legend(handles=legend_elements, loc='upper left', bbox_to_anchor=(1, 1), fontsize=12)
    plt.title("Hierarchical Macro View: Cyber Terrain Depth", fontsize=16, fontweight='bold')
    plt.axis('off')
    plt.tight_layout()
    plt.show()
    
def plot_multiple_attack_paths_clean(edges, num_nodes, source, target, allocation, node_registry=None, k=3):
    """
    Extracts top K paths and places them on a rigid X/Y grid for a clean,
    flowchart-like visualization without overlapping tangled lines.
    """
    G = nx.DiGraph()
    G.add_nodes_from(range(num_nodes))
    G.add_edges_from(edges)

    try:
        # Get the top k shortest simple paths
        paths_generator = nx.shortest_simple_paths(G, source=source, target=target)
        top_k_paths = list(itertools.islice(paths_generator, k))

        print(f"Found {len(top_k_paths)} alternative paths from {source} to {target}:")
        for i, p in enumerate(top_k_paths):
            print(f"  Path {i+1}: {' -> '.join([str(n) for n in p])}")

    except nx.NetworkXNoPath:
        print(f"No valid path found between Source {source} and Target {target}.")
        return
    except nx.NetworkXNotImplemented:
        print("Source and Target are the same node.")
        return

    # Create a subgraph containing ONLY the nodes/edges from these top K paths
    path_nodes = set(n for path in top_k_paths for n in path)
    H = G.subgraph(path_nodes).copy()

    # --- CUSTOM GRID LAYOUT ENGINE ---
    pos = {}
    # X-coordinate: Distance from source
    lengths = nx.single_source_shortest_path_length(H, source)

    # Track which path(s) each node belongs to for Y-coordinate
    node_to_path_indices = {n: [] for n in H.nodes()}
    for i, path in enumerate(top_k_paths):
        for n in path:
            node_to_path_indices[n].append(i)

    for node in H.nodes():
        x = lengths.get(node, 0)

        # Y-coordinate: Average index of the paths it belongs to.
        # Negated so Path 0 is visually at the top, Path 1 below it, etc.
        y = - (sum(node_to_path_indices[node]) / len(node_to_path_indices[node]))

        # Force Source and Target to be perfectly centered vertically
        if node == source or node == target:
            y = - (len(top_k_paths) - 1) / 2.0

        pos[node] = (x, y)
    # ---------------------------------

    # Styling
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

    # Draw the graph
    plt.figure(figsize=(14, 6))

    # We can use straighter lines now since the nodes are perfectly organized
    nx.draw_networkx_nodes(H, pos, node_color=node_colors, node_size=node_sizes, edgecolors='black')
    nx.draw_networkx_edges(H, pos, alpha=0.6, arrowsize=20, edge_color='gray', width=2)

    # Labels
    node_labels = {}
    for node in H.nodes():
        if node_registry is not None:
            node_data = node_registry[str(node)]
            raw_name = node_data['properties']['properties'].get('name', str(node))
            clean_name = raw_name.split('@')[0].split('.')[0]
            node_labels[node] = f"{clean_name}\n(ID:{node})"
        else:
            node_labels[node] = str(node)

    nx.draw_networkx_labels(H, pos, labels=node_labels, font_size=9, font_weight='bold', font_color='black')

    legend_elements = [
        Patch(facecolor='limegreen', edgecolor='black', label='Attacker Source'),
        Patch(facecolor='red', edgecolor='black', label='Target Domain'),
        Patch(facecolor=plt.cm.Blues(0.8), edgecolor='black', label='Heavy Defense'),
        Patch(facecolor=plt.cm.Blues(0.3), edgecolor='black', label='Light Defense')
    ]

    plt.legend(handles=legend_elements, loc='center left', bbox_to_anchor=(1, 0.5), fontsize=11)
    plt.title(f"Alternative Attack Routes: Source {source} -> Target {target}", fontsize=16, fontweight='bold')
    plt.axis('off')
    plt.tight_layout()
    plt.show()