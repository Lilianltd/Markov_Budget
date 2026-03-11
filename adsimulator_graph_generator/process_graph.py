import json
import networkx as nx
import numpy as np
import os
import sys
import random
from random_best_alloc import *
from datetime import datetime

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

def find_viable_sources(G, terminals, max_hops=30):
    """
    Identifie les nœuds (User/Computer) qui ont un chemin réel 
    vers les terminaux dans la limite de max_hops.
    """
    viable_sources = set()
    G_rev = G.reverse(copy=True)
    
    for target in terminals:
        # On cherche tous les nœuds pouvant atteindre la cible (BFS arrière)
        reachable = nx.single_source_shortest_path_length(G_rev, target, cutoff=max_hops)
        for node_id, dist in reachable.items():
            labels = G.nodes[node_id].get('labels', [])
            # On considère comme source potentielle tout User ou Computer capable d'atteindre la cible
            if 'User' in labels:
                viable_sources.add(node_id)
                
    return list(viable_sources)

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

def build_graph(jsonl_path) -> nx.DiGraph:
    nodes_data, edges_data = load_jsonl(jsonl_path)
    G_full = nx.DiGraph()
    
    # 1. Ajout des nœuds avec leurs métadonnées
    for n in nodes_data:
        node_id = str(n['id'])
        G_full.add_node(
            node_id, 
            labels=n.get('labels', []), 
            properties=n.get('properties', {})
        )

    # 2. Ajout des arêtes filtrées
    ATTACK_EDGES = [
        'MemberOf', 'TrustedBy', 'GenericAll', 'GenericWrite', 
        'WriteOwner', 'Owns', 'WriteDacl', 'AddMember', 
        'ForceChangePassword', 'AllExtendedRights', 'AdminTo', 
        'HasSession', 'CanRDP', 'CanPSRemote', 'AllowedToDelegate', 
        'AllowedToAct', 'ExecuteDCOM', 'SyncLAPSPassword', 'GpLink', 'Contains'
    ]
    for e in edges_data:
        rel_type = e['label']
        if rel_type in ATTACK_EDGES:
            u = str(e['start']['id'])
            v = str(e['end']['id'])
            props = e.get('properties', {})
            G_full.add_edge(u, v, type=rel_type, **props)
            
    return G_full

def get_domain_group(G):
    full_nodes_list = list(G.nodes())
    terminals_ids = []

    for n in full_nodes_list:
        labels = G.nodes[n].get('labels', [])
        props = G.nodes[n].get('properties', {})
        if 'Group' in labels and props.get('highvalue') == True: #found target groups admin
            terminals_ids.append(n)
    return terminals_ids

def process_and_save_dataset(jsonl_path, out_json_path):
    print(f"[*] Processing {jsonl_path}...")
    G_full = build_graph(jsonl_path)
    terminals_ids = get_domain_group(G_full)
    sources_ids = find_viable_sources(G_full, terminals_ids, max_hops=30)
    
    print("[*] Extraction du sous-graphe d'attaque...")
    G = extract_attack_subgraph(G_full, sources_ids, terminals_ids, max_hops=30)

    if G.number_of_nodes() == 0:
        print("[!] Aucune surface d'attaque détectée. Fin du traitement.")
        return
    
    nodes_list = list(G.nodes())
    node_to_idx = {n: i for i, n in enumerate(nodes_list)}
    num_nodes = len(nodes_list)

    terminals = [node_to_idx[n] for n in terminals_ids if n in node_to_idx]
    sources = [node_to_idx[n] for n in sources_ids if n in node_to_idx]
    
    # 4. Features & Classes
    features = []
    node_classes = []
    for _, n in enumerate(nodes_list):
        d = G.nodes[n]
        lbls = d.get('labels', [])
        node_classes.append(lbls) # Sauvegarde des classes de noeuds
        is_computer = 1.0 if 'Computer' in lbls else 0.0
        is_user = 1.0 if 'User' in lbls else 0.0
        is_group = 1.0 if 'Group' in lbls else 0.0
        is_ou = 1.0 if d.get('OU') == True else 0.0
        is_gpo = 1.0 if d.get('GPO') == True else 0.0
        is_domain = 1.0 if d.get('Domain') == True else 0.0
        features.append([is_computer, is_user, is_group, is_ou, is_gpo, is_domain])

    edge_list = []
    edge_classes = []
    for u, v, data in G.edges(data=True):
        edge_list.append([node_to_idx[u], node_to_idx[v]])
        edge_classes.append(data.get('type', 'Unknown')) # Sauvegarde des classes d'arêtes

    # 5. Simulation de Monte Carlo pour trouver y et J_star
    target_budget = 5.0
    mc_iterations = 1000
    print(f"[*] Lancement Monte Carlo ({mc_iterations} itérations) pour l'allocation optimale...")
    T = build_transition_matrix(edge_list, num_nodes)
    baseline_risk = evaluate_subgraph_risk(np.zeros(num_nodes), T, sources, terminals)
    best_allocation, best_risk = find_best_alloc(num_nodes, baseline_risk, mc_iterations, target_budget, T, sources, terminals)

    print(f"[+] Risque initial : {baseline_risk:.4f} | Risque optimisé (J_star) : {best_risk:.4f}")

    # 6. Construction de la structure JSON (avec ajout des classes)
    instance = {
      "topology_type": "adsimulator_graph",
      "B": target_budget,
      "H": 8,
      "graph": {
        "nodes": list(range(num_nodes)),
        "edges": edge_list,
        "node_classes": node_classes,
        "edge_classes": edge_classes,
        "is_directed": True
      },
      "x": features,
      "y": best_allocation.tolist(),
      "J_star": float(best_risk),
      "terminals": terminals,
      "repairable_nodes": [i for i in range(num_nodes) if i not in terminals],
      "n_nodes": num_nodes,
      "n_edges": len(edge_list)
    }

    dataset = {
      "metadata": {
        "generated_at": datetime.now().isoformat(),
        "n_instances": 1,
        "topology": "Active Directory"
      },
      "instances": [instance]
    }

    with open(out_json_path, 'w') as f:
        json.dump(dataset, f, indent=2)
    print(f"[+] Dataset JSON sauvegardé dans {out_json_path}")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python process_graph.py <input_jsonl> <output_prefix>")
        sys.exit(1)
        
    input_jsonl = sys.argv[1]
    output_prefix = sys.argv[2]
    
    out_json = f"{output_prefix}_structured.json"
    
    process_and_save_dataset(input_jsonl, out_json)