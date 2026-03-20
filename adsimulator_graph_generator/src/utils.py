import json
import os
import networkx as nx
import numpy as np
from neo4j import GraphDatabase
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.patches import Patch
import json
import networkx as nx
import numpy as np
import subprocess


REMEDIATION_EFFORT = {
    'HasSession': 1, 'CanRDP': 3, 'CanPSRemote': 3, 'ExecuteDCOM': 3,
    'AllowedToDelegate': 5, 'GenericWrite': 6, 'AddMember': 6, 
    'ForceChangePassword': 6, 'WriteDacl': 7, 'WriteOwner': 7, 
    'GenericAll': 8, 'AllExtendedRights': 8, 'MemberOf': 9, 'Trust': 10
}


################################################################################
#Updater les valeurs d'un dictionnaire embriqué avec celles d'un autre#
################################################################################

def _deep_update(d, u):
    """
    Fonction utilitaire récursive pour fusionner deux dictionnaires imbriqués.
    Elle met à jour les clés existantes sans effacer les autres clés du même niveau.
    """
    for k, v in u.items():
        if isinstance(v, dict):
            d[k] = _deep_update(d.get(k, {}), v)
        else:
            d[k] = v
    return d

################################################################################
#Méthode génératrice de configuration aléatoire pour AdSimulator#
################################################################################

def generate_config(index, custom_params={}):
    """
    Génère une configuration aléatoire pour le simulateur Active Directory et l'enregistre.

    Args:
        index (int ou str): Un identifiant utilisé pour nommer 
                            le fichier de configuration unique généré.

    Returns:
        str: Le nom du fichier de configuration qui vient d'être créé 
    """

    config = {
        "Domain": {
            "functionalLevelProbability": {
                "2008": 0, "2008 R2": 0, "2012": 0, "2012 R2": 0, "2016": 100, "Unknown": 0
            },
            "Trusts": {
                "SIDFilteringProbability": 100, "Inbound": 0, "Outbound": 0, "Bidirectional": 0
            }
        },
        "Computer": {
            "nComputers": 5, # Augmenté pour correspondre au nombre d'OUs
            "CanRDPFromUserPercentage": 0,
            "CanRDPFromGroupPercentage": 0,
            "CanPSRemoteFromUserPercentage": 0,
            "CanPSRemoteFromGroupPercentage": 0,
            "ExecuteDCOMFromUserPercentage": 0,
            "ExecuteDCOMFromGroupPercentage": 0,
            "AllowedToDelegateFromUserPercentage": 0,
            "AllowedToDelegateFromComputerPercentage": 0,
            "enabled": 100,
            "haslaps": 0,
            "unconstraineddelegation": 0,
            "osProbability": {
                "Windows XP Professional Service Pack 3": 0,
                "Windows 7 Professional Service Pack 1": 0,
                "Windows 7 Ultimate Service Pack 1": 0,
                "Windows 7 Enterprise Service Pack 1": 0,
                "Windows 10 Pro": 0,
                "Windows 10 Enterprise": 100
            }
        },
        "DC": {
            "enabled": 100,
            "haslaps": 0,
            "osProbability": {
                "Windows Server 2003 Enterprise Edition": 0,
                "Windows Server 2008 Standard": 0,
                "Windows Server 2008 Datacenter": 0,
                "Windows Server 2008 Enterprise": 0,
                "Windows Server 2008 R2 Standard": 0,
                "Windows Server 2008 R2 Datacenter": 0,
                "Windows Server 2008 R2 Enterprise": 0,
                "Windows Server 2012 Standard": 0,
                "Windows Server 2012 Datacenter": 0,
                "Windows Server 2012 R2 Standard": 0,
                "Windows Server 2012 R2 Datacenter": 0,
                "Windows Server 2016 Standard": 0,
                "Windows Server 2016 Datacenter": 100
            }
        },
        "User": {
            "nUsers": 5, # Augmenté légèrement par sécurité
            "enabled": 100, "dontreqpreauth": 0, "hasspn": 0, "passwordnotreqd": 0,
            "pwdneverexpires": 0, "sidhistory": 0, "unconstraineddelegation": 0
        },
        "OU": {
            "nOUs": 5 # Augmenté pour éviter la division par zéro
        },
        "Group": {
            "nGroups": 2,
            "nestingGroupProbability": 0,
            "departmentProbability": {
                "IT": 100, "HR": 0, "MARKETING": 0, "OPERATIONS": 0, "BIDNESS": 0
            }
        },
        "GPO": {
            "nGPOs": 1
        },
        "ACLs": {
            "ACLPrincipalsPercentage": 0,
            "ACLsProbability": {
                "GenericAll": 0,
                "GenericWrite": 0,
                "WriteOwner": 0,
                "WriteDacl": 0,
                "AddMember": 0,
                "ForceChangePassword": 0,
                "ReadLAPSPassword": 0
            }
        }
    }

    # On fusionne le template par défaut avec nos paramètres personnalisés
    config = _deep_update(config, custom_params)

    # Création et sauvegarde de la configuration dans le répertoire courant
    filename = f"adsimulator_config_{index}.json"
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=4)

    # Mise à jour des paramètres globaux de l'outil
    # os.path.expanduser convertit le "~" en chemin absolu vers le dossier utilisateur (ex: /home/user ou C:\Users\user)
    settings_path = os.path.expanduser("~/.adsimulator/settings.json")
    
    with open(settings_path, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=4)

    # Confirmation dans la console
    print(f"[+] Config générée : {filename}")
      
    return filename

def load_jsonl(filepath):
    """
    Lit un fichier JSONL (JSON Lines) et sépare les éléments en nœuds et relations.

    Args:
        filepath (str): Le chemin d'accès vers le fichier JSONL à lire.

    Returns:
        tuple: Un tuple de deux éléments (nodes, edges) où :
            - nodes (list): Liste des dictionnaires représentant les nœuds.
            - edges (list): Liste des dictionnaires représentant les relations (arêtes).
    """
    
    # Initialisation des listes pour stocker les deux types de données
    nodes, edges = [], []
    
    # Ouverture du fichier en mode lecture (avec encodage UTF-8 par précaution)
    with open(filepath, 'r', encoding='utf-8') as f:
        for line in f:
            # Ignorer les lignes vides pour éviter les erreurs lors de la conversion
            if not line.strip(): 
                continue
            
            # Convertir la chaîne de caractères JSON en dictionnaire Python
            data = json.loads(line)
            
            # Trier les données en fonction de leur type
            if data['type'] == 'node':
                nodes.append(data)
            elif data['type'] == 'relationship':
                edges.append(data)
                
    return nodes, edges

def export_complete_attack_instance(G_full, nodes_list, edge_list, features, 
    node_classes, edge_classes, terminals, sources, 
    best_allocation, best_risk, baseline_risk, target_budget, output_path
):
    """
    Exports the subgraph topology, node-level attributes, and the 
    Monte Carlo optimization results in a format for ML training.
    """
    num_nodes = len(nodes_list)
    
    unique_edge_types = sorted(list(set(edge_classes)))
    edge_type_to_idx = {t: i for i, t in enumerate(unique_edge_types)}
    edge_attr = [edge_type_to_idx[t] for t in edge_classes]

    node_registry = {}
    for i, node_id in enumerate(nodes_list):
        full_data = G_full.nodes[node_id]
        
        node_registry[i] = {
            "original_id": node_id,
            "labels": node_classes[i],
            "features_vector": features[i],
            "is_terminal": i in terminals,
            "is_source": i in sources,
            "best_allocation_weight": float(best_allocation[i]),
            "properties": {k: v for k, v in full_data.items() if k != 'labels'}
        }

    # 3. Create the JSON Object
    export_data = {
        "metadata": {
            "nodes_count": num_nodes,
            "edges_count": len(edge_list),
            "budget_limit": float(target_budget),
            "baseline_risk":baseline_risk,
        },
        "subgraph_topology": {
            "edge_index": edge_list,
            "edge_type_indices": edge_attr,
            "edge_type_map": edge_type_to_idx,
            "is_directed": True
        },
        "ml_targets": {
            "y_best_alloc": best_allocation.tolist(),
            "j_star_risk": float(best_risk),
            "baseline_risk": float(baseline_risk)
        },
        "node_registry": node_registry
    }

    # 4. Save to file
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(export_data, f, indent=4, ensure_ascii=False)
    
    print(f"[+] Export complete: {output_path}")

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
    print(G_full)
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

    export_complete_attack_instance(G_full, nodes_list, edge_list, features, 
        node_classes, edge_classes, terminals, sources, 
        best_allocation, best_risk, baseline_risk, target_budget, out_json_path)

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

################################################################################
#Pipeline#
################################################################################



def run_pipeline(instance_id, adsimulator_path, custom_params={}):
    """
    Orchestre le pipeline complet de simulation et de traitement d'un graphe Active Directory.

    Cette fonction exécute la chaîne de traitement de bout en bout pour une instance donnée :
    1. Génération de la configuration aléatoire.
    2. Connexion à la base de données Neo4j locale.
    3. Exécution de l'outil ADSimulator en ligne de commande pour générer le graphe.
    4. Extraction manuelle des nœuds et des relations depuis Neo4j (alternative à APOC) 
       vers un fichier JSONL temporaire.
    5. Traitement du graphe et sauvegarde des matrices (.npy) sur Google Drive pour le ML.

    Args:
        instance_id (int ou str): Identifiant unique de l'itération (utilisé pour nommer 
                                  le domaine, la configuration et les fichiers de sortie).
        adsimulator_path (str): Le chemin d'accès absolu vers l'exécutable ou le script ADSimulator.

    Returns:
        None: Les résultats finaux sont directement sauvegardés dans le dossier Dataset sur Drive.
    """
    print(f"\n=======================================================")
    print(f"[*] Lancement du pipeline pour l'Instance {instance_id}")
    print(f"=======================================================")

    # =========================================================================
    # Étape 1 : Génération de la configuration
    # =========================================================================
    # Fait appel à la fonction définie précédemment pour créer le .json de config
    config_filename = generate_config(instance_id, custom_params)
    chemin_absolu_config = os.path.abspath(config_filename)
    
    # On lit le fichier JSON généré pour extraire les valeurs aléatoires
    with open(chemin_absolu_config, 'r', encoding='utf-8') as f:
        config_data = json.load(f)

    # =========================================================================
    # Étape 2 : Connexion au serveur Neo4j
    # =========================================================================
    # Initialisation du driver Neo4j (Assurez-vous que les identifiants par défaut sont corrects)
    driver = GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j", "password"))

    # =========================================================================
    # Étape 3 : Exécution d'ADSimulator en arrière-plan
    # =========================================================================
    # Préparation des commandes interactives à envoyer à l'outil
    n_comp = config_data.get('nComputers', 5)
    n_users = config_data.get('nUsers', 5)

    commands = (
        f"connect bolt://localhost:7687 neo4j password\n"
        f"setparams {config_filename}\n"
        f"setdomain INSTANCE{instance_id}.LOCAL\n"
        f"generate\n"
        f"exit\n"
    )

    # Lancement du sous-processus simulant les entrées clavier (via l'argument 'input')
    result = subprocess.run(
        [adsimulator_path],
        input=commands,
        text=True,
        capture_output=True,
        shell=True
    )

    # Affichage des logs générés par l'outil pour faciliter le débogage
    print("--- LOGS ADSIMULATOR ---")
    print(result.stdout)
    if result.stderr:
        print("ERREURS :", result.stderr)
    print("------------------------")
    
    # Sécurité : Alerte si l'outil n'a absolument rien renvoyé
    if not result.stdout and not result.stderr:
        print("[!] ATTENTION : ADSimulator n'a renvoyé aucun log. Vérifiez la syntaxe de vos commandes interactives.")

    # =========================================================================
    # Étape 4 : Exportation du graphe (Méthode manuelle de contournement APOC)
    # =========================================================================
    print("[*] Exportation du graphe (sans APOC)...")
    
    # Fichier temporaire stocké sur la machine Linux de Colab
    export_path = '/tmp/export.json'

    # Ouverture de la session Neo4j pour requêter les données brutes
    with driver.session() as session:
        # Récupération de tous les nœuds
        nodes = session.run("MATCH (n) RETURN elementId(n) AS id, labels(n) AS labels, properties(n) AS props")
        # Récupération de toutes les relations (arêtes)
        edges = session.run("MATCH (n)-[r]->(m) RETURN elementId(r) AS id, elementId(n) AS start, elementId(m) AS end, type(r) AS label, properties(r) AS props")

        # Écriture progressive (ligne par ligne) au format JSONL
        with open(export_path, 'w', encoding='utf-8') as f:
            # Traitement et formatage des nœuds
            for record in nodes:
                node_data = {
                    "type": "node",
                    "id": record["id"],
                    "labels": record["labels"],
                    "properties": record["props"]
                }
                f.write(json.dumps(node_data) + "\n")

            # Traitement et formatage des relations
            for record in edges:
                rel_data = {
                    "type": "relationship",
                    "id": record["id"],
                    "start": {"id": record["start"]},
                    "end": {"id": record["end"]},
                    "label": record["label"],
                    "properties": record["props"]
                }
                f.write(json.dumps(rel_data) + "\n")

    print(f"[+] Données exportées avec succès vers {export_path}.")

    # =========================================================================
    # Étape 5 : Post-processing et sauvegarde sur Google Drive
    # =========================================================================
    # Création du dossier cible sur le Drive s'il n'existe pas encore
    dataset_dir = "/content/drive/MyDrive/Dataset"
    os.makedirs(dataset_dir, exist_ok=True)

    # Création du préfixe unique pour cette instance (ex: graph_1_adj.npy, etc.)
    out_prefix = f"{dataset_dir}/graph_{instance_id}"
    
    # Appel de la fonction de traitement Machine Learning (NetworkX -> NumPy)
    process_and_save_dataset(export_path, out_prefix)
    
    print(f"[*] Pipeline terminé pour l'Instance {instance_id}.\n")

################################################################################
#Plotting ADS graphs#
################################################################################

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

################################################################################
#Transition matrix from edges and nodes#
################################################################################

def build_transition_matrix(edges, num_nodes):
    """Construit la matrice de transition probabiliste T."""
    T = np.zeros((num_nodes, num_nodes))
    if not edges: return T
    sources = [e[0] for e in edges]
    targets = [e[1] for e in edges]
    out_degrees = np.bincount(sources, minlength=num_nodes)
    out_degrees[out_degrees == 0] = 1.0 
    T[sources, targets] = 1.0 / out_degrees[sources]
    return T

################################################################################
#Plotting attack graphs#
################################################################################

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

def plot_attack_paths_from_json(json_path):
    """Charge un export ADSim (format JSONL), reconstruit les données et affiche les chemins."""
    import json
    import numpy as np

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