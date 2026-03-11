import numpy as np
import sys
import os

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

def generate_subgraph_allocation(num_nodes, target_budget):
    """Génère une allocation aléatoire via distribution de Dirichlet."""
    alpha = np.ones(num_nodes) * 0.1 
    raw_alloc = np.random.dirichlet(alpha) * target_budget
    return np.clip(raw_alloc, 0.0, 1.0)

def evaluate_subgraph_risk(alloc, T, source_nodes, target_nodes, iterations=10):
    """Évaluation du risque (probabilité d'atteindre les cibles) en fonction des défenses."""
    state = np.zeros(len(alloc))
    state[source_nodes] = 1.0
    
    # L'allocation réduit la probabilité de transition
    T_defended = T.copy()
    for i in range(len(alloc)):
        T_defended[:, i] *= max(0, 1.0 - alloc[i])
        
    for _ in range(iterations):
        state = state @ T_defended
        
    return float(np.sum(state[target_nodes]))
