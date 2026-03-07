# Active Directory Graph Dataset Generator

The goal is to exploit the already existing ad simulator to generate custom graph.
To do so there is special steps : generate, export, and post-process realistic Active Directory (AD) attack graphs. It generate a dataset suitable for machine learning, graph neural networks (GNNs), and random walk simulations.

## Pipeline Overview

The pipeline consists of three main components that work together to create a varied dataset of Active Directory environments:

1. **`generate_configs.py`** (Configuration Randomizer) for adsimulator
2. **`test.sh`** (Bash Orchestrator) Use to generate
3. **`process_graph.py`** (Graph Post-Processor) -> convert the jsonl into npy cleaned graph

## File Descriptions

### 1. `generate_configs.py`
This Python script is responsible for generating dynamic configuration files for `adsimulator`. 
* **Purpose:** Ensures that every generated graph represents a unique Active Directory environment.
* **Functionality:** It randomizes some AD properties (some can be add later) such as the number of users, computers, RDP percentages, PSRemote percentages, and ACL (Access Control List) misconfiguration probabilities.
* **Output:** Produces JSON configuration files (e.g., `adsimulator_config_1.json`) that can be passed to `adsimulator`'s requirements.

### 2. `test.sh`
The central script that make the entire pipeline.
* **Purpose:** Automates the end-to-end generation loop.
* **Functionality:** * Calls `generate_configs.py` to create a new simulation profile.
  * Restarts the `neo4j` service to clear prior state and waits for the port (7687) to come online (I add trouble before as if not awake it doesn't work), Gemini gave me this work around.
  * Feeds the generated configuration into `adsimulator` using the `setparams` and `generate` commands via a prompt block.
  * Uses `cypher-shell` to trigger the APOC plugin to export the entire Neo4j graph into a JSONL format (it has been a bit a nightmare, to do this part maybe it's easier with the normal export command but i didn't achieve to make it works due to permission issue with my linux setup).
  * Hands the exported graph over to the Python post-processor.

### 3. `process_graph.py`
The data extraction and standardization engine.
* **Purpose:** Converts the raw Neo4j JSONL export into structured, machine-learning-ready matrices.
* **Functionality:**
  * **Standardization:** Parses the Neo4j output and loads it into a standard `NetworkX` Directed Graph (`DiGraph`). By using directed edges, it inherently preserves hierarchical "MemberOf" group properties without creating looping logic.
  * **Pathfinding:** Identifies source nodes (Compromised/Owned users) and target nodes (Domain Computers). It then calculates the shortest acyclic paths (preventing infinite circles/loops) between them.
  * **Feature Extraction:** Extracts node features (e.g., IsComputer, IsUser, IsGroup, IsOwned) into vector format.
* **Output:** Generates three `.npy` (NumPy) files per graph instance:
  * `*_adj.npy`: The Adjacency matrix of the graph.
  * `*_feat.npy`: The node feature matrix.
  * `*_walks.npy`: An array of padded, cycle-free logical paths (random walks) traversing the graph.

## Prerequisites

Ensure you have the following installed and configured:
* **Neo4j** (with APOC plugin installed and file export enabled in `apoc.conf`)
* **adsimulator** (accessible via the path defined in `test.sh`)
* **Python 3** with the following libraries:
  ```bash
  pip install networkx numpy