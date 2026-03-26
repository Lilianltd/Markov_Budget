# Active Directory Graph & Defense Simulation Pipeline

This repository contains an automated, end-to-end pipeline for generating Active Directory (AD) attack graphs, calculating shortest attack paths, and simulating optimal defense budget allocations using Monte Carlo methods.

The pipeline is designed to be completely **sudo-free**. It automatically downloads and manages a local, containerized-style instance of Neo4j, generates randomized AD environments using `adsimulator`, and exports Machine Learning-ready datasets (nodes, edges, features, and optimal defense allocations).

---

## Architecture & File Overview

The project is modularized into a bash orchestrator and a suite of Python scripts:

* **`generate.sh`**: The main entry point. It handles the local installation of Neo4j v5 and the APOC plugin (if not already present), configures them, and triggers the Python pipeline loop.
* **`adsim_utils.py`**: The core Python engine. It manages the Neo4j lifecycle (starting, wiping state, stopping), interfaces with `adsimulator` to build the graph, runs Cypher queries via APOC to export JSONs, and orchestrates the post-processing.
* **`generate_configs.py`**: A configuration randomizer. It generates unique environmental parameters (number of users/computers, RDP access probabilities, ACL vulnerabilities) for every graph iteration to ensure dataset variance.
* **`process_graph.py`**: The graph parser and ML-formatter. It reads the exported Neo4j JSON, extracts node features (User, Computer, Group, etc.), identifies attacker starting points (Compromised/Owned) and targets (Domain Admins/Computers), and formats the graph for Machine Learning.
* **`random_best_alloc.py`**: The simulation engine. It converts the graph into a probabilistic transition matrix $T$ and uses Dirichlet distributions and Monte Carlo simulations to find the optimal defense budget allocation ($J^*$) that minimizes the attacker's probability of reaching the target.
* **`viz_tools.py`**: Some plot function for the graph

## Prerequisites

Before running the pipeline, ensure you have the following installed on your system:

1. **Bash environment** (Linux/macOS or WSL on Windows).
2. **Java 17** (Strict requirement for Neo4j v5).
3. **Python 3.8+** with the following libraries:
```bash
pip install networkx numpy neo4j matplotlib
```

4. **AdSimulator**: Must be installed and accessible in your system/virtual environment's PATH. The git repo is already install if submodule init have be done

*(Note: You do **not** need `sudo` privileges or Docker. The script downloads a standalone Neo4j tarball and runs it entirely in user-space).*

## ⚙️ How to Use
If you make sure adsimulator is installed and runnable (it can be installed only in linux with installer_linux.sh), if not please refer to the notebook
Simply execute the bash script. You can optionally define the number of graphs you want to generate using an environment variable.

```bash
# Make the script executable
chmod +x generate.sh

# Run the pipeline (defaults to 2 graphs)
./generate.sh

# Or run it for a specific number of graphs
NUM_GRAPHS=10 ./generate.sh

```

### What happens during execution?

1. **Setup**: Downloads Neo4j 5.18.0 and APOC into `./neo4j_local` (if they don't exist).
2. **Loop Begins**: For each instance $i$:
* Generates a randomized AD topology config.
* Starts the local Neo4j database (clearing any previous graph state safely).
* Runs `adsimulator` to populate the Neo4j database.
* Uses APOC to export the full graph and specific shortest paths (e.g., to Domain Admins) into JSON.
* Parses the JSON, calculates the baseline risk, runs a Monte Carlo simulation (1000 iterations) to find the best defensive allocation, and saves everything.
3. **Cleanup**: Shuts down the local Neo4j server.

## 📂 Output Format

All generated data is saved in the `./Dataset/` directory.

For every iteration `i`, you will find:

* `config/adsimulator_config_i.json`: The randomized parameters used to generate the AD environment.
* `graph_i_structured.json`: **The final ML-ready file**. This contains:
* `nodes` and `edges` (IDs and classifications).
* `features`: Boolean feature arrays for every node (Computer, User, Group, etc.).
* `terminals` & `sources`: Target nodes and attacker entry points.
* `budget`: The target defense budget used.
* `baseline_risk`: Probability of compromise without defenses.
* `best_allocation`: The optimal array of defensive investments across the graph.
* `best_risk`: The mitigated compromise probability ($J^*$).

* **`AdSimulator_Local.ipynb`** : A jupyter notebook, runnable in colab for non linux user or to avoid installation locally of the libraries. It will clone and get everything from the repository