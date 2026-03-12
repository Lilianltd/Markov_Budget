#!/bin/bash
#!/usr/bin/env bash
# Use /usr/bin/env bash for better portability across different Linux distros

set -e

# ==============================================================================
# Configuration & Environment Variables (Override these via environment)
# ==============================================================================
AD_PATH="${AD_PATH:-adsimulator}"
DATASET_DIR="${DATASET_DIR:-./Dataset}"
NUM_GRAPHS="${NUM_GRAPHS:-2}"

NEO4J_USER="${NEO4J_USER:-neo4j}"
NEO4J_PASS="${NEO4J_PASS:-password}"
CYPHER_SHELL="${CYPHER_SHELL:-cypher-shell}"
PYTHON_CMD="${PYTHON_CMD:-python3}"

TMP_EXPORT="/tmp/export.json"
CURRENT_USER=$(id -un)
CURRENT_GROUP=$(id -gn)

# ==============================================================================
# Pre-flight Checks
# ==============================================================================
if ! command -v "$AD_PATH" &> /dev/null; then
    echo "[-] Error: Cannot find adsimulator at '$AD_PATH'."
    echo "    Either activate your environment or set the AD_PATH variable:"
    echo "    export AD_PATH=/path/to/your/adsimulator"
    exit 1
fi

if ! command -v "$CYPHER_SHELL" &> /dev/null; then
    echo "[-] Error: cypher-shell not found. Please install Neo4j or ensure it is in your PATH."
    exit 1
fi

# Ensure output directory exists
mkdir -p "$DATASET_DIR"

# ==============================================================================
# Main Loop
# ==============================================================================
for i in $(seq 1 "$NUM_GRAPHS"); do
    echo "================================================="
    echo "[*] Processing Dataset Instance $i / $NUM_GRAPHS"
    echo "================================================="
    
    echo "[*] Step 1: Generating AD Simulator Configuration..."
    "$PYTHON_CMD" generate_configs.py "$i"

    echo "[*] Step 2: Restarting Neo4j Service to clear state..."
    # Requires sudo privileges to restart the service
    sudo systemctl restart neo4j

    echo "[*] Waiting for Neo4j Bolt (Port 7687) to wake up..."
    # Use native bash /dev/tcp instead of 'nc' to ensure it works on every Linux
    while ! (echo > /dev/tcp/localhost/7687) >/dev/null 2>&1; do   
      sleep 2
      echo -n "."
    done
    echo -e "\n[+] Neo4j is online!"

    echo "[*] Step 3: Running adsimulator Generation..."
    "$AD_PATH" <<EOF
connect
setdomain INSTANCE${i}.LOCAL
setparams ./Dataset/config/adsimulator_config_${i}.json
generate
exit
EOF

    echo "[*] Step 4: Exporting Graph to JSON..."
    
    # --- Query 1: Shortest Path for Domain Admins ---
    sudo rm -f "$TMP_EXPORT" 
    # Notice the bug fix here: INSTANCE1 is now INSTANCE${i}
    "$CYPHER_SHELL" -u "$NEO4J_USER" -p "$NEO4J_PASS" "CALL apoc.export.json.query(\"MATCH p=shortestPath((n:User)-[*1..]->(m:Group {name: \\\"DOMAIN ADMINS@INSTANCE${i}.LOCAL\\\"})) WHERE NOT n=m RETURN p\", \"$TMP_EXPORT\", {useTypes:true});"

    echo "[*] Step 5a: Formatting Shortest Path dataset..."
    if [ -f "$TMP_EXPORT" ]; then
        INSTANCE_JSON="$DATASET_DIR/graph_shortest_path${i}.json"
        sudo mv "$TMP_EXPORT" "$INSTANCE_JSON"
        sudo chown "$CURRENT_USER":"$CURRENT_GROUP" "$INSTANCE_JSON"
    fi

    # --- Query 2: Corrupted Domain ---
    sudo rm -f "$TMP_EXPORT" 
    "$CYPHER_SHELL" -u "$NEO4J_USER" -p "$NEO4J_PASS" "CALL apoc.export.json.query(\"MATCH p=shortestPath((n:Compromised)-[*1..]->(m:Group {name: \\\"DOMAIN ADMINS@INSTANCE${i}.LOCAL\\\"})) WHERE NOT n=m RETURN p\", \"$TMP_EXPORT\", {useTypes:true});"    
    
    echo "[*] Step 5b: Formatting Corrupted Domain dataset..."
    if [ -f "$TMP_EXPORT" ]; then
        INSTANCE_JSON="$DATASET_DIR/graph_corrupt_domain${i}.json"
        sudo mv "$TMP_EXPORT" "$INSTANCE_JSON"
        sudo chown "$CURRENT_USER":"$CURRENT_GROUP" "$INSTANCE_JSON"
    fi

    # --- Query 3: Full Graph Export ---
    sudo rm -f "$TMP_EXPORT" 
    "$CYPHER_SHELL" -u "$NEO4J_USER" -p "$NEO4J_PASS" "CALL apoc.export.json.all('$TMP_EXPORT', {useTypes:true});"

    echo "[*] Step 5c: Formatting and Generating .npy dataset arrays..."
    if [ -f "$TMP_EXPORT" ]; then
        INSTANCE_JSON="$DATASET_DIR/graph_${i}.json"
        sudo mv "$TMP_EXPORT" "$INSTANCE_JSON"
        sudo chown "$CURRENT_USER":"$CURRENT_GROUP" "$INSTANCE_JSON"
        
        # Launch python post-processor
        "$PYTHON_CMD" process_graph.py "$INSTANCE_JSON" "$DATASET_DIR/graph_${i}"
        
        echo "[+] SUCCESS: Post-processed Graph $i saved to $DATASET_DIR"
    else
        echo "[-] ERROR: Export failed. Check Neo4j."
    fi

done

echo "[+] ALL DONE"