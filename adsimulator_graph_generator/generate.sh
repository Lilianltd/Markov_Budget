#!/bin/bash

AD_PATH="${AD_PATH:-adsimulator}"
# Verify it actually exists/is executable before continuing
if ! command -v "$AD_PATH" &> /dev/null; then
    echo "[-] Error: Cannot find adsimulator at '$AD_PATH'."
    echo "    Either activate your environment or set the AD_PATH variable:"
    echo "    export AD_PATH=/path/to/your/adsimulator"
    exit 1
fi

APOC_CONF="/etc/neo4j/apoc.conf"
EXPORT_PATH="/var/lib/neo4j/import/export.json"
DATASET_DIR="./Dataset"
NUM_GRAPHS=2

# Ensure output directory exists
mkdir -p "$DATASET_DIR"

for i in $(seq 1 $NUM_GRAPHS); do
    echo "================================================="
    echo "[*] Processing Dataset Instance $i / $NUM_GRAPHS"
    echo "================================================="
    
    echo "[*] Step 1: Generating AD Simulator Configuration..."
    python generate_configs.py $i

    echo "[*] Step 2: Restarting Neo4j Service to clear state..."
    # Optionally: sudo rm -rf /var/lib/neo4j/data/databases/neo4j/* to strictly wipe previous graphs
    sudo systemctl restart neo4j

    echo "[*] Waiting for Neo4j Bolt (Port 7687) to wake up..."
    while ! nc -z localhost 7687; do   
      sleep 2
      echo -n "."
    done
    echo -e "\n[+] Neo4j is online!"

    echo "[*] Step 3: Running adsimulator Generation..."
    # We pipe the dynamic config right into the simulation requirements
    "$AD_PATH" <<EOF
connect
setdomain INSTANCE${i}.LOCAL
setparams ./Dataset/config/adsimulator_config_${i}.json
generate
exit
EOF


    echo "[*] Step 4: Exporting Graph to JSON..."
    sudo rm -f /tmp/export.json 
    /usr/bin/cypher-shell -u neo4j -p password 'CALL apoc.export.json.query("MATCH p=shortestPath((n:User)-[*1..]->(m:Group {name: \"DOMAIN ADMINS@INSTANCE1.LOCAL\"})) WHERE NOT n=m RETURN p", "/tmp/export.json", {useTypes:true});'

    echo "[*] Step 5: Formatting and Generating .npy dataset arrays..."
    if [ -f "/tmp/export.json" ]; then
        INSTANCE_JSON="$DATASET_DIR/graph_shortest_path${i}.json"
        sudo mv /tmp/export.json "$INSTANCE_JSON"
        sudo chown lilian:lilian "$INSTANCE_JSON"
    fi
    sudo rm -f /tmp/export.json 
    /usr/bin/cypher-shell -u neo4j -p password "CALL apoc.export.json.query(\"MATCH p=shortestPath((n)-[*1..15]->(m:Group {name: 'DOMAIN ADMINS@INSTANCE1.LOCAL'})) WHERE n.owned = true AND NOT n=m RETURN p\", \"/tmp/export.json\", {useTypes:true});"
    echo "[*] Step 5: Formatting and Generating .npy dataset arrays..."
    if [ -f "/tmp/export.json" ]; then
        INSTANCE_JSON="$DATASET_DIR/graph_corrupt_domain${i}.json"
        sudo mv /tmp/export.json "$INSTANCE_JSON"
        sudo chown lilian:lilian "$INSTANCE_JSON"
    fi


    sudo rm -f /tmp/export.json 
    /usr/bin/cypher-shell -u neo4j -p password "CALL apoc.export.json.all('/tmp/export.json', {useTypes:true});"

    echo "[*] Step 5: Formatting and Generating .npy dataset arrays..."
    if [ -f "/tmp/export.json" ]; then
        INSTANCE_JSON="$DATASET_DIR/graph_${i}.json"
        sudo mv /tmp/export.json "$INSTANCE_JSON"
        sudo chown lilian:lilian "$INSTANCE_JSON"
        
        # Launch python post-processor
        python process_graph.py "$INSTANCE_JSON" "$DATASET_DIR/graph_${i}"
        
        echo "[+] SUCCESS: Post-processed Graph $i saved to $DATASET_DIR"
    else
        echo "[-] ERROR: Export failed. Check Neo4j."
    fi

done

echo "[+] ALL DONE"