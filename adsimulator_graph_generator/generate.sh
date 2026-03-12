#!/usr/bin/env bash
set -e

# ==============================================================================
# Configuration initiale (Installation & Setup)
# ==============================================================================
NEO4J_VERSION="5.18.0"
NEO4J_HOME="./neo4j_local"
NUM_GRAPHS="${NUM_GRAPHS:-2}"
PYTHON_CMD="${PYTHON_CMD:-python3}"

echo "[*] Vérification de l'installation locale de Neo4j..."
if [ ! -d "$NEO4J_HOME" ]; then
    echo "[*] Téléchargement de Neo4j Community $NEO4J_VERSION..."
    wget -q -nc "https://neo4j.com/artifact.php?name=neo4j-community-$NEO4J_VERSION-unix.tar.gz" -O neo4j.tar.gz
    tar -xzf neo4j.tar.gz
    mv "neo4j-community-$NEO4J_VERSION" "$NEO4J_HOME"
    rm neo4j.tar.gz
fi

if [ ! -f "$NEO4J_HOME/plugins/apoc-$NEO4J_VERSION-core.jar" ]; then
    echo "[*] Téléchargement du plugin APOC..."
    wget -q -nc "https://github.com/neo4j/apoc/releases/download/$NEO4J_VERSION/apoc-$NEO4J_VERSION-core.jar" -P "$NEO4J_HOME/plugins/"
fi

# Configuration stricte de Neo4j (v5)
CONF_FILE="$NEO4J_HOME/conf/neo4j.conf"
APOC_CONF="$NEO4J_HOME/conf/apoc.conf"

if ! grep -q "dbms.security.procedures.unrestricted=apoc.\*" "$CONF_FILE"; then
    echo "dbms.security.procedures.unrestricted=apoc.*" >> "$CONF_FILE"
    echo "apoc.export.file.enabled=true" > "$APOC_CONF"
    "$NEO4J_HOME/bin/neo4j-admin" dbms set-initial-password "password"
fi

# ==============================================================================
# Lancement de la génération via le moteur Python (adsim_utils.py)
# ==============================================================================
echo "[*] Lancement de la pipeline de génération..."

# On appelle simplement la fonction Python en boucle !
"$PYTHON_CMD" -c "
import adsim_utils
NUM_GRAPHS = $NUM_GRAPHS
for i in range(1, NUM_GRAPHS + 1):
    adsim_utils.run_pipeline(i)
print('\n[+] GÉNÉRATION TERMINÉE !')
"

echo "[+] ALL DONE"