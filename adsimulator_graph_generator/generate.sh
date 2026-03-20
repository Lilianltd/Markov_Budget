#!/usr/bin/env bash
set -e

# ==============================================================================
# Configuration initiale (Installation & Setup)
# ==============================================================================
NEO4J_VERSION="5.18.0"
NEO4J_HOME="./neo4j_local"
NUM_GRAPHS="${NUM_GRAPHS:-1000}"
PYTHON_CMD="${PYTHON_CMD:-python3}"

echo "[*] Vérification de l'installation locale de Neo4j..."
NEO4J_VERSION="5.18.0"
if [ ! -d "neo4j_local" ]; then
    wget -q -nc https://neo4j.com/artifact.php?name=neo4j-community-$NEO4J_VERSION-unix.tar.gz -O neo4j.tar.gz
    tar -xzf neo4j.tar.gz
    mv neo4j-community-$NEO4J_VERSION neo4j_local
    rm neo4j.tar.gz
fi
if [ ! -f "neo4j_local/plugins/apoc-$NEO4J_VERSION-core.jar" ]; then
    wget -q -nc https://github.com/neo4j/apoc/releases/download/$NEO4J_VERSION/apoc-$NEO4J_VERSION-core.jar -P neo4j_local/plugins/
fi
CONF_FILE="neo4j_local/conf/neo4j.conf"
APOC_CONF="neo4j_local/conf/apoc.conf"
if ! grep -q "dbms.security.procedures.unrestricted=apoc.\*" "$CONF_FILE"; then
    echo "dbms.security.procedures.unrestricted=apoc.*" >> "$CONF_FILE"
    echo "apoc.export.file.enabled=true" > "$APOC_CONF"
    ./neo4j_local/bin/neo4j-admin dbms set-initial-password "password"
fi
echo "[+] Environnement Neo4j prêt !"

# ==============================================================================
# Lancement de la génération via le moteur Python (adsim_utils.py)
# ==============================================================================
echo "[*] Lancement de la pipeline de génération..."

# On appelle simplement la fonction Python en boucle !
"$PYTHON_CMD" -c "
import src.adsim_utils as adsim_utils
NUM_GRAPHS = $NUM_GRAPHS
for i in range(1, NUM_GRAPHS + 1):
    adsim_utils.run_pipeline(i)
print('\n[+] GÉNÉRATION TERMINÉE !')
"

echo "[+] ALL DONE"