# adsim_utils.py
import os
import time
import socket
import shutil
import subprocess
from neo4j import GraphDatabase
from src.generate_configs import generate_config
from src.process_graph import *

def wait_for_port(port, host='localhost', timeout=60) -> bool:
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            with socket.create_connection((host, port), timeout=1):
                return True
        except OSError:
            time.sleep(2)
    return False

def run_pipeline(instance_id: int, custom_config = None):
    print(f"\n=====================================")
    print(f"[*] Traitement de l'Instance {instance_id}")
    print(f"=====================================")

    # 1. DYNAMIC PATH RESOLUTION
    # This guarantees the paths are correct whether in Colab or Local Ubuntu
    current_dir = os.path.abspath(os.getcwd())
    neo4j_dir = os.path.join(current_dir, "neo4j_local")
    import_dir = os.path.join(neo4j_dir, "import")
    dataset_dir = os.path.join(current_dir, "Dataset")
    
    os.makedirs(import_dir, exist_ok=True)
    os.makedirs(dataset_dir, exist_ok=True)

    # Use absolute path for the config file so ADSimulator doesn't lose it
    config_filename = generate_config(instance_id, custom_config = custom_config)
    config_abspath = os.path.abspath(config_filename)

    # 2. NEO4J STATE MANAGEMENT (Pythonic approach)
    print("[*] Nettoyage de l'état Neo4j et démarrage du serveur local...")
    subprocess.run([os.path.join(neo4j_dir, "bin", "neo4j"), "stop"], capture_output=True)
    
    # We use shutil instead of raw 'rm -rf' for better cross-environment stability
    db_path = os.path.join(neo4j_dir, "data", "databases", "neo4j")
    tx_path = os.path.join(neo4j_dir, "data", "transactions", "neo4j")
    if os.path.exists(db_path): shutil.rmtree(db_path)
    if os.path.exists(tx_path): shutil.rmtree(tx_path)
    
    subprocess.run([os.path.join(neo4j_dir, "bin", "neo4j"), "start"], capture_output=True)

    print("[*] Attente du réveil de Neo4j (Port 7687)...")
    if not wait_for_port(7687):
        print("[-] Erreur: Neo4j n'a pas démarré à temps.")
        return
    print("[+] Neo4j est en ligne !")

    # 3. ADSIMULATOR EXECUTION
    print("[*] Lancement d'AdSimulator...")
    # Note: Passed config_abspath instead of just the filename
    commands = f"connect bolt://localhost:7687 neo4j password\nload {config_abspath}\nsetdomain INSTANCE{instance_id}.LOCAL\ngenerate\nexit\n"
    
    res = subprocess.run(["adsimulator"], input=commands, text=True, capture_output=True, shell=True)
    if "Error" in res.stderr or not res.stdout.strip():
        print(f"[!] Warning ADSimulator logs: {res.stderr} | {res.stdout}")

    # 4. EXPORT VIA APOC WITH SAFETY CHECKS
    print("[*] Vérification et Exportation des graphes via APOC...")
    driver = GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j", "password"))
    
    with driver.session() as session:
        # Crucial sanity check: Did ADSimulator actually generate data?
        node_count = session.run("MATCH (n) RETURN count(n) AS c").single()["c"]
        if node_count == 0:
            print("[-] ERREUR: La base Neo4j est vide. ADSimulator a échoué silencieusement.")
            driver.close()
            return
        
        print(f"[+] {node_count} nœuds détectés. Lancement des exports APOC...")

        # APOC exports (APOC resolves 'filename.json' automatically to the neo4j_local/import folder)
        query_sp = f"MATCH p=shortestPath((n:User)-[*1..]->(m:Group {{name: 'DOMAIN ADMINS@INSTANCE{instance_id}.LOCAL'}})) WHERE NOT n=m RETURN p"
        session.run(f"CALL apoc.export.json.query(\"{query_sp}\", 'graph_shortest_path{instance_id}.json', {{useTypes:true}})")
        
        query_cp = f"MATCH p=shortestPath((n:Compromised)-[*1..]->(m:Group {{name: 'DOMAIN ADMINS@INSTANCE{instance_id}.LOCAL'}})) WHERE NOT n=m RETURN p"
        session.run(f"CALL apoc.export.json.query(\"{query_cp}\", 'graph_corrupt_domain{instance_id}.json', {{useTypes:true}})")
        
        session.run(f"CALL apoc.export.json.all('graph_{instance_id}.json', {{useTypes:true}})")
    
    driver.close()

    # 5. SAFE FILE MOVEMENT (Handles empty/failed exports gracefully)
    print("[*] Déplacement des exports JSON vers ./Dataset...")
    for suffix in [f"shortest_path{instance_id}", f"corrupt_domain{instance_id}", str(instance_id)]:
        src = os.path.join(import_dir, f"graph_{suffix}.json")
        dst = os.path.join(dataset_dir, f"graph_{suffix}.json")
        
        # If the file exists and has content, move it
        if os.path.exists(src) and os.path.getsize(src) > 0:
            shutil.move(src, dst)
        else:
            print(f"[!] Fichier vide ou manquant généré pour: graph_{suffix}.json (Création d'un JSON vide de secours)")
            # Create an empty valid JSON file to prevent downstream script crashes
            with open(dst, 'w') as f:
                f.write("[]")

    # 6. POST-PROCESSING
    full_graph_json = os.path.join(dataset_dir, f"graph_{instance_id}.json")
    if os.path.exists(full_graph_json) and os.path.getsize(full_graph_json) > 2: # Check it's not just "[]"
        process_and_save_dataset(full_graph_json, os.path.join(dataset_dir, f"graph_{instance_id}_structured.json"))

    print("[*] Arrêt de Neo4j...")
    subprocess.run([os.path.join(neo4j_dir, "bin", "neo4j"), "stop"], capture_output=True)