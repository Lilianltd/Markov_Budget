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

def run_pipeline(instance_id : int):
    print(f"\n=====================================")
    print(f"[*] Traitement de l'Instance {instance_id}")
    print(f"=====================================")

    config_filename = generate_config(instance_id)

    # Création du dossier import avant le démarrage
    os.makedirs("./neo4j_local/import", exist_ok=True)
    dataset_dir = "./Dataset"
    os.makedirs(dataset_dir, exist_ok=True)

    print("[*] Nettoyage de l'état Neo4j et démarrage du serveur local...")
    subprocess.run(["./neo4j_local/bin/neo4j", "stop"], capture_output=True)
    # On supprime UNIQUEMENT la base 'neo4j' et on garde 'system'
    os.system("rm -rf ./neo4j_local/data/databases/neo4j ./neo4j_local/data/transactions/neo4j")
    subprocess.run(["./neo4j_local/bin/neo4j", "start"], capture_output=True)

    print("[*] Attente du réveil de Neo4j (Port 7687)...")
    if not wait_for_port(7687):
        print("[-] Erreur: Neo4j n'a pas démarré à temps.")
        return
    print("[+] Neo4j est en ligne !")

    print("[*] Lancement d'AdSimulator...")
    commands = f"connect bolt://localhost:7687 neo4j password\nload {config_filename}\nsetdomain INSTANCE{instance_id}.LOCAL\ngenerate\nexit\n"
    subprocess.run(["adsimulator"], input=commands, text=True, capture_output=True, shell=True)

    print("[*] Exportation des graphes via APOC...")
    driver = GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j", "password"))
    with driver.session() as session:
        query_sp = f"MATCH p=shortestPath((n:User)-[*1..]->(m:Group {{name: 'DOMAIN ADMINS@INSTANCE{instance_id}.LOCAL'}})) WHERE NOT n=m RETURN p"
        session.run(f"CALL apoc.export.json.query(\"{query_sp}\", 'graph_shortest_path{instance_id}.json', {{useTypes:true}})")
        
        query_cp = f"MATCH p=shortestPath((n:Compromised)-[*1..]->(m:Group {{name: 'DOMAIN ADMINS@INSTANCE{instance_id}.LOCAL'}})) WHERE NOT n=m RETURN p"
        session.run(f"CALL apoc.export.json.query(\"{query_cp}\", 'graph_corrupt_domain{instance_id}.json', {{useTypes:true}})")
        
        session.run(f"CALL apoc.export.json.all('graph_{instance_id}.json', {{useTypes:true}})")
    driver.close()

    print("[*] Déplacement des exports JSON vers ./Dataset...")
    import_dir = "./neo4j_local/import"
    for suffix in [f"shortest_path{instance_id}", f"corrupt_domain{instance_id}", str(instance_id)]:
        src = os.path.join(import_dir, f"graph_{suffix}.json")
        dst = os.path.join(dataset_dir, f"graph_{suffix}.json")
        if os.path.exists(src):
            shutil.move(src, dst)

    full_graph_json = os.path.join(dataset_dir, f"graph_{instance_id}.json")
    if os.path.exists(full_graph_json):
        process_and_save_dataset(full_graph_json, os.path.join(dataset_dir, f"graph_{instance_id}_structured.json"))

    print("[*] Arrêt de Neo4j...")
    subprocess.run(["./neo4j_local/bin/neo4j", "stop"], capture_output=True)