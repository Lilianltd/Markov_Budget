import json
import random
import sys
import os

def generate_config(index):
    # Randomize core adsimulator properties for variet, keep it simple for the moment as i don't understand fully what are all the parameters and if they are usefull for us later on
    config = {
        "nComputers": random.randint(30, 80),
        "nUsers": random.randint(50, 100),
        "CanRDPFromUserPercentage": random.randint(20, 50),
        "CanRDPFromGroupPercentage": random.randint(20, 50),
        "CanPSRemoteFromUserPercentage": random.randint(15, 30),
        "CanPSRemoteFromGroupPercentage": random.randint(15, 30),
        "ACLsProbability": {
            "GenericAll": random.randint(5, 15),
            "GenericWrite": random.randint(5, 15),
            "WriteOwner": random.randint(5, 15),
            "WriteDacl": random.randint(5, 15),
            "AddMember": random.randint(30, 70)
        }
    }
    
    # Normalize ACLs probability to strictly sum to 100
    total_acl = sum(config["ACLsProbability"].values())
    for k in config["ACLsProbability"]:
        config["ACLsProbability"][k] = int((config["ACLsProbability"][k] / total_acl) * 100)
    
    # Pad any rounding discrepancy
    diff = 100 - sum(config["ACLsProbability"].values())
    config["ACLsProbability"]["AddMember"] += diff

    filename = f"./Dataset/config/adsimulator_config_{index}.json"
    os.makedirs(f'./Dataset/config/', exist_ok=True)
    with open(filename, "w") as f:
        json.dump(config, f, indent=4)
        
    print(f"[+] Generated config: {filename}")
    return filename

if __name__ == "__main__":
    idx = sys.argv[1] if len(sys.argv) > 1 else "0"
    generate_config(idx)