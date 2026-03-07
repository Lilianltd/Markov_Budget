import json
import random
import sys

def generate_config(index):
    # Randomize core adsimulator properties for variet, keep it simple for the moment as i don't understand fully what are all the parameters and if they are usefull for us later on
    config = {
        "nComputers": random.randint(1, 4),
        "nUsers": random.randint(1, 2),
        "CanRDPFromUserPercentage": random.randint(5, 30),
        "CanRDPFromGroupPercentage": random.randint(5, 30),
        "CanPSRemoteFromUserPercentage": random.randint(5, 20),
        "CanPSRemoteFromGroupPercentage": random.randint(5, 20),
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

    filename = f"adsimulator_config_{index}.json"
    with open(filename, "w") as f:
        json.dump(config, f, indent=4)
        
    print(f"[+] Generated config: {filename}")

if __name__ == "__main__":
    idx = sys.argv[1] if len(sys.argv) > 1 else "0"
    generate_config(idx)