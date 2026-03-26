import json
import random
import sys
import os
import copy

BASE_CONFIG = {
    "Domain": {
        "functionalLevelProbability": {
            "2008": 10,
            "2008 R2": 27,
            "2012": 12,
            "2012 R2": 27,
            "2016": 10,
            "Unknown": 14
        },
        "Trusts": {
            "SIDFilteringProbability": 15,
            "Inbound": 80,
            "Outbound": 89,
            "Bidirectional": 79
        }
    },
    "Computer": {
        "nComputers": 14,
        "CanRDPFromUserPercentage": 92,
        "CanRDPFromGroupPercentage": 23,
        "CanPSRemoteFromUserPercentage": 7,
        "CanPSRemoteFromGroupPercentage": 26,
        "ExecuteDCOMFromUserPercentage": 83,
        "ExecuteDCOMFromGroupPercentage": 27,
        "AllowedToDelegateFromUserPercentage": 46,
        "AllowedToDelegateFromComputerPercentage": 53,
        "enabled": 73,
        "haslaps": 11,
        "unconstraineddelegation": 60,
        "osProbability": {
            "Windows XP Professional Service Pack 3": 33,
            "Windows 7 Professional Service Pack 1": 4,
            "Windows 7 Ultimate Service Pack 1": 2,
            "Windows 7 Enterprise Service Pack 1": 22,
            "Windows 10 Pro": 30,
            "Windows 10 Enterprise": 9
        }
    },
    "DC": {
        "enabled": 25,
        "haslaps": 2,
        "osProbability": {
            "Windows Server 2003 Enterprise Edition": 8,
            "Windows Server 2008 Standard": 4,
            "Windows Server 2008 Datacenter": 3,
            "Windows Server 2008 Enterprise": 15,
            "Windows Server 2008 R2 Standard": 12,
            "Windows Server 2008 R2 Datacenter": 6,
            "Windows Server 2008 R2 Enterprise": 9,
            "Windows Server 2012 Standard": 13,
            "Windows Server 2012 Datacenter": 10,
            "Windows Server 2012 R2 Standard": 4,
            "Windows Server 2012 R2 Datacenter": 12,
            "Windows Server 2016 Standard": 0,
            "Windows Server 2016 Datacenter": 4
        }
    },
    "User": {
        "nUsers": 6,
        "enabled": 54,
        "dontreqpreauth": 56,
        "hasspn": 53,
        "passwordnotreqd": 16,
        "pwdneverexpires": 4,
        "sidhistory": 83,
        "unconstraineddelegation": 85
    },
    "OU": {
        "nOUs": 6
    },
    "Group": {
        "nGroups": 8,
        "nestingGroupProbability": 4,
        "departmentProbability": {
            "IT": 3,
            "HR": 30,
            "MARKETING": 29,
            "OPERATIONS": 17,
            "BIDNESS": 21
        }
    },
    "GPO": {
        "nGPOs": 7
    },
    "ACLs": {
        "ACLPrincipalsPercentage": 54,
        "ACLsProbability": {
            "GenericAll": 41,
            "GenericWrite": 67,
            "WriteOwner": 91,
            "WriteDacl": 43,
            "AddMember": 64,
            "ForceChangePassword": 41,
            "ReadLAPSPassword": 52
        }
    }
}

def randomize_distribution(d : dict):
    """Randomizes a dictionary of probabilities so they sum to exactly 100. modify in place the dict structure"""
    keys = list(d.keys())
    if not keys: 
        return d
    
    weights = [random.randint(0, 100) for _ in keys]
    total = sum(weights)
    
    # Fallback if all random weights happen to be 0
    if total == 0:
        weights[0] = 100
        total = 100
        
    normalized = {}
    current_sum = 0
    
    # Normalize all but the last one
    for i, key in enumerate(keys[:-1]):
        val = int(round((weights[i] / total) * 100))
        normalized[key] = val
        current_sum += val
        
    # Give the remainder to the last key to ensure an exact sum of 100
    normalized[keys[-1]] = max(0, 100 - current_sum) 
    
    return normalized

def generate_config(index : int, custom_config : dict = None) -> str:
    """Takes an AD configuration dictionary and randomizes all of its values. Return a path where the config has been savec"""
    # Deep copy so we don't modify your original template dictionary
    if not custom_config:
        config = copy.deepcopy(BASE_CONFIG)        
        # Define maximum limits for counts so the AD lab doesn't get too large
        MAX_COUNTS = {
            'nComputers': 50, 
            'nUsers': 100, 
            'nOUs': 15, 
            'nGroups': 20, 
            'nGPOs': 10
        }
        
        for section_name, section_data in config.items():
            for key, value in section_data.items():
                
                # 1. Randomize raw counts (nUsers, nComputers, etc.)
                if key in MAX_COUNTS:
                    section_data[key] = random.randint(1, MAX_COUNTS[key])
                
                # 2. Randomize distributions that MUST sum to 100 (OS, Functional Level, etc.)
                elif isinstance(value, dict) and 'Probability' in key and key not in ['ACLsProbability', 'Trusts']:
                    section_data[key] = randomize_distribution(value)
                
                # 3. Randomize independent probabilities inside a dictionary (ACLs, Trusts)
                elif isinstance(value, dict):
                    section_data[key] = {k: random.randint(0, 100) for k in value.keys()}
                
                # 4. Randomize standalone percentages and booleans (0 to 100)
                elif isinstance(value, int):
                    section_data[key] = random.randint(0, 100)
        else:
            config = custom_config
                
    filename = f"./Dataset/config/adsimulator_config_{index}.json"
    os.makedirs(f'./Dataset/config/', exist_ok=True)
    with open(filename, "w") as f:
        json.dump(config, f, indent=4)
        
    print(f"[+] Generated config: {filename}")
    return filename

if __name__ == "__main__":
    idx = sys.argv[1] if len(sys.argv) > 1 else "0"
    generate_config(idx)