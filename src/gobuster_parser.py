import subprocess
import re
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
from utils.helpers import sanitize_filename  # Add this import

def run_gobuster(target, gobuster_arguments="dir -w /usr/share/wordlists/dirb/common.txt"):
    """Runs a Gobuster scan with user-provided arguments."""
    # SANITIZE THE TARGET NAME FOR THE FILENAME
    safe_target = sanitize_filename(target)
    output_file = f"data/{safe_target}_gobuster.txt"
    #output_file = f"data/{target}_gobuster.txt"
    if not target.startswith("http"):
        target = f"http://{target}"
    
    # Construct the command with user arguments
    command = f"gobuster {gobuster_arguments} -u {target} -o {output_file}"
    
    print(f"[*] Running command: {command}")
    
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=3600)
        return output_file
    except subprocess.TimeoutExpired:
        print(f"Gobuster scan timed out for {target}")
        return None

def parse_gobuster_output(output_file):
    """Parses Gobuster's output file into our defined features."""
    gobuster_features = {
        "count_path_200": 0, "count_path_403": 0, "count_path_500": 0,
        "path_contains_admin": 0, "path_contains_login": 0, "path_contains_config": 0,
        "path_contains_backup": 0, "path_contains_api": 0
    }
    
    try:
        with open(output_file, 'r') as f:
            lines = f.readlines()
    except FileNotFoundError:
        print("Gobuster output file not found.")
        return gobuster_features

    sensitive_keywords = ['admin', 'login', 'config', 'backup', 'api']
    
    for line in lines:
        # Gobuster output lines typically look like: /admin (Status: 200)
        if "Status:" in line:
            gobuster_features["count_path_200"] += 1 if "200" in line else 0
            gobuster_features["count_path_403"] += 1 if "403" in line else 0
            gobuster_features["count_path_500"] += 1 if "500" in line else 0
            
            # Check for sensitive keywords in the path
            for keyword in sensitive_keywords:
                if keyword in line.lower():
                    gobuster_features[f"path_contains_{keyword}"] = 1

    return gobuster_features

# Test the functions
if __name__ == "__main__":
    target = "127.0.0.1" # Test on a simple local web server if you have one running
    output_path = run_gobuster(target)
    if output_path:
        features = parse_gobuster_output(output_path)
        print(features)
