import json
from src.nmap_parser import run_nmap, parse_nmap_xml
from src.gobuster_parser import run_gobuster, parse_gobuster_output

def collect_data(target):
    print(f"[+] Starting scan on target: {target}")
    
    # Run and parse Nmap
    print("[+] Running Nmap...")
    nmap_xml = run_nmap(target)
    if not nmap_xml:
        return None
    nmap_features = parse_nmap_xml(nmap_xml)
    
    # Run and parse Gobuster
    print("[+] Running Gobuster...")
    gobuster_output = run_gobuster(target)
    gobuster_features = parse_gobuster_output(gobuster_output)
    
    # Combine all features into one dictionary
    all_features = {**nmap_features, **gobuster_features}
    
    # Save the features to a JSON file
    output_filename = f"data/{target}_features.json"
    with open(output_filename, 'w') as f:
        json.dump(all_features, f, indent=4)
    
    print(f"[+] Scan complete! Features saved to {output_filename}")
    return all_features

if __name__ == "__main__":
    target = input("Enter target IP or hostname: ").strip()
    features = collect_data(target)
    if features:
        print("\nExtracted Feature Vector:")
        print(json.dumps(features, indent=4))
