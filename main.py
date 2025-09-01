import json
from src.nmap_parser import run_nmap, parse_nmap_xml
from src.gobuster_parser import run_gobuster, parse_gobuster_output
from src.nikto_parser import run_nikto, parse_nikto_output # Import the new Nikto functions
from utils.helpers import extract_hostname, sanitize_filename 

def collect_data(target):
    print(f"[+] Starting scan on target: {target}")
    
    # EXTRACT THE PROPER TARGET FOR EACH TOOL
    nmap_gobuster_target, nikto_target = extract_hostname(target)
    safe_target_name = sanitize_filename(target)
    
    print(f"[+] Using '{nmap_gobuster_target}' for Nmap/Gobuster")
    print(f"[+] Using '{nikto_target}' for Nikto")
    
    # Run and parse Nmap (use the hostname only)
    print("[+] Running Nmap...")
    nmap_xml = run_nmap(nmap_gobuster_target)
    if not nmap_xml:
        return None
    nmap_features = parse_nmap_xml(nmap_xml)
    
    # Run and parse Gobuster (use the hostname only)
    print("[+] Running Gobuster...")
    gobuster_output = run_gobuster(nmap_gobuster_target)
    gobuster_features = parse_gobuster_output(gobuster_output)
    
    # Run and parse Nikto (use the full URL)
    print("[+] Running Nikto... (This may take a while)")
    nikto_output = run_nikto(nikto_target)
    nikto_features = parse_nikto_output(nikto_output)
    
    # Combine all features into one dictionary
    all_features = {**nmap_features, **gobuster_features, **nikto_features}
    
    # Save the features to a JSON file (use original target for filename)
    output_filename = f"data/{safe_target_name}_features.json"
    with open(output_filename, 'w') as f:
        json.dump(all_features, f, indent=4)
    
    print(f"[+] Scan complete! Features saved to {output_filename}")
    return all_features


if __name__ == "__main__":
    target = input("Enter target IP, hostname, or URL: ").strip()
    features = collect_data(target)
    if features:
        print("\nExtracted Feature Vector:")
        print(json.dumps(features, indent=4))
