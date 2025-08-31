# utils/labeler.py
import json
import sys

def generate_labels_for_target(target_ip, feature_dict):
    """
    Based on the target IP, we know what vulnerabilities it should have.
    This is our auto-labeling function for known lab machines.
    """
    # Initialize all vulnerability labels to 0
    labels = {
        "vuln_sqli": 0,
        "vuln_xss": 0,
        "vuln_directory_traversal": 0,
        "vuln_command_injection": 0,
        "vuln_misconfiguration": 0,
        "vuln_outdated_service": 1,  # Metasploitable is almost entirely this
        "cvss_score": 9.0  # Overall, it's a very vulnerable machine
    }
    
    # Specific rules for Metasploitable 2 (192.168.56.102)
    if target_ip == "192.168.56.102":
        if feature_dict.get('port_21_open') == 1:
            # vsftpd 2.3.4 is vulnerable to backdoor command execution
            labels["vuln_command_injection"] = 1 
        if feature_dict.get('port_445_open') == 1:
            # Samba has vulnerabilities
            labels["vuln_directory_traversal"] = 1
        if feature_dict.get('port_80_open') == 1:
            # The web app has many vulns
            labels["vuln_sqli"] = 1
            labels["vuln_xss"] = 1
        labels['vuln_misconfiguration'] = 1 # It has many config issues

    # Add more rules for other known VMs here later (e.g., Juice Shop)
    
    return labels

if __name__ == "__main__":
    # Example usage: python3 utils/labeler.py data/192.168.56.102_features.json
    if len(sys.argv) < 2:
        print("Usage: python3 labeler.py <path_to_features.json>")
        sys.exit(1)
    
    features_file = sys.argv[1]
    target_ip = features_file.split('/')[-1].split('_')[0] # Extract IP from filename
    
    with open(features_file, 'r') as f:
        features = json.load(f)
    
    labels = generate_labels_for_target(target_ip, features)
    
    # Create the final labeled data point
    labeled_data = {"features": features, "labels": labels}
    
    # Save it to a new file in a dedicated folder for training data
    output_file = f"data/labeled_{target_ip}.json"
    with open(output_file, 'w') as f:
        json.dump(labeled_data, f, indent=4)
    
    print(f"[+] Auto-labeled data saved to {output_file}")
