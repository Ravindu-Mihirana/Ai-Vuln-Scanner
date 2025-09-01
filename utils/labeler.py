# utils/labeler.py
import json
import sys
import os
# Add the project root directory to Python path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

# Now import from utils
from utils.cvss_calculator import calculate_cvss_base_score

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
        "vuln_outdated_service": 0,
        "cvss_score": 0.0  # Start with 0, will be calculated
    }
    
    # Specific rules for known targets
    if target_ip == "192.168.56.102":  # Metasploitable
        labels.update({
            "vuln_sqli": 1,
            "vuln_xss": 1,
            "vuln_directory_traversal": 1,
            "vuln_command_injection": 1,
            "vuln_misconfiguration": 1,
            "vuln_outdated_service": 1
        })
    
    # Calculate REAL CVSS score based on actual features
    labels['cvss_score'] = calculate_cvss_base_score({**feature_dict, **labels})
    
    return labels

if __name__ == "__main__":
    # Example usage: python3 utils/labeler.py data/192.168.56.102_features.json
    if len(sys.argv) < 2:
        print("Usage: python3 labeler.py <path_to_features.json>")
        sys.exit(1)
    
    features_file = sys.argv[1]
    # Extract the sanitized target name from the filename
    filename = features_file.split('/')[-1]
    target_ip = filename.replace('_features.json', '') # Now it gets the safe name
    
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
