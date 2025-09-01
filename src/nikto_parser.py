import subprocess
import re
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
from utils.helpers import sanitize_filename  # Add this import

def run_nikto(target):
    """Runs a Nikto scan on the target."""
    safe_target = sanitize_filename(target)
    output_file = f"data/{safe_target}_nikto.txt"
    #output_file = f"data/{target}_nikto.txt"
    # Ensure target has http:// or https://
    if not target.startswith("http"):
        target = f"http://{target}"
    
    # Nikto command. -o writes the output to a file.
    command = f"nikto -h {target} -o {output_file} -Format txt"
    
    try:
        # Nikto can be very verbose, we capture output to avoid clutter
        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=1800) # 30 min timeout
        return output_file
    except subprocess.TimeoutExpired:
        print(f"Nikto scan timed out for {target}")
        return None
    except FileNotFoundError:
        print("Nikto is not installed. Please install it: 'sudo apt install nikto'")
        return None

def parse_nikto_output(output_file):
    """Parses Nikto's text output into our defined features."""
    # Initialize our Nikto feature dictionary with default zeros
    nikto_features = {
        "nikto_high_risk_findings": 0,
        "nikto_medium_risk_findings": 0,
        "nikto_low_risk_findings": 0,
        "nikto_found_xss": 0,
        "nikto_found_sqli": 0,
        "nikto_found_trace": 0,
        "nikto_found_misconfig": 0,
        "nikto_found_os_filenames": 0,
        "nikto_found_infoleak": 0,
    }
    
    # Keywords to search for in Nikto's findings
    high_risk_keywords = [r'\bOSVDB-\d', r'allowd methods', r'XSS', r'SQL injection', r'root shell', r'exploit']
    medium_risk_keywords = [r'misconfigured', r'informational', r'retrieved', r'debug', r'trace', r'track']
    xss_keywords = [r'XSS', r'Cross-Site Scripting']
    sqli_keywords = [r'SQL injection', r'SQLi']
    
    try:
        with open(output_file, 'r') as f:
            content = f.read().lower()  # Read the entire file and convert to lowercase for easier matching
    except FileNotFoundError:
        print("Nikto output file not found.")
        return nikto_features

    # Count findings by risk level (simple heuristic based on keywords)
    for line in content.split('\n'):
        if any(re.search(keyword, line, re.IGNORECASE) for keyword in high_risk_keywords):
            nikto_features["nikto_high_risk_findings"] += 1
        if any(re.search(keyword, line, re.IGNORECASE) for keyword in medium_risk_keywords):
            nikto_features["nikto_medium_risk_findings"] += 1
        # For low risk, we can count all lines that start with "+" (Nikto's finding indicator)
        if line.strip().startswith('+'):
            nikto_features["nikto_low_risk_findings"] += 1

    # Check for specific vulnerability types
    if any(re.search(keyword, content, re.IGNORECASE) for keyword in xss_keywords):
        nikto_features["nikto_found_xss"] = 1
    if any(re.search(keyword, content, re.IGNORECASE) for keyword in sqli_keywords):
        nikto_features["nikto_found_sqli"] = 1
    if re.search(r'trace.*enable', content, re.IGNORECASE) or re.search(r'track.*enable', content, re.IGNORECASE):
        nikto_features["nikto_found_trace"] = 1
    if re.search(r'misconfig', content, re.IGNORECASE):
        nikto_features["nikto_found_misconfig"] = 1
    if re.search(r'osvdb', content, re.IGNORECASE):
        nikto_features["nikto_found_os_filenames"] = 1
    if re.search(r'information.*leak', content, re.IGNORECASE) or re.search(r'debug.*enable', content, re.IGNORECASE):
        nikto_features["nikto_found_infoleak"] = 1

    return nikto_features

# Test the functions
if __name__ == "__main__":
    target = "127.0.0.1" # Test on a local web server if you have one
    output_path = run_nikto(target)
    if output_path:
        features = parse_nikto_output(output_path)
        print("Nikto Features:")
        for k, v in features.items():
            print(f"  {k}: {v}")
