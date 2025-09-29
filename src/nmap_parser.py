import subprocess
# Add at the top of the file
import sys
import os
# Add the utils directory to the path so we can import helpers
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
from utils.helpers import sanitize_filename  # Add this import
from libnmap.parser import NmapParser

def run_nmap(target, nmap_arguments="-sV -O"):
    """Runs an Nmap scan with user-provided arguments and saves the XML output."""
    xml_file = f"data/{target}_nmap.xml"
    # Sanitize the target and arguments to prevent command injection!
    # This is a basic safety measure. For a real tool, you'd need more robust sanitization.
    safe_target = sanitize_filename(target)
    xml_file = f"data/{safe_target}_nmap.xml"
    target = target.replace(";", "").replace("|", "").replace("&", "")
    
    # Use the provided arguments
    command = f"nmap {nmap_arguments} {target} -oX {xml_file}"
    
    print(f"[*] Running command: {command}")
    
    try:
        subprocess.run(command, shell=True, check=True, timeout=3600) # Longer timeout for custom scans
        return xml_file
    except subprocess.TimeoutExpired:
        print(f"Nmap scan timed out for {target}")
        return None
    except subprocess.CalledProcessError as e:
        print(f"Nmap scan failed: {e}")
        return None
        
def parse_nmap_xml(xml_file):
    """Enhanced parser to extract vulnerability information"""
    try:
        report = NmapParser.parse_fromfile(xml_file)
    except Exception as e:
        print(f"Failed to parse XML: {e}")
        return None

    # Initialize features
    nmap_features = {
        "port_21_open": 0, "port_22_open": 0, "port_23_open": 0,
        "port_80_open": 0, "port_443_open": 0, "port_445_open": 0,
        "service_contains_apache": 0, "service_contains_openssh": 0,
        "version_contains_old": 0, "total_open_ports": 0,
        # New vulnerability features
        "critical_vuln_count": 0,
        "high_vuln_count": 0, 
        "medium_vuln_count": 0,
        "vuln_backdoor_detected": 0,
        "vuln_sqli_detected": 0,
        "vuln_rce_detected": 0,
        "vuln_info_disclosure": 0
    }

    host = report.hosts[0]
    if host.is_up():
        nmap_features["total_open_ports"] = len(host.get_ports())
        
        for service in host.services:
            port = service.port
            # Port detection
            if port in [21, 22, 23, 80, 443, 445]:
                nmap_features[f"port_{port}_open"] = 1
            
            # Service detection
            banner = service.banner.lower() if service.banner else ""
            if 'apache' in banner:
                nmap_features['service_contains_apache'] = 1
            if 'openssh' in banner:
                nmap_features['service_contains_openssh'] = 1
                
            # Version age detection
            if any(x in banner for x in ['2.3.4', '4.7p1', '2.2.8', '9.4.2']):
                nmap_features['version_contains_old'] = 1
            
            # Script output analysis for vulnerabilities
            for script in service.scripts_results:
                script_output = script.get('output', '').lower()
                
                # Detect critical vulnerabilities
                if 'vulnerable' in script_output and 'exploitable' in script_output:
                    nmap_features['critical_vuln_count'] += 1
                    if 'backdoor' in script_output:
                        nmap_features['vuln_backdoor_detected'] = 1
                
                if 'sql injection' in script_output:
                    nmap_features['vuln_sqli_detected'] = 1
                    nmap_features['high_vuln_count'] += 1
                
                if 'remote code execution' in script_output or 'rce' in script_output:
                    nmap_features['vuln_rce_detected'] = 1
                    nmap_features['high_vuln_count'] += 1
                
                if 'information disclosure' in script_output or 'info leak' in script_output:
                    nmap_features['vuln_info_disclosure'] = 1
                    nmap_features['medium_vuln_count'] += 1

    return nmap_features

# Test the functions
if __name__ == "__main__":
    target = "127.0.0.1" # Test on your own machine first!
    xml_path = run_nmap(target)
    if xml_path:
        features = parse_nmap_xml(xml_path)
        print(features)
