import subprocess
from libnmap.parser import NmapParser

def run_nmap(target, nmap_arguments="-sV -O"):
    """Runs an Nmap scan with user-provided arguments and saves the XML output."""
    xml_file = f"data/{target}_nmap.xml"
    # Sanitize the target and arguments to prevent command injection!
    # This is a basic safety measure. For a real tool, you'd need more robust sanitization.
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
    """Parses the Nmap XML file and extracts our defined features."""
    try:
        report = NmapParser.parse_fromfile(xml_file)
    except Exception as e:
        print(f"Failed to parse XML: {e}")
        return None

    # Initialize a dictionary for our features. We'll start with zeros.
    nmap_features = {
        "port_21_open": 0, "port_22_open": 0, "port_23_open": 0,
        "port_80_open": 0, "port_443_open": 0, "port_445_open": 0,
        "port_3306_open": 0, "port_3389_open": 0,
        "service_contains_apache": 0, "service_contains_nginx": 0,
        "service_contains_iis": 0, "service_contains_openssh": 0,
        "version_contains_old": 0,
        "total_open_ports": 0
    }

    # Get the first host from the scan
    host = report.hosts[0]
    if host.is_up():
        nmap_features["total_open_ports"] = len(host.get_ports())
        
        for service in host.services:
            port = service.port
            # Check for specific ports
            if port in [21, 22, 23, 80, 443, 445, 3306, 3389]:
                nmap_features[f"port_{port}_open"] = 1
            
            # Check service version for keywords
            banner = service.banner.lower() if service.banner else ""
            if 'apache' in banner:
                nmap_features['service_contains_apache'] = 1
            if 'nginx' in banner:
                nmap_features['service_contains_nginx'] = 1
            if 'iis' or 'microsoft' in banner:
                nmap_features['service_contains_iis'] = 1
            if 'openssh' in banner:
                nmap_features['service_contains_openssh'] = 1
                
            # Simple heuristic for "old" version
            if any(x in banner for x in ['1.', '2.0', '2.2', '7.2']):
                nmap_features['version_contains_old'] = 1

    return nmap_features

# Test the functions
if __name__ == "__main__":
    target = "127.0.0.1" # Test on your own machine first!
    xml_path = run_nmap(target)
    if xml_path:
        features = parse_nmap_xml(xml_path)
        print(features)
