# utils/helpers.py
import re
from urllib.parse import urlparse  # This is the correct import

def sanitize_filename(target):
    """
    Converts a target string (e.g., a URL or IP) into a safe filename.
    Replaces problematic characters like :, /, ?, &, etc., with underscores.
    """
    # Replace any non-alphanumeric character (except dots and hyphens) with an underscore
    safe_name = re.sub(r'[^a-zA-Z0-9.-]', '_', target)
    # Collapse multiple consecutive underscores into a single one
    safe_name = re.sub(r'_+', '_', safe_name)
    # Remove any leading or trailing underscores
    safe_name = safe_name.strip('_')
    return safe_name

def extract_hostname(target):
    """
    Extracts the hostname from a target input.
    Handles both IP addresses/domains and full URLs.
    Returns (hostname_for_nmap, full_url_for_nikto)
    """
    # If it looks like a URL (starts with http:// or https://), parse it
    if target.startswith('http://') or target.startswith('https://'):
        parsed_url = urlparse(target)  # Now this will work correctly
        hostname_for_nmap = parsed_url.hostname
        # For Nikto, we want to keep the full URL including path if provided
        full_url_for_nikto = target
    else:
        # If it's just an IP or hostname, use it as is
        hostname_for_nmap = target
        full_url_for_nikto = f"http://{target}"  # Default to HTTP
    
    return hostname_for_nmap, full_url_for_nikto

# Test the new function
if __name__ == "__main__":
    test_url = "https://saza-dev.vercel.app/"
    test_ip = "192.168.1.1:8080"
    
    hostname, full_url = extract_hostname(test_url)
    print(f"Input: {test_url} -> Hostname: {hostname}, Full URL: {full_url}")
    
    hostname, full_url = extract_hostname(test_ip)
    print(f"Input: {test_ip} -> Hostname: {hostname}, Full URL: {full_url}")
