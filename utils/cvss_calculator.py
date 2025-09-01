# src/cvss_calculator.py
"""
Simplified CVSS Calculator that provides realistic scores based on scan findings.
This uses a points-based system that maps to real CVSS ranges.
"""

def calculate_cvss_base_score(features):
    """
    Calculate realistic CVSS score based on scan findings.
    Returns a score between 0.0 and 10.0
    """
    total_score = 0.0
    
    # CRITICAL FINDINGS (Adds 2.0-3.0 points each)
    if features.get('vuln_sqli', 0) == 1:
        total_score += 2.8  # SQL Injection - critical data breach
    if features.get('vuln_command_injection', 0) == 1:
        total_score += 3.0  # Command Injection - full system compromise
    if features.get('vuln_directory_traversal', 0) == 1:
        total_score += 2.5  # Directory Traversal - file system access
    
    # HIGH RISK FINDINGS (Adds 1.5-2.0 points each)
    if features.get('nikto_high_risk_findings', 0) > 0:
        total_score += min(2.0, features['nikto_high_risk_findings'] * 0.3)
    if features.get('vuln_xss', 0) == 1:
        total_score += 1.7  # XSS - session hijacking, but requires interaction
    if features.get('port_23_open', 0) == 1:  # Telnet
        total_score += 2.0  # Cleartext credentials - critical exposure
    
    # MEDIUM RISK FINDINGS (Adds 0.5-1.5 points each)
    if features.get('nikto_medium_risk_findings', 0) > 0:
        total_score += min(1.5, features['nikto_medium_risk_findings'] * 0.2)
    if features.get('version_contains_old', 0) == 1:
        total_score += 1.2  # Outdated software - known exploits likely
    if features.get('port_21_open', 0) == 1:  # FTP
        total_score += 1.0  # Often misconfigured, credentials exposed
    if features.get('port_22_open', 0) == 1:  # SSH
        total_score += 0.8  # Brute force risk, but can be secure
    
    # LOW RISK FINDINGS (Adds 0.1-0.5 points each)
    if features.get('nikto_low_risk_findings', 0) > 0:
        total_score += min(0.5, features['nikto_low_risk_findings'] * 0.05)
    if features.get('path_contains_admin', 0) == 1:
        total_score += 0.3  # Admin interface exposed
    if features.get('path_contains_config', 0) == 1:
        total_score += 0.4  # Config files exposed
    if features.get('has_uncommon_ports', 0) == 1:
        total_score += 0.5 + (features.get('other_ports_open', 0) * 0.2)
    
    # Apply CVSS severity ranges
    return _map_to_cvss_range(total_score)

def _map_to_cvss_range(points):
    """
    Map accumulated points to CVSS severity ranges.
    This creates realistic score distributions.
    """
    if points >= 9.0:
        return min(10.0, round(points, 1))  # Critical: 9.0-10.0
    elif points >= 7.0:
        return round(7.0 + (points - 7.0) * 0.66, 1)  # High: 7.0-8.9
    elif points >= 4.0:
        return round(4.0 + (points - 4.0) * 1.0, 1)   # Medium: 4.0-6.9
    elif points >= 1.0:
        return round(1.0 + (points - 1.0) * 1.5, 1)   # Low: 1.0-3.9
    else:
        return round(points * 0.5, 1)                 # None: 0.0-0.9

def test_cvss_calculator():
    """Test the CVSS calculator with realistic scenarios."""
    print("Testing CVSS Calculator with Realistic Scenarios...")
    
    # 1. CRITICAL: Metasploitable-like system
    critical_features = {
        'nikto_high_risk_findings': 8,
        'nikto_medium_risk_findings': 4,
        'vuln_sqli': 1,
        'vuln_command_injection': 1,
        'vuln_directory_traversal': 1,
        'vuln_xss': 1,
        'version_contains_old': 1,
        'port_21_open': 1,
        'port_22_open': 1,
        'port_23_open': 1,
        'port_445_open': 1,
        'path_contains_admin': 1
    }
    
    # 2. HIGH: Compromised system with several issues
    high_features = {
        'nikto_high_risk_findings': 3,
        'nikto_medium_risk_findings': 6,
        'vuln_xss': 1,
        'version_contains_old': 1,
        'port_21_open': 1,
        'port_22_open': 1,
        'path_contains_admin': 1
    }
    
    # 3. MEDIUM: Typical vulnerable web app
    medium_features = {
        'nikto_medium_risk_findings': 4,
        'nikto_low_risk_findings': 12,
        'version_contains_old': 1,
        'port_80_open': 1,
        'path_contains_config': 1
    }
    
    # 4. LOW: Minor issues
    low_features = {
        'nikto_low_risk_findings': 5,
        'port_22_open': 1
    }
    
    # 5. CLEAN: Secure system
    clean_features = {
        'nikto_low_risk_findings': 1
    }
    
    scores = {}
    scores['Critical'] = calculate_cvss_base_score(critical_features)
    scores['High'] = calculate_cvss_base_score(high_features)
    scores['Medium'] = calculate_cvss_base_score(medium_features)
    scores['Low'] = calculate_cvss_base_score(low_features)
    scores['Clean'] = calculate_cvss_base_score(clean_features)
    
    for severity, score in scores.items():
        print(f"{severity:8} risk score: {score}")
    
    return scores

if __name__ == "__main__":
    test_cvss_calculator()
