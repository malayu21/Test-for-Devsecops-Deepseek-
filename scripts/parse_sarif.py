import json
import os

def parse_codeql_sarif(sarif_file):
    """Parse CodeQL SARIF file for SAST vulnerabilities."""
    try:
        with open(sarif_file, 'r') as f:
            sarif = json.load(f)
        results = sarif.get('runs', [{}])[0].get('results', [])
        vulnerabilities = []
        for result in results:
            rule_id = result.get('ruleId', 'unknown')
            message = result.get('message', {}).get('text', 'No description')
            severity = result.get('level', 'note').capitalize()
            locations = [
                {
                    'file': loc.get('physicalLocation', {}).get('artifactLocation', {}).get('uri', ''),
                    'line': loc.get('physicalLocation', {}).get('region', {}).get('startLine', 0)
                } for loc in result.get('locations', [])
            ]
            vulnerabilities.append({
                'rule_id': f"codeql-{rule_id}",
                'message': message,
                'severity': severity,
                'locations': locations
            })
        return vulnerabilities
    except Exception as e:
        print(f"Error parsing CodeQL SARIF: {e}")
        return []

def parse_safety_results(safety_file):
    """Parse Safety JSON file for dependency vulnerabilities."""
    try:
        with open(safety_file, 'r') as f:
            safety = json.load(f)
        vulnerabilities = []
        for vuln in safety.get('vulnerabilities', []):
            vulnerabilities.append({
                'rule_id': f"safety-{vuln.get('id', 'unknown')}",
                'package': vuln.get('package_name', ''),
                'installed_version': vuln.get('analyzed_version', ''),
                'message': vuln.get('advisory', 'No advisory'),
                'severity': vuln.get('severity', 'Medium').capitalize()
            })
        return vulnerabilities
    except Exception as e:
        print(f"Error parsing Safety results: {e}")
        return []

def parse_zap_results(zap_file):
    """Parse ZAP JSON report for DAST vulnerabilities, filtering app-specific URLs."""
    try:
        with open(zap_file, 'r') as f:
            zap = json.load(f)
        vulnerabilities = []
        app_url = "https://51d829f58a12.ngrok-free.app"  # Replace with dynamic ngrok URL if needed
        for site in zap.get('site', []):
            site_url = site.get('@name', '')
            if app_url not in site_url:  # Filter out external URLs
                continue
            for alert in site.get('alerts', []):
                rule_id = alert.get('alertRef', 'unknown')
                severity = alert.get('riskdesc', 'Informational').split(' ')[0].capitalize()
                vulnerabilities.append({
                    'rule_id': f"zap-{rule_id}",
                    'url': site_url,
                    'method': alert.get('method', 'GET'),
                    'message': alert.get('alert', 'No description'),
                    'evidence': alert.get('evidence', ''),
                    'solution': alert.get('solution', ''),
                    'severity': severity
                })
        return vulnerabilities
    except Exception as e:
        print(f"Error parsing ZAP results: {e}")
        return []

def main():
    """Merge security results from CodeQL, Safety, and ZAP."""
    codeql_file = 'sarif-results/python.sarif'
    safety_file = 'safety-results.json'
    zap_file = 'report_json.json'
    
    sast_vulns = parse_codeql_sarif(codeql_file) if os.path.exists(codeql_file) else []
    dep_vulns = parse_safety_results(safety_file) if os.path.exists(safety_file) else []
    dast_vulns = parse_zap_results(zap_file) if os.path.exists(zap_file) else []
    
    merged_results = {
        'sast': sast_vulns,
        'dependencies': dep_vulns,
        'dast': dast_vulns,
        'summary': {
            'total_vulnerabilities': len(sast_vulns) + len(dep_vulns) + len(dast_vulns)
        }
    }
    
    os.makedirs('security-results', exist_ok=True)
    output_file = 'security-results/merged-results.json'
    with open(output_file, 'w') as f:
        json.dump(merged_results, f, indent=2)
    
    print(f"Merged results saved to {output_file}")

if __name__ == "__main__":
    main()
