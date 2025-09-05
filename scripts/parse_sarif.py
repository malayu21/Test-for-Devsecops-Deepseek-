"""
parse_sarif.py - Converts security scan results into a unified format

This script takes results from different security tools (CodeQL, Safety, OWASP ZAP)
and combines them into one JSON file that the AI can understand.

SARIF = Static Analysis Results Interchange Format (standard for security tools)
"""

import json
import os
import glob
from pathlib import Path

def parse_codeql_sarif(sarif_file):
    """
    Parse CodeQL SARIF results (SAST - Source code analysis)
    
    Args:
        sarif_file: Path to the SARIF file from CodeQL
        
    Returns:
        List of vulnerability dictionaries
    """
    vulnerabilities = []
    
    try:
        with open(sarif_file, 'r') as f:
            sarif_data = json.load(f)
            
        # SARIF has a specific structure: runs -> results -> each result is a finding
        for run in sarif_data.get('runs', []):
            for result in run.get('results', []):
                # Extract key information about each vulnerability
                vuln = {
                    'type': 'sast',  # Static Analysis Security Testing
                    'tool': 'CodeQL',
                    'rule_id': result.get('ruleId', 'unknown'),
                    'severity': get_severity(result),
                    'message': result.get('message', {}).get('text', ''),
                    'locations': []
                }
                
                # Get file locations where the issue was found
                for location in result.get('locations', []):
                    phys_loc = location.get('physicalLocation', {})
                    artifact = phys_loc.get('artifactLocation', {})
                    region = phys_loc.get('region', {})
                    
                    vuln['locations'].append({
                        'file': artifact.get('uri', ''),
                        'line': region.get('startLine', 0),
                        'column': region.get('startColumn', 0),
                        'code_snippet': region.get('snippet', {}).get('text', '')
                    })
                
                vulnerabilities.append(vuln)
                
    except FileNotFoundError:
        print(f"SARIF file not found: {sarif_file}")
    except json.JSONDecodeError:
        print(f"Invalid JSON in SARIF file: {sarif_file}")
        
    return vulnerabilities

def parse_safety_results(safety_file):
    """
    Parse Safety dependency scan results
    
    Safety checks your requirements.txt for known vulnerable packages
    """
    vulnerabilities = []
    
    try:
        with open(safety_file, 'r') as f:
            safety_data = json.load(f)
            
        # Safety format: list of vulnerable packages
        for vuln in safety_data:
            vulnerability = {
                'type': 'dependency',
                'tool': 'Safety',
                'rule_id': f"safety-{vuln.get('id', 'unknown')}",
                'severity': 'high',  # Most dependency vulns are serious
                'message': f"Vulnerable package: {vuln.get('package', '')} {vuln.get('installed_version', '')}",
                'package': vuln.get('package', ''),
                'installed_version': vuln.get('installed_version', ''),
                'vulnerable_spec': vuln.get('vulnerable_spec', ''),
                'advisory': vuln.get('advisory', ''),
                'locations': [{
                    'file': 'requirements.txt',
                    'line': 0,
                    'fix_suggestion': f"Update {vuln.get('package')} to version >= {vuln.get('vulnerable_spec', 'latest')}"
                }]
            }
            vulnerabilities.append(vulnerability)
            
    except FileNotFoundError:
        print(f"Safety results not found: {safety_file}")
    except json.JSONDecodeError:
        print(f"Invalid JSON in safety file: {safety_file}")
        
    return vulnerabilities

def parse_zap_results():
    """
    Parse OWASP ZAP DAST results
    
    ZAP tests your running application by sending requests and analyzing responses
    """
    vulnerabilities = []
    
    # ZAP typically outputs to a JSON report
    zap_files = glob.glob("**/zap_report.json", recursive=True)
    
    for zap_file in zap_files:
        try:
            with open(zap_file, 'r') as f:
                zap_data = json.load(f)
                
            # ZAP structure: site -> alerts
            for site in zap_data.get('site', []):
                for alert in site.get('alerts', []):
                    vuln = {
                        'type': 'dast',  # Dynamic Analysis Security Testing
                        'tool': 'OWASP ZAP',
                        'rule_id': f"zap-{alert.get('pluginid', 'unknown')}",
                        'severity': map_zap_severity(alert.get('riskdesc', '')),
                        'message': alert.get('desc', ''),
                        'url': alert.get('url', ''),
                        'method': alert.get('method', 'GET'),
                        'evidence': alert.get('evidence', ''),
                        'solution': alert.get('solution', ''),
                        'locations': [{
                            'url': alert.get('url', ''),
                            'parameter': alert.get('param', ''),
                            'evidence': alert.get('evidence', '')
                        }]
                    }
                    vulnerabilities.append(vuln)
                    
        except FileNotFoundError:
            print(f"ZAP results not found: {zap_file}")
        except json.JSONDecodeError:
            print(f"Invalid JSON in ZAP file: {zap_file}")
            
    return vulnerabilities

def get_severity(result):
    """Convert SARIF severity levels to standard levels"""
    level = result.get('level', 'warning')
    
    severity_map = {
        'error': 'high',
        'warning': 'medium',
        'note': 'low',
        'info': 'info'
    }
    
    return severity_map.get(level, 'medium')

def map_zap_severity(risk_desc):
    """Convert ZAP risk descriptions to standard severity"""
    if 'High' in risk_desc:
        return 'high'
    elif 'Medium' in risk_desc:
        return 'medium'
    elif 'Low' in risk_desc:
        return 'low'
    else:
        return 'info'

def main():
    """
    Main function that combines all security scan results
    """
    print("🔍 Parsing security scan results...")
    
    all_vulnerabilities = {
        'sast': [],      # Source code issues
        'dependencies': [], # Package vulnerabilities  
        'dast': [],      # Runtime application issues
        'summary': {}
    }
    
    # Parse SAST results (CodeQL)
    print("📋 Processing SAST results...")
    sarif_files = glob.glob("sarif-results/**/*.sarif", recursive=True)
    for sarif_file in sarif_files:
        sast_vulns = parse_codeql_sarif(sarif_file)
        all_vulnerabilities['sast'].extend(sast_vulns)
        print(f"   Found {len(sast_vulns)} SAST issues in {sarif_file}")
    
    # Parse dependency results (Safety)
    print("📦 Processing dependency scan results...")
    dep_vulns = parse_safety_results('safety-results.json')
    all_vulnerabilities['dependencies'].extend(dep_vulns)
    print(f"   Found {len(dep_vulns)} dependency vulnerabilities")
    
    # Parse DAST results (OWASP ZAP)
    print("🌐 Processing DAST results...")
    dast_vulns = parse_zap_results()
    all_vulnerabilities['dast'].extend(dast_vulns)
    print(f"   Found {len(dast_vulns)} DAST issues")
    
    # Create summary
    all_vulnerabilities['summary'] = {
        'total_vulnerabilities': len(all_vulnerabilities['sast']) + 
                               len(all_vulnerabilities['dependencies']) + 
                               len(all_vulnerabilities['dast']),
        'sast_count': len(all_vulnerabilities['sast']),
        'dependency_count': len(all_vulnerabilities['dependencies']),
        'dast_count': len(all_vulnerabilities['dast']),
        'severity_breakdown': get_severity_breakdown(all_vulnerabilities)
    }
    
    # Save merged results
    with open('merged-results.json', 'w') as f:
        json.dump(all_vulnerabilities, f, indent=2)
    
    print(f"✅ Merged results saved. Total vulnerabilities: {all_vulnerabilities['summary']['total_vulnerabilities']}")
    
    return all_vulnerabilities['summary']['total_vulnerabilities'] > 0

def get_severity_breakdown(vulns):
    """Count vulnerabilities by severity level"""
    severity_counts = {'high': 0, 'medium': 0, 'low': 0, 'info': 0}
    
    for vuln_type in ['sast', 'dependencies', 'dast']:
        for vuln in vulns[vuln_type]:
            severity = vuln.get('severity', 'medium')
            if severity in severity_counts:
                severity_counts[severity] += 1
                
    return severity_counts

if __name__ == "__main__":
    vulnerabilities_found = main()
    
    # Exit with error code if vulnerabilities found (for GitHub Actions)
    if vulnerabilities_found:
        exit(1)
    else:
        exit(0)
