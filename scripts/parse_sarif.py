import json
import glob

def parse_codeql_sarif(sarif_file):
    vulnerabilities = []
    try:
        with open(sarif_file, 'r') as f:
            sarif_data = json.load(f)
        for run in sarif_data.get('runs', []):
            for result in run.get('results', []):
                vuln = {
                    'type': 'sast',
                    'tool': 'CodeQL',
                    'rule_id': result.get('ruleId', 'unknown'),
                    'severity': get_severity(result),
                    'message': result.get('message', {}).get('text', ''),
                    'locations': []
                }
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
    except (FileNotFoundError, json.JSONDecodeError):
        pass
    return vulnerabilities

def parse_safety_results(safety_file):
    vulnerabilities = []
    try:
        with open(safety_file, 'r') as f:
            safety_data = json.load(f)
        for vuln in safety_data:
            vulnerabilities.append({
                'type': 'dependency',
                'tool': 'Safety',
                'rule_id': f"safety-{vuln.get('id','unknown')}",
                'severity': 'high',
                'message': f"{vuln.get('package','')} {vuln.get('installed_version','')} vulnerable",
                'package': vuln.get('package',''),
                'installed_version': vuln.get('installed_version',''),
                'vulnerable_spec': vuln.get('vulnerable_spec',''),
                'advisory': vuln.get('advisory',''),
                'locations':[{'file':'requirements.txt','line':0,'fix_suggestion':f"Update {vuln.get('package')} >= {vuln.get('vulnerable_spec','latest')}"}]
            })
    except (FileNotFoundError, json.JSONDecodeError):
        pass
    return vulnerabilities

def parse_zap_results():
    vulnerabilities = []
    zap_files = glob.glob("**/zap_report.json", recursive=True)
    for zap_file in zap_files:
        try:
            with open(zap_file, 'r') as f:
                zap_data = json.load(f)
            for site in zap_data.get('site', []):
                for alert in site.get('alerts', []):
                    vulnerabilities.append({
                        'type': 'dast',
                        'tool': 'OWASP ZAP',
                        'rule_id': f"zap-{alert.get('pluginid','unknown')}",
                        'severity': map_zap_severity(alert.get('riskdesc','')),
                        'message': alert.get('desc',''),
                        'url': alert.get('url',''),
                        'method': alert.get('method','GET'),
                        'evidence': alert.get('evidence',''),
                        'solution': alert.get('solution',''),
                        'locations':[{'url':alert.get('url',''),'parameter':alert.get('param',''),'evidence':alert.get('evidence','')}]
                    })
        except (FileNotFoundError, json.JSONDecodeError):
            pass
    return vulnerabilities

def get_severity(result):
    level = result.get('level','warning')
    return {'error':'high','warning':'medium','note':'low','info':'info'}.get(level,'medium')

def map_zap_severity(risk_desc):
    if 'High' in risk_desc: return 'high'
    if 'Medium' in risk_desc: return 'medium'
    if 'Low' in risk_desc: return 'low'
    return 'info'

def get_severity_breakdown(vulns):
    counts = {'high':0,'medium':0,'low':0,'info':0}
    for t in ['sast','dependencies','dast']:
        for v in vulns[t]:
            sev = v.get('severity','medium')
            if sev in counts: counts[sev] += 1
    return counts

def main():
    all_vulns = {'sast':[], 'dependencies':[], 'dast':[], 'summary':{}}
    for f in glob.glob("sarif-results/**/*.sarif", recursive=True):
        all_vulns['sast'].extend(parse_codeql_sarif(f))
    all_vulns['dependencies'].extend(parse_safety_results('safety-results.json'))
    all_vulns['dast'].extend(parse_zap_results())
    all_vulns['summary'] = {
        'total_vulnerabilities': len(all_vulns['sast'])+len(all_vulns['dependencies'])+len(all_vulns['dast']),
        'sast_count': len(all_vulns['sast']),
        'dependency_count': len(all_vulns['dependencies']),
        'dast_count': len(all_vulns['dast']),
        'severity_breakdown': get_severity_breakdown(all_vulns)
    }
    with open('merged-results.json','w') as f:
        json.dump(all_vulns,f,indent=2)
    return all_vulns['summary']['total_vulnerabilities']>0

if __name__=="__main__":
    main()
