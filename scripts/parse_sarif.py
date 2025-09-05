import json
import os
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
    except:
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
                'message': f"Vulnerable package: {vuln.get('package','')} {vuln.get('installed_version','')}",
                'package': vuln.get('package',''),
                'installed_version': vuln.get('installed_version',''),
                'vulnerable_spec': vuln.get('vulnerable_spec',''),
                'advisory': vuln.get('advisory',''),
                'locations':[{'file':'requirements.txt','line':0}]
            })
    except:
        pass
    return vulnerabilities

def parse_zap_results():
    vulnerabilities = []
    zap_files = glob.glob("**/zap_report.json", recursive=True)
    for zap_file in zap_files:
        try:
            with open(zap_file,'r') as f:
                zap_data = json.load(f)
            for site in zap_data.get('site',[]):
                for alert in site.get('alerts',[]):
                    vulnerabilities.append({
                        'type':'dast',
                        'tool':'OWASP ZAP',
                        'rule_id':f"zap-{alert.get('pluginid','unknown')}",
                        'severity': map_zap_severity(alert.get('riskdesc','')),
                        'message': alert.get('desc',''),
                        'url': alert.get('url',''),
                        'method': alert.get('method','GET'),
                        'evidence': alert.get('evidence',''),
                        'solution': alert.get('solution',''),
                        'locations':[{'url': alert.get('url',''),'parameter':alert.get('param',''),'evidence':alert.get('evidence','')}]
                    })
        except:
            pass
    return vulnerabilities

def parse_npm_audit(audit_file):
    vulnerabilities = []
    try:
        with open(audit_file,'r') as f:
            audit_data = json.load(f)
        for advisory in audit_data.get('advisories', {}).values():
            vulnerabilities.append({
                'type':'dependency',
                'tool':'npm-audit',
                'rule_id':f"npm-{advisory.get('id','unknown')}",
                'severity': advisory.get('severity','high'),
                'message': f"{advisory.get('module_name','')} {advisory.get('vulnerable_versions','')}",
                'package': advisory.get('module_name',''),
                'installed_version': advisory.get('findings',[{}])[0].get('version',''),
                'vulnerable_spec': advisory.get('vulnerable_versions',''),
                'advisory': advisory.get('overview',''),
                'locations':[{'file':'package.json','line':0}]
            })
    except:
        pass
    return vulnerabilities

def parse_eslint_results(eslint_file):
    vulnerabilities = []
    try:
        with open(eslint_file,'r') as f:
            eslint_data = json.load(f)
        for result in eslint_data:
            for message in result.get('messages',[]):
                vulnerabilities.append({
                    'type':'sast',
                    'tool':'ESLint',
                    'rule_id': message.get('ruleId','unknown'),
                    'severity':'high' if message.get('severity',1)==2 else 'medium',
                    'message': message.get('message',''),
                    'locations':[{'file':result.get('filePath',''),'line':message.get('line',0),'column':message.get('column',0)}]
                })
    except:
        pass
    return vulnerabilities

def get_severity(result):
    level = result.get('level','warning')
    severity_map = {'error':'high','warning':'medium','note':'low','info':'info'}
    return severity_map.get(level,'medium')

def map_zap_severity(risk_desc):
    if 'High' in risk_desc:
        return 'high'
    elif 'Medium' in risk_desc:
        return 'medium'
    elif 'Low' in risk_desc:
        return 'low'
    else:
        return 'info'

def get_severity_breakdown(vulns):
    severity_counts={'high':0,'medium':0,'low':0,'info':0}
    for t in ['sast','dependencies','dast']:
        for v in vulns[t]:
            sev=v.get('severity','medium')
            if sev in severity_counts:
                severity_counts[sev]+=1
    return severity_counts

def main():
    all_vulnerabilities={'sast':[],'dependencies':[],'dast':[],'summary':{}}
    sarif_files=glob.glob("sarif-results/**/*.sarif", recursive=True)
    for f in sarif_files:
        all_vulnerabilities['sast'].extend(parse_codeql_sarif(f))
    all_vulnerabilities['dependencies'].extend(parse_safety_results('safety-results.json'))
    all_vulnerabilities['dast'].extend(parse_zap_results())
    all_vulnerabilities['dependencies'].extend(parse_npm_audit('npm-audit.json'))
    all_vulnerabilities['sast'].extend(parse_eslint_results('eslint-results.json'))
    all_vulnerabilities['summary']={
        'total_vulnerabilities':len(all_vulnerabilities['sast'])+len(all_vulnerabilities['dependencies'])+len(all_vulnerabilities['dast']),
        'sast_count':len(all_vulnerabilities['sast']),
        'dependency_count':len(all_vulnerabilities['dependencies']),
        'dast_count':len(all_vulnerabilities['dast']),
        'severity_breakdown':get_severity_breakdown(all_vulnerabilities)
    }
    with open('merged-results.json','w') as f:
        json.dump(all_vulnerabilities,f,indent=2)
    return all_vulnerabilities['summary']['total_vulnerabilities']>0

if __name__=="__main__":
    vulnerabilities_found=main()
    exit(1 if vulnerabilities_found else 0)
