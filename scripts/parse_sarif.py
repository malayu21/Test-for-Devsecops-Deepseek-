import json
import os
import glob
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def parse_codeql_results():
    results = []
    sarif_files = glob.glob("sarif-results/*.sarif")
    for sarif_file in sarif_files:
        try:
            with open(sarif_file, 'r') as f:
                sarif_data = json.load(f)
            for run in sarif_data.get('runs', []):
                for result in run.get('results', []):
                    vuln = {
                        'rule_id': result.get('ruleId'),
                        'message': result.get('message', {}).get('text'),
                        'location': result.get('locations', [{}])[0].get('physicalLocation', {}).get('artifactLocation', {}).get('uri'),
                        'severity': result.get('level', 'warning')
                    }
                    results.append(vuln)
        except Exception as e:
            logger.error(f"Error parsing CodeQL SARIF file {sarif_file}: {str(e)}")
    return results

def parse_safety_results():
    results = []
    safety_file = 'safety-results.json'
    if not os.path.exists(safety_file):
        logger.warning(f"No Safety report file found: {safety_file}, returning empty results")
        return results
    try:
        with open(safety_file, 'r') as f:
            safety_data = json.load(f)
        for issue in safety_data.get('vulnerabilities', []):
            vuln = {
                'rule_id': f"safety-{issue.get('id')}",
                'message': issue.get('description'),
                'package': issue.get('package'),
                'severity': issue.get('severity', 'warning')
            }
            results.append(vuln)
    except Exception as e:
        logger.error(f"Error parsing Safety results: {str(e)}")
    return results

def parse_zap_results():
    results = []
    zap_files = ['report_json.json']
    for zap_file in zap_files:
        if not os.path.exists(zap_file):
            logger.warning(f"No ZAP report file found: {zap_file}")
            continue
        try:
            with open(zap_file, 'r') as f:
                zap_data = json.load(f)
            for site in zap_data.get('site', []):
                for alert in site.get('alerts', []):
                    vuln = {
                        'rule_id': f"zap-{alert.get('alertid')}",
                        'message': alert.get('alert'),
                        'location': alert.get('uri'),
                        'severity': alert.get('riskdesc', 'warning').split(' ')[0].lower()
                    }
                    results.append(vuln)
        except Exception as e:
            logger.error(f"Error parsing ZAP report {zap_file}: {str(e)}")
    return results

def main():
    all_vulns = {
        'sast': parse_codeql_results(),
        'dependencies': parse_safety_results(),
        'dast': parse_zap_results(),
        'summary': {'total_vulnerabilities': 0}
    }
    all_vulns['summary']['total_vulnerabilities'] = (
        len(all_vulns['sast']) + len(all_vulns['dependencies']) + len(all_vulns['dast'])
    )
    os.makedirs('security-results', exist_ok=True)
    output_file = 'security-results/merged-results.json'
    with open(output_file, 'w') as f:
        json.dump(all_vulns, f, indent=2)
    logger.info(f"Merged security results into {output_file}")

if __name__ == "__main__":
    main()
