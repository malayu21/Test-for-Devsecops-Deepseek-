import json
import argparse
from openai import OpenAI
import os
import requests
from tenacity import retry, stop_after_attempt, wait_fixed
from tqdm import tqdm

# Configure OpenAI API
client = Openai.api_key = os.getenv("OPENAI_API_KEY")

def load_vulnerabilities(input_file):
    try:
        with open(input_file, 'r') as f:
            data = json.load(f)
        return data
    except Exception as e:
        print(f"Error loading {input_file}: {e}")
        raise

@retry(stop=stop_after_attempt(3), wait=wait_fixed(2))
def generate_fix(vulnerability):
    prompt = f"""
    Vulnerability: {vulnerability['message']}
    Severity: {vulnerability['severity']}
    Location: {vulnerability.get('location', 'N/A')}
    Rule ID: {vulnerability['rule_id']}
    
    Provide a fix for this vulnerability in a web application context (e.g., HTML, Python, or server configuration).
    """
    try:
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=500
        )
        return response.choices[0].message.content.strip()
    except Exception as e:
        print(f"Error generating fix for {vulnerability['message']}: {e}")
        return None

def generate_fixes(vulnerabilities, output_file):
    fixes = []
    for vuln in tqdm(vulnerabilities, desc="Generating fixes"):
        fix = generate_fix(vuln)
        if fix:
            fixes.append({
                "vulnerability": vuln,
                "fix": fix
            })
    
    summary = f"Generated fixes for {len(fixes)} of {len(vulnerabilities)} vulnerabilities"
    print(summary)
    
    with open(output_file, 'w') as f:
        json.dump({"fixes": fixes}, f, indent=4)
    
    with open('fixes-summary.txt', 'w') as f:
        f.write(summary)
    
    return fixes

def main():
    parser = argparse.ArgumentParser(description="Generate AI-based fixes for security vulnerabilities")
    parser.add_argument('--input', required=True, help="Input JSON file with vulnerabilities")
    parser.add_argument('--output', required=True, help="Output JSON file for fixes")
    args = parser.parse_args()
    
    vulnerabilities = load_vulnerabilities(args.input)
    all_vulns = []
    all_vulns.extend(vulnerabilities.get('sast', []))
    all_vulns.extend(vulnerabilities.get('dependencies', []))
    all_vulns.extend(vulnerabilities.get('dast', []))
    
    if not all_vulns:
        print("No vulnerabilities found to fix")
        with open(args.output, 'w') as f:
            json.dump({"fixes": []}, f, indent=4)
        with open('fixes-summary.txt', 'w') as f:
            f.write("No vulnerabilities found")
        return
    
    generate_fixes(all_vulns, args.output)

if __name__ == "__main__":
    main()
