import json
import os
import argparse
import openai
import time
from pathlib import Path

class AIRemediator:
    def __init__(self, api_key):
        """
        Initialize the AI remediation system
        
        Args:
            api_key: OpenAI API key
        """
        self.client = openai.OpenAI(api_key=api_key)
        self.fixes = []  # Store all generated fixes
        self.fix_summary = []  # Human-readable summary
        self.model_sast = "gpt-4o"  # Model for SAST
        self.model_dependency = "gpt-4o"  # Model for dependency fixes
        self.model_dast = "gpt-4o"  # Model for DAST
        
    def generate_sast_fix(self, vulnerability):
        """
        Generate fix for SAST (source code) vulnerabilities
        
        Args:
            vulnerability: Dict containing vuln details from CodeQL
            
        Returns:
            Dict with fix information
        """
        location = vulnerability['locations'][0] if vulnerability['locations'] else {}
        file_path = location.get('file', '')
        line_number = location.get('line', 0)
        
        vulnerable_code = self._read_code_context(file_path, line_number)
        
        prompt = f"""
You are a security expert tasked with fixing code vulnerabilities.

VULNERABILITY DETAILS:
- Rule: {vulnerability['rule_id']}
- Severity: {vulnerability['severity']}
- File: {file_path}
- Line: {line_number}
- Issue: {vulnerability['message']}

VULNERABLE CODE:
```python
{vulnerable_code}
```

Please provide:
1. A secure replacement for the vulnerable code
2. Explanation of why the original code was insecure
3. Explanation of how your fix addresses the issue

Respond in JSON format:
{{
    "fixed_code": "your secure code here",
    "explanation": "why this fixes the vulnerability",
    "confidence": "high/medium/low based on how certain you are"
}}

Focus on OWASP security principles and Python best practices.
"""
        try:
            response = self.client.chat.completions.create(
                model=self.model_sast,
                messages=[
                    {"role": "system", "content": "You are a cybersecurity expert specializing in secure code fixes."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.1,
                max_tokens=1000
            )
            
            ai_response = response.choices[0].message.content
            
            if "```json" in ai_response:
                json_start = ai_response.find("```json") + 7
                json_end = ai_response.find("```", json_start)
                ai_response = ai_response[json_start:json_end]
            
            fix_data = json.loads(ai_response)
            
            fix = {
                'type': 'sast',
                'file': file_path,
                'line': line_number,
                'vulnerability': vulnerability,
                'original_code': vulnerable_code,
                'fixed_code': fix_data.get('fixed_code', ''),
                'explanation': fix_data.get('explanation', ''),
                'confidence': fix_data.get('confidence', 'medium'),
                'ai_model': self.model_sast
            }
            
            return fix
            
        except (openai.OpenAIError, json.JSONDecodeError) as e:
            print(f"Error generating SAST fix for {file_path}:{line_number}: {e}")
            return None

    def generate_dependency_fix(self, vulnerability):
        """
        Generate fix for dependency vulnerabilities
        """
        package = vulnerability.get('package', '')
        current_version = vulnerability.get('installed_version', '')
        
        prompt = f"""
Security vulnerability in Python package dependency:

Package: {package}
Current Version: {current_version}
Issue: {vulnerability['message']}
Advisory: {vulnerability.get('advisory', '')}

Provide the safest way to fix this dependency issue:
1. Recommended version to upgrade to
2. Any breaking changes to watch for
3. Alternative packages if upgrade isn't possible

Respond in JSON:
{{
    "recommended_version": "version string",
    "breaking_changes": "list of potential issues",
    "alternative_solution": "if upgrade not recommended",
    "confidence": "high/medium/low"
}}
"""
        try:
            response = self.client.chat.completions.create(
                model=self.model_dependency,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.1,
                max_tokens=500
            )
            
            ai_response = response.choices[0].message.content
            
            if "```json" in ai_response:
                json_start = ai_response.find("```json") + 7
                json_end = ai_response.find("```", json_start)
                ai_response = ai_response[json_start:json_end]
            
            fix_data = json.loads(ai_response)
            
            fix = {
                'type': 'dependency',
                'file': 'requirements.txt',
                'package': package,
                'current_version': current_version,
                'recommended_version': fix_data.get('recommended_version', 'latest'),
                'explanation': f"Update {package} to fix security vulnerability",
                'breaking_changes': fix_data.get('breaking_changes', ''),
                'confidence': fix_data.get('confidence', 'high'),
                'ai_model': self.model_dependency
            }
            
            return fix
            
        except (openai.OpenAIError, json.JSONDecodeError) as e:
            print(f"Error generating dependency fix for {package}: {e}")
            return None

    def generate_dast_fix(self, vulnerability):
        """
        Generate fix for DAST (web application) vulnerabilities
        """
        url = vulnerability.get('url', '')
        evidence = vulnerability.get('evidence', '')
        solution = vulnerability.get('solution', '')
        
        prompt = f"""
Web application security vulnerability found during DAST scanning:

URL: {url}
Method: {vulnerability.get('method', 'GET')}
Issue: {vulnerability['message']}
Evidence: {evidence}
Suggested Solution: {solution}

Provide specific code changes or configuration changes to fix this web security issue:

Respond in JSON:
{{
    "fix_type": "code_change/config_change/both",
    "changes": "specific changes to make",
    "files_to_modify": ["list of files"],
    "explanation": "how this fixes the issue",
    "confidence": "high/medium/low"
}}
"""
        try:
            response = self.client.chat.completions.create(
                model=self.model_dast,
                messages=[
                    {"role": "system", "content": "You are a web security expert specializing in fixing OWASP Top 10 vulnerabilities."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.1,
                max_tokens=800
            )
            
            ai_response = response.choices[0].message.content
            
            if "```json" in ai_response:
                json_start = ai_response.find("```json") + 7
                json_end = ai_response.find("```", json_start)
                ai_response = ai_response[json_start:json_end]
            
            fix_data = json.loads(ai_response)
            
            fix = {
                'type': 'dast',
                'url': url,
                'vulnerability': vulnerability,
                'fix_type': fix_data.get('fix_type', 'code_change'),
                'changes': fix_data.get('changes', ''),
                'files_to_modify': fix_data.get('files_to_modify', []),
                'explanation': fix_data.get('explanation', ''),
                'confidence': fix_data.get('confidence', 'medium'),
                'ai_model': self.model_dast
            }
            
            return fix
            
        except (openai.OpenAIError, json.JSONDecodeError) as e:
            print(f"Error generating DAST fix for {url}: {e}")
            return None

    def _read_code_context(self, file_path, line_number, context_lines=5):
        """
        Read vulnerable code with surrounding context
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            start = max(0, line_number - context_lines - 1)
            end = min(len(lines), line_number + context_lines)
            
            context = ""
            for i in range(start, end):
                marker = ">>> " if i == line_number - 1 else "    "
                context += f"{marker}{i+1:4}: {lines[i]}"
            
            return context
            
        except FileNotFoundError:
            return f"# File not found: {file_path}"
        except Exception as e:
            return f"# Error reading file: {e}"

    def process_vulnerabilities(self, vulnerabilities_file):
        """
        Main function to process all vulnerabilities and generate fixes
        """
        print("Starting AI-powered vulnerability remediation...")
        
        try:
            with open(vulnerabilities_file, 'r') as f:
                vulns = json.load(f)
        except (json.JSONDecodeError, FileNotFoundError) as e:
            print(f"Error reading vulnerabilities file {vulnerabilities_file}: {e}")
            with open('fixes-summary.txt', 'w') as f:
                f.write(f"Error: Failed to read vulnerabilities file: {e}\n")
            return []
        
        total_vulns = vulns.get('summary', {}).get('total_vulnerabilities', 0)
        print(f"Processing {total_vulns} vulnerabilities...")
        
        if total_vulns == 0:
            print("No vulnerabilities to process. Skipping AI remediation.")
            with open('fixes-summary.txt', 'w') as f:
                f.write("No vulnerabilities found to fix.\n")
            return []
        
        processed = 0
        
        print(f"\nProcessing {len(vulns.get('sast', []))} SAST vulnerabilities...")
        for vuln in vulns.get('sast', []):
            print(f"  Fixing: {vuln['rule_id']} in {vuln['locations'][0].get('file', 'unknown')}...")
            fix = self.generate_sast_fix(vuln)
            if fix:
                self.fixes.append(fix)
                self.fix_summary.append(f"SAST: {vuln['rule_id']} in {fix['file']}")
            
            processed += 1
            time.sleep(1)
            
        print(f"\nProcessing {len(vulns.get('dependencies', []))} dependency vulnerabilities...")
        for vuln in vulns.get('dependencies', []):
            print(f"  Fixing: {vuln['package']} v{vuln['installed_version']}...")
            fix = self.generate_dependency_fix(vuln)
            if fix:
                self.fixes.append(fix)
                self.fix_summary.append(f"Dependency: {vuln['package']} -> {fix['recommended_version']}")
            
            processed += 1
            time.sleep(0.5)
            
        print(f"\nProcessing {len(vulns.get('dast', []))} DAST vulnerabilities...")
        for vuln in vulns.get('dast', []):
            print(f"  Fixing: {vuln['rule_id']} at {vuln.get('url', 'unknown URL')}...")
            fix = self.generate_dast_fix(vuln)
            if fix:
                self.fixes.append(fix)
                self.fix_summary.append(f"DAST: {vuln['rule_id']} - {fix['fix_type']}")
            
            processed += 1
            time.sleep(1)
            
        print(f"\nGenerated {len(self.fixes)} fixes out of {total_vulns} vulnerabilities")
        
        return self.fixes

    def save_fixes(self, output_file):
        """
        Save all generated fixes to JSON file for apply_fixes.py to use
        """
        fixes_data = {
            'metadata': {
                'generated_at': time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime()),
                'total_fixes': len(self.fixes),
                'ai_models_used': list(set(fix.get('ai_model', 'unknown') for fix in self.fixes))
            },
            'fixes': self.fixes,
            'summary': self.fix_summary
        }
        
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        with open(output_file, 'w') as f:
            json.dump(fixes_data, f, indent=2)
            
        with open('fixes-summary.txt', 'w') as f:
            f.write("AI-Generated Security Fixes Summary\n")
            f.write("=" * 50 + "\n\n")
            
            for i, summary in enumerate(self.fix_summary, 1):
                f.write(f"{i}. {summary}\n")
                
            f.write(f"\nTotal: {len(self.fixes)} fixes generated\n")
            f.write(f"Time: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}\n")
        
        print(f"Fixes saved to {output_file}")
        print(f"Summary saved to fixes-summary.txt")

def main():
    """
    Command line interface for the AI remediation tool
    """
    parser = argparse.ArgumentParser(description='AI-powered security vulnerability remediation')
    parser.add_argument('--input', required=True, help='Path to merged vulnerabilities JSON file')
    parser.add_argument('--output', required=True, help='Path to save generated fixes JSON')
    parser.add_argument('--api-key', help='OpenAI API key (or set OPENAI_API_KEY env var)')
    
    args = parser.parse_args()
    
    api_key = args.api_key or os.getenv('OPENAI_API_KEY')
    if not api_key:
        print("Error: OpenAI API key required. Set OPENAI_API_KEY environment variable or use --api-key")
        exit(1)
    
    if not os.path.exists(args.input):
        print(f"Error: Input file not found: {args.input}")
        exit(1)
    
    try:
        remediate = AIRemediator(api_key)
        fixes = remediate.process_vulnerabilities(args.input)
        
        if fixes or remediate.fixes:
            remediate.save_fixes(args.output)
            print(f"\nSuccessfully generated {len(fixes)} fixes!")
            print(f"Next step: Run 'python scripts/apply_fixes.py --fixes {args.output}' to apply them")
        else:
            print("No fixes generated due to no vulnerabilities found.")
            with open('fixes-summary.txt', 'w') as f:
                f.write("No vulnerabilities found to fix.\n")
            exit(0)
            
    except Exception as e:
        print(f"Fatal error: {e}")
        exit(1)

if __name__ == "__main__":
    main()
