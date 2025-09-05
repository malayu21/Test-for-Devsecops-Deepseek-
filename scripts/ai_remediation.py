"""
ai_remediation.py - AI-powered security vulnerability fixing

This script takes security vulnerabilities and uses AI (OpenAI GPT) to generate fixes.
It's the "brain" of our automated security remediation system.
"""

import json
import os
import argparse
from openai import OpenAI
import time
from pathlib import Path

class AIRemediator:
    def __init__(self, api_key):
        """
        Initialize the AI remediation system
        
        Args:
            api_key: OpenAI API key for accessing GPT models
        """
        self.client = OpenAI(api_key=api_key)
        self.fixes = []  # Store all generated fixes
        self.fix_summary = []  # Human-readable summary
        
    def generate_sast_fix(self, vulnerability):
        """
        Generate fix for SAST (source code) vulnerabilities
        
        Args:
            vulnerability: Dict containing vuln details from CodeQL
            
        Returns:
            Dict with fix information
        """
        # Get the vulnerable code location
        location = vulnerability['locations'][0] if vulnerability['locations'] else {}
        file_path = location.get('file', '')
        line_number = location.get('line', 0)
        
        # Read the actual vulnerable code
        vulnerable_code = self._read_code_context(file_path, line_number)
        
        # Create a detailed prompt for the AI
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
                model="gpt-4",  # Use GPT-4 for better security knowledge
                messages=[
                    {"role": "system", "content": "You are a cybersecurity expert specializing in secure code fixes."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.1,  # Low temperature for consistent, conservative fixes
                max_tokens=1000
            )
            
            # Parse AI response
            ai_response = response.choices[0].message.content
            
            # Try to extract JSON from response
            try:
                # Sometimes AI wraps JSON in markdown, so clean it
                if "```json" in ai_response:
                    json_start = ai_response.find("```json") + 7
                    json_end = ai_response.find("```", json_start)
                    ai_response = ai_response[json_start:json_end]
                
                fix_data = json.loads(ai_response)
                
                # Structure the fix for our apply_fixes.py script
                fix = {
                    'type': 'sast',
                    'file': file_path,
                    'line': line_number,
                    'vulnerability': vulnerability,
                    'original_code': vulnerable_code,
                    'fixed_code': fix_data.get('fixed_code', ''),
                    'explanation': fix_data.get('explanation', ''),
                    'confidence': fix_data.get('confidence', 'medium'),
                    'ai_model': 'gpt-4'
                }
                
                return fix
                
            except json.JSONDecodeError:
                print(f"⚠️  AI returned invalid JSON for {file_path}:{line_number}")
                return None
                
        except Exception as e:
            print(f"❌ Error generating fix for {file_path}:{line_number}: {e}")
            return None

    def generate_dependency_fix(self, vulnerability):
        """
        Generate fix for dependency vulnerabilities
        
        These are usually simple - just update the package version
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
                model="gpt-3.5-turbo",  # Cheaper model for simpler dependency fixes
                messages=[{"role": "user", "content": prompt}],
                temperature=0.1,
                max_tokens=500
            )
            
            ai_response = response.choices[0].message.content
            
            # Clean and parse JSON
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
                'ai_model': 'gpt-3.5-turbo'
            }
            
            return fix
            
        except Exception as e:
            print(f"❌ Error generating dependency fix for {package}: {e}")
            return None

    def generate_dast_fix(self, vulnerability):
        """
        Generate fix for DAST (web application) vulnerabilities
        
        These are usually configuration or code changes for web security
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
                model="gpt-4",
                messages=[
                    {"role": "system", "content": "You are a web security expert specializing in fixing OWASP Top 10 vulnerabilities."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.1,
                max_tokens=800
            )
            
            ai_response = response.choices[0].message.content
            
            # Clean and parse JSON
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
                'ai_model': 'gpt-4'
            }
            
            return fix
            
        except Exception as e:
            print(f"❌ Error generating DAST fix for {url}: {e}")
            return None

    def _read_code_context(self, file_path, line_number, context_lines=5):
        """
        Read vulnerable code with surrounding context
        
        Args:
            file_path: Path to the vulnerable file
            line_number: Line number with the issue
            context_lines: How many lines before/after to include
            
        Returns:
            String with code context
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            # Calculate range (1-indexed to 0-indexed)
            start = max(0, line_number - context_lines - 1)
            end = min(len(lines), line_number + context_lines)
            
            # Add line numbers for clarity
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
        
        Args:
            vulnerabilities_file: Path to merged-results.json
        """
        print("Starting AI-powered vulnerability remediation...")
        
        # Load vulnerabilities
        with open(vulnerabilities_file, 'r') as f:
            vulns = json.load(f)
