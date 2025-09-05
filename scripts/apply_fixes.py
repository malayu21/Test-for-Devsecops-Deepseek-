"""
apply_fixes.py - Apply AI-generated security fixes to code

This script takes the fixes.json from ai_remediation.py and actually modifies
your code files to implement the security fixes.
"""

import json
import os
import re
import argparse
import shutil
from pathlib import Path

class FixApplier:
    def __init__(self, dry_run=False):
        """
        Initialize the fix applier
        
        Args:
            dry_run: If True, show what would be changed without actually changing files
        """
        self.dry_run = dry_run
        self.applied_fixes = []
        self.failed_fixes = []
        
    def apply_sast_fix(self, fix):
        """
        Apply a fix for SAST (source code) vulnerability
        
        Args:
            fix: Dict containing fix details from AI
        """
        file_path = fix['file']
        line_number = fix['line']
        fixed_code = fix['fixed_code']
        
        print(f" Applying SAST fix to {file_path}:{line_number}")
        
        if not os.path.exists(file_path):
            print(f" File not found: {file_path}")
            self.failed_fixes.append(f"File not found: {file_path}")
            return False
        
        try:
            # Create backup
            if not self.dry_run:
                backup_path = f"{file_path}.backup"
                shutil.copy2(file_path, backup_path)
                print(f" Backup created: {backup_path}")
            
            # Read current file
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            if line_number > len(lines):
                print(f" Line number {line_number} exceeds file length ({len(lines)} lines)")
                self.failed_fixes.append(f"Invalid line number in {file_path}")
                return False
            
            # Show what's changing
            print(f" Original code (line {line_number}):")
            print(f"      {lines[line_number-1].rstrip()}")
            print(f" Fixed code:")
            print(f"      {fixed_code.strip()}")
            
            if not self.dry_run:
                # Apply the fix
                lines[line_number-1] = fixed_code + '\n'
                
                # Write back to file
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.writelines(lines)
                
                print(f" Fix applied successfully")
            else:
                print(f" DRY RUN: Would apply this fix")
            
            self.applied_fixes.append({
                'type': 'sast',
                'file': file_path,
                'line': line_number,
                'description': fix['explanation']
            })
            
            return True
            
        except Exception as e:
            print(f" Error applying fix: {e}")
            self.failed_fixes.append(f"Error in {file_path}: {e}")
            return False

    def apply_dependency_fix(self, fix):
        """
        Apply a fix for dependency vulnerability
        
        Args:
            fix: Dict containing dependency fix details
        """
        package = fix['package']
        current_version = fix['current_version']
        recommended_version = fix['recommended_version']
        
        print(f" Applying dependency fix: {package} {current_version} -> {recommended_version}")
        
        requirements_file = 'requirements.txt'
        
        if not os.path.exists(requirements_file):
            print(f" Requirements file not found: {requirements_file}")
            self.failed_fixes.append(f"Requirements file not found")
            return False
        
        try:
            # Create backup
            if not self.dry_run:
                backup_path = f"{requirements_file}.backup"
                shutil.copy2(requirements_file, backup_path)
                print(f"  Backup created: {backup_path}")
            
            # Read requirements
            with open(requirements_file, 'r') as f:
                lines = f.readlines()
            
            # Find and update the package line
            updated = False
            for i, line in enumerate(lines):
                line_stripped = line.strip()
                
                # Match package name (handle different formats like package==1.0, package>=1.0, etc.)
                if re.match(f'^{re.escape(package)}[>=<!=]+', line_stripped):
                    old_line = line_stripped
                    new_line = f"{package}>={recommended_version}"
                    
                    print(f" Original: {old_line}")
                    print(f" Updated:  {new_line}")
                    
                    if not self.dry_run:
                        lines[i] = new_line + '\n'
                    
                    updated = True
                    break
            
            if not updated:
                # Package not found, add it
                new_line = f"{package}>={recommended_version}"
                print(f" Adding new package: {new_line}")
                
                if not self.dry_run:
                    lines.append(new_line + '\n')
                
                updated = True
            
            if updated:
                if not self.dry_run:
                    # Write back to file
                    with open(requirements_file, 'w') as f:
                        f.writelines(lines)
                    
                    print(f" Dependency fix applied")
                else:
                    print(f" DRY RUN: Would update {requirements_file}")
                
                self.applied_fixes.append({
                    'type': 'dependency',
                    'package': package,
                    'old_version': current_version,
                    'new_version': recommended_version,
                    'description': fix['explanation']
                })
                
                return True
            else:
                print(f" Could not find package {package} in requirements.txt")
                self.failed_fixes.append(f"Package {package} not found in requirements")
                return False
                
        except Exception as e:
            print(f"  Error applying dependency fix: {e}")
            self.failed_fixes.append(f"Error updating {package}: {e}")
            return False

    def apply_dast_fix(self, fix):
        """
        Apply a fix for DAST (web application) vulnerability
        
        Args:
            fix: Dict containing DAST fix details
        """
        fix_type = fix.get('fix_type', 'code_change')
        changes = fix.get('changes', '')
        files_to_modify = fix.get('files_to_modify', [])
        
        print(f" Applying DAST fix: {fix_type}")
        print(f" Changes needed: {changes}")
        
        if fix_type == 'config_change':
            # For configuration changes, we'll create a recommendations file
            # since these often require manual review
            
            config_file = 'security-config-recommendations.md'
            
            recommendation = f"""
# Security Configuration Recommendation

## Issue
{fix['vulnerability']['message']}

## Affected URL
{fix.get('url', 'N/A')}

## Recommended Changes
{changes}

## Files to Review
{', '.join(files_to_modify) if files_to_modify else 'Configuration files'}

## Implementation Notes
- Review these changes carefully before applying
- Test in a staging environment first
- Some changes may require server restart

Generated: {fix.get('generated_at', 'Unknown time')}
"""

            if not self.dry_run:
                with open(config_file, 'a') as f:
                    f.write(recommendation)
                
                print(f" Configuration recommendations added to {config_file}")
            else:
                print(f" DRY RUN: Would create recommendations in {config_file}")
            
            self.applied_fixes.append({
                'type': 'dast_config',
                'description': 'Configuration recommendations created',
                'file': config_file
            })
            
            return True
            
        elif fix_type == 'code_change':
            # For code changes, we need specific file modifications
            # This is more complex and might need manual review
            
            if not files_to_modify:
                print(f" No specific files mentioned for code changes")
                # Create a general recommendations file
                
                code_fix_file = 'security-code-recommendations.md'
                
                recommendation = f"""
# Security Code Fix Recommendation

## Issue
{fix['vulnerability']['message']}

## Affected URL
{fix.get('url', 'N/A')}

## Code Changes Needed
```
{changes}
```

## Explanation
{fix.get('explanation', 'No detailed explanation provided')}

## AI Confidence
{fix.get('confidence', 'unknown')}

Generated: {fix.get('generated_at', 'Unknown time')}

---
"""

                if not self.dry_run:
                    with open(code_fix_file, 'a') as f:
                        f.write(recommendation)
                    
                    print(f" Code fix recommendations added to {code_fix_file}")
                else:
                    print(f" DRY RUN: Would create code recommendations in {code_fix_file}")
                
                self.applied_fixes.append({
                    'type': 'dast_code',
                    'description': 'Code fix recommendations created',
                    'file': code_fix_file
                })
                
                return True
        
        print(f" DAST fixes often require manual review - recommendations file created")
        return False

    def apply_fixes(self, fixes_file):
        """
        Apply all fixes from the fixes JSON file
        
        Args:
            fixes_file: Path to the fixes.json file
        """
        print(f"🔧 {'DRY RUN: ' if self.dry_run else ''}Applying security fixes from {fixes_file}")
        
        # Load fixes
        with open(fixes_file, 'r') as f:
            fixes_data = json.load(f)
        
        fixes = fixes_data.get('fixes', [])
        print(f" Found {len(fixes)} fixes to apply")
        
        success_count = 0
        
        # Apply each fix based on its type
        for i, fix in enumerate(fixes, 1):
            print(f"\n[{i}/{len(fixes)}] Processing {fix['type']} fix...")
            
            try:
                if fix['type'] == 'sast':
                    success = self.apply_sast_fix(fix)
                elif fix['type'] == 'dependency':
                    success = self.apply_dependency_fix(fix)
                elif fix['type'] == 'dast':
                    success = self.apply_dast_fix(fix)
                else:
                    print(f"  Unknown fix type: {fix['type']}")
                    continue
                
                if success:
                    success_count += 1
                    
            except Exception as e:
                print(f" Unexpected error applying fix: {e}")
                self.failed_fixes.append(f"Unexpected error: {e}")
        
        # Summary
        print(f"\n{'='*50}")
        print(f" {'DRY RUN ' if self.dry_run else ''}SUMMARY")
        print(f"{'='*50}")
        print(f" Successfully applied: {success_count}/{len(fixes)} fixes")
        print(f" Failed: {len(self.failed_fixes)} fixes")
        
        if self.applied_fixes:
            print(f"\n Applied fixes:")
            for fix in self.applied_fixes:
                print(f"   • {fix['type']}: {fix.get('description', 'No description')}")
        
        if self.failed_fixes:
            print(f"\n  Failed fixes:")
            for failure in self.failed_fixes:
                print(f"   • {failure}")
        
        if not self.dry_run:
            print(f"\n Tip: Check .backup files if you need to revert changes")
            print(f" Tip: Test your application to ensure fixes don't break functionality")
        
        return success_count, len(self.failed_fixes)

def main():
    """
    Command line interface for applying fixes
    """
    parser = argparse.ArgumentParser(description='Apply AI-generated security fixes')
    parser.add_argument('--fixes', required=True, help='Path to fixes JSON file')
    parser.add_argument('--dry-run', action='store_true', help='Show what would be changed without applying')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.fixes):
        print(f" Error: Fixes file not found: {args.fixes}")
        exit(1)
    
    try:
        # Initialize fix applier
        applier = FixApplier(dry_run=args.dry_run)
        
        # Apply all fixes
        successes, failures = applier.apply_fixes(args.fixes)
        
        if args.dry_run:
            print(f"\n DRY RUN complete. Use without --dry-run to apply changes.")
        else:
            if successes > 0:
                print(f"\n Applied {successes} security fixes!")
            if failures > 0:
                print(f" {failures} fixes need manual attention.")
        
    except Exception as e:
        print(f" Fatal error: {e}")
        exit(1)

if __name__ == "__main__":
    main()
