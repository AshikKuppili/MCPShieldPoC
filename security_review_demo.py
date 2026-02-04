import os
import subprocess

# Security Review Demo
# This script performs a quick security audit as per instructions from related issue.

# 1. Setup
# Identify the tech stack by simple file presence checks

def identify_tech_stack():
    stacks = []
    if os.path.exists('package.json'):
        stacks.append('Node.js')
    if os.path.exists('requirements.txt') or os.path.exists('Pipfile'):
        stacks.append('Python')
    if os.path.exists('go.mod'):
        stacks.append('Go')
    return stacks

# 2. Dependency Audit - Calls relevant commands

def dependency_audit(stacks):
    results = {}
    for stack in stacks:
        if stack == 'Node.js':
            try:
                output = subprocess.check_output(['npm', 'audit', '--json'], text=True)
                results['Node.js'] = output
            except Exception as e:
                results['Node.js'] = f'Error running npm audit: {str(e)}'
        elif stack == 'Python':
            try:
                output = subprocess.check_output(['pip', 'list'], text=True)
                results['Python'] = output
            except Exception as e:
                results['Python'] = f'Error running pip list: {str(e)}'
        elif stack == 'Go':
            try:
                output = subprocess.check_output(['govulncheck', './...'], text=True)
                results['Go'] = output
            except Exception as e:
                results['Go'] = f'Error running govulncheck: {str(e)}'
    return results

# 3. Secret Scanning - Simple search for common keywords

def secret_scanning():
    keywords = ['AKIA', 'sk_live', 'Bearer', 'BEGIN RSA PRIVATE KEY', 'password', 'postgres://']
    hits = []
    for root, dirs, files in os.walk('.'):
        for file in files:
            if file.endswith(('.js', '.py', '.env', '.txt', '.json', '.yaml', '.yml')):
                try:
                    with open(os.path.join(root, file), 'r', errors='ignore') as f:
                        content = f.read()
                        for kw in keywords:
                            if kw in content:
                                hits.append(f'Possible secret "{kw}" found in file {file}')
                except Exception:
                    continue
    return hits

# 4. Dangerous Patterns
# Checking for dangerous patterns in JS and Python (eval, exec, subprocess call with shell=True, etc.)

def dangerous_patterns():
    patterns = {
        'JS': ['eval(', 'dangerouslySetInnerHTML', 'exec('],
        'Python': ['eval(', 'exec(', 'subprocess.call(', 'pickle.load(']
    }
    hits = []
    for root, dirs, files in os.walk('.'):
        for file in files:
            ext = file.split('.')[-1].lower()
            if ext in ['js', 'jsx', 'ts', 'tsx']:
                try:
                    with open(os.path.join(root, file), 'r', errors='ignore') as f:
                        content = f.read()
                        for p in patterns['JS']:
                            if p in content:
                                hits.append(f'Dangerous pattern "{p}" found in JS file {file}')
                except Exception:
                    continue
            elif ext == 'py':
                try:
                    with open(os.path.join(root, file), 'r', errors='ignore') as f:
                        content = f.read()
                        for p in patterns['Python']:
                            if p in content:
                                hits.append(f'Dangerous pattern "{p}" found in Python file {file}')
                except Exception:
                    continue
    return hits

# Main demo review function

def run_security_review_demo():
    print('Starting security review demo...')
    tech_stack = identify_tech_stack()
    print(f'Identified tech stack: {tech_stack}')

    dependency_results = dependency_audit(tech_stack)
    print('Dependency audit results:')
    for stack, result in dependency_results.items():
        print(f'--- {stack} ---')
        print(result)

    secret_hits = secret_scanning()
    print('Secret scanning hits:')
    for hit in secret_hits:
        print(hit)

    dangerous_hits = dangerous_patterns()
    print('Dangerous pattern hits:')
    for hit in dangerous_hits:
        print(hit)

    print('Security review demo completed.')

if __name__ == '__main__':
    run_security_review_demo()
