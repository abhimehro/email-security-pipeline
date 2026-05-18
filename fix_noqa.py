import os

def fix_noqa(filepath):
    with open(filepath, 'r') as f:
        lines = f.readlines()
        
    for i, line in enumerate(lines):
        if '# noqa: E402' in line:
            lines[i] = line.replace('', '')
            
    with open(filepath, 'w') as f:
        f.writelines(lines)

for root, _, files in os.walk('.'):
    for file in files:
        if file.endswith('.py'):
            fix_noqa(os.path.join(root, file))
