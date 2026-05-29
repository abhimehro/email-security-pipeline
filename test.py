with open('.github/workflows/bandit.yml', 'r') as f:
    lines = f.readlines()
for line in lines:
    if 'uses: actions/upload-artifact@' in line or 'uses: github/codeql-action/upload-sarif@' in line:
        print(line)
