with open('.bandit', 'r') as f:
    lines = f.readlines()

with open('.bandit', 'w') as f:
    for line in lines:
        if line.startswith('exclude_dirs:') or line.startswith('skips:'):
            f.write(line)
        elif line.strip().startswith('-'):
            f.write(f"  - '{line.strip()[2:]}'\n")
        else:
            f.write(line)
