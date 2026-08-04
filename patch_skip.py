import re
with open('d:/webpentest/modules/autopwn.py', 'r', encoding='utf-8') as f:
    lines = f.readlines()

new_lines = []
in_for = False
for i, line in enumerate(lines):
    if line.strip() == 'for vc in run_order:':
        new_lines.append('        if not ctf_confirmed:\n')
        new_lines.append('            ' + line.strip() + '\n')
        in_for = True
    elif in_for and line.startswith('        # Always run these regardless of prediction'):
        in_for = False
        new_lines.append(line)
    elif in_for:
        if line.startswith('        ') and not line.strip() == '':
            new_lines.append('    ' + line)
        elif line.strip() == '':
            new_lines.append(line)
        else:
            new_lines.append(line)
    else:
        new_lines.append(line)

with open('d:/webpentest/modules/autopwn.py', 'w', encoding='utf-8') as f:
    f.writelines(new_lines)
