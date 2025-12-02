# Quick script to fix indentation in main.py
import re

file_path = r'c:\Users\mahi\Desktop\FW_CSV_Export_new\FW_CSV_Export_new\backend_fastapi\backend_fastapi\app\main.py'

with open(file_path, 'r', encoding='utf-8') as f:
    lines = f.readlines()

# Find the range that needs indentation
# From line 2181 (data_summary +=) to line 2593 (before prompt = f""")
# These lines need to be indented by 4 more spaces

output_lines = []
for i, line in enumerate(lines):
    line_num = i + 1
    
    # Lines 2181-2593 need 4 more spaces of indentation
    if 2181 <= line_num <= 2593:
        # Only add indentation if the line is not empty
        if line.strip():
            output_lines.append('    ' + line)
        else:
            output_lines.append(line)
    else:
        output_lines.append(line)

# Write back
with open(file_path, 'w', encoding='utf-8') as f:
    f.writelines(output_lines)

print(f"Fixed indentation for lines 2181-2593")
