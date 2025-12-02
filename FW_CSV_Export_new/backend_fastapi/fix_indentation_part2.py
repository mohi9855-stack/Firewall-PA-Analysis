# Quick script to fix indentation in main.py (part 2)
import re

file_path = r'c:\Users\mahi\Desktop\FW_CSV_Export_new\FW_CSV_Export_new\backend_fastapi\backend_fastapi\app\main.py'

with open(file_path, 'r', encoding='utf-8') as f:
    lines = f.readlines()

# Find the range that needs indentation
# From line 2594 (prompt = f""") to line 2823 (before # Call LLM API)
# These lines need to be indented by 4 more spaces

output_lines = []
for i, line in enumerate(lines):
    line_num = i + 1
    
    # Lines 2594-2823 need 4 more spaces of indentation
    if 2594 <= line_num <= 2823:
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

print(f"Fixed indentation for lines 2594-2823")
