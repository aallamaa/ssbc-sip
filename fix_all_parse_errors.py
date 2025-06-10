#!/usr/bin/env python3

import re
import os

def fix_parse_errors(file_path):
    with open(file_path, 'r') as f:
        content = f.read()
    
    # Pattern to match SsbcError::ParseError without context field
    pattern = r'(SsbcError::ParseError\s*\{[^}]*?)(\})'
    
    def check_and_fix(match):
        block = match.group(1)
        closing = match.group(2)
        
        # Check if context field exists
        if 'context:' not in block:
            # Add context field
            # Remove any trailing comma or whitespace
            block = block.rstrip().rstrip(',')
            # Add comma if needed
            if not block.endswith(','):
                block += ','
            # Add context field
            block += '\n                context: None,'
            # Remove trailing comma before closing brace
            block = block.rstrip(',') + '\n            '
        
        return block + closing
    
    # Apply fixes
    fixed_content = re.sub(pattern, check_and_fix, content, flags=re.DOTALL)
    
    # Write back
    with open(file_path, 'w') as f:
        f.write(fixed_content)
    
    return content != fixed_content

# Fix all rust files in src
src_dir = '/home/kader/Code/claude/ssbc/src'
for filename in os.listdir(src_dir):
    if filename.endswith('.rs'):
        file_path = os.path.join(src_dir, filename)
        if fix_parse_errors(file_path):
            print(f"Fixed {filename}")
        else:
            print(f"No changes needed in {filename}")

print("\nDone!")