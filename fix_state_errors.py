#!/usr/bin/env python3

import re
import sys

def fix_state_error(content):
    # Pattern to match StateError with wrong fields
    pattern = r'SsbcError::StateError\s*\{[^}]*(?:call_id|state):[^}]*\}'
    
    def replace_func(match):
        # Extract any operation or reason if they exist in the match
        match_text = match.group(0)
        
        # Try to extract meaningful values
        operation = "state_operation"
        reason = "state_error"
        
        if "operation:" in match_text:
            op_match = re.search(r'operation:\s*"([^"]*)"', match_text)
            if op_match:
                operation = op_match.group(1)
        
        if "reason:" in match_text:
            reason_match = re.search(r'reason:\s*"([^"]*)"', match_text)
            if reason_match:
                reason = reason_match.group(1)
        
        # Return the corrected format
        return f'SsbcError::StateError {{\n                operation: "{operation}".to_string(),\n                reason: "{reason}".to_string(),\n                context: None,\n            }}'
    
    # Apply the replacement
    return re.sub(pattern, replace_func, content, flags=re.DOTALL)

# Read the file
with open('/home/kader/Code/claude/ssbc/src/b2bua.rs', 'r') as f:
    content = f.read()

# Fix the errors
fixed_content = fix_state_error(content)

# Write back
with open('/home/kader/Code/claude/ssbc/src/b2bua.rs', 'w') as f:
    f.write(fixed_content)

print("Fixed StateError instances")