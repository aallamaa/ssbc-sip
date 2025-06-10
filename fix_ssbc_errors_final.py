#!/usr/bin/env python3

import re
import sys

def fix_malformed_errors(content):
    # Pattern 1: Fix "context: None, message:" patterns
    pattern1 = r'context:\s*None,\s*message:'
    content = re.sub(pattern1, 'message:', content)
    
    # Pattern 2: Fix message fields that have been split
    # Look for patterns like 'message: format!("{,' or 'message: format!("text {'
    pattern2 = r'message:\s*format!\("([^"]*)\{,\s*\n\s*context:\s*None\s*\}\s*([^"]*)"'
    content = re.sub(pattern2, r'message: format!("\1{}\2"', content)
    
    # Pattern 3: Fix simple message strings that have been split
    pattern3 = r'message:\s*"([^"]*)\{,\s*\n\s*context:\s*None\s*\}\s*([^"]*)"'
    content = re.sub(pattern3, r'message: "\1{}\2"', content)
    
    # Pattern 4: Fix ParseError constructions with split format strings
    def fix_parse_error(match):
        indent = match.group(1)
        before_brace = match.group(2)
        after_brace = match.group(3)
        position = match.group(4)
        return f'''{indent}Err(SsbcError::ParseError {{
{indent}    message: format!("{before_brace}{{}}{after_brace}"),
{indent}    position: {position},
{indent}    context: None,
{indent}}})'''
    
    pattern4 = r'(\s*)Err\(SsbcError::ParseError\s*\{\s*\n\s*message:\s*format!\("([^{]*)\{,\s*\n\s*context:\s*None\s*\}\s*([^"]*)"[^)]*\),\s*\n\s*position:\s*([^,]+),\s*\n\s*context:\s*None,\s*\n\s*\}\)'
    content = re.sub(pattern4, fix_parse_error, content, flags=re.MULTILINE)
    
    # Pattern 5: Fix errors where message is on a separate line with context before it
    pattern5 = r'SsbcError::ParseError\s*\{\s*\n\s*context:\s*None,\s*message:'
    content = re.sub(pattern5, 'SsbcError::ParseError {\n                message:', content)
    
    # Pattern 6: Fix duplicate context fields
    lines = content.split('\n')
    fixed_lines = []
    i = 0
    while i < len(lines):
        line = lines[i]
        # Check if this is the start of a ParseError
        if 'SsbcError::ParseError {' in line:
            error_lines = [line]
            i += 1
            context_count = 0
            brace_count = 1
            
            while i < len(lines) and brace_count > 0:
                curr_line = lines[i]
                if '{' in curr_line:
                    brace_count += curr_line.count('{')
                if '}' in curr_line:
                    brace_count -= curr_line.count('}')
                
                # Skip duplicate context fields
                if 'context: None' in curr_line:
                    context_count += 1
                    if context_count > 1:
                        i += 1
                        continue
                
                error_lines.append(curr_line)
                i += 1
            
            fixed_lines.extend(error_lines)
        else:
            fixed_lines.append(line)
            i += 1
    
    return '\n'.join(fixed_lines)

def main():
    file_path = sys.argv[1] if len(sys.argv) > 1 else '/home/kader/Code/claude/ssbc/src/main_impl.rs'
    
    with open(file_path, 'r') as f:
        content = f.read()
    
    fixed_content = fix_malformed_errors(content)
    
    with open(file_path, 'w') as f:
        f.write(fixed_content)
    
    print(f"Fixed malformed errors in {file_path}")

if __name__ == "__main__":
    main()