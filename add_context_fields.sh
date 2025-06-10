#!/bin/bash

# Fix all SsbcError::ParseError instances that don't have context field

cd /home/kader/Code/claude/ssbc

# Find all ParseError instances and add context field if missing
for file in src/*.rs; do
    # Check if file has ParseError without context
    if grep -q "SsbcError::ParseError {" "$file" && grep -q "SsbcError::ParseError {" "$file" | grep -v "context:"; then
        echo "Fixing $file"
        
        # Use perl to fix multi-line ParseError structs
        perl -i -0pe 's/(SsbcError::ParseError\s*\{[^}]*?)(\s*\})/
            my $match = $1;
            my $end = $2;
            if ($match !~ m\/context:\/s) {
                # Add context field before closing brace
                $match =~ s\/(\s*)$\/,\n                context: None$1\/;
            }
            $match . $end
        /gse' "$file"
    fi
done

echo "Fixes applied"