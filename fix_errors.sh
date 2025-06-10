#!/bin/bash

# Script to fix SSBC compilation errors

echo "Fixing SSBC compilation errors..."

# Fix ParseError references in main_impl.rs
sed -i 's/Result<(), ParseError>/Result<(), SsbcError>/g' /home/kader/Code/claude/ssbc/src/main_impl.rs
sed -i 's/Err(ParseError::/Err(SsbcError::/g' /home/kader/Code/claude/ssbc/src/main_impl.rs
sed -i 's/:: ParseError::/:: SsbcError::/g' /home/kader/Code/claude/ssbc/src/main_impl.rs

# Fix parsing.rs macro references
sed -i 's/return Err(ParseError::/return Err(SsbcError::/g' /home/kader/Code/claude/ssbc/src/parsing.rs

# Fix MediaError references in b2bua.rs
sed -i 's/SsbcError::MediaError/SsbcError::StateError/g' /home/kader/Code/claude/ssbc/src/b2bua.rs

# Fix StateError field names in b2bua.rs
# Replace the old pattern with the new pattern
perl -i -pe 's/SsbcError::StateError\s*\{[^}]*call_id:[^,}]*,?[^}]*state:[^,}]*,?[^}]*\}/SsbcError::StateError { operation: "call_handling".to_string(), reason: "Invalid call state".to_string(), context: None }/g' /home/kader/Code/claude/ssbc/src/b2bua.rs

echo "Fixes applied. Running build test..."
cd /home/kader/Code/claude/ssbc && cargo check 2>&1 | head -20