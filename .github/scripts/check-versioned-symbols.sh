#!/bin/bash
# Check for unversioned symbols in libraries

set -e

# Function to check if a library has versioned symbols
has_versioned_symbols() {
    local lib=$1
    # Check if the library has version definitions
    if readelf -V "$lib" 2>/dev/null | grep -q "Version definition section"; then
        return 0
    else
        return 1
    fi
}

# Function to get unversioned symbols from a library
get_unversioned_symbols() {
    local lib=$1
    objdump -T "$lib" | \
        grep -F .text | \
        awk '{if($6=="Base") {print $7;}}' | \
        c++filt | \
        awk '/[() ]/ {print "    \"" $0 "\";";}
            !/[() ]/ {print "    " $0 ";";}' | \
        sort
}

# Libraries to check
LIBRARIES=(
    "lib/.libs/libaudit.so"
    "auparse/.libs/libauparse.so"
    "auplugin/.libs/libauplugin.so"
)

echo "Checking for versioned symbols in built libraries..."

# Track if any library uses versioned symbols
has_versioned=0
# Track if we found any unversioned symbols
found_unversioned=0

for lib in "${LIBRARIES[@]}"; do
    if [ ! -f "$lib" ]; then
        echo "Warning: Library $lib not found, skipping..."
        continue
    fi

    if has_versioned_symbols "$lib"; then
        echo "- Library $lib has versioned symbols"
        has_versioned=1

        # Check for unversioned symbols
        unversioned=$(get_unversioned_symbols "$lib")
        if [ -n "$unversioned" ]; then
            echo "ERROR: Found unversioned symbols in $lib:"
            echo "$unversioned"
            found_unversioned=1
        else
            echo "  No unversioned symbols found"
        fi
    else
        echo "- Library $lib does not have versioned symbols (version script not applied)"
    fi
    echo
done

if [ $has_versioned -eq 0 ]; then
    echo "No libraries with versioned symbols were found."
    echo "This is expected if the linker does not support version scripts."
    exit 0
fi

if [ $found_unversioned -eq 1 ]; then
    echo "FAIL: Unversioned symbols were found in libraries with version scripts!"
    exit 1
fi

echo "SUCCESS: All libraries with versioned symbols have all symbols properly versioned."
exit 0
