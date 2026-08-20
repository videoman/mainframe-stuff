#!/bin/sh
#
# z/OS USS File Permission Scanner
# Finds files readable and writable by the current user
#
# Usage: ./file_permissions.sh [directory] [options]
#   directory: Starting directory (default: current directory)
#   -v: Verbose output
#   -h: Show help
#

# Function to display help
show_help() {
    echo "z/OS USS File Permission Scanner"
    echo "Usage: $0 [directory] [options]"
    echo ""
    echo "Options:"
    echo "  -v    Verbose output (show progress and details)"
    echo "  -h    Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                    # Scan current directory"
    echo "  $0 /u/myuser         # Scan specific directory"
    echo "  $0 /tmp -v           # Scan /tmp with verbose output"
    echo ""
    echo "Output files:"
    echo "  writable_files.txt   # Files writable by current user"
    echo "  readable_files.txt   # Files readable by current user"
}

# Initialize variables
SEARCH_DIR="."
VERBOSE=0

# Parse command line arguments
while [ $# -gt 0 ]; do
    case "$1" in
        -h|--help)
            show_help
            exit 0
            ;;
        -v|--verbose)
            VERBOSE=1
            shift
            ;;
        -*)
            echo "Unknown option: $1"
            show_help
            exit 1
            ;;
        *)
            if [ -d "$1" ]; then
                SEARCH_DIR="$1"
            else
                echo "Error: Directory '$1' does not exist"
                exit 1
            fi
            shift
            ;;
    esac
done

# Get current user info
CURRENT_USER=$(whoami)
CURRENT_UID=$(id -u)
CURRENT_GROUPS=$(id -G)

# Output files
WRITABLE_FILE="writable_files.txt"
READABLE_FILE="readable_files.txt"

# Initialize output files
> "$WRITABLE_FILE"
> "$READABLE_FILE"

# Function for verbose output
verbose_echo() {
    if [ $VERBOSE -eq 1 ]; then
        echo "$1"
    fi
}

echo "z/OS USS File Permission Scanner"
echo "================================"
echo "Current user: $CURRENT_USER (UID: $CURRENT_UID)"
echo "Searching in: $SEARCH_DIR"
echo "Groups: $CURRENT_GROUPS"
echo ""

verbose_echo "Starting file scan..."

# Function to check if user can read a file
can_read() {
    local file="$1"
    local perms=$(ls -l "$file" 2>/dev/null | cut -c2-10)
    local owner_uid=$(ls -ln "$file" 2>/dev/null | awk '{print $3}')
    local group_gid=$(ls -ln "$file" 2>/dev/null | awk '{print $4}')
    
    # Check if file exists and we can get permissions
    if [ -z "$perms" ]; then
        return 1
    fi
    
    # Owner read permission
    if [ "$owner_uid" = "$CURRENT_UID" ] && [ "${perms#?}" != "${perms#?r}" ]; then
        return 0
    fi
    
    # Group read permission
    for gid in $CURRENT_GROUPS; do
        if [ "$group_gid" = "$gid" ] && [ "${perms#????}" != "${perms#????r}" ]; then
            return 0
        fi
    done
    
    # Other read permission
    if [ "${perms#???????}" != "${perms#???????r}" ]; then
        return 0
    fi
    
    return 1
}

# Function to check if user can write to a file
can_write() {
    local file="$1"
    local perms=$(ls -l "$file" 2>/dev/null | cut -c2-10)
    local owner_uid=$(ls -ln "$file" 2>/dev/null | awk '{print $3}')
    local group_gid=$(ls -ln "$file" 2>/dev/null | awk '{print $4}')
    
    # Check if file exists and we can get permissions
    if [ -z "$perms" ]; then
        return 1
    fi
    
    # Owner write permission
    if [ "$owner_uid" = "$CURRENT_UID" ] && [ "${perms#??}" != "${perms#??w}" ]; then
        return 0
    fi
    
    # Group write permission
    for gid in $CURRENT_GROUPS; do
        if [ "$group_gid" = "$gid" ] && [ "${perms#?????}" != "${perms#?????w}" ]; then
            return 0
        fi
    done
    
    # Other write permission
    if [ "${perms#????????}" != "${perms#????????w}" ]; then
        return 0
    fi
    
    return 1
}

# Counter variables
readable_count=0
writable_count=0
total_files=0

# Find and process all files
find "$SEARCH_DIR" -type f 2>/dev/null | while read -r file; do
    total_files=$((total_files + 1))
    
    verbose_echo "Checking: $file"
    
    # Check if readable
    if can_read "$file"; then
        echo "$file" >> "$READABLE_FILE"
        readable_count=$((readable_count + 1))
        verbose_echo "  -> Readable"
    fi
    
    # Check if writable
    if can_write "$file"; then
        echo "$file" >> "$WRITABLE_FILE"
        writable_count=$((writable_count + 1))
        verbose_echo "  -> Writable"
    fi
    
    # Progress indicator for large scans
    if [ $VERBOSE -eq 1 ] && [ $((total_files % 100)) -eq 0 ]; then
        echo "Processed $total_files files..."
    fi
done

# Get final counts
readable_count=$(wc -l < "$READABLE_FILE" 2>/dev/null || echo 0)
writable_count=$(wc -l < "$WRITABLE_FILE" 2>/dev/null || echo 0)

echo ""
echo "Scan complete!"
echo "=============="
echo "Readable files: $readable_count (saved to $READABLE_FILE)"
echo "Writable files: $writable_count (saved to $WRITABLE_FILE)"
echo ""

# Show sample of results if files were found
if [ "$readable_count" -gt 0 ]; then
    echo "Sample readable files:"
    head -5 "$READABLE_FILE" | sed 's/^/  /'
    if [ "$readable_count" -gt 5 ]; then
        echo "  ... and $((readable_count - 5)) more"
    fi
    echo ""
fi

if [ "$writable_count" -gt 0 ]; then
    echo "Sample writable files:"
    head -5 "$WRITABLE_FILE" | sed 's/^/  /'
    if [ "$writable_count" -gt 5 ]; then
        echo "  ... and $((writable_count - 5)) more"
    fi
    echo ""
fi

echo "Results saved to:"
echo "  Readable files: $READABLE_FILE"
echo "  Writable files: $WRITABLE_FILE"
