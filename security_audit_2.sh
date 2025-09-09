#!/bin/sh

# z/OS Security Audit Script
# Finds SSH private keys and potential password files
# Usage: ./security_audit.sh [output_file]

OUTPUT_FILE=${1:-"security_audit_$(date +%Y%m%d_%H%M%S).log"}
TEMP_DIR="/tmp/audit_$$"
mkdir -p "$TEMP_DIR"

echo "=== z/OS Security Audit Started: $(date) ===" | tee "$OUTPUT_FILE"
echo "Audit running as user: $(id)" | tee -a "$OUTPUT_FILE"
echo "" | tee -a "$OUTPUT_FILE"

# Function to safely search files
safe_search() {
    local search_path="$1"
    local pattern="$2"
    local description="$3"
    
    echo "Searching for $description in $search_path..." | tee -a "$OUTPUT_FILE"
    
    # Use find with error redirection and file type checking
    find "$search_path" -type f -readable 2>/dev/null | while read -r file; do
        # Skip binary files and very large files (>10MB)
        if [ -f "$file" ] && [ -r "$file" ]; then
            file_size=$(wc -c < "$file" 2>/dev/null || echo "0")
            if [ "$file_size" -lt 10485760 ]; then  # 10MB limit
                if file "$file" 2>/dev/null | grep -q text; then
                    if grep -l "$pattern" "$file" 2>/dev/null; then
                        echo "  FOUND: $file" | tee -a "$OUTPUT_FILE"
                        # Show first few matching lines for context
                        echo "    Context:" | tee -a "$OUTPUT_FILE"
                        grep -n "$pattern" "$file" 2>/dev/null | head -3 | sed 's/^/    /' | tee -a "$OUTPUT_FILE"
                        echo "" | tee -a "$OUTPUT_FILE"
                    fi
                fi
            fi
        fi
    done
}

# 1. Search for SSH Private Keys
echo "=== SSH Private Key Search ===" | tee -a "$OUTPUT_FILE"

# Common locations for SSH keys on z/OS
SSH_LOCATIONS="/u /home /.ssh /etc/ssh /usr/lpp/ssh"

for location in $SSH_LOCATIONS; do
    if [ -d "$location" ]; then
        echo "Checking $location for SSH keys..." | tee -a "$OUTPUT_FILE"
        
        # Look for private key files by name
        find "$location" -type f \( -name "id_rsa" -o -name "id_dsa" -o -name "id_ecdsa" -o -name "id_ed25519" -o -name "*_rsa" -o -name "*.pem" -o -name "*.key" \) 2>/dev/null | while read -r keyfile; do
            if [ -r "$keyfile" ]; then
                echo "  SSH KEY FILE: $keyfile" | tee -a "$OUTPUT_FILE"
                echo "    Permissions: $(ls -l "$keyfile" 2>/dev/null)" | tee -a "$OUTPUT_FILE"
            fi
        done
        
        # Look for private key content patterns
        safe_search "$location" "BEGIN.*PRIVATE KEY" "SSH private key headers"
        safe_search "$location" "BEGIN RSA PRIVATE KEY" "RSA private keys"
        safe_search "$location" "BEGIN DSA PRIVATE KEY" "DSA private keys"
        safe_search "$location" "BEGIN EC PRIVATE KEY" "EC private keys"
        safe_search "$location" "BEGIN OPENSSH PRIVATE KEY" "OpenSSH private keys"
    fi
done

# 2. Search for Password Files and Configurations
echo "=== Password and Configuration File Search ===" | tee -a "$OUTPUT_FILE"

# z/OS specific locations
ZOS_LOCATIONS="/etc /usr/lpp /var /u /home"

for location in $ZOS_LOCATIONS; do
    if [ -d "$location" ]; then
        echo "Checking $location for password-related files..." | tee -a "$OUTPUT_FILE"
        
        # Look for common password/config files by name
        find "$location" -type f \( -name "*.conf" -o -name "*.cfg" -o -name "*.config" -o -name "passwd*" -o -name "shadow*" -o -name "*.properties" -o -name "*.ini" -o -name ".env" -o -name "*.yaml" -o -name "*.yml" -o -name "*.json" \) 2>/dev/null | head -100 | while read -r configfile; do
            if [ -r "$configfile" ]; then
                # Check for password patterns in config files
                if grep -i "password\|passwd\|pwd\|secret\|key\|token" "$configfile" 2>/dev/null | head -1 >/dev/null; then
                    echo "  CONFIG FILE: $configfile" | tee -a "$OUTPUT_FILE"
                    echo "    Contains password-related content:" | tee -a "$OUTPUT_FILE"
                    grep -i "password\|passwd\|pwd\|secret\|key\|token" "$configfile" 2>/dev/null | head -3 | sed 's/^/    /' | tee -a "$OUTPUT_FILE"
                    echo "" | tee -a "$OUTPUT_FILE"
                fi
            fi
        done
        
        # Search for password patterns in text files
        safe_search "$location" "[Pp]assword.*=" "password assignments"
        safe_search "$location" "[Pp]wd.*=" "pwd assignments"
        safe_search "$location" "[Ss]ecret.*=" "secret assignments"
        safe_search "$location" "[Tt]oken.*=" "token assignments"
        safe_search "$location" "API[_-][Kk]ey" "API keys"
    fi
done

# 4. z/OS Specific Security Files
echo "=== z/OS Specific Security Files ===" | tee -a "$OUTPUT_FILE"

# Check for RACF database (if accessible)
if [ -f "/etc/racf/racfdb" ]; then
    echo "  RACF Database found: /etc/racf/racfdb" | tee -a "$OUTPUT_FILE"
fi

# Check for security configuration files
SECURITY_FILES="/etc/security /etc/racf.conf /etc/ssh/sshd_config"
for secfile in $SECURITY_FILES; do
    if [ -f "$secfile" ] && [ -r "$secfile" ]; then
        echo "  SECURITY FILE: $secfile" | tee -a "$OUTPUT_FILE"
        echo "    Permissions: $(ls -l "$secfile" 2>/dev/null)" | tee -a "$OUTPUT_FILE"
    fi
done

# 4. Look for database connection strings and credentials
echo "=== Database and Application Credentials ===" | tee -a "$OUTPUT_FILE"

# Search for database connection patterns
safe_search "/u" "jdbc:" "JDBC connection strings"
safe_search "/u" "DATABASE.*=" "database configurations"
safe_search "/u" "DB2.*PASSWORD" "DB2 passwords"
safe_search "/u" "ORACLE.*PASSWORD" "Oracle passwords"

# 5. Check file permissions on sensitive areas
echo "=== File Permission Analysis ===" | tee -a "$OUTPUT_FILE"

# Check for world-readable sensitive files
echo "Checking for world-readable sensitive files..." | tee -a "$OUTPUT_FILE"
find /u /home -type f \( -name "*.key" -o -name "*.pem" -o -name "*password*" -o -name "*secret*" \) -perm -o+r 2>/dev/null | while read -r file; do
    echo "  WORLD-READABLE: $file $(ls -l "$file" 2>/dev/null | cut -d' ' -f1)" | tee -a "$OUTPUT_FILE"
done

# 6. Check SSH Known Hosts
echo "=== SSH Known Hosts Analysis ===" | tee -a "$OUTPUT_FILE"

# Look for known_hosts files
KNOWN_HOSTS_LOCATIONS="/u /home /.ssh /etc/ssh"
for location in $KNOWN_HOSTS_LOCATIONS; do
    if [ -d "$location" ]; then
        find "$location" -name "known_hosts*" -type f 2>/dev/null | while read -r khfile; do
            if [ -r "$khfile" ]; then
                echo "  KNOWN_HOSTS: $khfile" | tee -a "$OUTPUT_FILE"
                echo "    Permissions: $(ls -l "$khfile" 2>/dev/null)" | tee -a "$OUTPUT_FILE"
                echo "    Host count: $(wc -l < "$khfile" 2>/dev/null || echo "unknown")" | tee -a "$OUTPUT_FILE"
                
                # Show unique hostnames (first field after key type)
                if [ -s "$khfile" ]; then
                    echo "    Sample hosts:" | tee -a "$OUTPUT_FILE"
                    awk '{print $1}' "$khfile" 2>/dev/null | sed 's/,.*$//' | sort -u | head -10 | sed 's/^/      /' | tee -a "$OUTPUT_FILE"
                fi
                echo "" | tee -a "$OUTPUT_FILE"
            fi
        done
    fi
done

# 7. Shell History Analysis
echo "=== Shell History Analysis ===" | tee -a "$OUTPUT_FILE"

# Common shell history files
HISTORY_FILES=".sh_history .bash_history .ksh_history .history"
HISTORY_LOCATIONS="/u /home"

for location in $HISTORY_LOCATIONS; do
    if [ -d "$location" ]; then
        # Find all user home directories
        find "$location" -type d -maxdepth 2 2>/dev/null | while read -r homedir; do
            for histfile in $HISTORY_FILES; do
                full_path="$homedir/$histfile"
                if [ -f "$full_path" ] && [ -r "$full_path" ]; then
                    echo "  HISTORY FILE: $full_path" | tee -a "$OUTPUT_FILE"
                    echo "    Permissions: $(ls -l "$full_path" 2>/dev/null)" | tee -a "$OUTPUT_FILE"
                    echo "    Lines: $(wc -l < "$full_path" 2>/dev/null || echo "unknown")" | tee -a "$OUTPUT_FILE"
                    
                    # Check for sensitive commands in history
                    echo "    Sensitive commands found:" | tee -a "$OUTPUT_FILE"
                    
                    # Password-related commands
                    if grep -i "password\|passwd\|pwd.*=" "$full_path" 2>/dev/null | head -5 > "$TEMP_DIR/pwd_cmds"; then
                        if [ -s "$TEMP_DIR/pwd_cmds" ]; then
                            echo "      Password commands:" | tee -a "$OUTPUT_FILE"
                            sed 's/^/        /' "$TEMP_DIR/pwd_cmds" | tee -a "$OUTPUT_FILE"
                        fi
                    fi
                    
                    # SSH/SCP commands with potential keys or passwords
                    if grep -E "ssh.*-i|scp.*-i|ssh-keygen|ssh-add" "$full_path" 2>/dev/null | head -5 > "$TEMP_DIR/ssh_cmds"; then
                        if [ -s "$TEMP_DIR/ssh_cmds" ]; then
                            echo "      SSH key commands:" | tee -a "$OUTPUT_FILE"
                            sed 's/^/        /' "$TEMP_DIR/ssh_cmds" | tee -a "$OUTPUT_FILE"
                        fi
                    fi
                    
                    # FTP/SFTP with embedded credentials
                    if grep -E "ftp.*@|sftp.*@|curl.*:.*@|wget.*:.*@" "$full_path" 2>/dev/null | head -5 > "$TEMP_DIR/ftp_cmds"; then
                        if [ -s "$TEMP_DIR/ftp_cmds" ]; then
                            echo "      FTP/URL with credentials:" | tee -a "$OUTPUT_FILE"
                            sed 's/^/        /' "$TEMP_DIR/ftp_cmds" | tee -a "$OUTPUT_FILE"
                        fi
                    fi
                    
                    # Database connections
                    if grep -i "sqlplus\|db2\|mysql.*-p\|psql.*password" "$full_path" 2>/dev/null | head -5 > "$TEMP_DIR/db_cmds"; then
                        if [ -s "$TEMP_DIR/db_cmds" ]; then
                            echo "      Database commands:" | tee -a "$OUTPUT_FILE"
                            sed 's/^/        /' "$TEMP_DIR/db_cmds" | tee -a "$OUTPUT_FILE"
                        fi
                    fi
                    
                    # sudo/su commands that might reveal privilege escalation patterns
                    if grep -E "sudo.*password|su.*-|sudo -u" "$full_path" 2>/dev/null | head -5 > "$TEMP_DIR/sudo_cmds"; then
                        if [ -s "$TEMP_DIR/sudo_cmds" ]; then
                            echo "      Privilege escalation:" | tee -a "$OUTPUT_FILE"
                            sed 's/^/        /' "$TEMP_DIR/sudo_cmds" | tee -a "$OUTPUT_FILE"
                        fi
                    fi
                    
                    # Environment variable exports with sensitive data
                    if grep -E "export.*[Pp]assword|export.*[Kk]ey|export.*[Tt]oken|export.*[Ss]ecret" "$full_path" 2>/dev/null | head -5 > "$TEMP_DIR/env_cmds"; then
                        if [ -s "$TEMP_DIR/env_cmds" ]; then
                            echo "      Environment variables:" | tee -a "$OUTPUT_FILE"
                            sed 's/^/        /' "$TEMP_DIR/env_cmds" | tee -a "$OUTPUT_FILE"
                        fi
                    fi
                    
                    # File operations on sensitive files
                    if grep -E "cp.*\.key|mv.*\.key|cp.*\.pem|mv.*\.pem|chmod.*\.key|chmod.*\.pem" "$full_path" 2>/dev/null | head -5 > "$TEMP_DIR/file_cmds"; then
                        if [ -s "$TEMP_DIR/file_cmds" ]; then
                            echo "      Key file operations:" | tee -a "$OUTPUT_FILE"
                            sed 's/^/        /' "$TEMP_DIR/file_cmds" | tee -a "$OUTPUT_FILE"
                        fi
                    fi
                    
                    echo "" | tee -a "$OUTPUT_FILE"
                fi
            done
        done
    fi
done

# 8. SSH Configuration Files
echo "=== SSH Configuration Analysis ===" | tee -a "$OUTPUT_FILE"

# Check SSH client configurations
SSH_CONFIG_LOCATIONS="/u /home /.ssh /etc/ssh"
for location in $SSH_CONFIG_LOCATIONS; do
    if [ -d "$location" ]; then
        find "$location" -name "config" -o -name "ssh_config" 2>/dev/null | while read -r configfile; do
            if [ -f "$configfile" ] && [ -r "$configfile" ]; then
                echo "  SSH CONFIG: $configfile" | tee -a "$OUTPUT_FILE"
                echo "    Permissions: $(ls -l "$configfile" 2>/dev/null)" | tee -a "$OUTPUT_FILE"
                
                # Look for identity files and host configurations
                if grep -E "IdentityFile|Host |HostName|User " "$configfile" 2>/dev/null > "$TEMP_DIR/ssh_config"; then
                    if [ -s "$TEMP_DIR/ssh_config" ]; then
                        echo "    Configuration entries:" | tee -a "$OUTPUT_FILE"
                        head -10 "$TEMP_DIR/ssh_config" | sed 's/^/      /' | tee -a "$OUTPUT_FILE"
                    fi
                fi
                echo "" | tee -a "$OUTPUT_FILE"
            fi
        done
    fi
done

# 9. Recently Modified Sensitive Files
echo "=== Recently Modified Sensitive Files ===" | tee -a "$OUTPUT_FILE"

echo "Files modified in last 30 days:" | tee -a "$OUTPUT_FILE"
find /u /home -type f \( -name "*.key" -o -name "*.pem" -o -name "*password*" -o -name "*secret*" -o -name "known_hosts*" -o -name ".ssh_history" -o -name ".bash_history" \) -mtime -30 2>/dev/null | while read -r recentfile; do
    if [ -f "$recentfile" ]; then
        echo "  RECENT: $recentfile $(ls -l "$recentfile" 2>/dev/null | awk '{print $5, $6, $7, $8}')" | tee -a "$OUTPUT_FILE"
    fi
done

# 12. Summary
echo "" | tee -a "$OUTPUT_FILE"
echo "=== Audit Summary ===" | tee -a "$OUTPUT_FILE"
echo "Audit completed: $(date)" | tee -a "$OUTPUT_FILE"
echo "Results saved to: $OUTPUT_FILE" | tee -a "$OUTPUT_FILE"
echo "Review all findings carefully and secure any exposed credentials." | tee -a "$OUTPUT_FILE"

# Cleanup
rm -rf "$TEMP_DIR"

echo ""
echo "Audit complete. Check $OUTPUT_FILE for full results."
