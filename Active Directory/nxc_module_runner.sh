#!/bin/bash

# Ensure compatibility with zsh
[ -n "$ZSH_VERSION" ] && emulate -L bash

# Color codes (compatible with both bash and zsh)
RED='\033[91m'
GREEN='\033[92m'
YELLOW='\033[93m'
BLUE='\033[96m'
MAGENTA='\033[95m'
BOLD='\033[1m'
NC='\033[0m' # Reset

# Available protocols
available_protocols=("smb" "ldap" "mssql" "wmi" "winrm" "ftp" "ssh" "vnc" "rdp" "nfs")

# Trap Ctrl+C to exit the script entirely
trap 'printf "${RED}[!] Ctrl+C detected. Exiting script.${NC}\n"; exit 1' INT

# Check if nxc is available in PATH
if command -v nxc &> /dev/null; then
 printf "${YELLOW}[INFO]  Run this script without sudo.${NC}\n"
  printf "${YELLOW}[INFO] NetExec (nxc) is installed.${NC}\n"
  # Check if pipx is installed
  if command -v pipx &> /dev/null; then
    # Check if NetExec is installed via pipx
    if pipx list | grep -q netexec; then
      read -rp "Do you want to update NetExec to the latest version via pipx? (yes/no): " update_nxc
      if [[ $update_nxc == "yes" ]]; then
        pipx upgrade netexec
        printf "${GREEN}[SUCCESS] NetExec updated successfully.${NC}\n"
      else
        printf "${YELLOW}[INFO] Skipping NetExec update.${NC}\n"
      fi
    else
      printf "${YELLOW}[INFO] NetExec is installed, but not via pipx.${NC}\n"
    fi
  else
    printf "${YELLOW}[INFO] pipx is not installed. Cannot check or update NetExec via pipx.${NC}\n"
  fi
else
  printf "${RED}[WARNING] NetExec (nxc) is not installed or not in PATH.${NC}\n"
fi

printf "${BLUE}╔═════════════════════════════════════════════╗\n"
printf "║     🛠️  ${BOLD}NetExec Multi-Module Runner${NC}${BLUE}        ║\n"
printf "╚═════════════════════════════════════════════╝${NC}\n"

read -rp $'\n🔸 Do you want to BRUTE-FORCE modules (run them automatically)? (yes/no): ' brute

printf "\n${YELLOW}[?] Choose authentication method:${NC}\n"
printf "  ${GREEN}1) Anonymous + Guest (both tried)\n"
printf "  2) Provide Username/Password${NC}\n"
read -rp "[+] Enter 1 or 2: " auth_option

auth_methods=()

if [[ $auth_option == "1" ]]; then
  auth_methods=("anonymous" "guest")
elif [[ $auth_option == "2" ]]; then
  read -rp "👤 Username: " username
  read -rsp "🔑 Password: " password
  printf "\n"
  auth_methods=("custom")
else
  printf "${RED}[!] Invalid option. Exiting.${NC}\n"
  exit 1
fi

printf "\n${YELLOW}[?] Select module privilege level:${NC}\n"
printf "  ${GREEN}1) Low privilege (safe for anonymous, guest, and basic users)\n"
printf "     → Use for enumeration, scans, read access.\n"
printf "  2) High privilege (requires Admin)\n"
printf "     → Use for dumping credentials, lateral movement, command execution.\n"
printf "  3) Both${NC}\n"
read -rp "[+] Enter 1, 2, or 3: " priv_level

read -rp $'\n🌐 Enter target IP address: ' target_ip

# Check host reachability
if ping -c 1 -W 2 "$target_ip" >/dev/null 2>&1; then
  printf "${GREEN}[✓] Host %s is reachable.${NC}\n" "$target_ip"
else
  printf "${RED}[✗] Host %s is not reachable. Exiting.${NC}\n" "$target_ip"
  exit 1
fi

printf "\n${YELLOW}[?] Protocol scope:${NC}\n"
printf "  ${GREEN}1) All protocols\n"
printf "  2) Choose a single protocol\n"
printf "  3) Choose multiple protocols${NC}\n"
read -rp "[+] Enter 1, 2, or 3: " proto_mode

if [[ $proto_mode == "1" ]]; then
  protocols=("${available_protocols[@]}")
elif [[ $proto_mode == "2" ]]; then
  printf "${BLUE}Available protocols: %s${NC}\n" "${available_protocols[*]}"
  read -rp "[+] Enter one: " single_proto
  if [[ ! " ${available_protocols[*]} " =~ " ${single_proto} " ]]; then
    printf "${RED}[!] Invalid protocol. Exiting.${NC}\n"
    exit 1
  fi
  protocols=("$single_proto")
elif [[ $proto_mode == "3" ]]; then
  printf "${BLUE}Available protocols: %s${NC}\n" "${available_protocols[*]}"
  read -rp "[+] Enter multiple protocols separated by spaces: " selected_protocols
  IFS=' ' read -r -a selected_array <<< "$selected_protocols"
  protocols=()
  for proto in "${selected_array[@]}"; do
    if [[ " ${available_protocols[*]} " =~ " ${proto} " ]]; then
      protocols+=("$proto")
    else
      printf "${RED}[!] Invalid protocol: %s. Skipping.${NC}\n" "$proto"
    fi
  done
  if [[ ${#protocols[@]} -eq 0 ]]; then
    printf "${RED}[!] No valid protocols selected. Exiting.${NC}\n"
    exit 1
  fi
  # Remove duplicates
  protocols=($(printf "%s\n" "${protocols[@]}" | sort -u))
else
  printf "${RED}[!] Invalid option. Exiting.${NC}\n"
  exit 1
fi

# Debug: Print protocols to be processed
printf "${BLUE}[DEBUG] Protocols to process: %s${NC}\n" "${protocols[*]}"

# Loop through protocols
for proto in "${protocols[@]}"; do
  printf "\n${MAGENTA}🔍 Processing protocol: ${BOLD}%s${NC}\n" "$proto"
  printf "${MAGENTA}──────────────────────────────────────────────${NC}\n"

  # Get module list in a subshell with timeout and error handling
  module_output=$(timeout --signal=INT 120s /bin/bash -c "set +e; nxc \"$proto\" --list-modules 2>&1")
  if [[ $? -ne 0 ]]; then
    printf "${RED}[!] Failed to list modules for protocol %s. Output:\n%s${NC}\n" "$proto" "$module_output"
    printf "${RED}Skipping protocol %s.${NC}\n" "$proto"
    continue
  fi

  # Parse modules
  low_modules=$(echo "$module_output" | awk '/LOW PRIVILEGE MODULES/,/HIGH PRIVILEGE MODULES/ {if ($0 ~ /^\[\*\]/ && !/LOW PRIVILEGE MODULES/) print $2}' | sort -u)
  high_modules=$(echo "$module_output" | awk '/HIGH PRIVILEGE MODULES/,/^$/ {if ($0 ~ /^\[\*\]/ && !/HIGH PRIVILEGE MODULES/) print $2}' | sort -u)

  printf "${GREEN}[+] Low Privilege Modules:${NC}\n"
  if [[ -z "$low_modules" ]]; then
    printf "  ${RED}None${NC}\n"
  else
    printf "%s\n" "$low_modules"
  fi

  printf "${GREEN}[+] High Privilege Modules:${NC}\n"
  if [[ -z "$high_modules" ]]; then
    printf "  ${RED}None${NC}\n"
  else
    printf "%s\n" "$high_modules"
  fi

  case $priv_level in
    1) modules="$low_modules" ;;
    2) modules="$high_modules" ;;
    3) modules="$low_modules"$'\n'"$high_modules" ;;
    *) printf "${RED}[!] Invalid module level. Exiting.${NC}\n"; exit 1 ;;
  esac

  # Skip if no modules are available
  if [[ -z "$modules" ]]; then
    printf "${YELLOW}[!] No modules available for %s. Skipping.${NC}\n" "$proto"
    continue
  fi

  if [[ "$brute" == "yes" ]]; then
    for mod in $modules; do
      for method in "${auth_methods[@]}"; do
        case $method in
          anonymous) username=""; password=""; label="Anonymous" ;;
          guest) username="guest"; password=""; label="Guest" ;;
          custom) label="$username" ;;
        esac

        printf "\n${YELLOW}[→] Using credentials: ${BOLD}%s${NC}\n" "$label"
        printf "${GREEN}[⚙️ ] Running module: %s${NC}\n" "$mod"

        # Adjust command based on protocol
        if [[ "$proto" =~ ^(smb|winrm|wmi|ldap|rdp|mssql)$ ]]; then
          cmd="nxc $proto $target_ip -u \"$username\" -p \"$password\" -M $mod"
        else
          if [[ -z "$username" && -z "$password" ]]; then
            cmd="nxc $proto $target_ip -M $mod"
          else
            cmd="nxc $proto $target_ip -u \"$username\" -p \"$password\" -M $mod"
          fi
        fi

        printf "${BLUE}[DEBUG] Executing command: %s${NC}\n" "$cmd"
        # Run command with timeout and error handling
        output=$(timeout --signal=INT 120s /bin/bash -c "set +e; $cmd 2>&1")
        exit_status=$?
        printf "%s\n" "$output"
        if [[ $exit_status -ne 0 ]]; then
          printf "${RED}[!] Error running module %s for protocol %s (exit status %s). Continuing.${NC}\n" "$mod" "$proto" "$exit_status"
        fi
      done
    done
  fi
  printf "${BLUE}[DEBUG] Completed protocol: %s${NC}\n" "$proto"
done

printf "\n${GREEN}[✔] All module scans completed.${NC}\n"
