#!/bin/bash

# Check for required tools (all should be standard on most Linux systems)
# No additional installation needed - uses standard Linux utilities

# Extra users list
extrausers=("user1" "user2" "user3")

addUsers() {
    local option="${1:-1}"
    
    if [[ "$option" == "1" ]]; then
        # Create extra users from hardcoded list
        for user in "${extrausers[@]}"; do
            sudo useradd -m -s /bin/bash "$user" 2>/dev/null
        done
    else
        # Create users from CSV file
        if [[ ! -f "users.csv" ]]; then
            echo "Error: users.csv not found"
            return 1
        fi
        
        while IFS=',' read -r username rest; do
            # Skip empty lines
            [[ -z "$username" ]] && continue
            
            # Trim whitespace
            username=$(echo "$username" | xargs)
            
            # Only create if username is longer than 3 characters
            if [[ ${#username} -gt 3 ]]; then
                sudo useradd -m -s /bin/bash "$username" 2>/dev/null
            fi
        done < users.csv
    fi
}

readCurrentUser() {
    # Shells that indicate no login access
    local nologin_shells=(
        "/sbin/nologin"
        "/usr/sbin/nologin"
        "/bin/false"
        "/usr/bin/false"
        "/bin/nologin"
    )
    
    # Clear or create the output file
    > login_users.txt
    
    # Read /etc/passwd and filter for login users
    while IFS=':' read -r username password uid gid gecos home shell; do
        # Skip comments and empty lines
        [[ "$username" =~ ^#.*$ ]] && continue
        [[ -z "$username" ]] && continue
        
        # Check if UID is 0 (root) or >= 1000 (regular users)
        if [[ "$uid" -eq 0 ]] || [[ "$uid" -ge 1000 ]]; then
            # Check if shell is NOT in nologin list
            local is_nologin=false
            for nologin in "${nologin_shells[@]}"; do
                if [[ "$shell" == "$nologin" ]]; then
                    is_nologin=true
                    break
                fi
            done
            
            if [[ "$is_nologin" == false ]]; then
                echo "$username" >> login_users.txt
            fi
        fi
    done < /etc/passwd
}

plan_and_delete() {
    local csv_file="${1:-users.csv}"
    local have_file="${2:-login_users.txt}"
    local del_file="${3:-users_to_delete.txt}"
    
    # Check required files exist
    if [[ ! -f "$csv_file" ]]; then
        echo "Error: $csv_file not found"
        return 1
    fi
    
    if [[ ! -f "$have_file" ]]; then
        echo "Error: $have_file not found"
        return 1
    fi
    
    # Get desired users from CSV (first column only)
    declare -A want_users
    while IFS=',' read -r username rest; do
        username=$(echo "$username" | xargs)
        [[ -n "$username" ]] && want_users["$username"]=1
    done < "$csv_file"
    
    # Get current users from file
    declare -a have_users
    while IFS= read -r username; do
        username=$(echo "$username" | xargs)
        [[ -n "$username" ]] && have_users+=("$username")
    done < "$have_file"
    
    # Protected users (never delete)
    declare -A protect
    protect["root"]=1
    
    # Add the calling user to protected list
    if [[ -n "$SUDO_USER" ]]; then
        protect["$SUDO_USER"]=1
    elif [[ -n "$USER" ]]; then
        protect["$USER"]=1
    fi
    
    # Find candidates for deletion
    declare -a candidates
    for user in "${have_users[@]}"; do
        if [[ -z "${want_users[$user]}" ]] && [[ -z "${protect[$user]}" ]]; then
            candidates+=("$user")
        fi
    done
    
    # Confirm deletions with user
    declare -a confirmed
    for user in "${candidates[@]}"; do
        read -p "Delete user '$user'? [y/N]: " answer
        answer=$(echo "$answer" | tr '[:upper:]' '[:lower:]')
        if [[ "$answer" == "y" ]] || [[ "$answer" == "yes" ]]; then
            confirmed+=("$user")
        fi
    done
    
    # Write confirmed deletions to file
    > "$del_file"
    for user in "${confirmed[@]}"; do
        echo "$user" >> "$del_file"
    done
    
    # Display summary
    echo "Users confirmed for deletion (${#confirmed[@]}):"
    for user in "${confirmed[@]}"; do
        echo "  $user"
    done
    
    # Perform deletions
    for user in "${confirmed[@]}"; do
        sudo userdel --remove "$user" 2>/dev/null
        echo "deleted: $user"
    done
}

# Main execution
# Uncomment the line below if you want to add users
# addUsers

readCurrentUser
plan_and_delete