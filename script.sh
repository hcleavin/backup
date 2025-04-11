#!/bin/bash

startup() {
    echo "Welcome to DNS Setup Script!
######  #     #  #####   
#     # ##    # #     # 
#     # # #   # #
#     # #  #  #  #####
#     # #   # #       #
#     # #    ## #     # 
######  #     #  #####"                                  
}

check_permissions() {
    if [[ "$EUID" -ne 0 ]]; then
        echo "This script must be run as root (use sudo)"
        exit 1
    fi
}

install_bind() {
    if ! command -v named &> /dev/null; then
        apt install bind9 bind9utils bind9-doc -y
        if [ $? -ne 0 ]; then  
            echo "bind9 installation failed. Exiting"
            log_error "bind9 installation failed"
            exit 1
        fi
    else   
        echo "BIND already installed. Skipping install."
    fi
}

start_bind() {
    systemctl enable named
    systemctl restart named
}

config_setup() {
    install_bind
    if [ ! -d /etc/bind/ ]; then
        echo "/etc/bind directory not found. Exiting."
        log_error "/etc/bind directory not found"
        exit 1
    fi

    if [ ! -f "/var/log/dns-setup-errors.log" ]; then
        touch "/var/log/dns-setup-errors.log"
        chmod 644 "/var/log/dns-setup-errors.log"
    fi

    if [ ! -f "/var/log/named_query.log" ]; then
        touch "/var/log/named_query.log"
        chmod 644 "/var/log/named_query.log"
    fi

    if [ ! -f "/var/log/named.log" ]; then
        touch "/var/log/named.log"
        chmod 644 "/var/log/named.log"
    fi

    sed -i '/^include "\/etc\/bind\/named.conf.options";$/d' "/etc/bind/named.conf"

    if [ -f /etc/bind/named.conf.script_conf ]; then
        echo "Default configurations are already set! Try creating zone files/records instead!"
        log_error "Default configs already set"
        exit 1
    fi

    echo "Enter the internal IP/subnet for the 'internal' access control list (Ex. 192.168.0.0/24)"
    while true; do
        read internal_acl_and_subnet
        validate_ip_with_subnet "$internal_acl_and_subnet" && break
    done

    echo "Enter the external IP/subnet for the 'external' access control list (Ex. 172.18.0.0/24)"
    while true; do
        read external_acl_and_subnet
        validate_ip_with_subnet "$external_acl_and_subnet" && break
    done

    while true; do
        echo "Enter this machine's internal IP"
        read internal_ip
        validate_ip "$internal_ip" && break
    done

    while true; do
        echo "Enter this machine's external IP"
        read external_ip
        validate_ip "$external_ip" && break
    done

    touch "/etc/bind/named.conf.script_conf"

    grep -q 'include "/etc/bind/named.conf.script_conf";' "/etc/bind/named.conf" || echo "include \"/etc/bind/named.conf.script_conf\";" >> "/etc/bind/named.conf"

    echo -e "acl \"internal\" {\n$internal_acl_and_subnet;\n};" >> "/etc/bind/named.conf.script_conf"

    echo -e "acl \"external\" {\n$external_acl_and_subnet;\n};" >> "/etc/bind/named.conf.script_conf"

    echo "" >> "/etc/bind/named.conf.script_conf"

    echo -e "options {\n\tdirectory \"/var/cache/bind\";\n\tallow-transfer { none; };\n\tallow-recursion { none; };\n\tallow-query { internal; external; };\n\tlisten-on { $internal_ip; $external_ip; };\n};" >> "/etc/bind/named.conf.script_conf"

    echo -e "logging {\n\tchannel query_log {\n\t\tfile \"/var/log/named_query.log\" versions 10 size 5m;\n\t\tseverity info;\n\t\tprint-time yes;\n\t\tprint-severity yes;\n\t\tprint-category yes;\n\t};\n\n\tchannel default_log {\n\t\tfile \"/var/log/named.log\" versions 10 size 5m;\n\t\tseverity warning;\n\t\tprint-time yes;\n\t\tprint-severity yes;\n\t\tprint-category yes;\n\t\t};\n\tcategory queries { query_log; };\n\tcategory default { default_log; };\n};" >> "/etc/bind/named.conf.script_conf"
    
    chown root:bind "/etc/bind/named.conf.script_conf"
    chmod 644 "/etc/bind/named.conf.script_conf"
    echo "Default configurations are set!"
}

create_zone_file() {
    mkdir -p "/etc/bind/zones/"
    chown root:bind "/etc/bind/zones"
    if [ ! -f /etc/bind/named.conf.script_zones ]; then
        touch "/etc/bind/named.conf.script_zones"
    fi

    grep -q 'include "named.conf.script_zones;"' "/etc/bind/named.conf" || echo "include \"/etc/bind/named.conf.script_zones\";" >> "/etc/bind/named.conf"

    while true; do
        echo "Will the records in this zone file be internally or externally available? (respond 'internal' or 'external')"
        read internal_external
        if [[ "$internal_external" == "internal" || "$internal_external" == "external" ]]; then
            break
        else
            echo "Invalid input. Please enter 'internal' or 'external'."
        fi
    done

    echo "Will this zone file be for forward or reverse lookups? (respond 'forward' or 'reverse') "
    read forward_or_reverse

    if [[ "$forward_or_reverse" == "forward" ]]; then
        echo "Please enter the domain you'd like to make a zone for"
        read domain
        cp "/etc/bind/db.empty" "/etc/bind/zones/db.$domain"
        sed -i "s/localhost./ns.$domain./g" "/etc/bind/zones/db.$domain"
        sed -i "s/root.ns./admin./g" "/etc/bind/zones/db.$domain"
        echo -e "zone \"$domain\" {\ntype master;\nfile \"/etc/bind/zones/db.$domain\";\nallow-query { $internal_external; };\n};" >> "/etc/bind/named.conf.script_zones"
        chown root:bind "/etc/bind/zones/db.$domain"
        chmod 644 "/etc/bind/zones/db.$domain"
        echo "Created zone file \"/etc/bind/zones/db.$domain\""
        echo "You must enter a forward record for the nameserver for this zone file!"
        while true; do
            echo "Please enter a valid IP for this record: ns.$domain."
            read ip_fwd
            validate_ip "$ip_fwd" && break
        done

        echo -e "$domain_fwd\tIN\tA\t$ip_fwd" >> "/etc/bind/zones/db.$domain"
    fi

    if [[ "$forward_or_reverse" == "reverse" ]]; then
        echo "Please enter the IP you'd like to make a zone for (ONE OCTET AT A TIME, first three octets)"
        
        while true; do
            echo "First octet"
            read octet1
            if [[ "$octet1" =~ ^[0-9]{1,3}$ ]] && (( octet1 >= 0 && octet1 <= 255 )); then
                break
            else
                echo "Invalid octet. Must be a number between 0 and 255. Try again."
            fi
        done

        while true; do
            echo "Second octet"
            read octet2
            if [[ "$octet2" =~ ^[0-9]{1,3}$ ]] && (( octet2 >= 0 && octet2 <= 255 )); then
                break
            else
                echo "Invalid octet. Must be a number between 0 and 255."
            fi
        done

        
        while true; do 
            echo "Third octet"
            read octet3
            if [[ "$octet3" =~ ^[0-9]{1,3}$ ]] && (( octet3 >= 0 && octet3 <= 255 )); then
                break
            else
                echo "Invalid octet. Must be a number between 0 and 255."
            fi
        done

        cp /etc/bind/db.empty /etc/bind/zones/db.$octet1.$octet2.$octet3
        echo -e "zone \"$octet3.$octet2.$octet1.in-addr.arpa\" {\ntype master;\nfile \"/etc/bind/zones/db.$octet1.$octet2.$octet3\";\nallow-query { $internal_external; };\n};" >> "/etc/bind/named.conf.script_zones"
        chown root:bind "/etc/bind/zones/db.$octet1.$octet2.$octet3"
        chmod 644 "/etc/bind/zones/db.$octet1.$octet2.$octet3"
        echo "Created zone file \"/etc/bind/zones/db.$octet1.$octet2.$octet3\""

        echo "You must enter a record for the nameserver for this zone file!"
        while true; do
            echo "Please enter the IP octet for the PTR record (This is the final octet in the IP that points to the nameserver)"
            read ip_rev
            if [[ "$ip_rev" =~ ^[0-9]{1,3}$ ]] && (( ip_rev >= 0 && ip_rev <= 255 )); then
                break
            else
                echo "Invalid octet. Must be a number between 0 and 255."
            fi
        done
        echo "Please enter the domain for the nameserver that will contain reverse records for this zone file (should be in the format of ns.rest_of_domain) (DO NOT ADD THE DOT AT THE END IT'S ADDED AUTOMATICALLY)"
        read domain_rev
        echo "$ip_rev\tIN\tPTR\t$domain_rev." >> "/etc/bind/zones/db.$octet1.$octet2.$octet3"
    fi
    record_zones_menu
}

make_record() {
    echo "What record type would you like to create? (available types are PTR, A, or CNAME)"
    read record_type
    if [[ "$record_type" != "PTR" && "$record_type" != "A" && "$record_type" != "CNAME" ]]; then
        echo "Invalid record type. Supported types: PTR, A, CNAME."
        return 1
    fi

    for file in /etc/bind/zones/*; do
        echo "$file"
    done

    while true; do
        echo "Please enter the zone file you'd like to add to (respond with the full path!)"
        read zone_file
        if [ ! -f "$zone_file" ]; then
            echo "Zone file does not exist"
        fi
        if [ -f "$zone_file" ]; then
            echo "Valid zone file!"
            break
        fi
    done

    if [[ "$record_type" == "PTR" ]]; then
        while true; do
            echo "Please enter the IP octet to complete this IP address: ${zone_file#"db."}"
            read ip_rev
            if [[ "$ip_rev" =~ ^[0-9]{1,3}$ ]] && (( ip_rev >= 0 && ip_rev <= 255 )); then
                break
            else
                echo "Invalid octet. Must be a number between 0 and 255."
            fi
        done
        echo "Please enter the subdomain for ${zone_file#"db."}."
        read domain_rev
        echo "$ip_rev\tIN\t$record_type\t$domain_rev" >> "$zone_file"
    else
        echo "Please enter the domain"
        read domain_fwd

        while true; do
            echo "Please enter the IP"
            read ip_fwd
            validate_ip "$ip_fwd" && break
        done

        echo -e "$domain_fwd\tIN\t$record_type\t$ip_fwd" >> "$zone_file"
    fi
    record_zones_menu
}

record_zones_menu() {
    while true; do
        echo "Please choose an option:"
        echo "1. Create zone files"
        echo "2. Create records"
        echo "3. Save and quit"
        echo "Enter your choice (pick a number): " 
        read choice

        case $choice in
            3) 
                echo "Checking configuration/zone files!"
                test_conf_zones
                break
                ;;
            2) 
                make_record
                break
                ;;
            1) 
                create_zone_file
                break
                ;;
            *)
                log_error "Invalid menu choice: $choice"
                echo "Please enter a valid choice"
                ;;
        esac
    done
}

main_menu() {
    while true; do
        echo "Please choose an option:"
        echo "1. Set default configurations"
        echo "2. Create zone files or records"
        echo "3. Save and quit" 
        echo "Enter your choice (pick a number): " 
        read choice

        case $choice in
            3) 
                echo "Checking configuration/zone files!"
                test_conf_zones
                break
                ;;
            2) 
                record_zones_menu
                break
                ;;
            1) 
                config_setup
                break
                ;;
            *)
                log_error "Invalid menu choice: $choice"
                echo "Please enter a valid choice"
                ;;
        esac
    done
}

test_conf_zones() {
    output=$(named-checkconf -z 2>&1)
    if [ $? -eq 0 ]; then
        echo "Everything passed the test! Starting the service and exiting!"
        start_bind
        exit 0
    else   
        echo "Errors: $output"
        echo "Please fix the errors"
        log_error "$output"
        exit 1
    fi
}

validate_ip() {
    local ip="$1"
    local valid_ip_regex="^([0-9]{1,3}\.){3}[0-9]{1,3}$"
    
    if [[ ! "$ip" =~ $valid_ip_regex ]]; then
        echo "Invalid IP format. Please enter a valid IPv4 address (ex. 192.168.1.1)."
        return 1
    fi

    IFS='.' read -r octet1 octet2 octet3 octet4 <<< "$ip"
    if (( octet1 < 0 || octet1 > 255 || octet2 < 0 || octet2 > 255 || octet3 < 0 || octet3 > 255 || octet4 < 0 || octet4 > 255 )); then
        echo "IP address octets must be between 0 and 255."
        return 1
    fi

    return 0
}

validate_ip_with_subnet() {
    local ip_subnet="$1"
    local valid_ip_regex="^([0-9]{1,3}\.){3}[0-9]{1,3}$"
    local valid_subnet_regex="^([0-9]{1,3}\.){3}[0-9]{1,3}/([0-9]|[1-2][0-9]|3[0-2])$" 

    if [[ ! "$ip_subnet" =~ $valid_subnet_regex ]]; then
        echo "Invalid format. The correct format is 'IP/Subnet', e.g., '192.168.1.0/24'."
        return 1
    fi

    ip=$(echo "$ip_subnet" | cut -d'/' -f1)
    subnet=$(echo "$ip_subnet" | cut -d'/' -f2)

    if [[ ! "$ip" =~ $valid_ip_regex ]]; then
        echo "Invalid IP address format. Please enter a valid IPv4 address (e.g., 192.168.1.1)."
        return 1
    fi

    if (( subnet < 0 || subnet > 32 )); then
        echo "Invalid subnet mask. It should be a number between 0 and 32."
        return 1
    fi

    IFS='.' read -r octet1 octet2 octet3 octet4 <<< "$ip"
    if (( octet1 < 0 || octet1 > 255 || octet2 < 0 || octet2 > 255 || octet3 < 0 || octet3 > 255 || octet4 < 0 || octet4 > 255 )); then
        echo "IP address octets must be between 0 and 255."
        return 1
    fi

    return 0
}

log_error() {
    echo "$(date) ERROR: $1" >> "/var/log/dns-setup-errors.log"
}

check_permissions
startup
main_menu
