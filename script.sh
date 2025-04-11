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

    systemctl start named

}

config_setup() {
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

    echo "Enter the internal IP/subnet (Ex. 192.168.1.1/24)"
    while true; do
        read internal_acl_and_subnet
        validate_ip_with_subnet "$internal_acl_and_subnet" && break
    done

    echo "Enter the external IP/subnet (Ex. 192.168.1.1/24)"
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

    echo -e "acl \"internal\" {\n$internal_acl_and_subnet\n};" >> "/etc/bind/named.conf.script_conf"

    echo -e "acl \"external\" {\n$external_acl_and_subnet\n};" >> "/etc/bind/named.conf.script_conf"

    echo -e "options {\nallow-transfer { none; };\nallow-recursion { no; };\nallow-query { internal; external; };\nlisten-on { $internal_ip; $external_ip; };\n};" >> "/etc/bind/named.conf.script_conf"

    echo -e "logging {\nchannel query_log {\nfile \"/var/log/named_query.log\" versions 10 size 5m;\nseverity info;\nprint-time yes;\nprint-severity yes;\nprint-category yes;\n};\nchannel default_log {\nfile \"/var/log/named.log\" versions 10 size 5m;\nseverity warning;\nprint-time yes;\nprint-severity yes;\nprint-category yes;\n};\ncategory queries { query_log; };\ncategory default { default_log; };\n};" >> "/etc/bind/named.conf.script_conf"
    
    chown root:bind "/etc/bind/named.conf.script_conf"
    chmod 644 "/etc/bind/named.conf.script_conf"
}

create_zone_file() {
    mkdir -p "/etc/bind/zones/"
    chown root:bind "/etc/bind/zones"

    touch "/etc/bind/named.conf.script_zones"
    grep -q 'include "named.conf.script_zones;"' "/etc/bind/named.conf" || echo "include \"/etc/bind/named.conf.script_zones\";" >> "/etc/bind/named.conf"

    while true; do
        echo "Is this record internally or externally available? (internal/external)"
        read internal_external
        if [[ "$internal_external" == "internal" || "$internal_external" == "external" ]]; then
            break
        else
            echo "Invalid input. Please enter 'internal' or 'external'."
        fi
    done

    echo "Forward or reverse zone?"
    read forward_or_reverse

    if [[ "$forward_or_reverse" == "forward" ]]; then
        echo "Please enter the domain you'd like to make forward records for"
        read domain
        cp "/etc/bind/db.empty" "/etc/bind/zones/db.$domain"
        sed -i "s/localhost./ns.$domain./g" "/etc/bind/zones/db.$domain"
        sed -i "s/root./admin./g" "/etc/bind/zones/db.$domain"
        echo -e "zone \"$domain\" {\ntype master;\nfile \"/etc/bind/zones/db.$domain\";\nallow-query { $internal_external; };\n};" >> "/etc/bind/named.conf.script_zones"
        chown root:bind "/etc/bind/zones/db.$domain"
        chmod 644 "/etc/bind/zones/db.$domain"
    fi

    if [[ "$forward_or_reverse" == "reverse" ]]; then
        echo "Please enter the IP you'd like to make reverse records for (ONE OCTET AT A TIME, first three octets)"
        while true; do
            read octet1
            read octet2
            read octet3
            reverse_ip="$octet1.$octet2.$octet3"
            validate_ip "$reverse_ip" && break
        done

        cp /etc/bind/db.empty /etc/bind/zones/db.$octet1.$octet2.$octet3
        echo -e "zone \"$octet3.$octet2.$octet1.in-addr.arpa\" {\ntype master;\nfile \"/etc/bind/zones/db.$octet1.$octet2.$octet3\";\nallow-query { $internal_external; };\n};" >> "/etc/bind/named.conf.script_zones"
        chown root:bind "/etc/bind/zones/db.$octet1.$octet2.$octet3"
        chmod 644 "/etc/bind/zones/db.$octet1.$octet2.$octet3"
    fi
    main_menu
}

make_record() {
    echo "What record type would you like to create?"
    read record_type
    if [[ "$record_type" != "PTR" && "$record_type" != "A" && "$record_type" != "CNAME" ]]; then
        echo "Invalid record type. Supported types: PTR, A, CNAME."
        return 1
    fi

    for file in /etc/bind/zones/*; do
        echo "$file"
    done

    echo "Please enter the zone file you'd like to add to"
    read zone_file

    if [ ! -f "$zone_file" ]; then
        echo "Zone file does not exist"
        return 1
    fi

    if [[ "$record_type" == "PTR" ]]; then
        while true; do
            echo "Please enter the IP octet"
            read ip_rev
            if [[ "$ip_rev" =~ ^[0-9]{1,3}$ ]] && (( ip_rev >= 0 && ip_rev <= 255 )); then
                break
            else
                echo "Invalid octet. Must be a number between 0 and 255."
            fi
        done
        echo "Please enter the domain"
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
    main_menu
}

main_menu() {
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


startup
install_bind
config_setup
main_menu
