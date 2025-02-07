#!/bin/bash

# Define color codes for pretty output
GREEN="\033[0;32m"
RED="\033[0;31m"
YELLOW="\033[1;33m"
TEXTRESET="\033[0m"

# Function to check if BIND (named) is installed
check_bind_installed() {
    if dnf list installed bind &> /dev/null; then
        echo -e "${GREEN}BIND is installed.${TEXTRESET}"
        return 0
    else
        echo -e "${RED}BIND is not installed.${TEXTRESET}"
        return 1
    fi
}

# Function to enable and start the BIND service
enable_and_start_bind() {
    echo -e "${YELLOW}Enabling named service to start on boot...${TEXTRESET}"
    sudo systemctl enable named

    echo -e "${YELLOW}Starting named service...${TEXTRESET}"
    sudo systemctl start named

    # Check if the service is running
    if systemctl is-active --quiet named; then
        echo -e "${GREEN}named service is running.${TEXTRESET}"
    else
        echo -e "${RED}named service failed to start.${TEXTRESET}"
    fi
}

# Function to check if KEA DHCPv4 is installed
check_kea_installed() {
    if dnf list installed isc-kea-dhcp4 &> /dev/null; then
        echo -e "${GREEN}KEA DHCPv4 is installed.${TEXTRESET}"
        return 0
    else
        echo -e "${RED}KEA DHCPv4 is not installed.${TEXTRESET}"
        return 1
    fi
}

# Function to enable and start the KEA DHCPv4 service
enable_and_start_kea() {
    echo -e "${YELLOW}Enabling kea-dhcp4 service to start on boot...${TEXTRESET}"
    sudo systemctl enable kea-dhcp4

    echo -e "${YELLOW}Starting kea-dhcp4 service...${TEXTRESET}"
    sudo systemctl start kea-dhcp4

    # Check if the service is running
    if systemctl is-active --quiet kea-dhcp4; then
        echo -e "${GREEN}kea-dhcp4 service is running.${TEXTRESET}"
    else
        echo -e "${RED}kea-dhcp4 service failed to start.${TEXTRESET}"
    fi
}

# Function to check if Cockpit is installed
check_cockpit_installed() {
    if dnf list installed cockpit &> /dev/null; then
        echo -e "${GREEN}Cockpit is installed.${TEXTRESET}"
        return 0
    else
        echo -e "${RED}Cockpit is not installed.${TEXTRESET}"
        return 1
    fi
}

# Function to enable and start the Cockpit service
enable_and_start_cockpit() {
    echo -e "${YELLOW}Enabling cockpit service to start on boot...${TEXTRESET}"
    sudo systemctl enable cockpit.socket

    echo -e "${YELLOW}Starting cockpit service...${TEXTRESET}"
    sudo systemctl start cockpit.socket

    # Check if the service is running
    if systemctl is-active --quiet cockpit.socket; then
        echo -e "${GREEN}cockpit service is running.${TEXTRESET}"
    else
        echo -e "${RED}cockpit service failed to start.${TEXTRESET}"
    fi
}

# Function to check if Webmin is installed
check_webmin_installed() {
    if dnf list installed webmin &> /dev/null; then
        echo -e "${GREEN}Webmin is installed.${TEXTRESET}"
        return 0
    else
        echo -e "${RED}Webmin is not installed.${TEXTRESET}"
        return 1
    fi
}

# Function to enable and start the Webmin service
enable_and_start_webmin() {
    echo -e "${YELLOW}Enabling webmin service to start on boot...${TEXTRESET}"
    sudo systemctl enable webmin

    echo -e "${YELLOW}Starting webmin service...${TEXTRESET}"
    sudo systemctl start webmin

    # Check if the service is running
    if systemctl is-active --quiet webmin; then
        echo -e "${GREEN}webmin service is running.${TEXTRESET}"
    else
        echo -e "${RED}webmin service failed to start.${TEXTRESET}"
    fi
}

# Function to check if ddclient is installed
check_ddclient_installed() {
    if dnf list installed ddclient &> /dev/null; then
        echo -e "${GREEN}ddclient is installed. But is not enabled for startup.${TEXTRESET}"
        echo -e "${YELLOW}Please manually configure ddclient for your DDNS requirements.${TEXTRESET}"
        echo -e "${YELLOW}Press Enter to continue...${TEXTRESET}"
        read -r
        return 0
    else
        echo -e "${RED}ddclient is not installed.${TEXTRESET}"
        return 1
    fi
}

# Function to check if ntopng is installed
check_ntopng_installed() {
    if dnf list installed ntopng &> /dev/null; then
        echo -e "${GREEN}ntopng is installed.${TEXTRESET}"
        return 0
    else
        echo -e "${RED}ntopng is not installed.${TEXTRESET}"
        return 1
    fi
}

# Function to enable and start the ntopng service
enable_and_start_ntopng() {
    echo -e "${YELLOW}Enabling ntopng service to start on boot...${TEXTRESET}"
    sudo systemctl enable ntopng

    echo -e "${YELLOW}Starting ntopng service...${TEXTRESET}"
    sudo systemctl start ntopng

    # Check if the service is running
    if systemctl is-active --quiet ntopng; then
        echo -e "${GREEN}ntopng service is running.${TEXTRESET}"
    else
        echo -e "${RED}ntopng service failed to start.${TEXTRESET}"
    fi
}

# Function to check if Suricata is installed
check_suricata_installed() {
    if dnf list installed suricata &> /dev/null; then
        echo -e "${GREEN}Suricata is installed.${TEXTRESET}"
        return 0
    else
        echo -e "${RED}Suricata is not installed.${TEXTRESET}"
        return 1
    fi
}

# Function to enable and start the Suricata service
enable_and_start_suricata() {
    echo -e "${YELLOW}Enabling suricata service to start on boot...${TEXTRESET}"
    sudo systemctl enable suricata

    echo -e "${YELLOW}Starting suricata service...${TEXTRESET}"
    sudo systemctl start suricata

    # Check if the service is running
    if systemctl is-active --quiet suricata; then
        echo -e "${GREEN}suricata service is running.${TEXTRESET}"
    else
        echo -e "${RED}suricata service failed to start.${TEXTRESET}"
    fi
}

# Function to check if Filebeat is installed
check_filebeat_installed() {
    if dnf list installed filebeat &> /dev/null; then
        echo -e "${GREEN}Filebeat is installed.${TEXTRESET}"
        return 0
    else
        echo -e "${RED}Filebeat is not installed.${TEXTRESET}"
        return 1
    fi
}

# Function to enable and start the Filebeat service
enable_and_start_filebeat() {
    echo -e "${YELLOW}Enabling filebeat service to start on boot...${TEXTRESET}"
    sudo systemctl enable filebeat

    echo -e "${YELLOW}Starting filebeat service...${TEXTRESET}"
    sudo systemctl start filebeat

    # Check if the service is running
    if systemctl is-active --quiet filebeat; then
        echo -e "${GREEN}filebeat service is running.${TEXTRESET}"
    else
        echo -e "${RED}filebeat service failed to start.${TEXTRESET}"
    fi
}

# Function to check if Kibana is installed
check_kibana_installed() {
    if dnf list installed kibana &> /dev/null; then
        echo -e "${GREEN}Kibana is installed.${TEXTRESET}"
        return 0
    else
        echo -e "${RED}Kibana is not installed.${TEXTRESET}"
        return 1
    fi
}

# Function to enable and start the Kibana service
enable_and_start_kibana() {
    echo -e "${YELLOW}Enabling kibana service to start on boot...${TEXTRESET}"
    sudo systemctl enable kibana

    echo -e "${YELLOW}Starting kibana service...${TEXTRESET}"
    sudo systemctl start kibana

    # Check if the service is running
    if systemctl is-active --quiet kibana; then
        echo -e "${GREEN}kibana service is running.${TEXTRESET}"
    else
        echo -e "${RED}kibana service failed to start.${TEXTRESET}"
    fi
}

# Function to check if Elasticsearch is installed
check_elasticsearch_installed() {
    if dnf list installed elasticsearch &> /dev/null; then
        echo -e "${GREEN}Elasticsearch is installed.${TEXTRESET}"
        return 0
    else
        echo -e "${RED}Elasticsearch is not installed.${TEXTRESET}"
        return 1
    fi
}

# Function to enable and start the Elasticsearch service
enable_and_start_elasticsearch() {
    echo -e "${YELLOW}Enabling elasticsearch service to start on boot...${TEXTRESET}"
    sudo systemctl enable elasticsearch

    echo -e "${YELLOW}Starting elasticsearch service...${TEXTRESET}"
    sudo systemctl start elasticsearch

    # Check if the service is running
    if systemctl is-active --quiet elasticsearch; then
        echo -e "${GREEN}elasticsearch service is running.${TEXTRESET}"
    else
        echo -e "${RED}elasticsearch service failed to start.${TEXTRESET}"
    fi
}

# Main script execution
if check_bind_installed; then
    enable_and_start_bind
else
    echo -e "${YELLOW}Skipping BIND service management as it is not installed.${TEXTRESET}"
fi

if check_kea_installed; then
    enable_and_start_kea
else
    echo -e "${YELLOW}Skipping KEA DHCPv4 service management as it is not installed.${TEXTRESET}"
fi

if check_cockpit_installed; then
    enable_and_start_cockpit
else
    echo -e "${YELLOW}Skipping Cockpit service management as it is not installed.${TEXTRESET}"
fi

if check_webmin_installed; then
    enable_and_start_webmin
else
    echo -e "${YELLOW}Skipping Webmin service management as it is not installed.${TEXTRESET}"
fi

check_ddclient_installed

if check_ntopng_installed; then
    enable_and_start_ntopng
else
    echo -e "${YELLOW}Skipping ntopng service management as it is not installed.${TEXTRESET}"
fi

if check_suricata_installed; then
    enable_and_start_suricata
else
    echo -e "${YELLOW}Skipping Suricata service management as it is not installed.${TEXTRESET}"
fi

if check_filebeat_installed; then
    enable_and_start_filebeat
else
    echo -e "${YELLOW}Skipping Filebeat service management as it is not installed.${TEXTRESET}"
fi

if check_kibana_installed; then
    enable_and_start_kibana
else
    echo -e "${YELLOW}Skipping Kibana service management as it is not installed.${TEXTRESET}"
fi

if check_elasticsearch_installed; then
    enable_and_start_elasticsearch
else
    echo -e "${YELLOW}Skipping Elasticsearch service management as it is not installed.${TEXTRESET}"
fi

echo -e "${GREEN}Script execution completed.${TEXTRESET}"
