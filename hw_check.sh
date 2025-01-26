#!/bin/bash

# Define color codes for formatting
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
RESET='\033[0m' # Text Reset

# Function to check if the system has at least 8 GB of RAM
check_ram() {
    # Get the total memory in KB
    total_mem_kb=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    # Convert the memory to GB and round up
    total_mem_gb=$(echo "$total_mem_kb / 1024 / 1024" | bc -l | awk '{print ($1 == int($1)) ? $1 : int($1) + 1}')

    # Check if the memory is at least 8 GB
    if (( total_mem_gb >= 8 )); then
        echo -e "${GREEN}RAM Check: Passed (Total RAM: ${total_mem_gb} GB)${RESET}"
        return 0
    else
        needed_ram=$((8 - total_mem_gb))
        echo -e "${RED}RAM Check: Failed (Total RAM: ${total_mem_gb} GB)${RESET}"
        echo -e "${YELLOW}Additional RAM needed: ${needed_ram} GB${RESET}"
        return 1
    fi
}

# Function to check if the system has at least 2 CPUs
check_cpus() {
    # Get the number of CPUs
    cpu_count=$(grep -c ^processor /proc/cpuinfo)

    # Check if the CPU count is at least 2
    if [ "$cpu_count" -ge 2 ]; then
        echo -e "${GREEN}CPU Check: Passed (Total CPUs: ${cpu_count})${RESET}"
        return 0
    else
        needed_cpus=$((2 - cpu_count))
        echo -e "${RED}CPU Check: Failed (Total CPUs: ${cpu_count})${RESET}"
        echo -e "${YELLOW}Additional CPUs needed: ${needed_cpus}${RESET}"
        return 1
    fi
}

# Run checks
check_ram
ram_status=$?

check_cpus
cpu_status=$?

# Evaluate results
echo -e "${CYAN}\nSummary:${RESET}"
if [ "$ram_status" -eq 0 ] && [ "$cpu_status" -eq 0 ]; then
    echo -e "${GREEN}System meets the minimum requirements.${RESET}"
else
    echo -e "${RED}System does not meet the minimum requirements.${RESET}"
    [ "$ram_status" -ne 0 ] && echo -e "${YELLOW}Please add more RAM.${RESET}"
    [ "$cpu_status" -ne 0 ] && echo -e "${YELLOW}Please add more CPUs.${RESET}"
    exit 1
fi
