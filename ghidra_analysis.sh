#!/bin/bash

# Truncate the log file at the beginning of each Docker run to ensure a fresh log
> /usr/local/src/boring_secret_hunter.log


# Function to parse the log and extract the relevant portions
parse_log() {
    local log_file=$1
    local bin_name=$2
    local start_marker="=== Start analyzing $bin_name ==="
    local end_marker="=== Finished analyzing $bin_name ==="

    # Extract the log section between start and end markers
    sed -n "/$start_marker/,/$end_marker/p" "$log_file"
}

# Loop through all binaries in the /usr/local/src/binaries folder
for bin in /usr/local/src/binaries/*; do
    bin_name=$(basename "$bin")

    # Print the analyzing message to the terminal (not redirected)
    echo "Analyzing $bin_name..."

    # Redirect all output of the current binary's analysis to the log file, with custom delimiters
    {
        echo "=== Start analyzing $bin_name ==="
        
        # Run the Ghidra analysis script for the current binary
        /opt/ghidra_11.1.2_PUBLIC/support/analyzeHeadless /tmp ghidra_project_$(date +%s) \
            -import "$bin" -postScript /usr/local/src/boring_secret_hunter.py
        
        echo "=== Finished analyzing $bin_name ==="
    } >> /usr/local/src/boring_secret_hunter.log 2>&1

    # Parse the log file for the current binary
    #parse_log /usr/local/src/boring_secret_hunter.log "$bin_name"
    # Parse the log file for relevant output
    sed -n "/=== Start analyzing $(basename "$bin") ===/,/=== Finished analyzing $(basename "$bin") ===/p" /usr/local/src/boring_secret_hunter.log | \
    sed -n '/BoringSecretHunter/,/Thx for using BoringSecretHunter/p'
done
