#!/bin/bash

DEBUG_FLAG=false
for arg in "$@"; do
    if [[ "$arg" == "-d" || "$arg" == "--debug" ]]; then
        DEBUG_FLAG=true
        break
    fi
done

if $DEBUG_FLAG; then
    DEBUG_ARGS="DEBUG_RUN=true"
    echo "[*] Debug mode enabled."
else
    DEBUG_ARGS=""
fi

# Truncate the log file at the beginning of each Docker run to ensure a fresh log
> /usr/local/src/boring_secret_hunter.log


# Loop through all binaries in the /usr/local/src/binaries folder
for bin in $(file /usr/local/src/binaries/*| grep -i -e "elf" -e "mach-o" -e "pe32" | awk -F':' '{print $1}' | awk '{print $1}' | uniq); do
    bin_name=$(basename "$bin")

    # Print the analyzing message to the terminal (not redirected)
    echo "Analyzing $bin_name..."

    # Redirect all output of the current binary's analysis to the log file, with custom delimiters
    {
        echo "=== Start analyzing $bin_name ==="
        
        # Run the Ghidra analysis script for the current binary
        #python3 /usr/local/src/boring_secret_hunter.py "$bin"

        /opt/ghidra_11.1.2_PUBLIC/support/analyzeHeadless /tmp ghidra_project_$(date +%s) \
            -import "$bin" -scriptPath /usr/local/src/ -prescript /usr/local/src/MinimalAnalysisOption.java -postScript /usr/local/src/BoringSecretHunter.java $DEBUG_ARGS
        
        echo "=== Finished analyzing $bin_name ==="
    } >> /usr/local/src/boring_secret_hunter.log 2>&1

    # Parse the log file for relevant output
    sed -n "/=== Start analyzing $(basename "$bin") ===/,/=== Finished analyzing $(basename "$bin") ===/p" /usr/local/src/boring_secret_hunter.log | \
    sed -n '/BoringSecretHunter/,/Thx for using BoringSecretHunter/p'
    #echo "\n"
done
