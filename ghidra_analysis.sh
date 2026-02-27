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
    # Check if DEBUG_RUN environment variable is set and true
    if [[ "${DEBUG_RUN,,}" == "true" ]]; then
        DEBUG_ARGS="DEBUG_RUN=true"
        echo "[*] Debug mode enabled."
    else
        DEBUG_ARGS=""
        #echo "[*] DEBUG_RUN is not set or false; proceeding without debug output."
    fi
fi





# Truncate the log file at the beginning of each Docker run to ensure a fresh log
> /usr/local/src/boring_secret_hunter.log

# === Pre-processing: Extract archives (IPA/APK) ===
EXTRACTED_FILES=()
TEMP_DIRS=()

for archive in /usr/local/src/binaries/*; do
    archive_name=$(basename "$archive")

    # Only process files with .ipa, .apk, or .zip extension
    case "${archive_name,,}" in
        *.ipa|*.apk|*.zip) ;;
        *) continue ;;
    esac

    echo "[*] Extracting archive: $archive_name ..."
    tmp_dir=$(mktemp -d /tmp/bsh_extract_XXXXXX)
    TEMP_DIRS+=("$tmp_dir")

    if ! unzip -q -o "$archive" -d "$tmp_dir" 2>/dev/null; then
        echo "[!] Warning: Failed to extract $archive_name, skipping."
        continue
    fi

    # Find binaries inside the extracted archive (type-aware extraction)
    while IFS= read -r extracted_bin; do
        file_type=$(file -b "$extracted_bin")
        should_extract=false

        case "${archive_name,,}" in
            *.apk)
                # APK: only extract .so files that are ELF
                if [[ "$extracted_bin" == *.so ]] && echo "$file_type" | grep -qi "elf"; then
                    should_extract=true
                fi
                ;;
            *.ipa)
                # IPA: extract all Mach-O files
                if echo "$file_type" | grep -qi "mach-o"; then
                    should_extract=true
                fi
                ;;
            *)
                # ZIP/other: extract all ELF and Mach-O
                if echo "$file_type" | grep -qi -e "elf" -e "mach-o"; then
                    should_extract=true
                fi
                ;;
        esac

        if $should_extract; then
            relative_path="${extracted_bin#$tmp_dir/}"
            sanitized=$(echo "$relative_path" | sed 's|/|__|g')
            dest_name="${archive_name}__${sanitized}"
            cp "$extracted_bin" "/usr/local/src/binaries/$dest_name"
            EXTRACTED_FILES+=("/usr/local/src/binaries/$dest_name")
            echo "    [+] Found: $relative_path"
        fi
    done < <(find "$tmp_dir" -type f -size +1k)
done

# === Detect processor for raw data files ===
detect_processor() {
    local bin_dir="$1"

    # Check for user override
    if [[ -n "${DATA_PROCESSOR:-}" ]]; then
        echo "$DATA_PROCESSOR"
        return
    fi

    # Auto-detect from sibling binaries in same folder
    for sibling in "$bin_dir"/*; do
        [[ -f "$sibling" ]] || continue
        local sibling_type
        sibling_type=$(file -b "$sibling" 2>/dev/null)
        case "$sibling_type" in
            *"ARM aarch64"*|*"aarch64"*)
                echo "AARCH64:LE:64:v8A"; return ;;
            *"ARM,"*|*"ARM "*|*"32-bit"*ARM*)
                echo "ARM:LE:32:v8"; return ;;
            *"x86-64"*|*"x86_64"*|*"AMD64"*)
                echo "x86:LE:64:default"; return ;;
            *"Intel 80386"*|*"i386"*)
                echo "x86:LE:32:default"; return ;;
        esac
    done

    # Default to AARCH64
    echo "AARCH64:LE:64:v8A"
}

# Ask user how to handle large raw data dumps
prompt_large_dump_mode() {
    local bin_name="$1"
    local size_mb="$2"

    # If env var is already set, use it without prompting
    if [[ -n "${LARGE_DUMP_MODE:-}" ]]; then
        echo "$LARGE_DUMP_MODE"
        return
    fi

    # If stdin is not a terminal (non-interactive), default to "normal"
    if [[ ! -t 0 ]]; then
        echo "normal"
        return
    fi

    echo ""
    echo "[?] Large raw data dump detected: $bin_name (${size_mb} MB)"
    echo "    How would you like to proceed?"
    echo "    1) normal  - Search using byte-by-byte scan (slower but thorough)"
    echo "    2) fast    - Search using Ghidra's optimized findBytes API (faster)"
    echo "    3) skip    - Skip this binary"
    echo ""
    read -r -p "    Choice [1/2/3] (default: 1): " choice

    case "$choice" in
        2|fast)  echo "fast" ;;
        3|skip)  echo "skip" ;;
        *)       echo "normal" ;;
    esac
}

# Loop through all binaries in the /usr/local/src/binaries folder
BINARIES=()
while IFS= read -r bin; do
    BINARIES+=("$bin")
done < <(file /usr/local/src/binaries/* | grep -iv -e "zip archive" -e "java archive" | grep -i -e "elf" -e "mach-o" -e "pe32" -e ":[[:space:]]*data" | awk -F': ' '{print $1}' | uniq)

TOTAL=${#BINARIES[@]}
if [[ $TOTAL -eq 0 ]]; then
    echo "[*] No supported binaries found. Supported types: ELF, Mach-O, PE32, raw data files."
    echo "[*] Place your binaries in the binary/ folder and try again."
    exit 0
fi

if [[ $TOTAL -eq 1 ]]; then
    echo "[*] Found 1 binary to analyze:"
else
    echo "[*] Found $TOTAL binaries to analyze:"
fi
COUNT=0
for i in "${!BINARIES[@]}"; do
    echo "    $((i+1)). $(basename "${BINARIES[$i]}")"
done
echo ""

for bin in "${BINARIES[@]}"; do
    COUNT=$((COUNT + 1))
    bin_name=$(basename "$bin")

    # Print the analyzing message to the terminal (not redirected)
    echo "[$COUNT/$TOTAL] Analyzing $bin_name..."

    # Detect if file is raw data and set processor flag
    EXTRA_ARGS=""
    bin_type=$(file -b "$bin")
    if [[ "$bin_type" == data* ]] || [[ "$bin_type" == "data" ]]; then
        PROC=$(detect_processor "$(dirname "$bin")")
        EXTRA_ARGS="-processor $PROC -loader BinaryLoader"
        echo "    [*] Raw data file detected, using processor: $PROC"

        # Check size and prompt for large dumps
        bin_size_bytes=$(stat -f%z "$bin" 2>/dev/null || stat -c%s "$bin" 2>/dev/null || echo 0)
        bin_size_mb=$((bin_size_bytes / 1024 / 1024))
        if [[ $bin_size_mb -gt 100 ]]; then
            DUMP_MODE=$(prompt_large_dump_mode "$bin_name" "$bin_size_mb")
            if [[ "$DUMP_MODE" == "skip" ]]; then
                echo "    [!] Skipping $bin_name (${bin_size_mb} MB) per user choice."
                continue
            fi
            DUMP_MODE_ARG="LARGE_DUMP_MODE=${DUMP_MODE}"
        else
            DUMP_MODE_ARG=""
        fi
    fi

    if [[ -n "$DEBUG_ARGS" ]]; then
        echo "    [!] file reports: $bin_type"
    fi

    # Redirect all output of the current binary's analysis to the log file, with custom delimiters
    {
        echo "=== Start analyzing $bin_name ==="

        # Run the Ghidra analysis script for the current binary
        /opt/ghidra_12.0.3_PUBLIC/support/analyzeHeadless /tmp ghidra_project_$(date +%s) \
            -import "$bin" $EXTRA_ARGS -scriptPath /usr/local/src/ -prescript /usr/local/src/MinimalAnalysisOption.java -postScript /usr/local/src/BoringSecretHunter.java $DEBUG_ARGS ${DUMP_MODE_ARG:-}

        echo "=== Finished analyzing $bin_name ==="
    } >> /usr/local/src/boring_secret_hunter.log 2>&1

    # Parse the log file for relevant output
    sed -n "/=== Start analyzing $(basename "$bin") ===/,/=== Finished analyzing $(basename "$bin") ===/p" /usr/local/src/boring_secret_hunter.log | \
    sed -n '/BoringSecretHunter/,/Thx for using BoringSecretHunter/p'
    echo ""
done

# === Cleanup: Remove extracted binaries and temp dirs ===
for extracted_file in "${EXTRACTED_FILES[@]}"; do
    rm -f "$extracted_file"
done
for tmp_dir in "${TEMP_DIRS[@]}"; do
    rm -rf "$tmp_dir"
done
