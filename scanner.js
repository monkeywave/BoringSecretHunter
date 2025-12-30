// Universal BoringSSL Scanner
// Uses Kernel-level memory maps to bypass APK-loading issues.
// -----------------------------------------------------------

const STRING_PATTERNS = [
    "CLIENT_RANDOM",
    "SERVER_HANDSHAKE_TRAFFIC_SECRET",
    "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
    "SSLKEYLOGFILE"
];

function scanForSecrets() {
    console.log("[-] Starting Kernel-Level Discovery Scan...");
    
    // 1. Get all loaded modules
    const modules = Process.enumerateModules();
    
    // 2. Get the TRUE memory map from the Kernel
    // We get ALL readable ranges in the entire process once.
    const allRanges = Process.enumerateRanges('r');

    modules.forEach(function(m) {
        // Optimization: Skip system libraries
        if (["libc.so", "libm.so", "libdl.so", "libart.so"].includes(m.name)) return;

        // 3. Manually find which memory ranges belong to this module
        // We filter the global list for ranges that fall inside the module's footprint.
        const moduleRanges = allRanges.filter(range => {
            return (range.base >= m.base) && 
                   (range.base < m.base.add(m.size));
        });

        // Skip if no ranges found (should only happen for weird virtual modules)
        if (moduleRanges.length === 0) return;

        // 4. Scan the identified ranges
        moduleRanges.forEach(function(range) {
            try {
                for (let pattern of STRING_PATTERNS) {
                    const results = Memory.scanSync(range.base, range.size, patternToHex(pattern));
                    
                    if (results.length > 0) {
                        printMatch(m, pattern, results[0].address, range.protection);
                        // We break here to avoid spamming the same module multiple times
                        return; 
                    }
                }
            } catch (e) {
                // Ignore read errors
            }
        });
    });

    console.log("[-] Scan Complete.");
}

function patternToHex(str) {
    let hex = "";
    for (let i = 0; i < str.length; i++) {
        hex += str.charCodeAt(i).toString(16) + " ";
    }
    return hex.trim();
}

function printMatch(module, pattern, address, protection) {
    console.log(`\n[+] CANDIDATE FOUND: ${module.name}`);
    console.log(`    |-- Match:      "${pattern}"`);
    console.log(`    |-- Segment:    ${protection}`);
    console.log(`    |-- Address:    ${address}`);
    console.log(`    |-- Offset:     ${address.sub(module.base)}`);
    console.log(`    |-- Path:       ${module.path}`);
}

setImmediate(scanForSecrets);