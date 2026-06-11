import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;

import java.util.*;


public class BoringSecretHunter extends GhidraScript {

    private static final String VERSION = "1.4.0";
    private static boolean DEBUG_RUN = false;
    private static String LARGE_DUMP_MODE = "normal";  // "normal", "fast", or "skip"
    private static boolean SKIP_SYMBOLS = false;
    private static String FORCED_STRATEGY = null;  // null = use all strategies in order
    private static boolean FIND_SSL_RW = false;
    private static boolean FIND_QUICHE = false;

    private void printBoringSecretHunterLogo() {
        if(DEBUG_RUN){
            System.out.println("[!] BoringSecretHunter Environment infos: ");
            System.out.println("[!] Running on Java version: " + System.getProperty("java.version"));
            System.out.println("[!] Current Ghidra version: " + currentProgram.getLanguage().getVersion()+"\n");
        }

        println("");
        System.out.println("""
                            BoringSecretHunter
        ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣀⣀⣀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
        ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⠾⠛⢉⣉⣉⣉⡉⠛⠷⣦⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀
        ⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⠋⣠⣴⣿⣿⣿⣿⣿⡿⣿⣶⣌⠹⣷⡀⠀⠀⠀⠀⠀⠀⠀
         ⠀⠀⠀⠀⠀⠀⠀⠀⣼⠁⣴⣿⣿⣿⣿⣿⣿⣿⣿⣆⠉⠻⣧⠘⣷⠀⠀⠀⠀⠀⠀⠀
        ⠀⠀⠀⠀⠀⠀⠀⠀⢰⡇⢰⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠀⠀⠈⠀⢹⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
        ⠀⠀⠀⠀⠀⠀⠀⠀⢸⡇⢸⣿⠛⣿⣿⣿⣿⣿⣿⡿⠃⠀⠀⠀⠀⢸⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
        ⠀⠀⠀⠀⠀⠀⠀⠀⠈⣷⠀⢿⡆⠈⠛⠻⠟⠛⠉⠀⠀⠀⠀⠀⠀⣾⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
        ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⣧⡀⠻⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣼⠃⠀⠀⠀⠀⠀⠀⠀ ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
        ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢼⠿⣦⣄⠀⠀⠀⠀⠀⠀⠀⣀⣴⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
        ⠀⠀⠀⠀⠀⠀⣠⣾⣿⣦⠀⠀⠈⠉⠛⠓⠲⠶⠖⠚⠋⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
        ⠀⠀⠀⠀⣠⣾⣿⣿⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
        ⠀⠀⣠⣾⣿⣿⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
        ⠀⣾⣿⣿⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
        ⣄⠈⠛⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
        ⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
        """);
        System.out.println("Identifying the ssl_log_secret() function for extracting key material using Frida.");
        System.out.println("Version: " + VERSION + " by Daniel Baier\n");
    }

    private String getBinaryInfos() {
        String binaryNameWithPath = currentProgram.getExecutablePath();
        String architecture = currentProgram.getLanguage().getProcessor().toString();

        if(architecture.contains("AARCH64")){
            architecture = "ARM64";
        }
        String binaryName = new java.io.File(binaryNameWithPath).getName();

        return "[*] Start analyzing binary " + binaryName + " (CPU Architecture: "+ architecture+"). This might take a while ...";
    }

    private void set_debug_option(){
        String[] args = getScriptArgs();
        for (String arg : args) {
            if (arg.equalsIgnoreCase("DEBUG_RUN=true")) {
                DEBUG_RUN = true;
            }
            if (arg.toUpperCase().startsWith("LARGE_DUMP_MODE=")) {
                LARGE_DUMP_MODE = arg.substring("LARGE_DUMP_MODE=".length()).toLowerCase();
            }
            if (arg.equalsIgnoreCase("SKIP_SYMBOLS=true")) {
                SKIP_SYMBOLS = true;
            }
            if (arg.toUpperCase().startsWith("STRATEGY=")) {
                FORCED_STRATEGY = arg.substring("STRATEGY=".length());
            }
            if (arg.equalsIgnoreCase("FIND_SSL_RW=true")) {
                FIND_SSL_RW = true;
            }
            if (arg.equalsIgnoreCase("FIND_QUICHE=true")) {
                FIND_QUICHE = true;
            }
        }
    }

    private boolean is_target_binary_a_rust_binary(GhidraContext ctx, MemorySearchUtils memUtils) {
        Memory memory = currentProgram.getMemory();
        for (MemoryBlock block : memory.getBlocks()) {
            String blockName = block.getName();
            if (blockName != null && (blockName.contains(".rustc") || blockName.contains("note.rustc"))) {
                return true;
            }
        }

        SymbolTable symbolTable = currentProgram.getSymbolTable();
        String[] rustSymbols = {
            "rust_eh_personality",
            "core::panicking::panic_fmt",
            "alloc::alloc::alloc",
            "std::rt::lang_start",
            "_ZN3std2rt10lang_start",
            "DW.ref.rust_eh_personality"
        };

        for (Symbol symbol : symbolTable.getAllSymbols(true)) {
            for (String rustSymbol : rustSymbols) {
                if (symbol.getName().contains(rustSymbol)) {
                    System.out.println("[*] Rust Binary Detected! Symbol found: " + symbol.getName());
                    return true;
                }
            }
        }

        List<String> rustStringMarkers = Arrays.asList(
            "rustls::record_layer",
            "Cargo.toml",
            "begin_panic",
            "panicked at",
            "core::"
        );

        for (String marker : rustStringMarkers) {
            boolean has_rust_String = memUtils.is_string_in_binary(marker);
            if(has_rust_String){
                return true;
            }
        }

        for (String marker : rustStringMarkers) {
            boolean has_rust_String = memUtils.isHexStringInRodata(marker);
            if(has_rust_String){
                return true;
            }
        }

        if(DEBUG_RUN){
            System.out.println("[*] None rust binary...");
        }

        return false;
    }

    private String get_rustcall_mangled_function_name(Address targetAddress) {
        SymbolTable symbolTable = currentProgram.getSymbolTable();

        for (Symbol symbol : symbolTable.getAllSymbols(false)) {
            Function function = getFunctionAt(symbol.getAddress());
            if (function != null) {
                if(targetAddress == symbol.getAddress() || function.getName().toLowerCase().contains("log_secret")){
                    String mangledName = symbol.getName();
                    if (mangledName.startsWith("_ZN")) {
                        return mangledName;
                    }
                }
            }
        }
        return "";
    }

    @Override
    protected void run() throws Exception {
        set_debug_option();
        printBoringSecretHunterLogo();
        String binInfoGreetings = getBinaryInfos();
        System.out.println(binInfoGreetings);

        // Build the context bridge
        GhidraContext ctx = new GhidraContext(
            currentProgram, getMonitor(),
            addr -> getFunctionContaining(addr),
            addr -> getFunctionAt(addr),
            addr -> getDataContaining(addr),
            addr -> getReferencesTo(addr),
            msg  -> println(msg)
        );

        MemorySearchUtils memUtils = new MemorySearchUtils(ctx, DEBUG_RUN, LARGE_DUMP_MODE);
        FunctionAnalysisUtils analysisUtils = new FunctionAnalysisUtils(ctx, DEBUG_RUN);

        // Phase 1: Find ssl_log_secret
        SSLLogSecretFinder secretFinder = new SSLLogSecretFinder(ctx, memUtils, analysisUtils, DEBUG_RUN);
        String primaryString = "EXPORTER_SECRET";
        String fallbackString = "CLIENT_RANDOM";
        secretFinder.find(primaryString, fallbackString);

        // Phase 2: Find SSL_read and SSL_write (opt-in via --find-ssl-rw)
        if (FIND_SSL_RW) {
            println("[*] SSL_read/SSL_write detection enabled (under development — may produce false positives).");
            SSLReadWriteHelper sslHelper = new SSLReadWriteHelper(
                ctx, memUtils, analysisUtils,
                secretFinder.getIdentifiedFunction(),
                DEBUG_RUN, SKIP_SYMBOLS, FORCED_STRATEGY
            );
            sslHelper.identify();
        }

        // Phase 2.5: Find Google QUICHE QUIC stream functions (opt-in via FIND_QUICHE=true)
        if (FIND_QUICHE) {
            if (memUtils.is_string_in_binary("quiche/quic/core/http/quic_spdy_stream.cc")
                || memUtils.is_string_in_binary("quiche/quic/core/quic_stream_sequencer.cc")) {
                QuicheFinder qf = new QuicheFinder(ctx, memUtils, analysisUtils, DEBUG_RUN);
                qf.identify();
            } else {
                println("[*] QUICHE source-path strings not present; skipping QUICHE detection.");
            }
        }

        // Phase 3: Rust TLS detection
        if (is_target_binary_a_rust_binary(ctx, memUtils)) {
            secretFinder.printMaxPattern();
            primaryString = "rustls";
            fallbackString = "not a loggable secret";

            GhidraContext.Pair<Set<Function>, Address> result = memUtils.findStringUsage(primaryString);

            if (result.getSecond() == null) {
                result = memUtils.findHexStringInRodataWrapper(fallbackString, false);
                if (result.getFirst().isEmpty()) {
                    System.out.println("\n[*] Rust code markers detected. Checking whether RusTLS is used for TLS...");
                    result = memUtils.findHexStringInRodataWrapper(primaryString, false);
                    if (result.getFirst().isEmpty()) {
                        System.out.println("[*] No RusTLS detected. Keep using the BoringSSL hooks!");
                        System.out.println("\nThx for using BoringSecretHunter. Have a nice day :)");
                        return;
                    } else {
                        System.out.println("[*] RusTLS detected. Try using the RusTLS hooks!");
                        System.out.println("\n[*] Previous pattern was only a TLS 1.3 pattern. Now looking for the TLS 1.2 pattern...");
                        result = memUtils.findHexStringInRodataWrapper("master secret", false);
                        if (result.getFirst() != null && result.getSecond() != null) {
                            secretFinder.processFoundFunctions(result, true);
                        }
                    }
                }
            }
            System.out.println("\n[*] This binary contains RusTLS try to use the RusTLS hooks for this pattern!");
            System.out.println("\nThx for using BoringSecretHunter. Have a nice day :)");

        } else {
            System.out.println("\nThx for using BoringSecretHunter. Have a nice day :)");
        }
    }
}
