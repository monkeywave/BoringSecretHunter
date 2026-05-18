import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;

import java.util.*;

/**
 * Strategy orchestration and shared logic for SSL_read/SSL_write identification.
 */
public class SSLReadWriteHelper {

    private final GhidraContext ctx;
    private final MemorySearchUtils memUtils;
    private final FunctionAnalysisUtils analysisUtils;
    private final Function tls13label;
    private final boolean debugRun;
    private final boolean skipSymbols;
    private final String forcedStrategy;

    private Function identifiedSSLWrite = null;
    private Function identifiedSSLRead = null;
    private Set<Function> sharedSSLWriteCandidates = new HashSet<>();
    private Set<Function> sharedSSLReadCandidates = new HashSet<>();

    private SSLWriteFinder writeFinder;
    private SSLReadFinder readFinder;

    public SSLReadWriteHelper(GhidraContext ctx, MemorySearchUtils memUtils,
                              FunctionAnalysisUtils analysisUtils, Function tls13label,
                              boolean debugRun, boolean skipSymbols, String forcedStrategy) {
        this.ctx = ctx;
        this.memUtils = memUtils;
        this.analysisUtils = analysisUtils;
        this.tls13label = tls13label;
        this.debugRun = debugRun;
        this.skipSymbols = skipSymbols;
        this.forcedStrategy = forcedStrategy;

        this.writeFinder = new SSLWriteFinder(ctx, memUtils, analysisUtils, debugRun);
        this.readFinder = new SSLReadFinder(ctx, memUtils, analysisUtils, debugRun);
    }

    public Function getIdentifiedSSLWrite() { return identifiedSSLWrite; }
    public Function getIdentifiedSSLRead() { return identifiedSSLRead; }

    public void identify() {
        System.out.println("\n[*] === Identifying SSL_read and SSL_write ===");

        String[] strategies;
        if (forcedStrategy != null) {
            System.out.println("[*] Using only strategy: " + forcedStrategy);
            strategies = new String[]{ forcedStrategy };
        } else if (skipSymbols) {
            System.out.println("[*] Skipping symbol-based identification (--no-symbols mode)");
            strategies = new String[]{
                "ErrorStringFingerprinting",
                "NumericErrorCodeFingerprinting",
                "ERRPutErrorCallerAnalysis",
                "CallGraphTracing",
                "AdjacentFunctionScanning",
                "ConstantFingerprinting",
                "FunctionSignatureAnalysis",
                "ErrorCodeTableScan"
            };
        } else {
            strategies = new String[]{
                "SymbolTableLookup",
                "ErrorStringFingerprinting",
                "NumericErrorCodeFingerprinting",
                "ERRPutErrorCallerAnalysis",
                "CallGraphTracing",
                "AdjacentFunctionScanning",
                "ConstantFingerprinting",
                "FunctionSignatureAnalysis",
                "ErrorCodeTableScan"
            };
        }

        for (String strategy : strategies) {
            if (identifiedSSLWrite != null && identifiedSSLRead != null) {
                break;
            }
            System.out.println("[*] Trying " + strategy + "...");
            boolean found = runStrategy(strategy);
            if (found) {
                if (identifiedSSLWrite != null && !validateSSLFunction(identifiedSSLWrite, "SSL_write")) {
                    if (debugRun) {
                        System.out.println("[!] SSL_write failed validation, discarding: " + identifiedSSLWrite.getName());
                    }
                    identifiedSSLWrite = null;
                    writeFinder.setIdentified(null);
                }
                if (identifiedSSLRead != null && !validateSSLFunction(identifiedSSLRead, "SSL_read")) {
                    if (debugRun) {
                        System.out.println("[!] SSL_read failed validation, discarding: " + identifiedSSLRead.getName());
                    }
                    identifiedSSLRead = null;
                    readFinder.setIdentified(null);
                }

                found = (identifiedSSLWrite != null || identifiedSSLRead != null);
                if (found) {
                    if (identifiedSSLWrite != null && identifiedSSLRead != null) {
                        System.out.println("[+] Both SSL_write and SSL_read identified via " + strategy + "!");
                    } else if (identifiedSSLWrite != null) {
                        System.out.println("[+] SSL_write identified via " + strategy + "!");
                    } else if (identifiedSSLRead != null) {
                        System.out.println("[+] SSL_read identified via " + strategy + "!");
                    }
                }
            }
            if (!found) {
                System.out.println("[-] " + strategy + " did not identify new functions");
            }
        }

        // General fallback: if SSL_write found but SSL_read still missing,
        // try SSL_write-relative search with validation
        if (identifiedSSLWrite != null && identifiedSSLRead == null) {
            if (debugRun) {
                System.out.println("[!] Post-strategy fallback: SSL_write found but SSL_read missing, trying SSL_write-relative search");
            }
            readFinder.trySSLWriteRelativeSearch(identifiedSSLWrite);
            identifiedSSLRead = readFinder.getIdentified();
            if (identifiedSSLRead != null) {
                if (!validateSSLFunction(identifiedSSLRead, "SSL_read")) {
                    if (debugRun) {
                        System.out.println("[!] SSL_write-relative SSL_read failed validation, discarding: " +
                            identifiedSSLRead.getName());
                    }
                    identifiedSSLRead = null;
                    readFinder.setIdentified(null);
                } else {
                    System.out.println("[+] SSL_read identified via SSL_write-relative search!");
                }
            }
        }

        // Always run NameFallback as a correction step — exact name matches
        // override potentially wrong heuristic identifications
        writeFinder.strategyNameFallback(identifiedSSLWrite, identifiedSSLRead, this);
        identifiedSSLWrite = writeFinder.getIdentified();
        // NameFallback updates SSL_read via helper.setIdentifiedSSLRead(), not readFinder
        // so identifiedSSLRead is already correct here

        // Print final confirmed results (not during strategy execution)
        if (identifiedSSLRead != null) {
            extractFunctionInfoForSSL(identifiedSSLRead, "SSL_read");
        }
        if (identifiedSSLWrite != null) {
            extractFunctionInfoForSSL(identifiedSSLWrite, "SSL_write");
        }

        if (identifiedSSLWrite == null) {
            System.out.println("[-] Could not identify SSL_write with any strategy.");
        }
        if (identifiedSSLRead == null) {
            System.out.println("[-] Could not identify SSL_read with any strategy.");
        }

        if (identifiedSSLWrite != null || identifiedSSLRead != null) {
            identifySSLReadWriteEx();
        }
    }

    private boolean runStrategy(String name) {
        boolean hadWrite = identifiedSSLWrite != null;
        boolean hadRead = identifiedSSLRead != null;

        switch (name) {
            case "SymbolTableLookup":
                writeFinder.strategySymbolTableLookup();
                readFinder.strategySymbolTableLookup();
                break;
            case "ErrorStringFingerprinting":
                strategyErrorStringFingerprinting();
                break;
            case "NumericErrorCodeFingerprinting":
                strategyNumericErrorCodeFingerprinting();
                break;
            case "ERRPutErrorCallerAnalysis":
                strategyERRPutErrorCallerAnalysis();
                break;
            case "CallGraphTracing":
                strategyCallGraphTracing();
                break;
            case "AdjacentFunctionScanning":
                strategyAdjacentFunctionScanning();
                break;
            case "ConstantFingerprinting":
                strategyConstantFingerprinting();
                break;
            case "FunctionSignatureAnalysis":
                strategyFunctionSignatureAnalysis();
                break;
            case "ErrorCodeTableScan":
                strategyErrorCodeTableScan();
                break;
        }

        // Sync state from finders
        if (writeFinder.getIdentified() != null && identifiedSSLWrite == null) {
            identifiedSSLWrite = writeFinder.getIdentified();
        }
        if (readFinder.getIdentified() != null && identifiedSSLRead == null) {
            identifiedSSLRead = readFinder.getIdentified();
        }

        boolean foundNew = (identifiedSSLWrite != null && !hadWrite) ||
                           (identifiedSSLRead != null && !hadRead);
        return foundNew;
    }

    public boolean validateSSLFunction(Function func, String role) {
        if (func == null) return false;

        String funcName = func.getName().toUpperCase();

        String[] nonSSLPrefixes = {"ASN1", "EVP_", "BN_", "RSA_", "EC_", "SHA", "MD5", "AES", "DES", "HMAC", "X509",
            "OPENSSL_", "PEM_", "BIO_", "PKCS", "V2I_", "I2V_", "D2I_", "I2D_", "GENERAL_NAME", "CRYPTO_"};
        for (String prefix : nonSSLPrefixes) {
            if (funcName.contains(prefix)) {
                if (debugRun) {
                    System.out.println("[!] Validation: rejecting " + func.getName() +
                        " as " + role + " (matches non-SSL prefix: " + prefix + ")");
                }
                return false;
            }
        }

        boolean has0x17 = false;
        boolean has0x4000 = false;
        AddressSetView body = func.getBody();
        InstructionIterator instIter = ctx.program.getListing().getInstructions(body, true);
        while (instIter.hasNext()) {
            Instruction inst = instIter.next();
            for (int i = 0; i < inst.getNumOperands(); i++) {
                Object[] opObjects = inst.getOpObjects(i);
                for (Object obj : opObjects) {
                    if (obj instanceof ghidra.program.model.scalar.Scalar) {
                        long val = ((ghidra.program.model.scalar.Scalar) obj).getUnsignedValue();
                        if (val == 0x17) has0x17 = true;
                        if (val == 0x4000) has0x4000 = true;
                    }
                }
            }
        }
        if (has0x17 && has0x4000) {
            if (debugRun) {
                System.out.println("[!] Validation: rejecting " + func.getName() +
                    " as " + role + " (uses both 0x17 and 0x4000 directly - likely internal TLS function)");
            }
            return false;
        }

        int params = func.getParameterCount();
        if (params > 6) {
            if (debugRun) {
                System.out.println("[!] Validation: rejecting " + func.getName() +
                    " as " + role + " (param count too high: " + params + ")");
            }
            return false;
        }

        long bodySize = func.getBody().getNumAddresses();
        if (role.equals("SSL_write") && bodySize > 3000) {
            if (debugRun) {
                System.out.println("[!] Validation: rejecting " + func.getName() +
                    " as SSL_write (body too large: " + bodySize + ")");
            }
            return false;
        }
        if (role.equals("SSL_read") && bodySize > 1000) {
            if (debugRun) {
                System.out.println("[!] Validation: rejecting " + func.getName() +
                    " as SSL_read (body too large: " + bodySize + ")");
            }
            return false;
        }

        String rawName = func.getName();
        if (rawName.startsWith("__Z") || rawName.startsWith("_Z")) {
            if (debugRun) {
                System.out.println("[!] Validation: rejecting " + rawName +
                    " as " + role + " (C++ mangled name - likely internal function)");
            }
            return false;
        }

        return true;
    }

    public void extractFunctionInfoForSSL(Function function, String sslFunctionName) {
        Address entryPoint = function.getEntryPoint();
        Memory memory = ctx.program.getMemory();

        if (memory.getBlock(entryPoint) == null) {
            System.err.println("[-] Memory block not found for entry point: " + entryPoint);
            return;
        }

        int numBytes = getLengthUntilBranch(function);
        if (numBytes == -42) {
            System.out.println("[*] No branch found in " + sslFunctionName + ", using 32 bytes default");
            numBytes = 32;
        }

        byte[] byteData = memUtils.readBytes(memory, entryPoint, numBytes);
        String bytePattern = memUtils.byteArrayToHex(byteData);

        System.out.println("[*] " + sslFunctionName + ":");
        System.out.println("[*] Function label: " + function.getName() + " (" + function.toString() + ")");
        System.out.println("[*] Function offset (Ghidra): " + entryPoint.toString().toUpperCase()
            + " (0x" + entryPoint.toString().toUpperCase() + ")");
        System.out.println("[*] Function offset (IDA with base 0x0): " + ctx.getIdaAddress(entryPoint)
            + " (0x" + ctx.getIdaAddress(entryPoint) + ")");
        System.out.println("[*] Byte pattern for frida (friTap): " + bytePattern);

        if (bytePattern.length() > 140) {
            System.out.println("[*] Byte pattern for frida (friTap) truncated version: "
                + bytePattern.substring(0, 140));
        }
    }

    private int getLengthUntilBranch(Function function) {
        Address entryPoint = function.getEntryPoint();
        ghidra.program.model.listing.Listing listing = ctx.program.getListing();
        AddressSetView functionBody = function.getBody();
        InstructionIterator instructions = listing.getInstructions(functionBody, true);
        ghidra.program.model.listing.Instruction startInstruction = listing.getInstructionAt(entryPoint);
        int length = 0;
        boolean foundCall = false;

        if (startInstruction == null) {
            ctx.println.accept("[-] No instruction found at entry point: " + entryPoint);
            ctx.println.accept("[-] Defaulting to 32 bytes");
            return 32;
        }

        while (instructions.hasNext()) {
            Instruction instruction = instructions.next();
            if (instruction == null) break;

            if (instruction.getFlowType().isJump() ||
                instruction.getFlowType().isConditional() ||
                instruction.getFlowType().isCall()) {
                length += instruction.getLength();

                Address[] flows = instruction.getFlows();
                if (flows.length > 0) {
                    Address targetAddress = flows[0];
                    if (function.getBody().contains(targetAddress) && (targetAddress.subtract(instruction.getAddress())) < 10) {
                        continue;
                    }
                }

                if (instruction.toString().toLowerCase().startsWith("call") && instruction.toString().toLowerCase().contains("$+")) {
                    continue;
                }

                foundCall = true;
                break;
            }

            length += instruction.getLength();
        }
        return foundCall ? length : -42;
    }

    // ========== Shared strategy implementations ==========

    private void strategyErrorStringFingerprinting() {
        if (debugRun) {
            System.out.println("[!] Searching for error string cross-references...");
        }

        Set<Function> uninitializedFuncs = memUtils.findAllFunctionsReferencingString("UNINITIALIZED");
        Set<Function> badLengthFuncs = memUtils.findAllFunctionsReferencingString("BAD_LENGTH");
        Set<Function> connectionTypeFuncs = memUtils.findAllFunctionsReferencingString("CONNECTION_TYPE_NOT_SET");
        Set<Function> protocolShutdownFuncs = memUtils.findAllFunctionsReferencingString("PROTOCOL_IS_SHUTDOWN");

        if (debugRun) {
            System.out.println("[!] Functions referencing 'UNINITIALIZED': " + uninitializedFuncs.size());
            System.out.println("[!] Functions referencing 'BAD_LENGTH': " + badLengthFuncs.size());
        }

        writeFinder.tryErrorStringFingerprinting(uninitializedFuncs, badLengthFuncs, this);
        identifiedSSLWrite = writeFinder.getIdentified();

        readFinder.tryErrorStringFingerprinting(uninitializedFuncs, badLengthFuncs,
            connectionTypeFuncs, protocolShutdownFuncs, identifiedSSLRead, this);
        identifiedSSLRead = readFinder.getIdentified();
    }

    private void strategyNumericErrorCodeFingerprinting() {
        if (debugRun) {
            System.out.println("[!] NumericErrorCodeFP: scanning for numeric error code immediates...");
        }

        Memory memory = ctx.program.getMemory();
        final long ERR_LIB_SSL = 0x14;
        final long SSL_R_UNINITIALIZED = 0xE2;
        final long SSL_R_BAD_LENGTH = 0x10F;

        Set<Function> funcsUsing20 = new HashSet<>();
        Set<Function> funcsUsing226 = new HashSet<>();
        Set<Function> funcsUsing271 = new HashSet<>();

        for (ghidra.program.model.mem.MemoryBlock block : memory.getBlocks()) {
            if (!block.isExecute()) continue;
            InstructionIterator instIter = ctx.program.getListing().getInstructions(block.getStart(), true);
            while (instIter.hasNext()) {
                Instruction inst = instIter.next();
                if (inst.getAddress().compareTo(block.getEnd()) > 0) break;

                for (int i = 0; i < inst.getNumOperands(); i++) {
                    Object[] opObjects = inst.getOpObjects(i);
                    for (Object obj : opObjects) {
                        if (obj instanceof ghidra.program.model.scalar.Scalar) {
                            long val = ((ghidra.program.model.scalar.Scalar) obj).getUnsignedValue();
                            if (val == ERR_LIB_SSL) {
                                Function func = ctx.getFunctionContaining.apply(inst.getAddress());
                                if (func != null) funcsUsing20.add(func);
                            } else if (val == SSL_R_UNINITIALIZED) {
                                Function func = ctx.getFunctionContaining.apply(inst.getAddress());
                                if (func != null) funcsUsing226.add(func);
                            } else if (val == SSL_R_BAD_LENGTH) {
                                Function func = ctx.getFunctionContaining.apply(inst.getAddress());
                                if (func != null) funcsUsing271.add(func);
                            }
                            if (val == 0x014000E2L) {
                                Function func = ctx.getFunctionContaining.apply(inst.getAddress());
                                if (func != null) { funcsUsing20.add(func); funcsUsing226.add(func); }
                            } else if (val == 0x0140010FL) {
                                Function func = ctx.getFunctionContaining.apply(inst.getAddress());
                                if (func != null) { funcsUsing20.add(func); funcsUsing271.add(func); }
                            }
                        }
                    }
                }
            }
        }

        if (debugRun) {
            System.out.println("[!] NumericErrorCodeFP: funcsUsing20 (ERR_LIB_SSL): " + funcsUsing20.size());
            System.out.println("[!] NumericErrorCodeFP: funcsUsing226 (SSL_R_UNINITIALIZED): " + funcsUsing226.size());
            System.out.println("[!] NumericErrorCodeFP: funcsUsing271 (SSL_R_BAD_LENGTH): " + funcsUsing271.size());
        }

        Set<Function> validUninitFuncs = new HashSet<>(funcsUsing226);
        validUninitFuncs.retainAll(funcsUsing20);

        if (validUninitFuncs.isEmpty()) {
            if (debugRun) {
                System.out.println("[!] NumericErrorCodeFP: no direct co-occurrence for 226+20, trying top-5 callee fallback");
            }
            Set<Function> top5 = analysisUtils.findTopCalledFunctions(5);
            for (Function func : funcsUsing226) {
                for (Function called : func.getCalledFunctions(ctx.monitor)) {
                    if (top5.contains(called)) {
                        validUninitFuncs.add(func);
                        break;
                    }
                }
            }
        }

        Set<Function> validBadLenFuncs = new HashSet<>(funcsUsing271);
        validBadLenFuncs.retainAll(funcsUsing20);

        if (validBadLenFuncs.isEmpty()) {
            if (debugRun) {
                System.out.println("[!] NumericErrorCodeFP: no direct co-occurrence for 271+20, trying top-5 callee fallback");
            }
            Set<Function> top5 = analysisUtils.findTopCalledFunctions(5);
            for (Function func : funcsUsing271) {
                for (Function called : func.getCalledFunctions(ctx.monitor)) {
                    if (top5.contains(called)) {
                        validBadLenFuncs.add(func);
                        break;
                    }
                }
            }
        }

        if (debugRun) {
            System.out.println("[!] NumericErrorCodeFP: validUninitFuncs: " + validUninitFuncs.size());
            System.out.println("[!] NumericErrorCodeFP: validBadLenFuncs: " + validBadLenFuncs.size());
        }

        sharedSSLWriteCandidates.addAll(validBadLenFuncs);
        sharedSSLReadCandidates.addAll(validUninitFuncs);
        sharedSSLReadCandidates.removeAll(validBadLenFuncs);

        writeFinder.tryNumericErrorCodeFingerprinting(validBadLenFuncs, identifiedSSLWrite, this);
        identifiedSSLWrite = writeFinder.getIdentified();

        Set<Function> sslReadImplCandidates = new HashSet<>(validUninitFuncs);
        sslReadImplCandidates.removeAll(validBadLenFuncs);
        readFinder.tryNumericErrorCodeFingerprinting(sslReadImplCandidates, identifiedSSLRead, this);
        identifiedSSLRead = readFinder.getIdentified();
    }

    private void strategyERRPutErrorCallerAnalysis() {
        Function errPutError = analysisUtils.findERRPutErrorFunction();
        if (errPutError == null) {
            if (debugRun) {
                System.out.println("[!] ERRPutErrorCallerAnalysis: could not find ERR_put_error");
            }
            return;
        }

        Memory memory = ctx.program.getMemory();

        // Literal pool scanning
        byte[] packedBadLenLE = new byte[] {0x0F, 0x01, 0x40, 0x01};
        byte[] packedUninitLE = new byte[] {(byte)0xE2, 0x00, 0x40, 0x01};

        Set<Function> literalPoolBadLen = new HashSet<>();
        Set<Function> literalPoolUninit = new HashSet<>();

        for (ghidra.program.model.mem.MemoryBlock block : memory.getBlocks()) {
            if (!block.isRead()) continue;
            try {
                Address search = block.getStart();
                while (search != null && search.compareTo(block.getEnd()) < 0) {
                    Address found = memory.findBytes(search, block.getEnd(), packedBadLenLE, null, true, ctx.monitor);
                    if (found == null) break;
                    ReferenceIterator refs = ctx.program.getReferenceManager().getReferencesTo(found);
                    while (refs.hasNext()) {
                        Reference ref = refs.next();
                        Function func = ctx.getFunctionContaining.apply(ref.getFromAddress());
                        if (func != null) literalPoolBadLen.add(func);
                    }
                    Function func = ctx.getFunctionContaining.apply(found);
                    if (func != null) literalPoolBadLen.add(func);
                    search = found.add(4);
                }

                search = block.getStart();
                while (search != null && search.compareTo(block.getEnd()) < 0) {
                    Address found = memory.findBytes(search, block.getEnd(), packedUninitLE, null, true, ctx.monitor);
                    if (found == null) break;
                    ReferenceIterator refs = ctx.program.getReferenceManager().getReferencesTo(found);
                    while (refs.hasNext()) {
                        Reference ref = refs.next();
                        Function func = ctx.getFunctionContaining.apply(ref.getFromAddress());
                        if (func != null) literalPoolUninit.add(func);
                    }
                    Function func = ctx.getFunctionContaining.apply(found);
                    if (func != null) literalPoolUninit.add(func);
                    search = found.add(4);
                }
            } catch (Exception e) { continue; }
        }

        if (debugRun) {
            System.out.println("[!] ERRPutErrorCallerAnalysis: literal pool BAD_LENGTH functions: " + literalPoolBadLen.size());
            System.out.println("[!] ERRPutErrorCallerAnalysis: literal pool UNINIT functions: " + literalPoolUninit.size());
        }

        // Instruction operand scanning
        Address errEntry = errPutError.getEntryPoint();
        ReferenceIterator refIter = ctx.program.getReferenceManager().getReferencesTo(errEntry);

        Set<Long> targetCodes = new HashSet<>(Arrays.asList(226L, 271L, 0x014000E2L, 0x0140010FL));
        Set<Function> callersWithBadLen = new HashSet<>(literalPoolBadLen);
        Set<Function> callersWithUninit = new HashSet<>(literalPoolUninit);
        Set<Function> processedCallers = new HashSet<>();

        while (refIter.hasNext()) {
            Reference ref = refIter.next();
            if (!ref.getReferenceType().isCall()) continue;
            Function caller = ctx.getFunctionContaining.apply(ref.getFromAddress());
            if (caller == null || processedCallers.contains(caller)) continue;
            processedCallers.add(caller);

            Set<Long> imms = analysisUtils.findImmediatesInBody(caller, targetCodes);
            boolean hasBadLen = imms.contains(271L) || imms.contains(0x0140010FL);
            boolean hasUninit = imms.contains(226L) || imms.contains(0x014000E2L);
            if (hasBadLen) callersWithBadLen.add(caller);
            if (hasUninit) callersWithUninit.add(caller);
        }

        if (debugRun) {
            System.out.println("[!] ERRPutErrorCallerAnalysis: total BAD_LENGTH callers: " + callersWithBadLen.size());
            System.out.println("[!] ERRPutErrorCallerAnalysis: total UNINIT callers: " + callersWithUninit.size());
        }

        // Find small uninit callers (ssl_can_write / ssl_can_read)
        List<Function> smallUninitCallers = new ArrayList<>();
        for (Function func : callersWithUninit) {
            long bodySize = func.getBody().getNumAddresses();
            if (bodySize < 200 && !analysisUtils.isLikelyNonSSLFunction(func)) {
                smallUninitCallers.add(func);
            }
        }

        // Delegate to finders
        writeFinder.tryERRPutErrorCallerAnalysis(smallUninitCallers, callersWithBadLen, memory, identifiedSSLWrite, this);
        identifiedSSLWrite = writeFinder.getIdentified();

        readFinder.tryERRPutErrorCallerAnalysis(smallUninitCallers, callersWithUninit,
            identifiedSSLWrite, identifiedSSLRead, this);
        identifiedSSLRead = readFinder.getIdentified();
    }

    private void strategyCallGraphTracing() {
        if (tls13label == null) {
            if (debugRun) {
                System.out.println("[!] CallGraphTracing requires ssl_log_secret, skipping");
            }
            return;
        }

        Set<Function> allCallers = new HashSet<>();
        Set<Function> currentLevel = new HashSet<>();
        currentLevel.add(tls13label);

        for (int depth = 0; depth < 10; depth++) {
            Set<Function> nextLevel = new HashSet<>();
            for (Function func : currentLevel) {
                Address entry = func.getEntryPoint();
                ReferenceIterator refIter = ctx.program.getReferenceManager().getReferencesTo(entry);
                while (refIter.hasNext()) {
                    Reference ref = refIter.next();
                    if (ref.getReferenceType().isCall()) {
                        Function caller = ctx.getFunctionContaining.apply(ref.getFromAddress());
                        if (caller != null && !allCallers.contains(caller)) {
                            nextLevel.add(caller);
                        }
                    }
                }
            }
            allCallers.addAll(nextLevel);
            currentLevel = nextLevel;
            if (debugRun) {
                System.out.println("[!] Call graph depth " + depth + ": " + nextLevel.size() + " new callers");
            }
            if (nextLevel.isEmpty()) break;
        }

        writeFinder.tryCallGraphTracing(allCallers, identifiedSSLWrite, this);
        identifiedSSLWrite = writeFinder.getIdentified();

        readFinder.tryCallGraphTracing(allCallers, identifiedSSLRead, this);
        identifiedSSLRead = readFinder.getIdentified();

        // Disambiguate if same function matched both
        if (identifiedSSLWrite != null && identifiedSSLRead != null &&
            identifiedSSLWrite.equals(identifiedSSLRead)) {
            long bodySize = identifiedSSLWrite.getBody().getNumAddresses();
            if (bodySize >= 100) {
                identifiedSSLRead = null;
                readFinder.setIdentified(null);
            } else {
                identifiedSSLWrite = null;
                writeFinder.setIdentified(null);
            }
        }
    }

    private void strategyAdjacentFunctionScanning() {
        if (tls13label == null) {
            if (debugRun) {
                System.out.println("[!] AdjacentFunctionScanning requires ssl_log_secret, skipping");
            }
            return;
        }

        Address anchorAddr = tls13label.getEntryPoint();
        long anchorOffset = anchorAddr.getOffset();
        long windowSize = 200 * 1024;
        List<Function> nearbyFunctions = new ArrayList<>();

        for (Function func : ctx.program.getFunctionManager().getFunctions(true)) {
            long funcOffset = func.getEntryPoint().getOffset();
            long distance = Math.abs(funcOffset - anchorOffset);
            if (distance <= windowSize) {
                nearbyFunctions.add(func);
            }
        }
        nearbyFunctions.sort((a, b) -> Long.compare(
            a.getEntryPoint().getOffset(), b.getEntryPoint().getOffset()));

        if (debugRun) {
            System.out.println("[!] AdjacentScan: Found " + nearbyFunctions.size() +
                " functions within " + (windowSize / 1024) + "KB of ssl_log_secret");
        }

        writeFinder.tryAdjacentFunctionScanning(nearbyFunctions, anchorOffset, windowSize, tls13label, identifiedSSLWrite, this);
        identifiedSSLWrite = writeFinder.getIdentified();

        readFinder.tryAdjacentFunctionScanning(nearbyFunctions, anchorOffset, windowSize, tls13label, identifiedSSLRead, this);
        identifiedSSLRead = readFinder.getIdentified();

        // Fallback: if SSL_write found but SSL_read not, search near SSL_write
        if (identifiedSSLWrite != null && identifiedSSLRead == null) {
            if (debugRun) {
                System.out.println("[!] AdjacentScan: SSL_write found but SSL_read missing, trying SSL_write-relative search");
            }
            readFinder.trySSLWriteRelativeSearch(identifiedSSLWrite);
            identifiedSSLRead = readFinder.getIdentified();
        }

        if (identifiedSSLWrite != null && identifiedSSLRead != null &&
            identifiedSSLWrite.equals(identifiedSSLRead)) {
            long bodySize = identifiedSSLWrite.getBody().getNumAddresses();
            if (bodySize >= 100) {
                identifiedSSLRead = null;
                readFinder.setIdentified(null);
            } else {
                identifiedSSLWrite = null;
                writeFinder.setIdentified(null);
            }
        }
    }

    private void strategyConstantFingerprinting() {
        Memory memory = ctx.program.getMemory();

        Set<Function> funcsUsing0x17 = new HashSet<>();
        Set<Function> funcsUsing0x4000 = new HashSet<>();

        for (ghidra.program.model.mem.MemoryBlock block : memory.getBlocks()) {
            if (!block.isExecute()) continue;
            InstructionIterator instIter = ctx.program.getListing().getInstructions(block.getStart(), true);
            while (instIter.hasNext()) {
                Instruction inst = instIter.next();
                if (inst.getAddress().compareTo(block.getEnd()) > 0) break;

                for (int i = 0; i < inst.getNumOperands(); i++) {
                    Object[] opObjects = inst.getOpObjects(i);
                    for (Object obj : opObjects) {
                        if (obj instanceof ghidra.program.model.scalar.Scalar) {
                            long val = ((ghidra.program.model.scalar.Scalar) obj).getUnsignedValue();
                            if (val == 0x17) {
                                Function func = ctx.getFunctionContaining.apply(inst.getAddress());
                                if (func != null) funcsUsing0x17.add(func);
                            } else if (val == 0x4000) {
                                Function func = ctx.getFunctionContaining.apply(inst.getAddress());
                                if (func != null) funcsUsing0x4000.add(func);
                            }
                        }
                    }
                }
            }
        }

        Set<Function> candidates = new HashSet<>(funcsUsing0x17);
        candidates.retainAll(funcsUsing0x4000);

        if (debugRun) {
            System.out.println("[!] ConstantFP: functions with 0x17: " + funcsUsing0x17.size() +
                ", with 0x4000: " + funcsUsing0x4000.size() +
                ", intersection: " + candidates.size());
        }

        Set<Function> callerCandidates = new HashSet<>();
        for (Function internalFunc : candidates) {
            ReferenceIterator refIter = ctx.program.getReferenceManager()
                .getReferencesTo(internalFunc.getEntryPoint());
            while (refIter.hasNext()) {
                Reference ref = refIter.next();
                if (ref.getReferenceType().isCall()) {
                    Function caller = ctx.getFunctionContaining.apply(ref.getFromAddress());
                    if (caller != null && !candidates.contains(caller)) {
                        int params = caller.getParameterCount();
                        long size = caller.getBody().getNumAddresses();
                        int xrefs = analysisUtils.countXRefs(caller);
                        if (params >= 2 && params <= 5 && size >= 40 && size <= 2000 && xrefs >= 2) {
                            callerCandidates.add(caller);
                        }
                    }
                }
            }
        }

        writeFinder.tryConstantFingerprinting(candidates, callerCandidates, identifiedSSLWrite, this);
        identifiedSSLWrite = writeFinder.getIdentified();

        readFinder.tryConstantFingerprinting(candidates, callerCandidates, identifiedSSLRead, this);
        identifiedSSLRead = readFinder.getIdentified();

        if (identifiedSSLWrite != null && identifiedSSLRead != null &&
            identifiedSSLWrite.equals(identifiedSSLRead)) {
            long bodySize = identifiedSSLWrite.getBody().getNumAddresses();
            if (bodySize >= 100) {
                identifiedSSLRead = null;
                readFinder.setIdentified(null);
            } else {
                identifiedSSLWrite = null;
                writeFinder.setIdentified(null);
            }
        }
    }

    private void strategyFunctionSignatureAnalysis() {
        List<GhidraContext.Pair<Function, Long>> candidates = new ArrayList<>();

        for (Function func : ctx.program.getFunctionManager().getFunctions(true)) {
            int paramCount = func.getParameterCount();
            if (paramCount < 2 || paramCount > 5) continue;

            long bodySize = func.getBody().getNumAddresses();
            if (bodySize < 40 || bodySize > 2000) continue;

            int callerCount = analysisUtils.countXRefs(func);
            if (callerCount < 2) continue;
            if (analysisUtils.isLikelyNonSSLFunction(func)) continue;

            candidates.add(new GhidraContext.Pair<>(func, bodySize));
        }

        writeFinder.tryFunctionSignatureAnalysis(candidates, identifiedSSLWrite, this);
        identifiedSSLWrite = writeFinder.getIdentified();

        readFinder.tryFunctionSignatureAnalysis(candidates, identifiedSSLRead, this);
        identifiedSSLRead = readFinder.getIdentified();
    }

    private void strategyErrorCodeTableScan() {
        writeFinder.tryErrorCodeTableScan(identifiedSSLWrite, this);
        identifiedSSLWrite = writeFinder.getIdentified();

        readFinder.setIdentifiedFromErrorCodeTableScan(writeFinder.getErrorCodeTableScanReadImpl(), identifiedSSLRead, this);
        identifiedSSLRead = readFinder.getIdentified();
    }

    private void identifySSLReadWriteEx() {
        if (identifiedSSLWrite != null) {
            Function writeEx = findExWrapper(identifiedSSLWrite);
            if (writeEx != null) {
                System.out.println("[+] SSL_write_ex identified!");
                extractFunctionInfoForSSL(writeEx, "SSL_write_ex");
            }
        }

        if (identifiedSSLRead != null) {
            Function readEx = findExWrapper(identifiedSSLRead);
            if (readEx != null) {
                System.out.println("[+] SSL_read_ex identified!");
                extractFunctionInfoForSSL(readEx, "SSL_read_ex");
            }
        }
    }

    private Function findExWrapper(Function baseFunc) {
        Address entry = baseFunc.getEntryPoint();
        ReferenceIterator refIter = ctx.program.getReferenceManager().getReferencesTo(entry);

        Function bestCandidate = null;
        long smallestSize = Long.MAX_VALUE;

        while (refIter.hasNext()) {
            Reference ref = refIter.next();
            if (ref.getReferenceType().isCall()) {
                Function caller = ctx.getFunctionContaining.apply(ref.getFromAddress());
                if (caller != null && !caller.equals(baseFunc)) {
                    long bodySize = caller.getBody().getNumAddresses();
                    int paramCount = caller.getParameterCount();

                    if (bodySize < 150 && paramCount >= 4 && bodySize < smallestSize) {
                        smallestSize = bodySize;
                        bestCandidate = caller;
                        if (debugRun) {
                            System.out.println("[!] _ex candidate: " + caller.getName() +
                                " (size=" + bodySize + ", params=" + paramCount + ")");
                        }
                    }
                }
            }
        }

        return bestCandidate;
    }

    // Used by finders to set identified functions
    public void setIdentifiedSSLWrite(Function func) { this.identifiedSSLWrite = func; }
    public void setIdentifiedSSLRead(Function func) { this.identifiedSSLRead = func; }
}
