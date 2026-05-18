import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;

import java.util.*;

/**
 * All SSL_write-specific identification logic.
 */
public class SSLWriteFinder {

    private final GhidraContext ctx;
    private final MemorySearchUtils memUtils;
    private final FunctionAnalysisUtils analysisUtils;
    private final boolean debugRun;

    private Function identifiedSSLWrite = null;

    // Temp state for error code table scan (shared with read finder)
    private Function errorCodeTableScanReadImpl = null;

    public SSLWriteFinder(GhidraContext ctx, MemorySearchUtils memUtils,
                          FunctionAnalysisUtils analysisUtils, boolean debugRun) {
        this.ctx = ctx;
        this.memUtils = memUtils;
        this.analysisUtils = analysisUtils;
        this.debugRun = debugRun;
    }

    public Function getIdentified() { return identifiedSSLWrite; }
    public void setIdentified(Function func) { this.identifiedSSLWrite = func; }
    public Function getErrorCodeTableScanReadImpl() { return errorCodeTableScanReadImpl; }

    public void strategySymbolTableLookup() {
        if (identifiedSSLWrite != null) return;
        SymbolTable symbolTable = ctx.program.getSymbolTable();
        String[] writeNames = {"SSL_write", "ssl_write"};

        for (String name : writeNames) {
            if (identifiedSSLWrite != null) break;
            for (Symbol symbol : symbolTable.getGlobalSymbols(name)) {
                Function func = ctx.getFunctionAt.apply(symbol.getAddress());
                if (func != null) {
                    if (debugRun) {
                        System.out.println("[!] Symbol match for SSL_write: " + name + " at " + symbol.getAddress());
                    }
                    identifiedSSLWrite = func;
                    break;
                }
            }
        }
    }

    public void tryErrorStringFingerprinting(Set<Function> uninitializedFuncs, Set<Function> badLengthFuncs,
                                             SSLReadWriteHelper helper) {
        if (identifiedSSLWrite != null) return;
        Set<Function> sslWriteCandidates = new HashSet<>(uninitializedFuncs);
        sslWriteCandidates.retainAll(badLengthFuncs);

        if (!sslWriteCandidates.isEmpty()) {
            identifiedSSLWrite = sslWriteCandidates.iterator().next();
        }
    }

    public void tryNumericErrorCodeFingerprinting(Set<Function> validBadLenFuncs,
                                                  Function currentWrite, SSLReadWriteHelper helper) {
        if (currentWrite != null) return;
        if (validBadLenFuncs.isEmpty()) return;

        Function bestWrite = null;
        long bestWriteSize = 0;
        for (Function func : validBadLenFuncs) {
            long size = func.getBody().getNumAddresses();
            if (size > bestWriteSize) {
                bestWriteSize = size;
                bestWrite = func;
            }
        }
        if (bestWrite != null) {
            identifiedSSLWrite = bestWrite;
            if (debugRun) {
                System.out.println("[!] NumericErrorCodeFP: identified SSL_write = " +
                    identifiedSSLWrite.getName() + " (size=" + bestWriteSize + ")");
            }
        }
    }

    public void tryERRPutErrorCallerAnalysis(List<Function> smallUninitCallers,
                                             Set<Function> callersWithBadLen,
                                             Memory memory,
                                             Function currentWrite, SSLReadWriteHelper helper) {
        if (currentWrite != null) { identifiedSSLWrite = currentWrite; return; }

        // Step 4: Find SSL_write via method table tracing
        if (!smallUninitCallers.isEmpty()) {
            for (Function sslCanFunc : smallUninitCallers) {
                Address canWriteEntry = sslCanFunc.getEntryPoint();
                ReferenceIterator canWriteRefs = ctx.program.getReferenceManager().getReferencesTo(canWriteEntry);
                List<Function> writeAppDataCandidates = new ArrayList<>();
                while (canWriteRefs.hasNext()) {
                    Reference ref = canWriteRefs.next();
                    if (!ref.getReferenceType().isCall()) continue;
                    Function caller = ctx.getFunctionContaining.apply(ref.getFromAddress());
                    if (caller != null && caller.getBody().getNumAddresses() > 200) {
                        writeAppDataCandidates.add(caller);
                        if (debugRun) {
                            System.out.println("[!] ERRPutErrorCallerAnalysis: tls_write_app_data candidate: " +
                                caller.getName() + " (size=" + caller.getBody().getNumAddresses() + ")");
                        }
                    }
                }

                for (Function writeAppData : writeAppDataCandidates) {
                    byte[] funcAddrBytes = memUtils.addressToBytes(writeAppData.getEntryPoint(), ctx.getPointerSize());
                    for (MemoryBlock block : memory.getBlocks()) {
                        if (!block.isRead() || block.isExecute()) continue;
                        try {
                            Address ptrAddr = memory.findBytes(block.getStart(), block.getEnd(),
                                funcAddrBytes, null, true, ctx.monitor);
                            if (ptrAddr == null) continue;
                            if (debugRun) {
                                System.out.println("[!] ERRPutErrorCallerAnalysis: method table entry at " +
                                    ptrAddr + " points to " + writeAppData.getName());
                            }
                            ReferenceIterator ptrRefs = ctx.program.getReferenceManager().getReferencesTo(ptrAddr);
                            while (ptrRefs.hasNext()) {
                                Reference ptrRef = ptrRefs.next();
                                Function sslWriteCandidate = ctx.getFunctionContaining.apply(ptrRef.getFromAddress());
                                if (sslWriteCandidate == null) continue;
                                if (analysisUtils.isLikelyNonSSLFunction(sslWriteCandidate)) continue;
                                long bodySize = sslWriteCandidate.getBody().getNumAddresses();
                                if (bodySize > 3000) continue;
                                if (debugRun) {
                                    System.out.println("[!] ERRPutErrorCallerAnalysis: SSL_write via method table: " +
                                        sslWriteCandidate.getName() + " (size=" + bodySize + ")");
                                }
                                identifiedSSLWrite = sslWriteCandidate;
                                break;
                            }
                            if (identifiedSSLWrite != null) break;
                        } catch (Exception e) { continue; }
                    }
                    if (identifiedSSLWrite != null) break;
                }
                if (identifiedSSLWrite != null) break;
            }
        }

        // Fallback: BAD_LENGTH callers
        if (identifiedSSLWrite == null && !callersWithBadLen.isEmpty()) {
            Function bestWrite = null;
            int bestWriteScore = -1;
            for (Function func : callersWithBadLen) {
                if (analysisUtils.isLikelyNonSSLFunction(func)) continue;
                long bodySize = func.getBody().getNumAddresses();
                int xrefs = analysisUtils.countXRefs(func);
                if (bodySize < 40 || bodySize > 3000 || xrefs < 1) continue;
                int score = xrefs;
                int params = func.getParameterCount();
                if (params == 3) score += 20;
                if (bodySize >= 80 && bodySize <= 1500) score += 10;
                if (score > bestWriteScore) {
                    bestWriteScore = score;
                    bestWrite = func;
                }
            }
            if (bestWrite != null) {
                identifiedSSLWrite = bestWrite;
            }
        }
    }

    public void tryCallGraphTracing(Set<Function> allCallers, Function currentWrite, SSLReadWriteHelper helper) {
        if (currentWrite != null) { identifiedSSLWrite = currentWrite; return; }

        Function bestCandidate = null;
        int bestScore = -1;

        for (Function func : allCallers) {
            int callerCount = analysisUtils.countXRefs(func);
            long bodySize = func.getBody().getNumAddresses();
            int paramCount = func.getParameterCount();

            if (callerCount < 1 || paramCount > 5) continue;
            if (analysisUtils.isLikelyNonSSLFunction(func)) continue;

            int score = callerCount;
            if (paramCount == 3) score += 10;

            if (bodySize >= 20 && bodySize <= 2000) {
                if (score > bestScore) {
                    bestScore = score;
                    bestCandidate = func;
                }
            }
        }

        if (bestCandidate != null) {
            identifiedSSLWrite = bestCandidate;
        }
    }

    public void tryAdjacentFunctionScanning(List<Function> nearbyFunctions, long anchorOffset,
                                            long windowSize, Function tls13label,
                                            Function currentWrite, SSLReadWriteHelper helper) {
        if (currentWrite != null) { identifiedSSLWrite = currentWrite; return; }

        Function bestCandidate = null;
        int bestScore = -1;

        for (Function func : nearbyFunctions) {
            if (func.equals(tls13label)) continue;
            if (analysisUtils.isLikelyNonSSLFunction(func)) continue;

            int paramCount = func.getParameterCount();
            long bodySize = func.getBody().getNumAddresses();
            int callerCount = analysisUtils.countXRefs(func);

            if (paramCount > 5 || callerCount < 1 || bodySize < 40 || bodySize > 2000) continue;

            // Cap xref contribution to prevent utility functions from dominating
            int score = Math.min(callerCount, 10);

            // Parameter bonus: SSL_write takes exactly 3 params (SSL*, buf, len)
            if (paramCount == 3) score += 10;

            // Proximity bonus
            long distance = Math.abs(func.getEntryPoint().getOffset() - anchorOffset);
            score += (int)(20.0 * (1.0 - (double)distance / windowSize));

            // Call pattern bonus: SSL_write calls a larger internal function (bodySize > 200)
            Set<Function> callees = analysisUtils.getCalledFunctions(func);
            for (Function callee : callees) {
                if (callee.getBody().getNumAddresses() > 200) {
                    score += 15;
                    break;
                }
            }

            // Body size sweet-spot bonus
            if (bodySize >= 60 && bodySize <= 500) score += 5;

            // Utility penalty: high-xref functions are unlikely to be SSL_write
            if (callerCount > 20) score -= 10;

            if (debugRun) {
                System.out.println("[!] AdjacentScan SSL_write candidate: " + func.getName() +
                    " score=" + score + " callers=" + callerCount + " bodySize=" + bodySize);
            }

            if (score > bestScore) {
                bestScore = score;
                bestCandidate = func;
            }
        }

        if (bestCandidate != null) {
            identifiedSSLWrite = bestCandidate;
        }
    }

    public void tryConstantFingerprinting(Set<Function> candidates, Set<Function> callerCandidates,
                                          Function currentWrite, SSLReadWriteHelper helper) {
        if (currentWrite != null) { identifiedSSLWrite = currentWrite; return; }

        Function bestCandidate = null;
        long bestSize = 0;

        // Tier 1: callerCandidates
        for (Function func : callerCandidates) {
            if (analysisUtils.isLikelyNonSSLFunction(func)) continue;
            long bodySize = func.getBody().getNumAddresses();
            if (bodySize >= 20 && bodySize > bestSize) {
                bestSize = bodySize;
                bestCandidate = func;
            }
        }

        // Tier 2: fallback to direct constant users
        if (bestCandidate == null) {
            if (debugRun) {
                System.out.println("[!] ConstantFP: Tier 1 empty for SSL_write, falling back to direct constant users");
            }
            for (Function func : candidates) {
                long bodySize = func.getBody().getNumAddresses();
                int callerCount = analysisUtils.countXRefs(func);
                if (callerCount < 1) continue;
                if (analysisUtils.isLikelyNonSSLFunction(func)) continue;

                if (bodySize >= 100 && bodySize > bestSize) {
                    bestSize = bodySize;
                    bestCandidate = func;
                }
            }
        }

        if (bestCandidate != null) {
            identifiedSSLWrite = bestCandidate;
        }
    }

    public void tryFunctionSignatureAnalysis(List<GhidraContext.Pair<Function, Long>> candidates,
                                             Function currentWrite, SSLReadWriteHelper helper) {
        if (currentWrite != null) { identifiedSSLWrite = currentWrite; return; }

        Function bestWrite = null;
        long bestWriteSize = 0;

        for (GhidraContext.Pair<Function, Long> entry : candidates) {
            Function func = entry.getFirst();
            long bodySize = entry.getSecond();

            if (bodySize >= 100 && bodySize > bestWriteSize) {
                boolean hasPrivateHelper = false;
                for (Function called : analysisUtils.getCalledFunctions(func)) {
                    int calledByCount = analysisUtils.countXRefs(called);
                    if (calledByCount == 1) {
                        hasPrivateHelper = true;
                        break;
                    }
                }
                if (hasPrivateHelper) {
                    bestWriteSize = bodySize;
                    bestWrite = func;
                }
            }
        }

        if (bestWrite != null) {
            identifiedSSLWrite = bestWrite;
        }
    }

    public void tryErrorCodeTableScan(Function currentWrite, SSLReadWriteHelper helper) {
        if (currentWrite != null) { identifiedSSLWrite = currentWrite; return; }
        errorCodeTableScanReadImpl = null;

        Memory memory = ctx.program.getMemory();
        int pointerSize = ctx.getPointerSize();

        byte[] searchBytes = memUtils.appendByte("UNINITIALIZED".getBytes(), (byte) 0x00);

        Address uninitAddr = null;
        List<MemoryBlock> rodataBlocks = memUtils.findAllRodataBlocks();

        for (MemoryBlock block : rodataBlocks) {
            try {
                Address found = memory.findBytes(block.getStart(), block.getEnd(), searchBytes, null, true, ctx.monitor);
                if (found != null) {
                    uninitAddr = found;
                    if (debugRun) {
                        System.out.println("[!] Found 'UNINITIALIZED' at " + found + " in " + block.getName());
                    }
                    break;
                }
            } catch (Exception e) { }
        }

        if (uninitAddr == null) {
            if (debugRun) {
                System.out.println("[!] Could not find 'UNINITIALIZED' string bytes");
            }
            return;
        }

        byte[] addrBytes = memUtils.addressToBytes(uninitAddr, pointerSize);
        Address tableEntry = null;

        for (MemoryBlock block : memory.getBlocks()) {
            if (!block.isRead()) continue;
            try {
                Address found = memory.findBytes(block.getStart(), block.getEnd(), addrBytes, null, true, ctx.monitor);
                if (found != null) {
                    tableEntry = found;
                    if (debugRun) {
                        System.out.println("[!] Found pointer to UNINITIALIZED at " + found + " in " + block.getName());
                    }
                    break;
                }
            } catch (Exception e) { }
        }

        if (tableEntry == null) {
            if (debugRun) {
                System.out.println("[!] No pointer to UNINITIALIZED address found, trying packed code search");
            }
            tryPackedErrorCodeFallback(memory, helper);
            return;
        }

        try {
            Address errorCodeAddr = tableEntry.subtract(pointerSize);
            long packedValue = 0;
            if (pointerSize == 8) {
                packedValue = memory.getLong(errorCodeAddr);
            } else {
                packedValue = memory.getInt(errorCodeAddr) & 0xFFFFFFFFL;
            }

            int reasonCode = (int) (packedValue & 0xFFFFFF);
            if (reasonCode == 0) {
                reasonCode = (int) packedValue;
            }

            if (debugRun) {
                System.out.println("[!] Packed error value: 0x" + Long.toHexString(packedValue) +
                    ", reason code: " + reasonCode);
            }

            byte[] badLengthSearch = memUtils.appendByte("BAD_LENGTH".getBytes(), (byte) 0x00);
            Address badLengthAddr = null;
            for (MemoryBlock block : rodataBlocks) {
                try {
                    Address found = memory.findBytes(block.getStart(), block.getEnd(), badLengthSearch, null, true, ctx.monitor);
                    if (found != null) { badLengthAddr = found; break; }
                } catch (Exception e) { }
            }

            int badLengthReasonCode = -1;
            if (badLengthAddr != null) {
                byte[] badLengthAddrBytes = memUtils.addressToBytes(badLengthAddr, pointerSize);
                Address badLengthTableEntry = null;
                for (MemoryBlock block : memory.getBlocks()) {
                    if (!block.isRead()) continue;
                    try {
                        Address found = memory.findBytes(block.getStart(), block.getEnd(), badLengthAddrBytes, null, true, ctx.monitor);
                        if (found != null) { badLengthTableEntry = found; break; }
                    } catch (Exception e) { }
                }

                if (badLengthTableEntry != null) {
                    Address blErrorCodeAddr = badLengthTableEntry.subtract(pointerSize);
                    long blPackedValue = 0;
                    if (pointerSize == 8) {
                        blPackedValue = memory.getLong(blErrorCodeAddr);
                    } else {
                        blPackedValue = memory.getInt(blErrorCodeAddr) & 0xFFFFFFFFL;
                    }
                    badLengthReasonCode = (int) (blPackedValue & 0xFFFFFF);
                    if (badLengthReasonCode == 0) {
                        badLengthReasonCode = (int) blPackedValue;
                    }
                    if (debugRun) {
                        System.out.println("[!] BAD_LENGTH reason code: " + badLengthReasonCode);
                    }
                }
            }

            // Scan instructions for functions using these error codes
            Set<Function> uninitFunctions = new HashSet<>();
            Set<Function> badLengthFunctions = new HashSet<>();

            for (MemoryBlock block : memory.getBlocks()) {
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
                                if (val == reasonCode) {
                                    Function func = ctx.getFunctionContaining.apply(inst.getAddress());
                                    if (func != null) uninitFunctions.add(func);
                                }
                                if (badLengthReasonCode > 0 && val == badLengthReasonCode) {
                                    Function func = ctx.getFunctionContaining.apply(inst.getAddress());
                                    if (func != null) badLengthFunctions.add(func);
                                }
                            }
                        }
                    }
                }
            }

            if (debugRun) {
                System.out.println("[!] Functions with UNINITIALIZED code: " + uninitFunctions.size());
                System.out.println("[!] Functions with BAD_LENGTH code: " + badLengthFunctions.size());
            }

            if (identifiedSSLWrite == null && !badLengthFunctions.isEmpty()) {
                Set<Function> writeCandidates = new HashSet<>(uninitFunctions);
                writeCandidates.retainAll(badLengthFunctions);
                if (!writeCandidates.isEmpty()) {
                    identifiedSSLWrite = writeCandidates.iterator().next();
                }
            }

            // Save read impl candidate for read finder
            Set<Function> readImplCandidates = new HashSet<>(uninitFunctions);
            readImplCandidates.removeAll(badLengthFunctions);
            if (!readImplCandidates.isEmpty()) {
                errorCodeTableScanReadImpl = readImplCandidates.iterator().next();
            }

        } catch (MemoryAccessException e) {
            if (debugRun) {
                System.out.println("[!] Memory access error in ErrorCodeTableScan: " + e.getMessage());
            }
        }
    }

    private void tryPackedErrorCodeFallback(Memory memory, SSLReadWriteHelper helper) {
        byte[] packedUninit = new byte[] {(byte)0xE2, 0x00, 0x40, 0x01};
        byte[] packedBadLen = new byte[] {(byte)0x0F, 0x01, 0x40, 0x01};

        boolean foundPackedCodes = false;
        for (MemoryBlock block : memory.getBlocks()) {
            if (!block.isRead()) continue;
            try {
                Address foundUninit = memory.findBytes(block.getStart(), block.getEnd(), packedUninit, null, true, ctx.monitor);
                if (foundUninit != null) {
                    Address searchEnd = foundUninit.add(Math.min(4096, block.getEnd().subtract(foundUninit)));
                    Address foundBadLen = memory.findBytes(foundUninit, searchEnd, packedBadLen, null, true, ctx.monitor);
                    if (foundBadLen != null) {
                        foundPackedCodes = true;
                    }
                }
            } catch (Exception e) { }
        }

        if (!foundPackedCodes) {
            if (debugRun) {
                System.out.println("[!] Packed code search also failed");
            }
            return;
        }

        int reasonCode = 226;
        int badLengthReasonCode = 271;

        Set<Function> uninitFunctions = new HashSet<>();
        Set<Function> badLengthFunctions = new HashSet<>();

        for (MemoryBlock block : memory.getBlocks()) {
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
                            if (val == reasonCode) {
                                Function func = ctx.getFunctionContaining.apply(inst.getAddress());
                                if (func != null) uninitFunctions.add(func);
                            }
                            if (val == badLengthReasonCode) {
                                Function func = ctx.getFunctionContaining.apply(inst.getAddress());
                                if (func != null) badLengthFunctions.add(func);
                            }
                        }
                    }
                }
            }
        }

        if (identifiedSSLWrite == null && !badLengthFunctions.isEmpty()) {
            Set<Function> writeCandidates = new HashSet<>(uninitFunctions);
            writeCandidates.retainAll(badLengthFunctions);
            if (!writeCandidates.isEmpty()) {
                identifiedSSLWrite = writeCandidates.iterator().next();
            }
        }

        // Save read impl for read finder
        Set<Function> readImplCandidates = new HashSet<>(uninitFunctions);
        readImplCandidates.removeAll(badLengthFunctions);
        if (!readImplCandidates.isEmpty()) {
            errorCodeTableScanReadImpl = readImplCandidates.iterator().next();
        }
    }

    public void strategyNameFallback(Function prevWrite, Function prevRead, SSLReadWriteHelper helper) {
        if (debugRun) {
            System.out.println("[!] NameFallback: searching for SSL_write/SSL_read by exact name...");
        }

        String[] writeNames = {"SSL_write", "_SSL_write", "ssl_write", "_ssl_write"};
        String[] readNames = {"SSL_read", "_SSL_read", "ssl_read", "_ssl_read"};

        Function foundWrite = null;
        Function foundRead = null;

        FunctionIterator funcIter = ctx.program.getFunctionManager().getFunctions(true);
        while (funcIter.hasNext()) {
            Function func = funcIter.next();
            String name = func.getName();

            if (foundWrite == null) {
                for (String wn : writeNames) {
                    if (name.equals(wn)) {
                        foundWrite = func;
                        break;
                    }
                }
            }

            if (foundRead == null) {
                for (String rn : readNames) {
                    if (name.equals(rn)) {
                        foundRead = func;
                        break;
                    }
                }
            }

            if (foundWrite != null && foundRead != null) break;
        }

        // NameFallback overrides previous heuristic identifications
        identifiedSSLWrite = (foundWrite != null) ? foundWrite : prevWrite;
        // Also update SSLReadFinder through the helper
        if (foundRead != null) {
            helper.setIdentifiedSSLRead(foundRead);
        } else if (prevRead != null) {
            helper.setIdentifiedSSLRead(prevRead);
        }
    }
}
