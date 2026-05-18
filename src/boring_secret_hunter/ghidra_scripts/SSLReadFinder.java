import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;

import java.util.*;

/**
 * All SSL_read-specific identification logic.
 */
public class SSLReadFinder {

    private final GhidraContext ctx;
    private final MemorySearchUtils memUtils;
    private final FunctionAnalysisUtils analysisUtils;
    private final boolean debugRun;

    private Function identifiedSSLRead = null;

    public SSLReadFinder(GhidraContext ctx, MemorySearchUtils memUtils,
                         FunctionAnalysisUtils analysisUtils, boolean debugRun) {
        this.ctx = ctx;
        this.memUtils = memUtils;
        this.analysisUtils = analysisUtils;
        this.debugRun = debugRun;
    }

    public Function getIdentified() { return identifiedSSLRead; }
    public void setIdentified(Function func) { this.identifiedSSLRead = func; }

    public void strategySymbolTableLookup() {
        if (identifiedSSLRead != null) return;
        SymbolTable symbolTable = ctx.program.getSymbolTable();
        String[] readNames = {"SSL_read", "ssl_read"};

        for (String name : readNames) {
            if (identifiedSSLRead != null) break;
            for (Symbol symbol : symbolTable.getGlobalSymbols(name)) {
                Function func = ctx.getFunctionAt.apply(symbol.getAddress());
                if (func != null) {
                    if (debugRun) {
                        System.out.println("[!] Symbol match for SSL_read: " + name + " at " + symbol.getAddress());
                    }
                    identifiedSSLRead = func;
                    break;
                }
            }
        }
    }

    public void tryErrorStringFingerprinting(Set<Function> uninitializedFuncs, Set<Function> badLengthFuncs,
                                             Set<Function> connectionTypeFuncs, Set<Function> protocolShutdownFuncs,
                                             Function currentRead, SSLReadWriteHelper helper) {
        if (currentRead != null) { identifiedSSLRead = currentRead; return; }

        Set<Function> readImplCandidates = new HashSet<>(uninitializedFuncs);
        readImplCandidates.removeAll(badLengthFuncs);
        readImplCandidates.removeAll(connectionTypeFuncs);
        readImplCandidates.removeAll(protocolShutdownFuncs);

        Function sslReadImpl = null;
        if (!readImplCandidates.isEmpty()) {
            sslReadImpl = readImplCandidates.iterator().next();
            if (debugRun) {
                System.out.println("[!] ssl_read_impl candidate: " + sslReadImpl.getName());
            }
        }

        if (sslReadImpl != null) {
            Function sslPeek = findCallerBySize(sslReadImpl, false);
            if (sslPeek != null) {
                if (debugRun) {
                    System.out.println("[!] SSL_peek candidate: " + sslPeek.getName());
                }
                Function sslRead = findSSLReadAmongCallers(sslPeek);
                if (sslRead != null) {
                    identifiedSSLRead = sslRead;
                }
            }
        }
    }

    public void tryNumericErrorCodeFingerprinting(Set<Function> sslReadImplCandidates,
                                                  Function currentRead, SSLReadWriteHelper helper) {
        if (currentRead != null) { identifiedSSLRead = currentRead; return; }
        if (sslReadImplCandidates.isEmpty()) return;

        Function sslReadImpl = sslReadImplCandidates.iterator().next();
        if (debugRun) {
            System.out.println("[!] NumericErrorCodeFP: ssl_read_impl candidate: " + sslReadImpl.getName());
        }

        Function sslPeek = findCallerBySize(sslReadImpl, false);
        if (sslPeek != null) {
            if (debugRun) {
                System.out.println("[!] NumericErrorCodeFP: SSL_peek candidate: " + sslPeek.getName());
            }
            Function sslRead = findSSLReadAmongCallers(sslPeek);
            if (sslRead != null) {
                identifiedSSLRead = sslRead;
                if (debugRun) {
                    System.out.println("[!] NumericErrorCodeFP: identified SSL_read = " + identifiedSSLRead.getName());
                }
            }
        }
    }

    public void tryERRPutErrorCallerAnalysis(List<Function> smallUninitCallers,
                                             Set<Function> callersWithUninit,
                                             Function identifiedSSLWrite,
                                             Function currentRead, SSLReadWriteHelper helper) {
        if (currentRead != null) { identifiedSSLRead = currentRead; return; }

        // Find SSL_read via ssl_can_read tracing
        if (!smallUninitCallers.isEmpty()) {
            Set<Function> sslWriteCallees = (identifiedSSLWrite != null) ?
                analysisUtils.getCalledFunctions(identifiedSSLWrite) : new HashSet<>();

            for (Function sslCanFunc : smallUninitCallers) {
                if (identifiedSSLWrite != null && sslWriteCallees.contains(sslCanFunc)) continue;

                Address canReadEntry = sslCanFunc.getEntryPoint();
                ReferenceIterator canReadRefs = ctx.program.getReferenceManager().getReferencesTo(canReadEntry);
                while (canReadRefs.hasNext()) {
                    Reference ref2 = canReadRefs.next();
                    if (!ref2.getReferenceType().isCall()) continue;
                    Function sslReadImpl = ctx.getFunctionContaining.apply(ref2.getFromAddress());
                    if (sslReadImpl == null) continue;
                    if (sslReadImpl.equals(identifiedSSLWrite)) continue;
                    if (analysisUtils.isLikelyNonSSLFunction(sslReadImpl)) continue;
                    long bodySize = sslReadImpl.getBody().getNumAddresses();
                    if (bodySize < 40 || bodySize > 3000) continue;

                    if (debugRun) {
                        System.out.println("[!] ERRPutErrorCallerAnalysis: ssl_read_impl candidate: " +
                            sslReadImpl.getName() + " (size=" + bodySize + ")");
                    }

                    Function sslPeek = findCallerBySize(sslReadImpl, false);
                    if (sslPeek != null) {
                        if (debugRun) {
                            System.out.println("[!] ERRPutErrorCallerAnalysis: SSL_peek candidate: " +
                                sslPeek.getName());
                        }
                        Function sslRead = findSSLReadAmongCallers(sslPeek);
                        if (sslRead != null) {
                            identifiedSSLRead = sslRead;
                            break;
                        }
                    }
                }
                if (identifiedSSLRead != null) break;
            }
        }

        // Fallback: use any large uninit caller as ssl_read_impl
        if (identifiedSSLRead == null) {
            for (Function func : callersWithUninit) {
                if (func.equals(identifiedSSLWrite)) continue;
                if (analysisUtils.isLikelyNonSSLFunction(func)) continue;
                long bodySize = func.getBody().getNumAddresses();
                if (bodySize < 200 || bodySize > 3000) continue;

                if (debugRun) {
                    System.out.println("[!] ERRPutErrorCallerAnalysis: fallback ssl_read_impl: " +
                        func.getName());
                }
                Function sslPeek = findCallerBySize(func, false);
                if (sslPeek != null) {
                    Function sslRead = findSSLReadAmongCallers(sslPeek);
                    if (sslRead != null && !analysisUtils.isLikelyNonSSLFunction(sslRead)) {
                        identifiedSSLRead = sslRead;
                        break;
                    }
                }
            }
        }
    }

    public void tryCallGraphTracing(Set<Function> allCallers, Function currentRead, SSLReadWriteHelper helper) {
        if (currentRead != null) { identifiedSSLRead = currentRead; return; }

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

            if (bodySize < 500) {
                if (score > bestScore) {
                    bestScore = score;
                    bestCandidate = func;
                }
            }
        }

        if (bestCandidate != null) {
            identifiedSSLRead = bestCandidate;
        }
    }

    public void tryAdjacentFunctionScanning(List<Function> nearbyFunctions, long anchorOffset,
                                            long windowSize, Function tls13label,
                                            Function currentRead, SSLReadWriteHelper helper) {
        if (currentRead != null) { identifiedSSLRead = currentRead; return; }

        Function bestCandidate = null;
        int bestScore = -1;

        for (Function func : nearbyFunctions) {
            if (func.equals(tls13label)) continue;
            if (analysisUtils.isLikelyNonSSLFunction(func)) continue;

            int paramCount = func.getParameterCount();
            long bodySize = func.getBody().getNumAddresses();
            int callerCount = analysisUtils.countXRefs(func);

            if (paramCount > 5 || callerCount < 1 || bodySize < 40 || bodySize > 500) continue;

            // Cap xref contribution to prevent utility functions from dominating
            int score = Math.min(callerCount, 10);

            // Parameter bonus: SSL_read takes exactly 3 params (SSL*, buf, len)
            if (paramCount == 3) score += 10;

            // Proximity bonus
            long distance = Math.abs(func.getEntryPoint().getOffset() - anchorOffset);
            score += (int)(20.0 * (1.0 - (double)distance / windowSize));

            // Call chain bonus: detect SSL_read → SSL_peek (40-200 bytes) → ssl_read_impl (>200 bytes)
            // This 3-level structure is highly distinctive — utility functions don't have it
            Set<Function> callees = analysisUtils.getCalledFunctions(func);
            for (Function callee : callees) {
                long calleeSize = callee.getBody().getNumAddresses();
                if (calleeSize >= 40 && calleeSize <= 200) {
                    Set<Function> innerCallees = analysisUtils.getCalledFunctions(callee);
                    for (Function inner : innerCallees) {
                        if (inner.getBody().getNumAddresses() > 200) {
                            score += 20;
                            break;
                        }
                    }
                    break;
                }
            }

            // Body size sweet-spot bonus
            if (bodySize >= 40 && bodySize <= 200) score += 5;

            // Utility penalty: high-xref functions are unlikely to be SSL_read
            if (callerCount > 20) score -= 10;

            if (debugRun) {
                System.out.println("[!] AdjacentScan SSL_read candidate: " + func.getName() +
                    " score=" + score + " callers=" + callerCount + " bodySize=" + bodySize);
            }

            if (score > bestScore) {
                bestScore = score;
                bestCandidate = func;
            }
        }

        if (bestCandidate != null) {
            identifiedSSLRead = bestCandidate;
        }
    }

    public void tryConstantFingerprinting(Set<Function> candidates, Set<Function> callerCandidates,
                                          Function currentRead, SSLReadWriteHelper helper) {
        if (currentRead != null) { identifiedSSLRead = currentRead; return; }

        Function bestCandidate = null;
        long bestSize = Long.MAX_VALUE;

        // Tier 1: callerCandidates
        for (Function func : callerCandidates) {
            if (analysisUtils.isLikelyNonSSLFunction(func)) continue;
            long bodySize = func.getBody().getNumAddresses();
            if (bodySize >= 40 && bodySize < 500 && bodySize < bestSize) {
                bestSize = bodySize;
                bestCandidate = func;
            }
        }

        // Tier 2: direct constant users
        if (bestCandidate == null) {
            for (Function func : candidates) {
                long bodySize = func.getBody().getNumAddresses();
                int callerCount = analysisUtils.countXRefs(func);
                if (callerCount < 1) continue;
                if (analysisUtils.isLikelyNonSSLFunction(func)) continue;

                if (bodySize >= 40 && bodySize < 500 && bodySize < bestSize) {
                    bestSize = bodySize;
                    bestCandidate = func;
                }
            }
        }

        if (bestCandidate != null) {
            identifiedSSLRead = bestCandidate;
        }
    }

    public void tryFunctionSignatureAnalysis(List<GhidraContext.Pair<Function, Long>> candidates,
                                             Function currentRead, SSLReadWriteHelper helper) {
        if (currentRead != null) { identifiedSSLRead = currentRead; return; }

        Function bestRead = null;
        long bestReadSize = Long.MAX_VALUE;

        for (GhidraContext.Pair<Function, Long> entry : candidates) {
            Function func = entry.getFirst();
            long bodySize = entry.getSecond();

            if (bodySize >= 40 && bodySize < 500 && bodySize < bestReadSize) {
                bestReadSize = bodySize;
                bestRead = func;
            }
        }

        if (bestRead != null) {
            identifiedSSLRead = bestRead;
        }
    }

    public void setIdentifiedFromErrorCodeTableScan(Function readImplCandidate,
                                                    Function currentRead, SSLReadWriteHelper helper) {
        if (currentRead != null) { identifiedSSLRead = currentRead; return; }
        if (readImplCandidate == null) return;

        if (debugRun) {
            System.out.println("[!] ssl_read_impl candidate from error codes: " + readImplCandidate.getName());
        }

        Function sslPeek = findCallerBySize(readImplCandidate, false);
        if (sslPeek != null) {
            Function sslRead = findSSLReadAmongCallers(sslPeek);
            if (sslRead != null) {
                identifiedSSLRead = sslRead;
            }
        }
    }

    /**
     * When SSL_write is found but SSL_read is not, search within 4KB of SSL_write.
     * In BoringSSL, both are compiled from ssl_lib.cc and always appear close together.
     * All criteria are structural — they work on FUN_xxxxx named functions.
     */
    public void trySSLWriteRelativeSearch(Function sslWrite) {
        if (identifiedSSLRead != null || sslWrite == null) return;

        Address writeAddr = sslWrite.getEntryPoint();
        long writeOffset = writeAddr.getOffset();
        long searchWindow = 4096;

        Function bestCandidate = null;
        int bestScore = -1;

        for (Function func : ctx.program.getFunctionManager().getFunctions(true)) {
            if (func.equals(sslWrite)) continue;

            long funcOffset = func.getEntryPoint().getOffset();
            long distance = Math.abs(funcOffset - writeOffset);
            if (distance > searchWindow) continue;

            if (analysisUtils.isLikelyNonSSLFunction(func)) continue;

            int paramCount = func.getParameterCount();
            long bodySize = func.getBody().getNumAddresses();
            int callerCount = analysisUtils.countXRefs(func);

            if (paramCount > 5 || callerCount < 1 || bodySize < 40 || bodySize > 500) continue;

            int score = 0;

            // Proximity to SSL_write (max +20)
            score += (int)(20.0 * (1.0 - (double)distance / searchWindow));

            // Parameter bonus: SSL_read takes exactly 3 params
            if (paramCount == 3) score += 15;

            // Call chain pattern: func → callee(30-300 bytes) → inner callee(>200 bytes)
            Set<Function> callees = analysisUtils.getCalledFunctions(func);
            for (Function callee : callees) {
                long calleeSize = callee.getBody().getNumAddresses();
                if (calleeSize >= 30 && calleeSize <= 300) {
                    Set<Function> innerCallees = analysisUtils.getCalledFunctions(callee);
                    for (Function inner : innerCallees) {
                        if (inner.getBody().getNumAddresses() > 200) {
                            score += 25;
                            break;
                        }
                    }
                    break;
                }
            }

            // Body size sweet-spot bonus
            if (bodySize >= 40 && bodySize <= 150) score += 5;

            // Utility penalty
            if (callerCount > 20) score -= 10;

            if (debugRun) {
                System.out.println("[!] SSLWriteRelativeSearch: candidate " + func.getName() +
                    " score=" + score + " distance=" + distance + " callers=" + callerCount +
                    " bodySize=" + bodySize);
            }

            if (score > bestScore) {
                bestScore = score;
                bestCandidate = func;
            }
        }

        if (bestCandidate != null) {
            if (debugRun) {
                System.out.println("[!] SSLWriteRelativeSearch: selected " + bestCandidate.getName() +
                    " with score " + bestScore);
            }
            identifiedSSLRead = bestCandidate;
        }
    }

    // ========== SSL_read-specific helper methods ==========

    public Function findSSLReadAmongCallers(Function sslPeek) {
        Address entry = sslPeek.getEntryPoint();
        ReferenceIterator refIter = ctx.program.getReferenceManager().getReferencesTo(entry);

        Function bestCandidate = null;
        long smallestSize = Long.MAX_VALUE;

        while (refIter.hasNext()) {
            Reference ref = refIter.next();
            if (ref.getReferenceType().isCall()) {
                Function caller = ctx.getFunctionContaining.apply(ref.getFromAddress());
                if (caller != null) {
                    long bodySize = caller.getBody().getNumAddresses();
                    if (bodySize < smallestSize && bodySize < 200) {
                        smallestSize = bodySize;
                        bestCandidate = caller;
                    }
                }
            }
        }
        return bestCandidate;
    }

    public Function findCallerBySize(Function target, boolean preferSmall) {
        Address entry = target.getEntryPoint();
        ReferenceIterator refIter = ctx.program.getReferenceManager().getReferencesTo(entry);

        List<Function> callers = new ArrayList<>();
        while (refIter.hasNext()) {
            Reference ref = refIter.next();
            if (ref.getReferenceType().isCall()) {
                Function caller = ctx.getFunctionContaining.apply(ref.getFromAddress());
                if (caller != null && !caller.equals(target)) {
                    callers.add(caller);
                }
            }
        }

        if (callers.isEmpty()) return null;
        if (callers.size() == 1) return callers.get(0);

        Function best = null;
        int bestCallerCount = 0;
        for (Function f : callers) {
            int callerCount = analysisUtils.countXRefs(f);
            if (callerCount >= 2 && (best == null || callerCount < bestCallerCount + 5)) {
                best = f;
                bestCallerCount = callerCount;
            }
        }
        return best != null ? best : callers.get(0);
    }
}
