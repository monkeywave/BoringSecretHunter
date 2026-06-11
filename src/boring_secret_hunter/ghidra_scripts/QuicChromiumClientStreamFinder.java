import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;

import java.util.*;

/**
 * Finds chrome-shim QUIC stream functions defined in
 * net/quic/quic_chromium_client_stream.cc. Chrome-shim layer sits above
 * third_party/quiche and lives in a different translation unit, so its
 * inlining decisions are independent: when quiche's QuicSpdyStream::WriteHeaders
 * is inlined out, the chrome-shim version typically survives (and vice-versa).
 *
 * Targets:
 *   - net::QuicChromiumClientStream::WriteHeaders
 *       (this, quiche::HttpHeaderBlock, bool fin,
 *        quiche::QuicheReferenceCountedPointer&lt;quic::QuicAckListenerInterface&gt;)
 *
 * Strategy chain:
 *   1. CallerOfQuicheWriteHeaders — given the already-identified quiche-internal
 *      QuicSpdyStream::WriteHeaders, find functions that BL to it AND reside in
 *      the chrome-shim cluster (XREF the chrome-shim file path or a
 *      Net.QuicChromiumClientStream.* histogram name). Most specific anchor.
 *   2. ChromeShimStructural — pure structural match within the chrome-shim
 *      cluster: 4-arg save (this, HttpHeaderBlock, fin, AckListener) with an
 *      immediate "load wrapped QuicSpdyStream from this+offset" pattern.
 */
public class QuicChromiumClientStreamFinder {

    private final GhidraContext ctx;
    private final MemorySearchUtils memUtils;
    private final FunctionAnalysisUtils analysisUtils;
    private final boolean debugRun;

    private static final String CHROMIUM_CLIENT_STREAM_TU = "quic_chromium_client_stream.cc";
    private static final String[] CHROMIUM_CLIENT_STREAM_UMA_ANCHORS = {
        "Net.QuicChromiumClientStream.HeaderDecodingDelay",
        "Net.QuicChromiumClientStream.TrailingHeadersProcessSuccess",
        "Net.QuicChromiumClientStream.HandleOnCloseNetError",
    };

    private Function identifiedWriteHeaders = null;
    private String writeHeadersStrategy = null;

    public QuicChromiumClientStreamFinder(GhidraContext ctx, MemorySearchUtils memUtils,
                                          FunctionAnalysisUtils analysisUtils, boolean debugRun) {
        this.ctx = ctx;
        this.memUtils = memUtils;
        this.analysisUtils = analysisUtils;
        this.debugRun = debugRun;
    }

    public Function getWriteHeaders() { return identifiedWriteHeaders; }
    public String getWriteHeadersStrategy() { return writeHeadersStrategy; }

    /**
     * Discover the chrome-shim cluster: union of functions that reference the
     * chrome-shim file path OR any of the chrome-shim UMA histogram strings.
     * Together, these XREFs land in multiple sibling methods of the same
     * QuicChromiumClientStream class which the linker emits contiguously in
     * .text.
     */
    private Set<Function> getChromeShimCluster() {
        Set<Function> cluster = new HashSet<>();
        cluster.addAll(memUtils.findAllFunctionsReferencingString(CHROMIUM_CLIENT_STREAM_TU));
        for (String uma : CHROMIUM_CLIENT_STREAM_UMA_ANCHORS) {
            cluster.addAll(memUtils.findAllFunctionsReferencingString(uma));
        }
        return cluster;
    }

    /**
     * Strategy 1: find the function that BL-targets the already-identified
     * quiche-internal QuicSpdyStream::WriteHeaders. The chrome-shim WriteHeaders
     * is its primary caller (the shim forwards to it after a header-validation
     * step). Optionally intersect with the chrome-shim cluster for confidence.
     */
    public void findWriteHeaders(Function quicheInternalWriteHeaders) {
        if (quicheInternalWriteHeaders == null) {
            if (debugRun) {
                System.out.println("[!] QuicChromiumClientStream::WriteHeaders: no quiche-internal "
                    + "WriteHeaders identified — falling back to ChromeShimStructural.");
            }
            findWriteHeadersStructural();
            return;
        }

        // Ghidra's native call-graph: who calls quiche-internal WriteHeaders?
        Set<Function> callers = quicheInternalWriteHeaders.getCallingFunctions(ctx.monitor);
        if (debugRun) {
            System.out.println("[!] QuicChromiumClientStream::WriteHeaders: callers of "
                + "quiche-internal WriteHeaders: " + callers.size());
        }

        Set<Function> cluster = getChromeShimCluster();
        if (debugRun) {
            System.out.println("[!] QuicChromiumClientStream::WriteHeaders: chrome-shim cluster: "
                + cluster.size());
        }

        // Intersect callers ∩ cluster — the chrome-shim WriteHeaders should be
        // in both sets. If exactly one candidate, accept.
        Set<Function> intersection = new HashSet<>(callers);
        intersection.retainAll(cluster);
        if (debugRun) {
            System.out.println("[!] QuicChromiumClientStream::WriteHeaders: callers ∩ cluster: "
                + intersection.size());
            for (Function f : intersection) {
                System.out.println("[!]   candidate " + f.getEntryPoint() + " ("
                    + f.getBody().getNumAddresses() + " bytes, params=" + f.getParameterCount() + ")");
            }
        }
        if (intersection.size() == 1) {
            identifiedWriteHeaders = intersection.iterator().next();
            writeHeadersStrategy = "CallerOfQuicheWriteHeadersInChromeShimCluster";
            return;
        }
        // If exactly one caller exists outside the cluster (cluster may be
        // empty if both anchor strings are stripped), accept the sole caller.
        if (callers.size() == 1) {
            Function sole = callers.iterator().next();
            if (matchesChromeShimWriteHeadersIdiom(sole)) {
                identifiedWriteHeaders = sole;
                writeHeadersStrategy = "SoleCallerOfQuicheWriteHeaders";
                return;
            }
        }
        // Multiple callers (rare — possible if other places also call WriteHeaders):
        // narrow to those matching the chrome-shim ABI idiom.
        if (intersection.size() > 1) {
            List<Function> matches = new ArrayList<>();
            for (Function f : intersection) {
                if (matchesChromeShimWriteHeadersIdiom(f)) matches.add(f);
            }
            if (matches.size() == 1) {
                identifiedWriteHeaders = matches.get(0);
                writeHeadersStrategy = "CallerIntersectionAbiNarrowed";
                return;
            }
        }
        // Final fallback.
        findWriteHeadersStructural();
    }

    /**
     * Strategy 2 (fallback): pure structural within the chrome-shim cluster.
     * Find a function with:
     *   - the chrome-shim ABI signature (saves x0/x1/w2/x3 to callee-preserves),
     *   - an early "ldr x0, [x0, #N]" (load wrapped QuicSpdyStream from this),
     *   - body 40..2000 bytes.
     */
    private void findWriteHeadersStructural() {
        Set<Function> cluster = getChromeShimCluster();
        List<Function> matches = new ArrayList<>();
        for (Function func : cluster) {
            if (matchesChromeShimWriteHeadersIdiom(func)) matches.add(func);
        }
        if (debugRun) {
            System.out.println("[!] QuicChromiumClientStream::WriteHeaders structural matches: "
                + matches.size());
            for (Function f : matches) {
                System.out.println("[!]   candidate " + f.getEntryPoint() + " ("
                    + f.getBody().getNumAddresses() + " bytes)");
            }
        }
        if (matches.size() == 1) {
            identifiedWriteHeaders = matches.get(0);
            writeHeadersStrategy = "ChromeShimStructural";
        }
    }

    /**
     * Chrome-shim WriteHeaders ABI idiom:
     *   - body 40..2000 bytes,
     *   - non-void return (returns int),
     *   - prologue contains BOTH "mov x19, x0" (save this) AND
     *     "ldr x0, [x0, #imm]" within the first 16 instructions, AND
     *   - bool-ish w2 reference somewhere in the body,
     *   - dereferences args[1] (the HttpHeaderBlock) at least once.
     */
    private boolean matchesChromeShimWriteHeadersIdiom(Function func) {
        long bodySize = func.getBody().getNumAddresses();
        if (bodySize < 40 || bodySize > 2000) return false;
        if (func.getReturnType() != null
            && "void".equalsIgnoreCase(func.getReturnType().getName())) {
            return false;
        }

        Listing listing = ctx.program.getListing();
        AddressSetView body = func.getBody();
        InstructionIterator instrs = listing.getInstructions(body, true);

        boolean saveThis = false;
        boolean loadFromThis = false;
        boolean usesW2 = false;
        boolean derefHeaderBlock = false;
        int seen = 0;

        while (instrs.hasNext()) {
            Instruction inst = instrs.next();
            String mnem = inst.getMnemonicString().toLowerCase();
            String text = inst.toString().toLowerCase();
            seen++;

            if (seen <= 16) {
                if (mnem.equals("mov") && text.contains("x0") && text.contains("x19")) {
                    saveThis = true;
                }
                if (mnem.equals("ldr") && (text.contains("[x0,") || text.contains("[x19,"))
                    && text.contains("x0")) {
                    loadFromThis = true;
                }
            }
            if (mnem.equals("ldr") && (text.contains("[x1]") || text.contains("[x1,"))) {
                derefHeaderBlock = true;
            }
            if (text.contains("w2")) {
                usesW2 = true;
            }
        }
        return saveThis && loadFromThis && (derefHeaderBlock || usesW2);
    }
}
