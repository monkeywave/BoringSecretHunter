import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;

import java.util.*;

/**
 * Finds the Google QUICHE targets defined in
 * quiche/quic/core/quic_stream_sequencer.cc:
 *   - QuicStreamSequencer::OnStreamFrame (distinctive rodata strings)
 *   - QuicStreamSequencer::Readv         (structural; adjacent-after OnStreamFrame)
 *
 * Mirrors the concrete-finder shape of SSLReadFinder / SSLWriteFinder.
 */
public class QuicStreamSequencerFinder {

    private static final String SEQUENCER_TU = "quiche/quic/core/quic_stream_sequencer.cc";

    private final GhidraContext ctx;
    private final MemorySearchUtils memUtils;
    private final FunctionAnalysisUtils analysisUtils;
    private final boolean debugRun;

    private Function identifiedOnStreamFrame = null;
    private Function identifiedReadv = null;
    private String onStreamFrameStrategy = null;
    private String readvStrategy = null;

    public QuicStreamSequencerFinder(GhidraContext ctx, MemorySearchUtils memUtils,
                                     FunctionAnalysisUtils analysisUtils, boolean debugRun) {
        this.ctx = ctx;
        this.memUtils = memUtils;
        this.analysisUtils = analysisUtils;
        this.debugRun = debugRun;
    }

    public Function getOnStreamFrame() { return identifiedOnStreamFrame; }
    public Function getReadv() { return identifiedReadv; }
    public String getOnStreamFrameStrategy() { return onStreamFrameStrategy; }
    public String getReadvStrategy() { return readvStrategy; }

    // ========== QuicStreamSequencer::OnStreamFrame ==========

    /**
     * Distinctive rodata strings are referenced from OnStreamFrame. Intersect
     * the referencing-function sets of several of those strings to isolate it.
     */
    public void findOnStreamFrame() {
        String[] anchorStrings = {
            "quic.stream_sequencer_invalid_state",
            " received new final offset: ",
            ", which is different from close offset: ",
            " received fin with offset: ",
            ", which reduces current highest offset: "
        };

        // Collect referencing-function sets for each anchor string.
        List<Set<Function>> sets = new ArrayList<>();
        for (String s : anchorStrings) {
            Set<Function> refs = memUtils.findAllFunctionsReferencingString(s);
            if (debugRun) {
                System.out.println("[!] OnStreamFrame: '" + s + "' referenced by " + refs.size() + " functions");
            }
            if (!refs.isEmpty()) {
                sets.add(refs);
            }
        }

        if (sets.isEmpty()) {
            if (debugRun) {
                System.out.println("[!] OnStreamFrame: no anchor strings referenced");
            }
            return;
        }

        // Tally how many anchor sets each function appears in; the function in
        // the most sets is OnStreamFrame (these offset-log strings co-occur there).
        Map<Function, Integer> tally = new HashMap<>();
        for (Set<Function> set : sets) {
            for (Function f : set) {
                tally.merge(f, 1, Integer::sum);
            }
        }

        Function best = null;
        int bestCount = 0;
        for (Map.Entry<Function, Integer> e : tally.entrySet()) {
            if (e.getValue() > bestCount) {
                bestCount = e.getValue();
                best = e.getKey();
            }
        }

        if (debugRun && best != null) {
            System.out.println("[!] OnStreamFrame: best candidate " + best.getEntryPoint()
                + " appears in " + bestCount + "/" + sets.size() + " anchor sets ("
                + best.getBody().getNumAddresses() + " bytes)");
        }

        // Require co-occurrence in at least two distinct anchor sets to avoid a
        // single-string false positive.
        if (best != null && bestCount >= 2) {
            identifiedOnStreamFrame = best;
            onStreamFrameStrategy = "StringIntersection";
        } else if (best != null && sets.size() == 1) {
            // Only the highly-distinctive invalid_state string resolved; accept it.
            identifiedOnStreamFrame = best;
            onStreamFrameStrategy = "DistinctiveStringAnchor";
        }
    }

    // ========== QuicStreamSequencer::Readv ==========

    /**
     * No unique string. Structural: medium function (~380 B) defined in
     * quic_stream_sequencer.cc, immediately adjacent (just after) OnStreamFrame.
     * Among functions referencing the sequencer TU path, pick the one that is
     * adjacent-after OnStreamFrame with param count 2 and a medium body.
     */
    public void findReadv() {
        if (identifiedOnStreamFrame == null) {
            if (debugRun) {
                System.out.println("[!] Readv: OnStreamFrame not identified, cannot anchor adjacency");
            }
            return;
        }

        // Functions that reference the sequencer source-path string (same TU).
        Set<Function> tuFuncs = memUtils.findAllFunctionsReferencingString(SEQUENCER_TU);
        if (debugRun) {
            System.out.println("[!] Readv: functions referencing '" + SEQUENCER_TU + "': " + tuFuncs.size());
        }

        long anchorOffset = identifiedOnStreamFrame.getEntryPoint().getOffset();

        // Find the function whose entry is the smallest offset strictly greater
        // than OnStreamFrame's entry (immediately adjacent-after).
        Function adjacentAfter = null;
        long bestDelta = Long.MAX_VALUE;
        for (Function func : ctx.program.getFunctionManager().getFunctions(true)) {
            long delta = func.getEntryPoint().getOffset() - anchorOffset;
            if (delta > 0 && delta < bestDelta) {
                bestDelta = delta;
                adjacentAfter = func;
            }
        }

        if (adjacentAfter == null) {
            if (debugRun) {
                System.out.println("[!] Readv: no function found after OnStreamFrame");
            }
            return;
        }

        if (debugRun) {
            System.out.println("[!] Readv: adjacent-after candidate " + adjacentAfter.getEntryPoint()
                + " (" + adjacentAfter.getBody().getNumAddresses() + " bytes, params="
                + adjacentAfter.getParameterCount() + ")");
        }

        if (isReadvCandidate(adjacentAfter, tuFuncs)) {
            identifiedReadv = adjacentAfter;
            readvStrategy = "AdjacentAfterOnStreamFrame";
            return;
        }

        // Fallback: among TU functions, pick the one closest after OnStreamFrame
        // that satisfies the structural band.
        Function best = null;
        long bestFallbackDelta = Long.MAX_VALUE;
        for (Function func : tuFuncs) {
            long delta = func.getEntryPoint().getOffset() - anchorOffset;
            if (delta > 0 && delta < bestFallbackDelta && isReadvCandidate(func, tuFuncs)) {
                bestFallbackDelta = delta;
                best = func;
            }
        }
        if (best != null) {
            identifiedReadv = best;
            readvStrategy = "TUNearestAfterOnStreamFrame";
        }
    }

    /**
     * Structural sanity for Readv: param count 2 (iovec*, len), medium body
     * (~200-500 addresses). Reject obviously-wrong functions.
     */
    private boolean isReadvCandidate(Function func, Set<Function> tuFuncs) {
        if (func == null) return false;
        if (func.equals(identifiedOnStreamFrame)) return false;

        long bodySize = func.getBody().getNumAddresses();
        if (bodySize < 200 || bodySize > 500) return false;

        int params = func.getParameterCount();
        // Readv(const struct iovec* iov, size_t iov_len) -> 2 params; allow a
        // little slack for ABI-derived param recovery.
        if (params < 1 || params > 3) return false;

        return true;
    }
}
