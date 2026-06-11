import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;

import java.util.*;

/**
 * Finds the Google QUICHE targets defined in
 * quiche/quic/core/http/quic_spdy_stream.cc:
 *   - QuicSpdyStream::WriteOrBufferBody  (unique rodata string "writing body data")
 *   - QuicSpdyStream::OnDataFramePayload (tiny thunk, structural idiom)
 *
 * Mirrors the concrete-finder shape of SSLReadFinder / SSLWriteFinder.
 */
public class QuicSpdyStreamFinder {

    private final GhidraContext ctx;
    private final MemorySearchUtils memUtils;
    private final FunctionAnalysisUtils analysisUtils;
    private final boolean debugRun;

    private static final String SPDY_STREAM_TU = "quiche/quic/core/http/quic_spdy_stream.cc";

    private Function identifiedWriteOrBufferBody = null;
    private Function identifiedOnDataFramePayload = null;
    private String writeOrBufferBodyStrategy = null;
    private String onDataFramePayloadStrategy = null;

    private Function identifiedOnHeadersDecoded = null;
    private Function identifiedWriteHeaders = null;
    private String onHeadersDecodedStrategy = null;
    private String writeHeadersStrategy = null;

    public QuicSpdyStreamFinder(GhidraContext ctx, MemorySearchUtils memUtils,
                                FunctionAnalysisUtils analysisUtils, boolean debugRun) {
        this.ctx = ctx;
        this.memUtils = memUtils;
        this.analysisUtils = analysisUtils;
        this.debugRun = debugRun;
    }

    public Function getWriteOrBufferBody() { return identifiedWriteOrBufferBody; }
    public Function getOnDataFramePayload() { return identifiedOnDataFramePayload; }
    public String getWriteOrBufferBodyStrategy() { return writeOrBufferBodyStrategy; }
    public String getOnDataFramePayloadStrategy() { return onDataFramePayloadStrategy; }

    public Function getOnHeadersDecoded() { return identifiedOnHeadersDecoded; }
    public Function getWriteHeaders() { return identifiedWriteHeaders; }
    public String getOnHeadersDecodedStrategy() { return onHeadersDecodedStrategy; }
    public String getWriteHeadersStrategy() { return writeHeadersStrategy; }

    // ========== QuicSpdyStream::WriteOrBufferBody ==========

    /**
     * STRONGEST anchor: the unique rodata string "writing body data" is
     * referenced from exactly this function. Use findStringUsage and take the
     * single referencing function.
     */
    public void findWriteOrBufferBody() {
        // On ARM64 the string is materialised with an ADRP+ADD pair, which is NOT
        // a Ghidra data reference, so findStringUsage's backward data-xref walk
        // misses it. findAllFunctionsReferencingString includes the ADRP+ADD
        // code-scan (the same path that locates OnStreamFrame), so lead with it.
        Set<Function> referencing = memUtils.findAllFunctionsReferencingString("writing body data");
        String strat = "UniqueStringAnchorCodeScan";

        if (debugRun) {
            System.out.println("[!] WriteOrBufferBody: code-scan referencing 'writing body data': "
                + referencing.size());
        }

        if (referencing.isEmpty()) {
            // Fallback to the data-xref walk (e.g. x86 with direct references).
            GhidraContext.Pair<Set<Function>, Address> result =
                memUtils.findStringUsage("writing body data");
            referencing = result.getFirst();
            strat = "UniqueStringAnchorXref";
            if (debugRun) {
                System.out.println("[!] WriteOrBufferBody: data-xref fallback referencing count: "
                    + referencing.size());
            }
        }

        Function candidate = pickSingleSmallest(referencing);
        if (candidate != null) {
            identifiedWriteOrBufferBody = candidate;
            writeOrBufferBodyStrategy = strat;
        }
    }

    /**
     * If the referencing set has more than one entry (rare), the smallest
     * function that actually loads the string is the most likely match. With a
     * truly unique string the set has exactly one element.
     */
    private Function pickSingleSmallest(Set<Function> functions) {
        Function best = null;
        long bestSize = Long.MAX_VALUE;
        for (Function f : functions) {
            long size = f.getBody().getNumAddresses();
            if (size < bestSize) {
                bestSize = size;
                best = f;
            }
        }
        return best;
    }

    // ========== QuicSpdyStream::OnDataFramePayload ==========

    /**
     * HARDEST: tiny thunk (~40 B, no string). Exact idiom on arm64:
     *   paciasp; stp x29,x30,[sp,#-0x10]!; mov x29,sp;
     *   ldr x8,[x0,#8]; add x0,x8,#imm; bl <bodyAppend>;
     *   mov w0,#1; ldp; autiasp; ret
     * The discriminator: it loads x8 from [x0,#8], computes add x0,x8,#imm,
     * tail-calls a body-append helper, and returns the constant 1 (mov w0,#1).
     * Only run on arm64; emit MISS otherwise.
     */
    public void findOnDataFramePayload() {
        if (!ctx.isARM64()) {
            if (debugRun) {
                System.out.println("[!] OnDataFramePayload: idiom scan only implemented for arm64");
            }
            return;
        }

        Listing listing = ctx.program.getListing();
        FunctionIterator funcIter = ctx.program.getFunctionManager().getFunctions(true);

        List<Function> matches = new ArrayList<>();
        while (funcIter.hasNext()) {
            Function func = funcIter.next();
            long bodySize = func.getBody().getNumAddresses();
            // Tiny thunk: ~40 bytes / ~10 instructions.
            if (bodySize < 20 || bodySize > 80) continue;
            if (matchesOnDataFramePayloadIdiom(func, listing)) {
                matches.add(func);
            }
        }

        if (debugRun) {
            System.out.println("[!] OnDataFramePayload: idiom matches: " + matches.size());
            for (Function f : matches) {
                System.out.println("[!]   candidate " + f.getEntryPoint() + " ("
                    + f.getBody().getNumAddresses() + " bytes)");
            }
        }

        // Only accept when exactly one function matches the idiom; otherwise we
        // cannot isolate it confidently -> caller emits a MISS line.
        if (matches.size() == 1) {
            identifiedOnDataFramePayload = matches.get(0);
            onDataFramePayloadStrategy = "ThunkIdiomScan";
        }
    }

    /**
     * Detects the OnDataFramePayload thunk idiom inside a function body:
     *   ldr  x8,[x0,#8]
     *   add  x0,x8,#imm
     *   bl   <helper>
     *   mov  w0,#1   (constant return value 1)
     *   ret
     */
    private boolean matchesOnDataFramePayloadIdiom(Function func, Listing listing) {
        AddressSetView body = func.getBody();
        InstructionIterator instrs = listing.getInstructions(body, true);

        boolean ldrX8FromX0 = false;
        boolean addX0FromX8 = false;
        boolean blAfterAdd = false;
        boolean movW0One = false;
        boolean hasRet = false;

        while (instrs.hasNext()) {
            Instruction inst = instrs.next();
            String mnem = inst.getMnemonicString().toLowerCase();
            String text = inst.toString().toLowerCase();

            if (mnem.equals("ldr") && text.contains("x8") && text.contains("[x0") ) {
                // ldr x8,[x0,#8]
                if (text.contains("#0x8") || text.contains(", #8") || text.contains(",#8")) {
                    ldrX8FromX0 = true;
                }
            } else if (mnem.equals("add") && text.contains("x0") && text.contains("x8")) {
                // add x0,x8,#imm
                if (ldrX8FromX0) addX0FromX8 = true;
            } else if (mnem.equals("bl")) {
                if (addX0FromX8) blAfterAdd = true;
            } else if (mnem.equals("mov") && text.contains("w0")) {
                // mov w0,#1
                if (text.contains("#0x1") || text.endsWith(", #1") || text.endsWith(",#1")) {
                    movW0One = true;
                }
            } else if (mnem.equals("ret")) {
                hasRet = true;
            }
        }

        return ldrX8FromX0 && addX0FromX8 && blAfterAdd && movW0One && hasRet;
    }

    // ========== QuicSpdyStream::OnHeadersDecoded ==========

    /**
     * OnHeadersDecoded(QuicHeaderList headers, bool fin) is a non-inlined VIRTUAL
     * OVERRIDE (it sits in the vtable, so it survives stripping). It frequently
     * owns no unique string of its own, but:
     *   - it is defined in quic_spdy_stream.cc (TU-path string), and
     *   - it is CALLED by the QPACK decoded-headers accumulator's
     *     OnDecodingCompleted, which DOES carry distinctive QPACK strings.
     *
     * Strategy A (primary): build referencing-function sets for several anchor
     * strings and tally co-occurrence exactly like OnStreamFrame. The TU-path
     * string yields the TU-membership set; the header-size-limit string and the
     * QPACK decode-completion strings narrow it down. If the QPACK accumulator
     * resolves but OnHeadersDecoded itself owns no string, fall back to scanning
     * the accumulator's bl callees and intersecting them with the TU set.
     *
     * Strategy B (fallback, single-match-gated): among TU functions, accept ONLY
     * if exactly one matches the structural virtual-override predicate.
     */
    public void findOnHeadersDecoded() {
        // `best`/`bestCount` declared at method scope so the Strategy C
        // fallback below can reuse the Strategy A tally winner (mirrors
        // QuicStreamSequencerFinder.findOnStreamFrame:99-108). Previously
        // these lived inside the `if (!sets.isEmpty())` block; the Strategy
        // C fallback then called pickSingleSmallest(sets.get(0)) which
        // picked by body size, not by tally — that picked the wrong
        // function on libcronet.148 (0x57f59c, fires 0×) over the tally
        // winner (0x57b258, fires 31×/response).
        Function best = null;
        int bestCount = 0;

        // --- Strategy A: distinctive-string co-occurrence in the TU. ---
        String[] anchorStrings = {
            SPDY_STREAM_TU,
            "Too large headers received on stream ",
            "quiche/quic/core/http/qpack/qpack_decoded_headers_accumulator.cc",
            "Error decoding headers on stream ",
            "Error decoding trailers on stream "
        };

        List<Set<Function>> sets = new ArrayList<>();
        Set<Function> tuFuncs = new HashSet<>();
        Set<Function> qpackAccumulatorFuncs = new HashSet<>();
        for (String s : anchorStrings) {
            Set<Function> refs = memUtils.findAllFunctionsReferencingString(s);
            if (debugRun) {
                System.out.println("[!] OnHeadersDecoded: '" + s + "' referenced by "
                    + refs.size() + " functions");
            }
            if (s.equals(SPDY_STREAM_TU)) {
                tuFuncs = refs;
            } else if (s.contains("qpack_decoded_headers_accumulator")) {
                qpackAccumulatorFuncs = refs;
            }
            if (!refs.isEmpty()) {
                sets.add(refs);
            }
        }

        // Tally co-occurrence; the function in the most anchor sets is the
        // strongest candidate for OnHeadersDecoded (header-limit + TU strings
        // co-occur there).
        if (!sets.isEmpty()) {
            Map<Function, Integer> tally = new HashMap<>();
            for (Set<Function> set : sets) {
                for (Function f : set) {
                    tally.merge(f, 1, Integer::sum);
                }
            }

            // best/bestCount declared at method scope above so Strategy C
            // can reuse the tally winner.
            for (Map.Entry<Function, Integer> e : tally.entrySet()) {
                if (e.getValue() > bestCount) {
                    bestCount = e.getValue();
                    best = e.getKey();
                }
            }

            if (debugRun && best != null) {
                System.out.println("[!] OnHeadersDecoded: best string candidate "
                    + best.getEntryPoint() + " appears in " + bestCount + "/" + sets.size()
                    + " anchor sets (" + best.getBody().getNumAddresses() + " bytes)");
            }

            if (best != null && bestCount >= 2) {
                identifiedOnHeadersDecoded = best;
                onHeadersDecodedStrategy = "StringIntersection";
                return;
            }
        }

        // OnHeadersDecoded may own no unique string. Resolve it via the callgraph:
        // the QPACK accumulator's OnDecodingCompleted calls OnHeadersDecoded, so
        // intersect the accumulator's bl callees with the TU-membership set.
        if (!qpackAccumulatorFuncs.isEmpty() && !tuFuncs.isEmpty()) {
            Set<Function> calleesInTu = new HashSet<>();
            for (Function caller : qpackAccumulatorFuncs) {
                for (Function callee : findCalleesOf(caller)) {
                    if (tuFuncs.contains(callee)) {
                        calleesInTu.add(callee);
                    }
                }
            }
            if (debugRun) {
                System.out.println("[!] OnHeadersDecoded: QPACK-accumulator callees in TU set: "
                    + calleesInTu.size());
            }
            Function candidate = pickSingleSmallest(calleesInTu);
            if (candidate != null) {
                identifiedOnHeadersDecoded = candidate;
                onHeadersDecodedStrategy = "CallgraphFromQpackAccumulator";
                return;
            }
        }

        // Only the highly distinctive header-limit / TU strings resolved into a
        // single set: accept the tally winner as the distinctive-string anchor.
        // Mirrors QuicStreamSequencerFinder.findOnStreamFrame:104-107. The
        // previous implementation called pickSingleSmallest(sets.get(0)) here,
        // which picks by body size and chose a different, colder function on
        // libcronet.148 (0x57f59c, fires 0×) over the correct tally winner
        // (0x57b258, fires 31×/response).
        if (best != null && sets.size() == 1) {
            identifiedOnHeadersDecoded = best;
            onHeadersDecodedStrategy = "DistinctiveStringAnchor";
            return;
        }

        // --- Strategy B: structural virtual-override, single-match-gated. ---
        if (!tuFuncs.isEmpty()) {
            Listing listing = ctx.program.getListing();
            List<Function> structuralMatches = new ArrayList<>();
            for (Function func : tuFuncs) {
                if (matchesOnHeadersDecodedIdiom(func, listing)) {
                    structuralMatches.add(func);
                }
            }
            if (debugRun) {
                System.out.println("[!] OnHeadersDecoded: structural matches in TU: "
                    + structuralMatches.size());
            }
            if (structuralMatches.size() == 1) {
                identifiedOnHeadersDecoded = structuralMatches.get(0);
                onHeadersDecodedStrategy = "StructuralVirtualOverride";
            }
        }
    }

    /**
     * Structural predicate for the OnHeadersDecoded virtual override:
     *   - medium body (avoid trivial thunks and giant functions),
     *   - dereferences the QuicHeaderList container argument in x1 in a loop
     *     (ldr from [x1] / [x1,#8] with a loop back-edge present), and
     *   - bool-ish use of the fin argument in w2.
     */
    private boolean matchesOnHeadersDecodedIdiom(Function func, Listing listing) {
        long bodySize = func.getBody().getNumAddresses();
        if (bodySize < 80 || bodySize > 2500) return false;

        AddressSetView body = func.getBody();
        InstructionIterator instrs = listing.getInstructions(body, true);

        boolean ldrFromX1 = false;
        boolean usesW2 = false;
        boolean hasBackEdge = false;

        while (instrs.hasNext()) {
            Instruction inst = instrs.next();
            String mnem = inst.getMnemonicString().toLowerCase();
            String text = inst.toString().toLowerCase();

            if (mnem.equals("ldr") && (text.contains("[x1]") || text.contains("[x1,")
                || text.contains("[x1 ,"))) {
                ldrFromX1 = true;
            }
            if (text.contains("w2")) {
                usesW2 = true;
            }
            // A backward branch (target before the branch instruction) inside the
            // body indicates a loop over the header container.
            if (inst.getFlowType().isJump() || inst.getFlowType().isConditional()) {
                Address[] flows = inst.getFlows();
                for (Address target : flows) {
                    if (body.contains(target)
                        && target.compareTo(inst.getAddress()) < 0) {
                        hasBackEdge = true;
                    }
                }
            }
        }

        return ldrFromX1 && usesW2 && hasBackEdge;
    }

    /**
     * Collects the callee Functions of `caller` by walking its instructions and
     * resolving each `bl` (call) flow target to its containing Function. Mirrors
     * the flow-target handling used in QuicheFinder.getLengthUntilBranch.
     */
    private Set<Function> findCalleesOf(Function caller) {
        Set<Function> callees = new HashSet<>();
        if (caller == null) return callees;

        Listing listing = ctx.program.getListing();
        InstructionIterator instrs = listing.getInstructions(caller.getBody(), true);
        while (instrs.hasNext()) {
            Instruction inst = instrs.next();
            if (!inst.getFlowType().isCall()) continue;
            for (Address target : inst.getFlows()) {
                Function callee = ctx.getFunctionContaining.apply(target);
                if (callee != null && !callee.equals(caller)) {
                    callees.add(callee);
                }
            }
        }
        return callees;
    }

    // ========== QuicSpdyStream::WriteHeaders ==========

    /**
     * WriteHeaders(quiche::HttpHeaderBlock, bool, QuicheReferenceCountedPointer<...>)
     * is LIKELY INLINED in release builds. Attempt a STRICT TU-constrained
     * structural match and accept ONLY a unique candidate:
     *   - this=x0, HttpHeaderBlock*=x1, bool=w2, plus a 4th pointer arg,
     *   - calls a QPACK-encoder callee (a bl target whose function references a
     *     QPACK-encoder string), and
     *   - returns a size_t (non-void).
     *
     * NEVER substitute QpackEncoder::EncodeHeaderList / WriteHeadersImpl: their
     * signatures differ, so a clean MISS is the correct outcome when no unique
     * structural match exists.
     */
    public void findWriteHeaders() {
        // STRATEGY 1 (primary, 2026-05-24): "writing headers" body-string anchor.
        //
        // QuicSpdyStream::WriteHeaders passes the literal "writing headers" as
        // the label argument to AssertNotOpen() in its prologue. The call site
        // materialises x1 with an ADRP+ADD pair, sets w2=#0xf (the length 15),
        // and BLs into the assertion helper. The string survives release
        // stripping because the assertion helper needs it for its error message.
        //
        // This anchor finds WriteHeaders even when the function carries NO
        // file-path XREF (Strategy 2 missed WriteHeaders on Chrome 148 release
        // builds because the function has no CHECK macro that expands __FILE__).
        //
        // Verified unique on libmainlinecronet.141.0.7340.3.so at offset
        // 0x4d08e4 (matches the symbol-resolved address) and on
        // libcronet.148.0.7778.120.so at offset 0x57b068 (matches structurally
        // to .141: same mov x22, x1; mov w2, #0xf; mov x19, x0 pattern).
        Set<Function> writingHeadersFuncs =
            memUtils.findAllFunctionsReferencingString("writing headers");
        if (debugRun) {
            System.out.println("[!] WriteHeaders: functions referencing 'writing headers': "
                + writingHeadersFuncs.size());
            for (Function f : writingHeadersFuncs) {
                System.out.println("[!]   candidate " + f.getEntryPoint() + " ("
                    + f.getBody().getNumAddresses() + " bytes, params=" + f.getParameterCount() + ")");
            }
        }
        if (writingHeadersFuncs.size() == 1) {
            identifiedWriteHeaders = writingHeadersFuncs.iterator().next();
            writeHeadersStrategy = "WritingHeadersStringAnchor";
            return;
        }
        if (writingHeadersFuncs.size() > 1) {
            // Multiple candidates — narrow by ABI shape: WriteHeaders returns
            // size_t (non-void), body 40..4000 bytes. Pick smallest matching
            // candidate (the direct AssertNotOpen call site is in WriteHeaders'
            // own body; any larger function referencing the string is likely
            // an inliner that contains WriteHeaders' code).
            Function chosen = null;
            for (Function f : writingHeadersFuncs) {
                if (f.getReturnType() != null
                    && "void".equalsIgnoreCase(f.getReturnType().getName())) {
                    continue;
                }
                long bs = f.getBody().getNumAddresses();
                if (bs < 40 || bs > 4000) continue;
                if (chosen == null || f.getBody().getNumAddresses() < chosen.getBody().getNumAddresses()) {
                    chosen = f;
                }
            }
            if (chosen != null) {
                identifiedWriteHeaders = chosen;
                writeHeadersStrategy = "WritingHeadersStringAnchorMultiNarrowed";
                return;
            }
        }

        // STRATEGY 2 (fallback): TU-constrained strict structural match.
        // Pre-2026-05-24 behaviour. Kept for builds where "writing headers"
        // was stripped/renamed but the function still has a CHECK macro that
        // XREFs the file path.
        Set<Function> tuFuncs = memUtils.findAllFunctionsReferencingString(SPDY_STREAM_TU);
        if (debugRun) {
            System.out.println("[!] WriteHeaders: functions referencing TU '" + SPDY_STREAM_TU
                + "': " + tuFuncs.size());
        }
        if (tuFuncs.isEmpty()) {
            return;
        }

        // Identify QPACK-encoder functions so we can confirm a call into the
        // encoder from the WriteHeaders candidate.
        Set<Function> qpackEncoderFuncs = new HashSet<>();
        String[] encoderAnchors = {
            "quiche/quic/core/qpack/qpack_encoder.cc",
            "QPACK encoder",
            "quic.qpack.encoder"
        };
        for (String s : encoderAnchors) {
            qpackEncoderFuncs.addAll(memUtils.findAllFunctionsReferencingString(s));
        }
        if (debugRun) {
            System.out.println("[!] WriteHeaders: QPACK-encoder anchor functions: "
                + qpackEncoderFuncs.size());
        }

        List<Function> matches = new ArrayList<>();
        for (Function func : tuFuncs) {
            if (matchesWriteHeadersIdiom(func, qpackEncoderFuncs)) {
                matches.add(func);
            }
        }

        if (debugRun) {
            System.out.println("[!] WriteHeaders: strict structural matches: " + matches.size());
            for (Function f : matches) {
                System.out.println("[!]   candidate " + f.getEntryPoint() + " ("
                    + f.getBody().getNumAddresses() + " bytes, params=" + f.getParameterCount() + ")");
            }
        }

        // Accept ONLY on a unique match; otherwise emit a clean MISS.
        if (matches.size() == 1) {
            identifiedWriteHeaders = matches.get(0);
            writeHeadersStrategy = "StrictStructuralInlined";
        }
    }

    /**
     * Strict structural predicate for the (possibly inlined) WriteHeaders body:
     *   - 4-ish args (this, HttpHeaderBlock*, bool, ref-counted ptr) -> bool-ish
     *     w2 usage and a [x1]/[x1,#..] dereference of the header block,
     *   - calls into a known QPACK-encoder function, and
     *   - is non-void (returns size_t).
     */
    private boolean matchesWriteHeadersIdiom(Function func, Set<Function> qpackEncoderFuncs) {
        long bodySize = func.getBody().getNumAddresses();
        if (bodySize < 40 || bodySize > 2000) return false;

        // Must not be void: WriteHeaders returns size_t.
        if (func.getReturnType() != null
            && "void".equalsIgnoreCase(func.getReturnType().getName())) {
            return false;
        }

        Listing listing = ctx.program.getListing();
        AddressSetView body = func.getBody();
        InstructionIterator instrs = listing.getInstructions(body, true);

        boolean derefHeaderBlock = false;
        boolean usesW2 = false;
        boolean callsQpackEncoder = false;

        while (instrs.hasNext()) {
            Instruction inst = instrs.next();
            String mnem = inst.getMnemonicString().toLowerCase();
            String text = inst.toString().toLowerCase();

            if (mnem.equals("ldr") && (text.contains("[x1]") || text.contains("[x1,")
                || text.contains("[x1 ,"))) {
                derefHeaderBlock = true;
            }
            if (text.contains("w2")) {
                usesW2 = true;
            }
            if (inst.getFlowType().isCall()) {
                for (Address target : inst.getFlows()) {
                    Function callee = ctx.getFunctionContaining.apply(target);
                    if (callee != null && qpackEncoderFuncs.contains(callee)) {
                        callsQpackEncoder = true;
                    }
                }
            }
        }

        return derefHeaderBlock && usesW2 && callsQpackEncoder;
    }
}
