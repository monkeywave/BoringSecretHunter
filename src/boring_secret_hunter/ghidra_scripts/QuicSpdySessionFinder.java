import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;

import java.util.*;

/**
 * Finds Google QUICHE session-level targets defined in
 * quiche/quic/core/http/quic_spdy_session.cc.
 *
 * Targets:
 *   - quic::QuicSpdySession::WriteHeadersOnHeadersStream
 *       (QuicStreamId id, HttpHeaderBlock headers, bool fin,
 *        const SpdyStreamPrecedence&amp;,
 *        QuicheReferenceCountedPointer&lt;QuicAckListenerInterface&gt;)
 *
 * NOTE: this is the gQUIC HTTP-over-QUIC path. Modern Chrome's HTTP/3 traffic
 * bypasses it via QuicSpdyStream::WriteHeadersImpl's UsesHttp3() branch — the
 * hook will essentially never fire on a real HTTP/3 capture. Kept here as
 * defense-in-depth for the Phase-2 chained-candidate resolver.
 *
 * Strategy chain:
 *   1. SixArgSaveSignature — the function's prologue saves SIX register args
 *      (this/x0, w1=QuicStreamId, x2=HttpHeaderBlock, w3=fin, x4=Precedence,
 *      x5=AckListener) and rearranges them for an inner call. The 6-arg save
 *      sequence is highly distinctive in any C++ codebase.
 *   2. SessionTuStructural — fallback: TU-constrained structural match using
 *      the quic_spdy_session.cc CHECK-macro file-path anchor.
 */
public class QuicSpdySessionFinder {

    private final GhidraContext ctx;
    private final MemorySearchUtils memUtils;
    private final FunctionAnalysisUtils analysisUtils;
    private final boolean debugRun;

    private static final String SPDY_SESSION_TU = "quic_spdy_session.cc";
    private static int DEBUG_SAMPLES_PRINTED = 0;

    private Function identifiedWriteHeadersOnHeadersStream = null;
    private String writeHeadersOnHeadersStreamStrategy = null;
    /** Raw entry address used when Ghidra hasn't auto-created a Function. */
    private Address synthEntry = null;
    private byte[] synthPatternBytes = null;

    public QuicSpdySessionFinder(GhidraContext ctx, MemorySearchUtils memUtils,
                                  FunctionAnalysisUtils analysisUtils, boolean debugRun) {
        this.ctx = ctx;
        this.memUtils = memUtils;
        this.analysisUtils = analysisUtils;
        this.debugRun = debugRun;
    }

    public Function getWriteHeadersOnHeadersStream() {
        return identifiedWriteHeadersOnHeadersStream;
    }
    public String getWriteHeadersOnHeadersStreamStrategy() {
        return writeHeadersOnHeadersStreamStrategy;
    }
    /** Raw entry address (Ghidra-space) when the Function couldn't be created. */
    public Address getSynthEntry() { return synthEntry; }
    /** First ~48 bytes at the synthetic entry, for direct pattern emission. */
    public byte[] getSynthPatternBytes() { return synthPatternBytes; }

    /**
     * Identify QuicSpdySession::WriteHeadersOnHeadersStream by intersecting:
     *   - functions XREFing the quic_spdy_session.cc file path (CHECK macro
     *     expansions), AND
     *   - functions whose prologue saves 6+ register args, AND
     *   - functions whose prologue rearranges args ("mov x0, sp" and
     *     "mov x1, x2" — the standard "build HpackHeaderBlock on stack then
     *     forward" idiom in the implementation).
     */
    public void findWriteHeadersOnHeadersStream() {
        // STRATEGY 0 (primary): direct byte-pattern scan of the
        // post-prologue 6-arg-save sequence. This 28-byte signature is the
        // most invariant across builds because the source argument registers
        // are fixed by the AArch64 Itanium ABI and the compiler always emits
        // the same MOV order for this 6-arg signature.
        //
        // Verified unique on:
        //   libmainlinecronet.141.0.7340.3.so @ post-prologue offset 0x4cb534
        //     (function entry 0x4cb51c)
        //   libcronet.148.0.7778.120.so       @ post-prologue offset 0x57570c
        //     (function entry 0x5756f4)
        //   libcronet.148.0.7778.167.so       @ post-prologue offset matches
        //     same structure (verified externally).
        //
        // Pattern (with one 4-byte ?? for the build-specific stack-prep
        // instruction between mov x20,x0 and mov x1,x2):
        //   F3 03 01 2A F4 03 00 AA  ?? ?? ?? ??  E1 03 02 AA
        //   F6 03 05 AA F7 03 04 AA  F5 03 03 2A
        // (corresponds to: mov w19,w1; mov x20,x0; <stack-prep>; mov x1,x2;
        //  mov x22,x5; mov x23,x4; mov w21,w3)
        Function patternMatch = findByPatternScan();
        if (patternMatch != null) {
            identifiedWriteHeadersOnHeadersStream = patternMatch;
            writeHeadersOnHeadersStreamStrategy = "PostPrologueSixArgSaveBytePattern";
            return;
        }
        // findByPatternScan may have populated synthEntry + synthPatternBytes
        // even without returning a Function (Ghidra didn't auto-create one).
        // Set the strategy so the orchestrator emits via the synth path.
        if (synthEntry != null && synthPatternBytes != null) {
            writeHeadersOnHeadersStreamStrategy = "PostPrologueSixArgSaveBytePatternSynth";
            return;
        }

        // Fallback strategies (TU-anchored structural + global structural).
        Set<Function> tuFuncs = memUtils.findAllFunctionsReferencingString(SPDY_SESSION_TU);
        if (debugRun) {
            System.out.println("[!] WriteHeadersOnHeadersStream: TU XREF set size: " + tuFuncs.size());
        }

        // Strategy 1: among the TU cluster, pick the function whose prologue
        // matches the 6-arg save signature. Highly specific to this target.
        List<Function> matches = new ArrayList<>();
        for (Function func : tuFuncs) {
            if (matchesSixArgSaveIdiom(func)) matches.add(func);
        }

        if (debugRun) {
            System.out.println("[!] WriteHeadersOnHeadersStream 6-arg-save matches: "
                + matches.size());
            for (Function f : matches) {
                System.out.println("[!]   candidate " + f.getEntryPoint() + " ("
                    + f.getBody().getNumAddresses() + " bytes, params=" + f.getParameterCount() + ")");
            }
        }

        if (matches.size() == 1) {
            identifiedWriteHeadersOnHeadersStream = matches.get(0);
            writeHeadersOnHeadersStreamStrategy = "SixArgSaveSignature";
            return;
        }

        // Strategy 2 fallback: scan the entire program (not just TU cluster)
        // for the 6-arg signature. Slower but catches WriteHeadersOnHeadersStream
        // even when its CHECK got inlined out and it's no longer in the TU set.
        if (matches.isEmpty()) {
            findGlobalSixArgSave();
        }
    }

    /**
     * Strategy 0: direct byte-pattern scan for the post-prologue 6-arg save
     * sequence. Returns the function CONTAINING the match (walking back from
     * the post-prologue PC to the function start via Ghidra's function
     * manager).
     */
    private Function findByPatternScan() {
        // Byte pattern for the post-prologue argument-save cluster. 28 bytes
        // total, 4 bytes wildcarded for the build-specific stack-prep
        // instruction (typically "mov x0, sp" = E0 03 00 91 but encoding can
        // shift if a different stack-prep helper is used).
        byte[][] PATTERN_VARIANTS = {
            // Concrete bytes around 4 wildcard bytes:
            //   F3 03 01 2A   mov w19, w1
            //   F4 03 00 AA   mov x20, x0
            //   ?? ?? ?? ??   (build-specific stack/arg prep, usually mov x0,sp)
            //   E1 03 02 AA   mov x1, x2
            //   F6 03 05 AA   mov x22, x5
            //   F7 03 04 AA   mov x23, x4
            //   F5 03 03 2A   mov w21, w3
            null,  // placeholder — handled specially with masking below
        };

        // The Ghidra MemorySearchUtils searchForPattern takes a flat byte[]
        // with no mask, so for the wildcard we have to do a two-step scan:
        // search for the concrete prefix, then verify the concrete suffix.
        byte[] prefix = hex("F3 03 01 2A F4 03 00 AA");                    // 8 bytes
        byte[] suffix = hex("E1 03 02 AA F6 03 05 AA F7 03 04 AA F5 03 03 2A");  // 16 bytes
        int wildcardLen = 4;

        Memory mem = ctx.program.getMemory();
        for (MemoryBlock block : mem.getBlocks()) {
            if (!block.isExecute() || !block.isInitialized()) continue;
            Address start = block.getStart();
            Address end = block.getEnd();
            Address cursor = start;
            while (cursor != null && cursor.compareTo(end) < 0) {
                Address hit;
                try {
                    hit = memUtils.searchForPattern(mem, cursor, end, prefix);
                } catch (Exception e) {
                    break;
                }
                if (hit == null) break;
                // Verify suffix at hit + 8 + 4 (prefix + wildcard).
                try {
                    Address suffixAddr = hit.add(prefix.length + wildcardLen);
                    if (suffixAddr.compareTo(end) >= 0) break;
                    byte[] bytes = new byte[suffix.length];
                    mem.getBytes(suffixAddr, bytes);
                    if (Arrays.equals(bytes, suffix)) {
                        if (debugRun) {
                            System.out.println("[!] WriteHeadersOnHeadersStream pattern hit @ "
                                + hit + " (post-prologue position)");
                        }
                        Function fn = ctx.getFunctionContaining.apply(hit);
                        if (fn != null) {
                            if (debugRun) {
                                System.out.println("[!]   containing function: " + fn.getEntryPoint()
                                    + " (" + fn.getBody().getNumAddresses() + " bytes)");
                            }
                            return fn;
                        }
                        // Ghidra didn't auto-create a Function — record the
                        // synthetic entry + pattern bytes for direct emission
                        // from QuicheFinder. Walk back from post-prologue hit
                        // to SUB sp (function entry).
                        Address inferredEntry = walkBackToSubSp(hit);
                        if (inferredEntry != null) {
                            // Capture 48 bytes at the entry for the friTap pattern.
                            byte[] pbytes = new byte[48];
                            try {
                                mem.getBytes(inferredEntry, pbytes);
                            } catch (Exception e) {
                                pbytes = null;
                            }
                            if (pbytes != null) {
                                synthEntry = inferredEntry;
                                synthPatternBytes = pbytes;
                                if (debugRun) {
                                    System.out.println("[!]   synthetic entry @ "
                                        + inferredEntry + " (48-byte pattern captured)");
                                }
                                return null;  // signal "no Function but synth available"
                            }
                        }
                    }
                } catch (Exception e) {
                    // skip
                }
                cursor = hit.add(4);
            }
        }
        return null;
    }

    private static byte[] hex(String spaced) {
        String[] parts = spaced.split(" ");
        byte[] out = new byte[parts.length];
        for (int i = 0; i < parts.length; i++) {
            out[i] = (byte) Integer.parseInt(parts[i], 16);
        }
        return out;
    }

    /**
     * Walk backwards 4 bytes at a time looking for SUB sp, sp, #imm — the
     * canonical ARM64 function start. Returns the inferred entry address
     * (preferring BTI-landing-pad 4 bytes earlier when present).
     */
    private Address walkBackToSubSp(Address hitAddr) {
        Memory mem = ctx.program.getMemory();
        for (int back = 0; back < 256; back += 4) {
            Address a;
            try {
                a = hitAddr.subtract(back);
            } catch (Exception e) {
                return null;
            }
            byte[] buf = new byte[4];
            try {
                mem.getBytes(a, buf);
            } catch (Exception e) {
                continue;
            }
            int instr = ((buf[0] & 0xFF))
                | ((buf[1] & 0xFF) << 8)
                | ((buf[2] & 0xFF) << 16)
                | ((buf[3] & 0xFF) << 24);
            if ((instr & 0xFFC003FF) == 0xD10003FF) {
                Address entry = a;
                try {
                    Address btiAddr = a.subtract(4);
                    byte[] btiBuf = new byte[4];
                    mem.getBytes(btiAddr, btiBuf);
                    int btiInstr = ((btiBuf[0] & 0xFF))
                        | ((btiBuf[1] & 0xFF) << 8)
                        | ((btiBuf[2] & 0xFF) << 16)
                        | ((btiBuf[3] & 0xFF) << 24);
                    if (btiInstr == 0xD503233F) entry = btiAddr;
                } catch (Exception e) { /* keep entry at SUB sp */ }
                return entry;
            }
        }
        return null;
    }

    /**
     * Walk backwards 4 bytes at a time from a post-prologue hit, looking for
     * `SUB sp, sp, #imm` (mask 0xFFC003FF, value 0xD10003FF) — the canonical
     * ARM64 function start. Once found, create a Function at that address via
     * Ghidra's FunctionManager (auto-analysis may have missed it because of
     * MinimalAnalysisOption pre-script).
     */
    private Function createFunctionAtInferredEntry(Address hitAddr) {
        Memory mem = ctx.program.getMemory();
        Address cursor = hitAddr;
        for (int back = 0; back < 256; back += 4) {
            Address a;
            try {
                a = hitAddr.subtract(back);
            } catch (Exception e) {
                return null;
            }
            byte[] buf = new byte[4];
            try {
                mem.getBytes(a, buf);
            } catch (Exception e) {
                continue;
            }
            int instr = ((buf[0] & 0xFF))
                | ((buf[1] & 0xFF) << 8)
                | ((buf[2] & 0xFF) << 16)
                | ((buf[3] & 0xFF) << 24);
            // SUB sp, sp, #imm12: bits 31..24 = 11010001, Rn = Rd = 31 (sp).
            // Mask 0xFFC003FF leaves only the opcode + Rn + Rd; value
            // 0xD10003FF picks SUB sp, sp, #anything.
            if ((instr & 0xFFC003FF) == 0xD10003FF) {
                // Found SUB sp at `a` — likely the function entry.
                // If a BTI instruction (`3F 23 03 D5` = bti c, encoding
                // 0xD503233F) sits 4 bytes earlier, the real entry is there
                // (Chrome 148+ targets ARMv8.5 with BTI landing pads).
                Address entry = a;
                try {
                    Address btiAddr = a.subtract(4);
                    byte[] btiBuf = new byte[4];
                    mem.getBytes(btiAddr, btiBuf);
                    int btiInstr = ((btiBuf[0] & 0xFF))
                        | ((btiBuf[1] & 0xFF) << 8)
                        | ((btiBuf[2] & 0xFF) << 16)
                        | ((btiBuf[3] & 0xFF) << 24);
                    if (btiInstr == 0xD503233F) {
                        entry = btiAddr;
                    }
                } catch (Exception e) {
                    // No prior bytes — entry stays at SUB sp.
                }
                FunctionManager fm = ctx.program.getFunctionManager();
                // Body: from entry forward to the next existing function or
                // to a reasonable upper bound. For now, give 0x400 bytes —
                // sufficient for WriteHeadersOnHeadersStream's typical size.
                Address bodyEnd;
                try {
                    bodyEnd = entry.add(0x400);
                } catch (Exception e) {
                    return null;
                }
                AddressSet body = new AddressSet(entry, bodyEnd);
                try {
                    Function created = fm.createFunction(
                        "QuicSpdySession_WriteHeadersOnHeadersStream_bsh",
                        entry, body, SourceType.ANALYSIS);
                    return created;
                } catch (Exception e) {
                    if (debugRun) {
                        System.out.println("[!]   createFunction failed: " + e);
                    }
                    // Fallback: try to fetch an existing function at this
                    // address (maybe just-created by another path).
                    return fm.getFunctionAt(entry);
                }
            }
        }
        return null;
    }

    /**
     * Pure-program-wide search for the 6-arg save idiom. Used when the TU
     * constraint set excludes WriteHeadersOnHeadersStream (e.g. CHECK macros
     * inlined out of its body).
     */
    private void findGlobalSixArgSave() {
        if (debugRun) {
            System.out.println("[!] WriteHeadersOnHeadersStream global 6-arg-save fallback.");
        }
        List<Function> matches = new ArrayList<>();
        for (Function func : ctx.program.getFunctionManager().getFunctions(true)) {
            // Limit to medium-sized functions (the gQUIC headers-stream writer
            // is non-trivial but bounded).
            long bodySize = func.getBody().getNumAddresses();
            if (bodySize < 80 || bodySize > 4000) continue;
            if (matchesSixArgSaveIdiom(func)) matches.add(func);
        }
        if (debugRun) {
            System.out.println("[!] WriteHeadersOnHeadersStream global matches: " + matches.size());
        }
        if (matches.size() == 1) {
            identifiedWriteHeadersOnHeadersStream = matches.get(0);
            writeHeadersOnHeadersStreamStrategy = "SixArgSaveSignatureGlobal";
        }
    }

    /**
     * Six-arg save idiom — strict. WriteHeadersOnHeadersStream takes
     *   (this=x0, w1=QuicStreamId, x2=HttpHeaderBlock, w3=fin,
     *    x4=SpdyStreamPrecedence&, x5=AckListener)
     * and the compiler always emits this exact set of MOVs in the prologue
     * (the destination registers vary across builds but the source regs do
     * not — they're fixed by the ABI). To be unique among ~14 unrelated
     * 4-arg-save callers, we require ALL SIX distinct arg regs to be
     * preserved AND the idiomatic "mov x0,sp ; mov x1,x2" call-prep pair.
     *
     * Verified on .141 @ 0x4cb51c and .148.120 @ 0x5756f4 / .148.167.
     */
    private boolean matchesSixArgSaveIdiom(Function func) {
        long bodySize = func.getBody().getNumAddresses();
        if (bodySize < 80 || bodySize > 4000) return false;

        // WriteHeadersOnHeadersStream returns size_t (non-void).
        if (func.getReturnType() != null
            && "void".equalsIgnoreCase(func.getReturnType().getName())) {
            return false;
        }

        // Debug: dump prologue for any function near 0x6756f0..0x6756f8 (the
        // known WriteHeadersOnHeadersStream on libcronet.148.0.7778.167.so).
        long fnOff = func.getEntryPoint().getOffset();
        boolean dbgThis = debugRun && (fnOff >= 0x6756f0L && fnOff <= 0x6756f8L);

        Listing listing = ctx.program.getListing();
        AddressSetView body = func.getBody();
        InstructionIterator instrs = listing.getInstructions(body, true);

        // Track which source arg registers we observed being copied to a
        // callee-preserved register (mov xDST, xSRC where SRC ∈ args).
        Set<String> savedFromArgs = new HashSet<>();
        boolean hasMovX0Sp = false;
        boolean hasMovX1X2 = false;
        int seen = 0;

        while (instrs.hasNext()) {
            Instruction inst = instrs.next();
            String mnem = inst.getMnemonicString().toLowerCase();
            String text = inst.toString().toLowerCase();
            seen++;
            if (seen > 40) break;  // only the prologue

            if (dbgThis) {
                System.out.println("[!]   DEBUG " + func.getEntryPoint() + " +" + seen
                    + ": mnem=" + mnem + " text=[" + text + "]");
            }

            // Detect both:
            //   mov xN, x{src}          (canonical alias)
            //   orr xN, xzr, x{src}     (real encoding emitted by Ghidra disasm)
            // Both copy x{src} into xN. We check the LAST operand which is the
            // source register in either form.
            boolean isMovLike =
                mnem.equals("mov") ||
                (mnem.equals("orr") && text.contains("xzr") || text.contains("wzr"));
            if (!isMovLike) continue;

            // Pull the trailing operand (after the last comma) — that's the
            // source register in mov xN, src and in orr xN, xzr, src.
            int lastComma = text.lastIndexOf(',');
            if (lastComma < 0) continue;
            String src = text.substring(lastComma + 1).trim();
            // Strip any trailing comment / size suffix.
            int sp = src.indexOf(' ');
            if (sp >= 0) src = src.substring(0, sp);

            // The 6 source arg registers per Itanium AArch64 ABI for this signature.
            for (String argReg : new String[] { "x0", "w1", "x2", "w3", "x4", "x5" }) {
                if (src.equals(argReg)) {
                    savedFromArgs.add(argReg);
                    break;
                }
            }

            // Detect "mov/orr x0, sp" — call-prep pattern.
            if (src.equals("sp") && (text.contains("x0,") || text.contains("x0 ,"))) {
                hasMovX0Sp = true;
            }
            // Detect "mov/orr x1, ..., x2" — arg-shift pattern.
            if (src.equals("x2") && (text.contains("x1,") || text.contains("x1 ,"))) {
                hasMovX1X2 = true;
            }
        }

        if (dbgThis) {
            DEBUG_SAMPLES_PRINTED++;
            System.out.println("[!]   DEBUG " + func.getEntryPoint() + " summary: "
                + "savedFromArgs=" + savedFromArgs + " hasMovX0Sp=" + hasMovX0Sp
                + " hasMovX1X2=" + hasMovX1X2);
        }

        // STRICT: require ALL six arg regs preserved + the idiomatic
        // mov x0,sp + mov x1,x2 pair. This rules out 4-arg / 5-arg lookalikes
        // that share part of the pattern but not the full signature.
        return savedFromArgs.size() >= 6 && hasMovX0Sp && hasMovX1X2;
    }
}
