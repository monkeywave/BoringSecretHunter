import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;

import java.util.*;

/**
 * Orchestrator for Google QUICHE QUIC stream-function detection in a stripped
 * Chrome/Cronet .so. Mirrors the role of SSLReadWriteHelper: it presence-gates,
 * runs the per-target strategies via the two sub-finders, validates results,
 * and prints the friTap byte patterns following the QUICHE output contract.
 *
 * Targets (Chrome 148 arm64; friTap labels):
 *   QuicSpdyStream_WriteOrBufferBody   (unique string "writing body data")
 *   QuicStreamSequencer_OnStreamFrame  (distinctive offset-log strings)
 *   QuicStreamSequencer_Readv          (structural, adjacent-after OnStreamFrame)
 *   QuicSpdyStream_OnDataFramePayload   (tiny thunk idiom)
 *   QuicSpdyStream_OnHeadersDecoded     (virtual override; string/callgraph/structural)
 *   QuicSpdyStream_WriteHeaders         (likely inlined; strict structural, clean-miss tolerant)
 */
public class QuicheFinder {

    private final GhidraContext ctx;
    private final MemorySearchUtils memUtils;
    private final FunctionAnalysisUtils analysisUtils;
    private final boolean debugRun;

    private final QuicSpdyStreamFinder spdyFinder;
    private final QuicStreamSequencerFinder sequencerFinder;
    private final QuicChromiumClientStreamFinder chromiumFinder;
    private final QuicSpdySessionFinder sessionFinder;

    public QuicheFinder(GhidraContext ctx, MemorySearchUtils memUtils,
                        FunctionAnalysisUtils analysisUtils, boolean debugRun) {
        this.ctx = ctx;
        this.memUtils = memUtils;
        this.analysisUtils = analysisUtils;
        this.debugRun = debugRun;
        this.spdyFinder = new QuicSpdyStreamFinder(ctx, memUtils, analysisUtils, debugRun);
        this.sequencerFinder = new QuicStreamSequencerFinder(ctx, memUtils, analysisUtils, debugRun);
        this.chromiumFinder = new QuicChromiumClientStreamFinder(ctx, memUtils, analysisUtils, debugRun);
        this.sessionFinder = new QuicSpdySessionFinder(ctx, memUtils, analysisUtils, debugRun);
    }

    public void identify() {
        System.out.println("[*] === QUICHE Detection ===");
        System.out.println("[QUICHE] arch=" + archString());

        // ----- quic_spdy_stream.cc TU -----
        spdyFinder.findWriteOrBufferBody();
        spdyFinder.findOnDataFramePayload();
        spdyFinder.findOnHeadersDecoded();
        spdyFinder.findWriteHeaders();

        // ----- quic_stream_sequencer.cc TU -----
        sequencerFinder.findOnStreamFrame();
        sequencerFinder.findReadv();

        // ----- Phase-2 chain candidates (added 2026-05-24) -----
        // Chrome-shim layer (net/quic/quic_chromium_client_stream.cc) — depends
        // on already-identified quiche-internal WriteHeaders for its primary
        // strategy (CallerOfQuicheWriteHeadersInChromeShimCluster).
        chromiumFinder.findWriteHeaders(spdyFinder.getWriteHeaders());
        // Session-level path (quiche/quic/core/http/quic_spdy_session.cc) — the
        // gQUIC HTTP-over-QUIC writer. Inert on modern HTTP/3, kept for chain
        // defense-in-depth.
        sessionFinder.findWriteHeadersOnHeadersStream();

        // Emit one line per target in a stable order.
        emit("QuicSpdyStream_WriteOrBufferBody",
            spdyFinder.getWriteOrBufferBody(), spdyFinder.getWriteOrBufferBodyStrategy(),
            "WriteOrBufferBody", 40);

        emit("QuicStreamSequencer_OnStreamFrame",
            sequencerFinder.getOnStreamFrame(), sequencerFinder.getOnStreamFrameStrategy(),
            "OnStreamFrame", 32);

        emit("QuicStreamSequencer_Readv",
            sequencerFinder.getReadv(), sequencerFinder.getReadvStrategy(),
            "Readv", 32);

        emit("QuicSpdyStream_OnDataFramePayload",
            spdyFinder.getOnDataFramePayload(), spdyFinder.getOnDataFramePayloadStrategy(),
            "OnDataFramePayload", 40);

        emit("QuicSpdyStream_OnHeadersDecoded",
            spdyFinder.getOnHeadersDecoded(), spdyFinder.getOnHeadersDecodedStrategy(),
            "OnHeadersDecoded", 48);

        emit("QuicSpdyStream_WriteHeaders",
            spdyFinder.getWriteHeaders(), spdyFinder.getWriteHeadersStrategy(),
            "WriteHeaders", 48);

        emit("QuicChromiumClientStream_WriteHeaders",
            chromiumFinder.getWriteHeaders(), chromiumFinder.getWriteHeadersStrategy(),
            "ChromeShimWriteHeaders", 32);

        // WriteHeadersOnHeadersStream may have a synthetic entry (raw address
        // + pattern bytes) when Ghidra didn't auto-create a Function. Emit
        // directly from those bytes in that case.
        Function sessionFn = sessionFinder.getWriteHeadersOnHeadersStream();
        if (sessionFn != null) {
            emit("QuicSpdySession_WriteHeadersOnHeadersStream",
                sessionFn,
                sessionFinder.getWriteHeadersOnHeadersStreamStrategy(),
                "WriteHeadersOnHeadersStream", 48);
        } else if (sessionFinder.getSynthEntry() != null && sessionFinder.getSynthPatternBytes() != null) {
            Address entry = sessionFinder.getSynthEntry();
            byte[] bytes = sessionFinder.getSynthPatternBytes();
            String pattern = memUtils.byteArrayToHex(bytes);
            System.out.println("[QUICHE_FUNC] label=QuicSpdySession_WriteHeadersOnHeadersStream"
                + " ghidra=0x" + entry.toString().toUpperCase()
                + " ida=0x" + ctx.getIdaAddress(entry)
                + " strategy=" + (sessionFinder.getWriteHeadersOnHeadersStreamStrategy() == null
                    ? "PostPrologueSixArgSaveBytePattern"
                    : sessionFinder.getWriteHeadersOnHeadersStreamStrategy())
                + " pattern=" + pattern);
        } else {
            System.out.println("[QUICHE_MISS] label=QuicSpdySession_WriteHeadersOnHeadersStream reason=not_found");
        }

        System.out.println("[*] === QUICHE Detection End ===");
    }

    private String archString() {
        if (ctx.isARM64()) return "arm64";
        if (ctx.isARM32()) return "arm";
        // No 32/64 distinction available beyond pointer size for x86.
        return ctx.getPointerSize() == 8 ? "x64" : "x86";
    }

    /**
     * Validates a found function and prints either a [QUICHE_FUNC] line (with
     * ghidra/ida offsets, strategy and byte pattern) or a [QUICHE_MISS] line.
     */
    private void emit(String label, Function func, String strategy, String role, int minWindow) {
        if (func == null) {
            System.out.println("[QUICHE_MISS] label=" + label + " reason=not_found");
            return;
        }
        if (!validateQuicheFunction(func, role)) {
            System.out.println("[QUICHE_MISS] label=" + label
                + " reason=failed_validation(" + func.getEntryPoint() + ")");
            return;
        }

        Address entry = func.getEntryPoint();
        Memory memory = ctx.program.getMemory();
        if (memory.getBlock(entry) == null) {
            System.out.println("[QUICHE_MISS] label=" + label + " reason=no_memory_block");
            return;
        }

        int numBytes = getLengthUntilBranch(func);
        if (numBytes == -42) {
            numBytes = 32;
        }
        // For very small functions extend the window so the pattern is not just
        // a too-generic prologue.
        if (numBytes < minWindow) {
            numBytes = minWindow;
        }

        byte[] bytes = memUtils.readBytes(memory, entry, numBytes);
        String pattern = memUtils.byteArrayToHex(bytes);

        System.out.println("[QUICHE_FUNC] label=" + label
            + " ghidra=0x" + entry.toString().toUpperCase()
            + " ida=0x" + ctx.getIdaAddress(entry)
            + " strategy=" + (strategy == null ? "Unknown" : strategy)
            + " pattern=" + pattern);
    }

    /**
     * Param-count band + body-size sanity for the QUICHE targets. Rejects
     * obviously-wrong functions while staying tolerant of ABI-derived param
     * recovery (Ghidra often under/over-counts reference params).
     *
     *   WriteOrBufferBody  : medium/large body
     *   OnStreamFrame      : large body (~900 B), 1 param (const QuicStreamFrame&)
     *   Readv              : medium body (~380 B), 2 params (iovec*, len)
     *   OnDataFramePayload : tiny thunk (~40 B), 1 param (string_view)
     */
    public boolean validateQuicheFunction(Function func, String role) {
        if (func == null) return false;

        long bodySize = func.getBody().getNumAddresses();
        int params = func.getParameterCount();

        switch (role) {
            case "WriteOrBufferBody":
                // Anchored by a unique string; only reject the absurd.
                if (bodySize < 16 || bodySize > 4000) return false;
                if (params > 6) return false;
                return true;

            case "OnStreamFrame":
                // Large function taking a single const-ref frame argument.
                if (bodySize < 200 || bodySize > 2000) return false;
                if (params > 4) return false;
                return true;

            case "Readv":
                if (bodySize < 200 || bodySize > 500) return false;
                if (params < 1 || params > 3) return false;
                return true;

            case "OnDataFramePayload":
                // Tiny thunk.
                if (bodySize < 16 || bodySize > 80) return false;
                if (params > 3) return false;
                return true;

            case "OnHeadersDecoded":
                // Non-inlined virtual override taking (QuicHeaderList, bool).
                return bodySize >= 80 && bodySize <= 2500 && params <= 5;

            case "WriteHeaders":
                // Possibly-inlined; (HttpHeaderBlock, bool, ref-counted ptr).
                return bodySize >= 40 && bodySize <= 2000 && params <= 6;

            case "ChromeShimWriteHeaders":
                // net::QuicChromiumClientStream::WriteHeaders — same arg shape
                // as the quiche-internal version but lives in a chromium/net/ TU.
                // Typically smaller body than the quiche-internal counterpart
                // because the shim just validates and forwards.
                return bodySize >= 40 && bodySize <= 2000 && params <= 6;

            case "WriteHeadersOnHeadersStream":
                // 6-arg gQUIC headers-stream writer; medium body.
                return bodySize >= 80 && bodySize <= 4000 && params <= 8;

            default:
                return bodySize >= 16 && bodySize <= 4000 && params <= 6;
        }
    }

    /**
     * Returns the number of bytes from the function entry up to and including
     * the first real branch/call. Sentinel -42 => no branch found, caller uses
     * the 32-byte default. Mirrors SSLReadWriteHelper.getLengthUntilBranch.
     */
    private int getLengthUntilBranch(Function function) {
        Address entryPoint = function.getEntryPoint();
        Listing listing = ctx.program.getListing();
        AddressSetView functionBody = function.getBody();
        InstructionIterator instructions = listing.getInstructions(functionBody, true);
        Instruction startInstruction = listing.getInstructionAt(entryPoint);
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
                    if (function.getBody().contains(targetAddress)
                        && (targetAddress.subtract(instruction.getAddress())) < 10) {
                        continue;
                    }
                }

                if (instruction.toString().toLowerCase().startsWith("call")
                    && instruction.toString().toLowerCase().contains("$+")) {
                    continue;
                }

                foundCall = true;
                break;
            }

            length += instruction.getLength();
        }
        return foundCall ? length : -42;
    }
}
