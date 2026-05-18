import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;

import java.util.*;

/**
 * ssl_log_secret identification logic.
 * Extensible for other TLS libraries (RustTLS, WolfSSL, etc.).
 */
public class SSLLogSecretFinder {

    private final GhidraContext ctx;
    private final MemorySearchUtils memUtils;
    private final FunctionAnalysisUtils analysisUtils;
    private final boolean debugRun;

    // Public results
    private Function identifiedFunction = null;
    private boolean identifiedTls13 = false;
    private String tls13GhidraOffset = null;
    private String tls13IdaOffset = null;
    private String tls13BytePattern = null;
    private String identifiedPattern = "";

    public SSLLogSecretFinder(GhidraContext ctx, MemorySearchUtils memUtils, FunctionAnalysisUtils analysisUtils, boolean debugRun) {
        this.ctx = ctx;
        this.memUtils = memUtils;
        this.analysisUtils = analysisUtils;
        this.debugRun = debugRun;
    }

    public Function getIdentifiedFunction() { return identifiedFunction; }
    public boolean isIdentifiedTls13() { return identifiedTls13; }
    public String getTls13GhidraOffset() { return tls13GhidraOffset; }
    public String getTls13IdaOffset() { return tls13IdaOffset; }
    public String getTls13BytePattern() { return tls13BytePattern; }
    public String getIdentifiedPattern() { return identifiedPattern; }

    public void find(String primaryString, String fallbackString) {
        System.out.println("[*] Looking for " + primaryString);
        if (debugRun) {
            System.out.println("[!] Memory blocks in binary:");
            Memory mem = ctx.program.getMemory();
            for (ghidra.program.model.mem.MemoryBlock block : mem.getBlocks()) {
                System.out.println("[!]   " + block.getName() + " [" + block.getStart() + " - " + block.getEnd() + "] " +
                    (block.isRead() ? "R" : "") + (block.isWrite() ? "W" : "") + (block.isExecute() ? "X" : ""));
            }
        }
        GhidraContext.Pair<Set<Function>, Address> result = memUtils.findStringUsage(primaryString);

        if (debugRun) {
            System.out.println("[!] Found " + result.getFirst().size() + " function(s) using the string: " + primaryString);
        }

        if (result.getSecond() == null) {
            System.out.println("[*] Trying fallback approach with String " + fallbackString);
            result = memUtils.findStringUsage(fallbackString);
        } else {
            System.out.println("[*] Found string reference at address: " + result.getSecond());
        }

        if (!result.getFirst().isEmpty()) {
            processFoundFunctions(result, false);
        } else {
            System.out.println("[*] No string found. Searching for its hex representation...");
            result = memUtils.findHexStringInRodataWrapper(primaryString, true);

            if (result.getSecond() == null) {
                System.out.println("[*] Trying fallback approach with hex representation of " + fallbackString);
                result = memUtils.findHexStringInRodataWrapper(fallbackString, true);
            }

            if (!result.getFirst().isEmpty()) {
                processFoundFunctions(result, false);
            } else {
                System.err.println("[-] No functions found using the string or its hex representation.");
                System.err.println("[-] ssl_log_secret() function not found.");
            }
        }
    }

    public void processFoundFunctions(GhidraContext.Pair<Set<Function>, Address> result, boolean isRustTls12Run) {
        Set<Function> functions = result.getFirst();
        Address referenceAddress = result.getSecond();

        Function firstFunction = functions.iterator().next();

        Address calledFunctionAddr = findReferenceToStringAtAddress(referenceAddress, firstFunction);
        if (calledFunctionAddr != null) {
            Function calledFunction = ctx.getFunctionAt.apply(calledFunctionAddr);
            if (calledFunction != null) {
                extractFunctionInfo(calledFunction, isRustTls12Run);
            } else {
                System.err.println("[-] No function found at address: " + calledFunctionAddr);
            }
        } else {
            int numberOfXrefs = analysisUtils.countXRefs(firstFunction);
            if (debugRun) {
                System.out.println("[!] Target function has " + numberOfXrefs + " invocation(s)");
            }
            Function callerFunction = null;
            if (numberOfXrefs <= 1) {
                System.out.println("[*] Trying to identify the calling function...");
                callerFunction = getFirstCaller(firstFunction);
            } else {
                System.out.println("[*] Using function with the identified label as ssl_log()...");
                extractFunctionInfo(firstFunction, isRustTls12Run);
                return;
            }

            if (callerFunction == null) {
                System.err.println("[-] Unable to identify target calling function...");
            } else {
                System.out.println("[*] Using calling function as ssl_log()...");
                extractFunctionInfo(callerFunction, isRustTls12Run);
            }
        }
    }

    private void extractFunctionInfo(Function function, boolean isRustTls12Run) {
        Address entryPoint = function.getEntryPoint();
        String label = function.getName();
        Memory memory = ctx.program.getMemory();

        if (memory.getBlock(entryPoint) == null) {
            System.err.println("[-] Memory block not found for entry point: " + entryPoint);
            return;
        }

        int numBytes = getLengthUntilBranch(function);

        if (numBytes == -42) {
            System.out.println("[*] Couldn't find a branching instruction in current function...");
            Function callerFunction = getFirstCaller(function);
            if (callerFunction == null) {
                System.err.println("[-] Unable to identify target calling function..");
            } else {
                System.out.println("[*] Using calling function as ssl_log()...");
                numBytes = getLengthUntilBranch(callerFunction);
                function = callerFunction;
                entryPoint = function.getEntryPoint();
                label = function.getName();
            }
        }

        byte[] byteData = memUtils.readBytes(memory, entryPoint, numBytes);

        StringBuilder bytePattern = new StringBuilder();
        for (byte b : byteData) {
            bytePattern.append(String.format("%02X ", b & 0xFF));
        }

        System.out.println();
        if (function.getCallingConventionName().contains("rust")) {
            System.out.println("[!] Keep in mind that hooking function using the " + function.getCallingConventionName() + " with frida is a little bit tricky...");
            // Note: Rust mangled name lookup would need to be called from BoringSecretHunter
            System.out.println("[*] Function label: " + label + " (" + function.toString() + ")");
        } else {
            System.out.println("[*] Function label: " + label + " (" + function.toString() + ")");
        }

        if (isRustTls12Run) {
            System.out.println("\n");
            System.out.println("[*] TLS 1.2 RusTLS:");
            System.out.println("[*] Function label: " + label + " (" + function.toString() + ")");
            System.out.println("[*] Function offset (Ghidra): " + entryPoint.toString().toUpperCase() + " (0x" + entryPoint.toString().toUpperCase() + ")");
            System.out.println("[*] Function offset (IDA with base 0x0): " + ctx.getIdaAddress(entryPoint) + " (0x" + ctx.getIdaAddress(entryPoint) + ")");
            System.out.println("[*] Byte pattern for frida (friTap): " + bytePattern.toString().trim());
            System.out.println();
            printTls13Info();
            return;
        }

        System.out.println("[*] Function offset (Ghidra): " + entryPoint.toString().toUpperCase() + " (0x" + entryPoint.toString().toUpperCase() + ")");
        System.out.println("[*] Function offset (IDA with base 0x0): " + ctx.getIdaAddress(entryPoint) + " (0x" + ctx.getIdaAddress(entryPoint) + ")");
        System.out.println("[*] Byte pattern for frida (friTap): " + bytePattern.toString().trim());
        System.out.println("");
        identifiedPattern = bytePattern.toString().trim();

        identifiedTls13 = true;
        tls13GhidraOffset = entryPoint.toString().toUpperCase();
        tls13IdaOffset = ctx.getIdaAddress(entryPoint);
        tls13BytePattern = bytePattern.toString().trim();
        identifiedFunction = function;
    }

    public void printTls13Info() {
        if (!identifiedTls13) {
            System.out.println("[-] TLS 1.3 pattern not yet identified.");
            return;
        }

        System.out.println("[*] TLS 1.3 RusTLS:");
        System.out.println("[*] Function label: " + identifiedFunction.getName() + " (" + identifiedFunction.toString() + ")");
        System.out.println("[*] Function offset (Ghidra): " + tls13GhidraOffset + " (0x" + tls13GhidraOffset + ")");
        System.out.println("[*] Function offset (IDA with base 0x0): " + tls13IdaOffset + " (0x" + tls13IdaOffset + ")");
        System.out.println("[*] Byte pattern for frida (friTap): " + tls13BytePattern);
    }

    public void printMaxPattern() {
        if (identifiedPattern.length() > 140) {
            System.out.println("[*] Orignal pattern was too long! Our analysis showed that a pattern longer than 140 (47 hex bytes) is unable to identify the target function...");
            System.out.println("[*] Byte pattern for frida (friTap) truncated version: " + identifiedPattern.substring(0, 140));
        }
    }

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
            if (instruction == null) {
                break;
            }

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
        if (foundCall) {
            return length;
        } else {
            return -42;
        }
    }

    private Address findReferenceToStringAtAddress(Address referenceAddr, Function function) {
        System.out.println("[*] Analyzing reference at address: " + referenceAddr + " in function: " + function.getName());
        Listing listing = ctx.program.getListing();
        Instruction instruction = listing.getInstructionAt(referenceAddr);

        if (instruction == null) {
            System.err.println("[-] No instruction found at reference address: " + referenceAddr);
            return null;
        }

        Function containingFunction = ctx.getFunctionContaining.apply(referenceAddr);

        if (ctx.isARM32()) {
            return containingFunction.getEntryPoint();
        }

        if (containingFunction != null) {
            if (debugRun) {
                System.out.println("[!] Start analyzing the function at ref: " + containingFunction.getName());
            }
            while (instruction != null && !instruction.getFlowType().isCall()) {
                instruction = instruction.getNext();
            }

            if (containingFunction.getBody().contains(instruction.getAddress())) {
                if (debugRun) {
                    System.out.println("[!] Target address is part of the analyzed function");
                }
            } else {
                if (debugRun) {
                    System.out.println("[!] Target address is not part of the analyzed function...");
                }
                return null;
            }

            if (instruction != null && instruction.getFlowType().isCall()) {
                Address[] flowRefs = instruction.getFlows();
                if (flowRefs.length > 0) {
                    return flowRefs[0];
                } else {
                    if (debugRun) {
                        System.out.println("[!] flowRefs: " + flowRefs.length + " on instruction: " + instruction.toString());
                    }
                }
            }
        }

        System.err.println("[-] No function call found near the string reference.");
        if (debugRun) {
            System.out.println("[!] instruction: " + instruction.toString());
        }
        return null;
    }

    private Function getFirstCaller(Function function) {
        Address entry = function.getEntryPoint();
        ghidra.program.model.symbol.ReferenceIterator refIter = ctx.program.getReferenceManager().getReferencesTo(entry);
        while (refIter.hasNext()) {
            ghidra.program.model.symbol.Reference ref = refIter.next();
            if (ref.getReferenceType().isCall()) {
                Function caller = ctx.getFunctionContaining.apply(ref.getFromAddress());
                if (caller != null) {
                    return caller;
                }
            }
        }
        return null;
    }
}
