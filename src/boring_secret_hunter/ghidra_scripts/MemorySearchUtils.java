import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;

import java.util.*;

/**
 * Pure memory/byte/pattern/rodata search operations.
 */
public class MemorySearchUtils {

    private final GhidraContext ctx;
    private final boolean debugRun;
    private final String largeDumpMode;

    public MemorySearchUtils(GhidraContext ctx, boolean debugRun, String largeDumpMode) {
        this.ctx = ctx;
        this.debugRun = debugRun;
        this.largeDumpMode = largeDumpMode;
    }

    public MemoryBlock findRodataBlock() {
        Memory memory = ctx.program.getMemory();
        String[] sectionNames = {".rodata", ".rdata", "__cstring", "__const"};
        for (String name : sectionNames) {
            MemoryBlock block = memory.getBlock(name);
            if (block != null) {
                return block;
            }
        }
        for (MemoryBlock block : memory.getBlocks()) {
            if (block.isRead()) {
                if (debugRun) {
                    System.out.println("[!] No named rodata section found, using block: " + block.getName());
                }
                return block;
            }
        }
        return null;
    }

    public List<MemoryBlock> findAllRodataBlocks() {
        Memory memory = ctx.program.getMemory();
        String[] sectionNames = {".rodata", ".rdata", "__cstring", "__const", ".data.rel.ro"};
        List<MemoryBlock> blocks = new ArrayList<>();
        for (String name : sectionNames) {
            MemoryBlock block = memory.getBlock(name);
            if (block != null) {
                blocks.add(block);
            }
        }
        if (blocks.isEmpty()) {
            for (MemoryBlock block : memory.getBlocks()) {
                if (block.isRead()) {
                    blocks.add(block);
                }
            }
            if (!blocks.isEmpty() && debugRun) {
                System.out.println("[!] No named rodata sections found, falling back to all readable memory blocks (" + blocks.size() + " block(s))");
            }
        }
        return blocks;
    }

    public boolean isDataSection(String blockName) {
        if (blockName == null) return false;
        String[] dataSections = {".data", ".rodata", ".rdata", "__const", "__cstring", "__data"};
        for (String section : dataSections) {
            if (blockName.contains(section)) {
                return true;
            }
        }
        return false;
    }

    public Address searchForPattern(Memory memory, Address start, Address end, byte[] pattern) {
        Address current = start;
        try {
            while (current.compareTo(end) <= 0) {
                byte[] memoryBytes = new byte[pattern.length];
                memory.getBytes(current, memoryBytes);
                if (java.util.Arrays.equals(memoryBytes, pattern)) {
                    return current;
                }
                current = current.add(1);
            }
        } catch (MemoryAccessException e) {
            ctx.println.accept("Memory access error at: " + current);
        }
        return null;
    }

    public Address searchPatterns(Memory memory, Address start, Address end, byte[][] patterns) throws Exception {
        for (byte[] pattern : patterns) {
            Address foundAddress = searchForPattern(memory, start, end, pattern);
            if (foundAddress != null) {
                System.out.println("[*] Found pattern: " + byteArrayToHex(pattern) + " at: " + foundAddress + " (IDA: 0x" + ctx.getIdaAddress(foundAddress) + ")");
                return foundAddress;
            }
        }
        return null;
    }

    public Address searchPatternFast(Memory memory, Address start, Address end, byte[] pattern) {
        try {
            return memory.findBytes(start, end, pattern, null, true, ctx.monitor);
        } catch (Exception e) {
            if (debugRun) {
                System.out.println("[!] Fast search failed, falling back to manual scan: " + e.getMessage());
            }
            return searchForPattern(memory, start, end, pattern);
        }
    }

    public Address searchPatternsFast(Memory memory, Address start, Address end, byte[][] patterns) throws Exception {
        for (byte[] pattern : patterns) {
            Address foundAddress = searchPatternFast(memory, start, end, pattern);
            if (foundAddress != null) {
                System.out.println("[*] Found pattern: " + byteArrayToHex(pattern) + " at: " + foundAddress + " (IDA: 0x" + ctx.getIdaAddress(foundAddress) + ")");
                return foundAddress;
            }
        }
        return null;
    }

    public byte[] appendByte(byte[] original, byte value) {
        byte[] result = new byte[original.length + 1];
        System.arraycopy(original, 0, result, 0, original.length);
        result[original.length] = value;
        return result;
    }

    public String byteArrayToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X ", b));
        }
        return sb.toString().trim();
    }

    public byte[] addressToBytes(Address addr, int pointerSize) {
        long offset = addr.getOffset();
        byte[] bytes = new byte[pointerSize];
        for (int i = 0; i < pointerSize; i++) {
            bytes[i] = (byte) (offset & 0xFF);
            offset >>= 8;
        }
        return bytes;
    }

    public byte[] readBytes(Memory memory, Address address, int numBytes) {
        byte[] byteData = new byte[numBytes];
        try {
            memory.getBytes(address, byteData);
        } catch (MemoryAccessException e) {
            System.err.println("[-] Error reading bytes from memory at " + address + ": " + e.getMessage());
        }
        return byteData;
    }

    public GhidraContext.Pair<Set<Function>, Address> findStringUsage(String stringToFind) {
        Set<Function> functions = new HashSet<>();
        Address referenceAddress = null;

        Listing listing = ctx.program.getListing();
        DataIterator dataIterator = listing.getDefinedData(true);

        while (dataIterator.hasNext()) {
            Data data = dataIterator.next();
            if (data.getDataType().getName().equals("string") && data.getValue().toString().toLowerCase().contains(stringToFind.toLowerCase())) {
                Reference[] references = ctx.getReferencesTo.apply(data.getAddress());
                if (debugRun) {
                    System.out.println("[!] Found string \"" + stringToFind + "\"at location " + data.getAddress() + " (IDA: 0x" + ctx.getIdaAddress(data.getAddress()) + ")" + " with value " + data.getValue().toString());
                }
                for (Reference ref : references) {
                    referenceAddress = ref.getFromAddress();
                    Function func = ctx.getFunctionContaining.apply(ref.getFromAddress());
                    if (func != null) {
                        functions.add(func);
                    }
                }
            }
        }
        return new GhidraContext.Pair<>(functions, referenceAddress);
    }

    public Set<Function> findAllFunctionsReferencingString(String stringToFind) {
        Set<Function> functions = new HashSet<>();

        Listing listing = ctx.program.getListing();
        DataIterator dataIterator = listing.getDefinedData(true);
        while (dataIterator.hasNext()) {
            Data data = dataIterator.next();
            if (data.getDataType().getName().equals("string")
                && data.getValue().toString().contains(stringToFind)) {
                Reference[] references = ctx.getReferencesTo.apply(data.getAddress());
                for (Reference ref : references) {
                    Function func = ctx.getFunctionContaining.apply(ref.getFromAddress());
                    if (func != null) {
                        functions.add(func);
                    }
                }
            }
        }

        if (functions.isEmpty()) {
            GhidraContext.Pair<Set<Function>, Address> hexResult = findHexStringInRodata(stringToFind, false);
            functions.addAll(hexResult.getFirst());
        }

        if (functions.isEmpty()) {
            Set<Function> codeScanResult = findFunctionsReferencingAddressViaCodeScan(stringToFind);
            functions.addAll(codeScanResult);
        }

        return functions;
    }

    public Set<Function> findFunctionsReferencingAddressViaCodeScan(String stringToFind) {
        Set<Function> functions = new HashSet<>();
        Memory memory = ctx.program.getMemory();
        int pointerSize = ctx.getPointerSize();

        byte[] searchBytes = appendByte(stringToFind.getBytes(), (byte) 0x00);

        Address targetAddr = null;
        for (MemoryBlock block : findAllRodataBlocks()) {
            try {
                Address found = memory.findBytes(block.getStart(), block.getEnd(), searchBytes, null, true, ctx.monitor);
                if (found != null) {
                    targetAddr = found;
                    break;
                }
            } catch (Exception e) {
                continue;
            }
        }

        if (targetAddr == null) {
            if (debugRun) {
                System.out.println("[!] CodeScan: Could not locate '" + stringToFind + "' bytes");
            }
            return functions;
        }

        if (debugRun) {
            System.out.println("[!] CodeScan: Found '" + stringToFind + "' at " + targetAddr);
        }

        byte[] addrBytes = addressToBytes(targetAddr, pointerSize);

        for (MemoryBlock block : memory.getBlocks()) {
            if (!block.isExecute()) continue;
            try {
                Address searchAddr = block.getStart();
                while (searchAddr != null && searchAddr.compareTo(block.getEnd()) < 0) {
                    Address found = memory.findBytes(searchAddr, block.getEnd(), addrBytes, null, true, ctx.monitor);
                    if (found == null) break;
                    Function func = ctx.getFunctionContaining.apply(found);
                    if (func != null) {
                        functions.add(func);
                        if (debugRun) {
                            System.out.println("[!] CodeScan: Found pointer reference in " + func.getName() + " at " + found);
                        }
                    }
                    searchAddr = found.add(1);
                }
            } catch (Exception e) {
                continue;
            }
        }

        // ADRP+ADD scanning for ARM64
        String langId = ctx.program.getLanguageID().toString().toUpperCase();
        if (langId.contains("AARCH64") || langId.contains("ARM:LE:64")) {
            long targetOffset = targetAddr.getOffset();
            long targetPage = targetOffset & ~0xFFF;
            long targetPageOff = targetOffset & 0xFFF;
            if (debugRun) {
                System.out.println("[!] CodeScan: Scanning for ADRP+ADD chain targeting 0x" +
                    Long.toHexString(targetOffset) + " (page=0x" + Long.toHexString(targetPage) +
                    ", offset=0x" + Long.toHexString(targetPageOff) + ")");
            }

            for (MemoryBlock block : memory.getBlocks()) {
                if (!block.isExecute()) continue;
                InstructionIterator instIter = ctx.program.getListing().getInstructions(block.getStart(), true);
                while (instIter.hasNext()) {
                    Instruction inst = instIter.next();
                    if (inst.getAddress().compareTo(block.getEnd()) > 0) break;
                    String mnemonic = inst.getMnemonicString();
                    if (!"adrp".equalsIgnoreCase(mnemonic)) continue;

                    long adrpPageBase = -1;
                    String adrpDestReg = null;

                    if (inst.getNumOperands() > 0) {
                        adrpDestReg = inst.getDefaultOperandRepresentation(0);
                    }

                    for (int i = 0; i < inst.getNumOperands(); i++) {
                        Object[] opObjects = inst.getOpObjects(i);
                        for (Object obj : opObjects) {
                            if (obj instanceof Address) {
                                adrpPageBase = ((Address) obj).getOffset();
                            }
                        }
                    }

                    if (adrpPageBase == -1 || adrpDestReg == null) continue;
                    if ((adrpPageBase & ~0xFFF) != targetPage) continue;

                    Instruction nextInst = inst.getNext();
                    boolean fullChainMatch = false;
                    for (int step = 0; step < 8 && nextInst != null; step++) {
                        String nextMnemonic = nextInst.getMnemonicString();
                        if ("add".equalsIgnoreCase(nextMnemonic) && nextInst.getNumOperands() >= 3) {
                            String addOp0 = nextInst.getDefaultOperandRepresentation(0);
                            String addOp1 = nextInst.getDefaultOperandRepresentation(1);

                            if (adrpDestReg.equals(addOp0) || adrpDestReg.equals(addOp1)) {
                                for (int opIdx = 0; opIdx < nextInst.getNumOperands(); opIdx++) {
                                    Object[] opObjects = nextInst.getOpObjects(opIdx);
                                    for (Object obj : opObjects) {
                                        if (obj instanceof ghidra.program.model.scalar.Scalar) {
                                            long addImm = ((ghidra.program.model.scalar.Scalar) obj).getUnsignedValue();
                                            long resolvedAddr = adrpPageBase + addImm;
                                            if (resolvedAddr == targetOffset) {
                                                fullChainMatch = true;
                                            }
                                            if (debugRun && addImm < 0x1000) {
                                                System.out.println("[!] CodeScan: ADRP+ADD candidate at " +
                                                    inst.getAddress() + ": page=0x" + Long.toHexString(adrpPageBase) +
                                                    " + imm=0x" + Long.toHexString(addImm) +
                                                    " = 0x" + Long.toHexString(resolvedAddr) +
                                                    (fullChainMatch ? " MATCH!" : " no match"));
                                            }
                                        }
                                    }
                                }
                                if (fullChainMatch) break;
                            }
                        }
                        if (nextInst.getFlowType().isCall() || nextInst.getFlowType().isJump() ||
                            nextInst.getFlowType().isTerminal()) {
                            break;
                        }
                        nextInst = nextInst.getNext();
                    }

                    if (fullChainMatch) {
                        Function func = ctx.getFunctionContaining.apply(inst.getAddress());
                        if (func != null) {
                            functions.add(func);
                            if (debugRun) {
                                System.out.println("[!] CodeScan: ADRP+ADD full chain match in " +
                                    func.getName() + " at " + inst.getAddress());
                            }
                        }
                    }
                }
            }
        }

        if (debugRun) {
            System.out.println("[!] CodeScan: Found " + functions.size() + " functions via code scanning");
        }

        return functions;
    }

    public Address findBackwardsXref(Program program, Address target) {
        int pointerSize = ctx.getPointerSize();
        ReferenceManager refMgr = program.getReferenceManager();
        AddressSpace space = target.getAddressSpace();
        long offset = target.getOffset();

        while (offset > space.getMinAddress().getOffset()) {
            offset -= pointerSize;
            Address candidate = space.getAddress(offset);
            Reference[] fromRefs = refMgr.getReferencesFrom(candidate);
            for (Reference ref : fromRefs) {
                if (ref.getToAddress().equals(target)) {
                    return candidate;
                }
            }
        }

        Address middle = target;
        Data data = ctx.getDataContaining.apply(middle);
        if (data == null) {
            System.out.println("[-] No data item containing " + middle + " (IDA: 0x" + ctx.getIdaAddress(middle) + ")");
            return null;
        }

        Address dataStart = data.getMinAddress();
        System.out.println("[*] Target starts at: " + dataStart + " (IDA: 0x" + ctx.getIdaAddress(dataStart) + ")");

        ReferenceManager refMgr1 = ctx.program.getReferenceManager();
        ReferenceIterator refIter = refMgr1.getReferencesTo(dataStart);

        if (!refIter.hasNext()) {
            System.out.println("[-] No references to " + dataStart + " (IDA: 0x" + ctx.getIdaAddress(dataStart) + ")");
        } else {
            while (refIter.hasNext()) {
                Reference ref = refIter.next();
                Address fromAddr = ref.getFromAddress();
                return fromAddr;
            }
        }

        return null;
    }

    public GhidraContext.Pair<Function, Address> findFunctionReferences(Address dataRelRoAddress, String sectionName) {
        List<GhidraContext.Pair<Function, Address>> functionAddressPairs = new ArrayList<>();

        ReferenceManager referenceManager = ctx.program.getReferenceManager();
        ReferenceIterator references = referenceManager.getReferencesTo(dataRelRoAddress);

        while (references.hasNext()) {
            Reference reference = references.next();
            Address refAddress = reference.getFromAddress();
            Function function = ctx.getFunctionContaining.apply(refAddress);

            if (function != null) {
                System.out.println("[*] Found reference to " + sectionName + " at " + refAddress + " (IDA: 0x" + ctx.getIdaAddress(refAddress) + ")" + " in function: " + function.getName());
                functionAddressPairs.add(new GhidraContext.Pair<>(function, refAddress));
            } else {
                Memory memory = ctx.program.getMemory();
                MemoryBlock block = memory.getBlock(refAddress);
                if (block != null) {
                    String blockName = block.getName();
                    if (isDataSection(blockName)) {
                        if (debugRun) {
                            System.out.println("[!] The address is pointing to another data section:" + blockName + " at address: " + refAddress);
                        }
                        GhidraContext.Pair<Function, Address> dataPair = traceDataSectionPointer(ctx.program, refAddress, 4);
                        if (dataPair != null && dataPair.first != null && dataPair.second != null) {
                            functionAddressPairs.add(dataPair);
                        }
                    } else {
                        System.out.println("The address is in an unknown section.");
                    }
                } else {
                    System.out.println("No memory block found for address: " + refAddress);
                }
            }
        }

        if (debugRun && functionAddressPairs.size() > 1) {
            System.out.println("[!] Found more than pair, but currently only the first one will be used for further processing...");
            System.out.println("[!] Full list of Pairs: ");
            for (GhidraContext.Pair<Function, Address> analysisPair : functionAddressPairs) {
                System.out.println("[!] Function: " + analysisPair.first.getName() + " at address: " + analysisPair.getSecond());
            }
        }

        if (functionAddressPairs == null || functionAddressPairs.size() == 0) {
            if (ctx.isARM32()) {
                GhidraContext.Pair<Set<Function>, Address> resBinder = findHexStringInRodataWrapper("res binder", false);
                if (resBinder.getFirst() != null && resBinder.getSecond() != null) {
                    Set<Function> functionSet = resBinder.getFirst();
                    if (functionSet != null && !functionSet.isEmpty()) {
                        Function firstFunction = functionSet.iterator().next();
                        functionAddressPairs.add(new GhidraContext.Pair<>(firstFunction, resBinder.getSecond()));
                    }
                }
            } else {
                Address refAddr = findBackwardsXref(ctx.program, dataRelRoAddress);
                if (refAddr != null) {
                    Function function = ctx.getFunctionContaining.apply(refAddr);
                    if (function == null) {
                        if (debugRun) {
                            System.out.println("[!] function is null and ref is probably pointing to another section (" + refAddr + ")...");
                        }
                    }
                    if (function != null) {
                        System.out.println("[*] Found a reference to " + dataRelRoAddress + " at: " + refAddr + " in function: " + function.getName());
                    } else {
                        System.out.println("[*] Found a reference to " + dataRelRoAddress + " at: " + refAddr + " in function: <UNDEFINED>");
                    }
                    functionAddressPairs.add(new GhidraContext.Pair<>(function, refAddr));
                } else {
                    System.out.println("[-] Error: No backwards reference found for " + dataRelRoAddress);
                    return null;
                }
            }
        }

        if (functionAddressPairs.isEmpty()) {
            return null;
        }
        return functionAddressPairs.getFirst();
    }

    public GhidraContext.Pair<Function, Address> traceDataSectionPointer(Program program, Address startAddress, int maxAttempts) {
        Listing listing = program.getListing();
        int addressSize = program.getAddressFactory().getDefaultAddressSpace().getPointerSize();
        Address refAddress = null;
        Address currentAddress = startAddress;

        for (int attempt = 0; attempt < maxAttempts; attempt++) {
            Function function = listing.getFunctionAt(currentAddress);

            ReferenceManager referenceManager = ctx.program.getReferenceManager();
            ReferenceIterator references = referenceManager.getReferencesTo(currentAddress);

            Reference reference = references.next();
            if (reference != null) {
                refAddress = reference.getFromAddress();
                Function function1 = ctx.getFunctionContaining.apply(refAddress);
                function = function1;
            }

            if (function != null && refAddress != null) {
                System.out.println("[*] Found reference to function: " + function.getName() +
                    " at target address: " + currentAddress + " (IDA: 0x" + ctx.getIdaAddress(currentAddress) + ")");
                return new GhidraContext.Pair<>(function, refAddress);
            }

            currentAddress = currentAddress.subtract(addressSize);
            if (currentAddress == null) {
                System.out.println("[-] Reached invalid address while stepping back.");
                break;
            }
        }

        System.out.println("[*] No function reference found after " + maxAttempts + " attempts.");
        return null;
    }

    public boolean isHexStringInRodata(String targetString) {
        byte[] targetBytes = targetString.getBytes();
        Memory memory = ctx.program.getMemory();
        List<MemoryBlock> rodataBlocks = findAllRodataBlocks();

        if (rodataBlocks.isEmpty()) {
            return false;
        }

        byte[] littleEndianPattern = new byte[targetBytes.length];
        for (int i = 0; i < targetBytes.length; i++) {
            littleEndianPattern[i] = targetBytes[targetBytes.length - 1 - i];
        }

        byte[] bigEndianWithNull = appendByte(targetBytes, (byte) 0x00);
        byte[] bigEndianWithSpace = appendByte(targetBytes, (byte) 0x20);
        byte[] littleEndianWithNull = appendByte(littleEndianPattern, (byte) 0x00);
        byte[] littleEndianWithSpace = appendByte(littleEndianPattern, (byte) 0x20);

        for (MemoryBlock rodataBlock : rodataBlocks) {
            Address start = rodataBlock.getStart();
            Address end = rodataBlock.getEnd();

            try {
                Address foundAddress = searchPatterns(memory, start, end,
                    new byte[][] {bigEndianWithNull, bigEndianWithSpace, targetBytes});
                if (foundAddress != null) {
                    return true;
                }

                foundAddress = searchPatterns(memory, start, end,
                    new byte[][] {littleEndianWithNull, littleEndianWithSpace, littleEndianPattern});
                if (foundAddress != null) {
                    return true;
                }
            } catch (MemoryAccessException e) {
                // continue to next block
            } catch (Exception e) {
                // continue to next block
            }
        }
        return false;
    }

    public GhidraContext.Pair<Set<Function>, Address> findHexStringInRodata(String targetString, boolean doPrintInfoMsg) {
        Set<Function> functions = new HashSet<>();
        GhidraContext.Pair<Function, Address> functionAddressPair;
        Address referenceAddress = null;

        byte[] targetBytes = targetString.getBytes();
        Memory memory = ctx.program.getMemory();
        List<MemoryBlock> rodataBlocks = findAllRodataBlocks();

        if (rodataBlocks.isEmpty()) {
            if (doPrintInfoMsg) {
                System.out.println("[-] No read-only data sections found (checked: .rodata, .rdata, __cstring, __const)!");
            }
            return new GhidraContext.Pair<>(functions, null);
        }

        if ("skip".equals(largeDumpMode)) {
            long totalSize = 0;
            for (MemoryBlock b : rodataBlocks) { totalSize += b.getSize(); }
            if (totalSize > 100 * 1024 * 1024) {
                System.out.println("[!] Skipping large memory region (" + (totalSize / (1024 * 1024)) + " MB) due to LARGE_DUMP_MODE=skip");
                return new GhidraContext.Pair<>(functions, null);
            }
        }

        byte[] littleEndianPattern = new byte[targetBytes.length];
        for (int i = 0; i < targetBytes.length; i++) {
            littleEndianPattern[i] = targetBytes[targetBytes.length - 1 - i];
        }

        byte[] bigEndianWithNull = appendByte(targetBytes, (byte) 0x00);
        byte[] bigEndianWithSpace = appendByte(targetBytes, (byte) 0x20);
        byte[] littleEndianWithNull = appendByte(littleEndianPattern, (byte) 0x00);
        byte[] littleEndianWithSpace = appendByte(littleEndianPattern, (byte) 0x20);
        Address foundAddress = null;
        String foundBlockName = null;

        for (MemoryBlock rodataBlock : rodataBlocks) {
            Address start = rodataBlock.getStart();
            Address end = rodataBlock.getEnd();

            try {
                if ("fast".equals(largeDumpMode)) {
                    foundAddress = searchPatternsFast(memory, start, end,
                        new byte[][] {bigEndianWithNull, bigEndianWithSpace, targetBytes});
                } else {
                    foundAddress = searchPatterns(memory, start, end,
                        new byte[][] {bigEndianWithNull, bigEndianWithSpace, targetBytes});
                }
                if (foundAddress != null && debugRun && doPrintInfoMsg) {
                    System.out.println("[*] Found big-endian pattern at: " + foundAddress + " in section " + rodataBlock.getName());
                }

                if (foundAddress == null) {
                    if ("fast".equals(largeDumpMode)) {
                        foundAddress = searchPatternsFast(memory, start, end,
                            new byte[][] {littleEndianWithNull, littleEndianWithSpace, littleEndianPattern});
                    } else {
                        foundAddress = searchPatterns(memory, start, end,
                            new byte[][] {littleEndianWithNull, littleEndianWithSpace, littleEndianPattern});
                    }
                    if (foundAddress != null && debugRun && doPrintInfoMsg) {
                        System.out.println("[*] Found little-endian pattern at: " + foundAddress + " in section " + rodataBlock.getName());
                    }
                }

                if (foundAddress != null) {
                    foundBlockName = rodataBlock.getName();
                    break;
                }

            } catch (MemoryAccessException e) {
                System.err.println("[-] Error accessing memory in " + rodataBlock.getName() + ": " + e.getMessage());
            } catch (Exception e) {
                System.err.println("[-] Error in pattern identification in " + rodataBlock.getName() + ": " + e.getMessage());
            }
        }

        if (foundAddress != null) {
            if (doPrintInfoMsg) {
                System.out.println("[*] String found in " + foundBlockName + " section at address: " + foundAddress);
            }
            functionAddressPair = findFunctionReferences(foundAddress, foundBlockName);
            if (functionAddressPair == null) {
                System.out.println("[-] Error in findFunctionReferences...");
                return new GhidraContext.Pair<>(functions, referenceAddress);
            }
            functions.add(functionAddressPair.getFirst());
            referenceAddress = functionAddressPair.getSecond();
        } else {
            if (doPrintInfoMsg) {
                StringBuilder checkedSections = new StringBuilder();
                for (MemoryBlock b : rodataBlocks) {
                    if (checkedSections.length() > 0) checkedSections.append(", ");
                    checkedSections.append(b.getName());
                }
                System.err.println("[-] Unable to find pattern in any read-only data section (checked: " + checkedSections + ")");
            }
        }

        return new GhidraContext.Pair<>(functions, referenceAddress);
    }

    public GhidraContext.Pair<Set<Function>, Address> findHexStringInRodataWrapper(String stringToFind, boolean doPrintInfoMsg) {
        if (doPrintInfoMsg) {
            System.out.println("[*] Searching for hex representation of: " + stringToFind);
        }
        return findHexStringInRodata(stringToFind, doPrintInfoMsg);
    }

    public boolean is_string_in_binary(String stringToFind) {
        Listing listing = ctx.program.getListing();
        DataIterator dataIterator = listing.getDefinedData(true);

        while (dataIterator.hasNext()) {
            Data data = dataIterator.next();
            if (data.getDataType().getName().equals("string") && data.getValue().toString().toLowerCase().contains(stringToFind.toLowerCase())) {
                return true;
            }
        }
        return false;
    }
}
