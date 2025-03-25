import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;

import java.util.*;


public class BoringSecretHunter extends GhidraScript {

private static String identified_pattern = "";

    // Custom implementation of Pair class
public class Pair<K, V> {
    private final K first;
    private final V second;

    public Pair(K first, V second) {
        this.first = first;
        this.second = second;
    }

    public K getFirst() {
        return first;
    }

    public V getSecond() {
        return second;
    }
}


    private static final String VERSION = "1.0.4";
    private static boolean DEBUG_RUN = false;
    public static boolean identifiedTls13 = false;
    public static String tls13GhidraOffset = null;
    public static String tls13IdaOffset = null;
    public static String tls13BytePattern = null;
    public static Function tls13label = null;

    private void printBoringSecretHunterLogo() {
        if(DEBUG_RUN){
            System.out.println("[!] BoringSecretHunter Environment infos: ");
            System.out.println("[!] Running on Java version: " + System.getProperty("java.version"));
            System.out.println("[!] Current Ghidra version: " + currentProgram.getLanguage().getVersion()+"\n");
        }
        
        println("");
        System.out.println("""
                            BoringSecretHunter
        ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣀⣀⣀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
        ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⠾⠛⢉⣉⣉⣉⡉⠛⠷⣦⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀
        ⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⠋⣠⣴⣿⣿⣿⣿⣿⡿⣿⣶⣌⠹⣷⡀⠀⠀⠀⠀⠀⠀⠀
         ⠀⠀⠀⠀⠀⠀⠀⠀⣼⠁⣴⣿⣿⣿⣿⣿⣿⣿⣿⣆⠉⠻⣧⠘⣷⠀⠀⠀⠀⠀⠀⠀
        ⠀⠀⠀⠀⠀⠀⠀⠀⢰⡇⢰⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠀⠀⠈⠀⢹⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
        ⠀⠀⠀⠀⠀⠀⠀⠀⢸⡇⢸⣿⠛⣿⣿⣿⣿⣿⣿⡿⠃⠀⠀⠀⠀⢸⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
        ⠀⠀⠀⠀⠀⠀⠀⠀⠈⣷⠀⢿⡆⠈⠛⠻⠟⠛⠉⠀⠀⠀⠀⠀⠀⣾⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
        ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⣧⡀⠻⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣼⠃⠀⠀⠀⠀⠀⠀⠀ ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
        ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢼⠿⣦⣄⠀⠀⠀⠀⠀⠀⠀⣀⣴⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
        ⠀⠀⠀⠀⠀⠀⣠⣾⣿⣦⠀⠀⠈⠉⠛⠓⠲⠶⠖⠚⠋⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
        ⠀⠀⠀⠀⣠⣾⣿⣿⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
        ⠀⠀⣠⣾⣿⣿⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
        ⠀⣾⣿⣿⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
        ⣄⠈⠛⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
        ⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
        """);
        System.out.println("Identifying the ssl_log_secret() function for extracting key material using Frida.");
        System.out.println("Version: " + VERSION + " by Daniel Baier\n");
    }

    private int get_pointer_size(){
        int pointer_size = 0x4;
        String languageID = currentProgram.getLanguageID().toString();
        if(languageID.contains("64")){
            pointer_size = 0x8;
        }
    
        return pointer_size;
    }

    public void printTls13Info() {
        if (!BoringSecretHunter.identifiedTls13) {
            System.out.println("[-] TLS 1.3 pattern not yet identified.");
            return;
        }
    
        System.out.println("[*] TLS 1.3 RusTLS:");
        System.out.println("[*] Function label: " + tls13label.getName()+  " ("+ tls13label.toString() +")");
        System.out.println("[*] Function offset (Ghidra): " + BoringSecretHunter.tls13GhidraOffset + " (0x" + BoringSecretHunter.tls13GhidraOffset + ")");
        System.out.println("[*] Function offset (IDA with base 0x0): " + BoringSecretHunter.tls13IdaOffset + " (0x" + BoringSecretHunter.tls13IdaOffset + ")");
        System.out.println("[*] Byte pattern for frida (friTap): " + BoringSecretHunter.tls13BytePattern);
    }

        /**
     * Searches backward from 'target' in steps of 'pointerSize' to find
     * the first address that has a reference (XREF) pointing to 'target'.
     * 
     * @param program     The current Program
     * @param target      The address (e.g. part of a string) for which we want to find a referencing pointer
     * @return            The address that references 'target', or null if none found
     */
    private Address findBackwardsXref(Program program, Address target) {
        int pointerSize = get_pointer_size();
        ReferenceManager refMgr = program.getReferenceManager();
        AddressSpace space = target.getAddressSpace();
        long offset = target.getOffset();

        // Keep stepping backwards by pointerSize until we go past the start of the address space
        while (offset > space.getMinAddress().getOffset()) {
            offset -= pointerSize;
            Address candidate = space.getAddress(offset);

            // Check if 'candidate' has references (XREFs) going TO 'target'
            Reference[] fromRefs = refMgr.getReferencesFrom(candidate);
            for (Reference ref : fromRefs) {
                if (ref.getToAddress().equals(target)) {
                    // Found an address that references our target
                    return candidate;
                }
            }
        }

        // Alternative approach when the target address is not in the beginning
        Address middle = target; // The offset you discovered in memory

        Data data = getDataContaining(middle);
        if (data == null) {
            System.out.println("[-] No data item containing " + middle + " (IDA: 0x"+get_ida_address(middle)+")");
            return null;
        }

        // 2) Ghidra's recognized data item might start earlier (e.g. 0x2e563)
        Address dataStart = data.getMinAddress();
        System.out.println("[*] Target starts at: " + dataStart + " (IDA: 0x"+get_ida_address(dataStart)+")");

        // 3) Retrieve references to that start address
        ReferenceManager refMgr1 = currentProgram.getReferenceManager();
         
        ReferenceIterator refIter = refMgr1.getReferencesTo(dataStart);

        if (refIter.hasNext() == false) {
            System.out.println("[-] No references to " + dataStart + " (IDA: 0x"+get_ida_address(dataStart)+")");
        } else {

            while (refIter.hasNext()) {
                Reference ref = refIter.next();
                Address fromAddr = ref.getFromAddress();
                //System.out.println("  " + fromAddr + " => " + dataStart + " (type: " + ref.getReferenceType() + ")");
                // returning reference
                return fromAddr;
            }
        }
    

        return null; // none found
    }

    private void print_rustls_results(String tls12_pattern){
        // TLS 1.3  BoringSecretHunter.identified_pattern;
        print_max_pattern();

    }

    private boolean is_string_in_binary(String stringToFind){
        Listing listing = currentProgram.getListing();
        DataIterator dataIterator = listing.getDefinedData(true);
    
        while (dataIterator.hasNext()) {
            Data data = dataIterator.next();
            if (data.getDataType().getName().equals("string") && data.getValue().toString().toLowerCase().contains(stringToFind.toLowerCase())) {
                return true;
            }
        }
        return false;

    }



    private void print_max_pattern(){
        String identfied_byte_pattern = BoringSecretHunter.identified_pattern;
    
        if(identfied_byte_pattern.length() > 140){
            System.out.println("[*] Orignal pattern was too long! Our analysis showed that a pattern longer than 140 (47 hex bytes) is unable to identify the target function...");
            System.out.println("[*] Byte pattern for frida (friTap) truncated version: " + identfied_byte_pattern.substring(0, 140));
        }
    }

    private Pair<Set<Function>, Address> findStringUsage(String stringToFind) {
        Set<Function> functions = new HashSet<>();
        Address referenceAddress = null;
    
        Listing listing = currentProgram.getListing();
        DataIterator dataIterator = listing.getDefinedData(true);
    
        while (dataIterator.hasNext()) {
            Data data = dataIterator.next();
            if (data.getDataType().getName().equals("string") && data.getValue().toString().toLowerCase().contains(stringToFind.toLowerCase())) {
                Reference[] references = getReferencesTo(data.getAddress());
                if(DEBUG_RUN){
                    System.out.println("[!] Found string\""+stringToFind+ "\"at location "+data.getAddress()+ " (IDA: 0x"+get_ida_address(data.getAddress())+")" +" with value "+data.getValue().toString());
                }
                for (Reference ref : references) {
                    referenceAddress = ref.getFromAddress(); // Store the reference address
                    Function func = getFunctionContaining(ref.getFromAddress());
                    if (func != null) {
                        functions.add(func);
                    }
                }
            }
        }
        return new Pair<>(functions, referenceAddress); // Return both the set of functions and the reference address
    }

    private boolean isARM32(){
        String languageID = currentProgram.getLanguageID().toString();
        String architecture_String = languageID.toString().toUpperCase();
        boolean isARM32 = architecture_String.contains("ARM:LE:32");
        return isARM32;
    }

    private int countXRefs(Function function){
        // Get the entry point of the function.
        Address entry = function.getEntryPoint();       

        // Obtain an iterator over all references to the entry point.
        ReferenceIterator refIter = currentProgram.getReferenceManager().getReferencesTo(entry);

        // Count the number of references.
        int count = 0;
        while (refIter.hasNext()) {
            Reference ref = refIter.next();
            if (ref.getReferenceType().isCall()) {
                count++;
            }
        }

        return count;
    }

    // Utility function to append a byte to a byte array
    private byte[] appendByte(byte[] original, byte value) {
        byte[] result = new byte[original.length + 1];
        System.arraycopy(original, 0, result, 0, original.length);
        result[original.length] = value;
        return result;
    }

    private String byteArrayToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X ", b));
        }
        return sb.toString().trim();
    }


    private Address searchForPattern(Memory memory, Address start, Address end, byte[] pattern) {
        Address current = start;
    
        try {
            while (current.compareTo(end) <= 0) {
                byte[] memoryBytes = new byte[pattern.length];
                memory.getBytes(current, memoryBytes);
    
                if (java.util.Arrays.equals(memoryBytes, pattern)) {
                    return current; // Pattern found
                }
    
                current = current.add(1); // Increment address by 1 byte
            }
        } catch (MemoryAccessException e) {
            println("Memory access error at: " + current);
        }
    
        return null; // Pattern not found
    }


    private Address searchPatterns(Memory memory, Address start, Address end, byte[][] patterns) throws Exception {
        for (byte[] pattern : patterns) {
            Address foundAddress = searchForPattern(memory, start, end, pattern);
            if (foundAddress != null) {
                System.out.println("[*] Found pattern: " + byteArrayToHex(pattern) + " at: " + foundAddress+ " (IDA: 0x"+get_ida_address(foundAddress)+")");
                return foundAddress;
            }
        }
        return null;
    }

public Pair<Function, Address> traceDataSectionPointer(Program program, Address startAddress, int maxAttempts) {
        Listing listing = program.getListing();
        int addressSize = program.getAddressFactory().getDefaultAddressSpace().getPointerSize();
        Address refAddress = null;
    
        Address currentAddress = startAddress;
    
        for (int attempt = 0; attempt < maxAttempts; attempt++) {
            // Check if the current address contains a pointer to a function
            Function function = listing.getFunctionAt(currentAddress);
            

            ReferenceManager referenceManager = currentProgram.getReferenceManager();
            ReferenceIterator references = referenceManager.getReferencesTo(currentAddress);

            Reference reference = references.next();
            if(reference != null){
                refAddress = reference.getFromAddress();
                Function function1 = getFunctionContaining(refAddress);
                function = function1;
            }
            

            if (function != null && refAddress != null) {
                System.out.println("[*] Found reference to function: " + function.getName() +
                                    " at target address: " + currentAddress+  " (IDA: 0x"+get_ida_address(currentAddress)+")");
                Pair<Function, Address> funcPair = new Pair<>(function,refAddress);
                return funcPair; // Found the function reference
            }
           
    
            // Move one address size backward
            currentAddress = currentAddress.subtract(addressSize);
            if (currentAddress == null) {
                System.out.println("[-] Reached invalid address while stepping back.");
                break;
            }
        }
    
        System.out.println("[*] No function reference found after " + maxAttempts + " attempts.");
        return null; // No valid function reference found
    }


    private Pair<Function, Address> findFunctionReferences(Address dataRelRoAddress, String sectionName) {
        List<Pair<Function, Address>> functionAddressPairs = new ArrayList<>();

        ReferenceManager referenceManager = currentProgram.getReferenceManager();
        ReferenceIterator references = referenceManager.getReferencesTo(dataRelRoAddress);

        while (references.hasNext()) {
            Reference reference = references.next();
            Address refAddress = reference.getFromAddress();
            Function function = getFunctionContaining(refAddress);

            if (function != null) {
                System.out.println("[*] Found reference to "+sectionName+" at " + refAddress+ " (IDA: 0x"+get_ida_address(refAddress)+")" + " in function: " + function.getName());
                functionAddressPairs.add(new Pair<>(function, refAddress));
            }else{
                
                Memory memory = currentProgram.getMemory();
                MemoryBlock block = memory.getBlock(refAddress);
                if (block != null) {
                    String blockName = block.getName();
            
                    // Determine if the address belongs to a data section
                    if (blockName.contains(".data") || blockName.contains(".rodata")) {
                        if(DEBUG_RUN){
                            System.out.println("[!] The address is pointing to another data section:"+blockName+ " at address: "+refAddress);
                        }

                        Pair<Function, Address> dataPair = traceDataSectionPointer(currentProgram, refAddress,4);
                        if(dataPair.first != null && dataPair.second != null){
                            functionAddressPairs.add(dataPair);
                        }
                    }else {
                        System.out.println("The address is in an unknown section.");
                    }
                } else {
                    System.out.println("No memory block found for address: " + refAddress);
                }
            }

        }

        if(DEBUG_RUN && functionAddressPairs.size() > 1){
            System.out.println("[!] Found more than pair, but currently only the first one will be used for further processing...");
            System.out.println("[!] Full list of Pairs: ");
            for(Pair<Function, Address> analysisPair : functionAddressPairs){
                System.out.println("[!] Function: "+analysisPair.first.getName() + " at address: "+analysisPair.getSecond());

            }
        }

        if(functionAddressPairs == null || functionAddressPairs.size() == 0){
            if(isARM32()){

                Pair<Set<Function>, Address> resBinder =  findHexStringInRodataWrapper("res binder", false);
                if(resBinder.getFirst() != null && resBinder.getSecond() != null){
                    Set<Function> functionSet = resBinder.getFirst();
                    if (functionSet != null && !functionSet.isEmpty()) {
                        Function firstFunction = functionSet.iterator().next();
                        functionAddressPairs.add(new Pair<>(firstFunction, resBinder.getSecond()));
                    }
                    
                }
                
            }else{
                Address refAddr = findBackwardsXref(getCurrentProgram(), dataRelRoAddress);
            if (refAddr != null) {
                Function function = getFunctionContaining(refAddr);
                if(function == null){
                    if(DEBUG_RUN){
                        System.out.println("[!] function is null and ref is probably pointing to another section ("+refAddr+")...");  
                    }
                }

                System.out.println("[*] Found a reference to " + dataRelRoAddress + " at: " + refAddr + " in function: " + function.getName());
                functionAddressPairs.add(new Pair<>(function, refAddr));
                
            }else{
                System.out.println("[-] Error: No backwards reference found for " + dataRelRoAddress);
                return null;
            }

            }
            
            
        }

        return functionAddressPairs.getFirst();
    }


    private boolean isHexStringInRodata(String targetString) {


        byte[] targetBytes = targetString.getBytes(); // Convert the target string to bytes
        Memory memory = currentProgram.getMemory();
        MemoryBlock rodataBlock = memory.getBlock(".rodata"); // Locate the .rodata section

        if (rodataBlock == null) {
            rodataBlock = memory.getBlock(".rdata");
            if (rodataBlock == null) {
                return false;
            }
        }

        Address start = rodataBlock.getStart();
        Address end = rodataBlock.getEnd();

        byte[] littleEndianPattern = new byte[targetBytes.length];
        for (int i = 0; i < targetBytes.length; i++) {
            littleEndianPattern[i] = targetBytes[targetBytes.length - 1 - i];
        }

        // Variants of the pattern
        byte[] bigEndianWithNull = appendByte(targetBytes, (byte) 0x00);
        byte[] bigEndianWithSpace = appendByte(targetBytes, (byte) 0x20);
        byte[] littleEndianWithNull = appendByte(littleEndianPattern, (byte) 0x00);
        byte[] littleEndianWithSpace = appendByte(littleEndianPattern, (byte) 0x20);
        Address foundAddress = null;

        try {

            // First, search for the big-endian pattern
            foundAddress = searchPatterns(memory, start, end,
            new byte[][] {bigEndianWithNull, bigEndianWithSpace, targetBytes});
            if (foundAddress != null) {
                return true;
            }

            if(foundAddress == null){
                // If not found, search for the little-endian pattern
                foundAddress = searchPatterns(memory, start, end,
                    new byte[][] {littleEndianWithNull, littleEndianWithSpace, littleEndianPattern});
                if (foundAddress != null) {
                    return true;
                }
            }

        } catch (MemoryAccessException e) {
           // System.err.println("[-] Error accessing memory: " + e.getMessage());
        } catch (Exception e) {
           // System.err.println("[-] Error in pattern identification: " + e.getMessage());
        }        
        return false;
    }


    private Pair<Set<Function>, Address> findHexStringInRodata(String targetString, boolean  do_print_info_msg) {
        Set<Function> functions = new HashSet<>();
        Pair<Function, Address> functionAddressPair;
        Address referenceAddress = null;

        byte[] targetBytes = targetString.getBytes(); // Convert the target string to bytes
        Memory memory = currentProgram.getMemory();
        MemoryBlock rodataBlock = memory.getBlock(".rodata"); // Locate the .rodata section

        if (rodataBlock == null) {
            rodataBlock = memory.getBlock(".rdata");
            if (rodataBlock == null) {
                if(do_print_info_msg){
                    System.out.println("[-] .rodata section not found!");
                }
                return new Pair<>(functions, null);
            }
        }

        Address start = rodataBlock.getStart();
        Address end = rodataBlock.getEnd();

        byte[] littleEndianPattern = new byte[targetBytes.length];
        for (int i = 0; i < targetBytes.length; i++) {
            littleEndianPattern[i] = targetBytes[targetBytes.length - 1 - i];
        }

        // Variants of the pattern
        byte[] bigEndianWithNull = appendByte(targetBytes, (byte) 0x00);
        byte[] bigEndianWithSpace = appendByte(targetBytes, (byte) 0x20);
        byte[] littleEndianWithNull = appendByte(littleEndianPattern, (byte) 0x00);
        byte[] littleEndianWithSpace = appendByte(littleEndianPattern, (byte) 0x20);
        Address foundAddress = null;

        try {

            // First, search for the big-endian pattern
            foundAddress = searchPatterns(memory, start, end,
            new byte[][] {bigEndianWithNull, bigEndianWithSpace, targetBytes});
            if (foundAddress != null && DEBUG_RUN && do_print_info_msg) {
                System.out.println("[*] Found big-endian pattern at: " + foundAddress);
    
            }

            if(foundAddress == null){
                // If not found, search for the little-endian pattern
                foundAddress = searchPatterns(memory, start, end,
                    new byte[][] {littleEndianWithNull, littleEndianWithSpace, littleEndianPattern});
                if (foundAddress != null && DEBUG_RUN && do_print_info_msg) {
                    System.out.println("[*] Found little-endian pattern at: " + foundAddress);
                }
            }

        } catch (MemoryAccessException e) {
            System.err.println("[-] Error accessing memory: " + e.getMessage());
        } catch (Exception e) {
            System.err.println("[-] Error in pattern identification: " + e.getMessage());
        }


        if(foundAddress != null){
            if(do_print_info_msg){
                System.out.println("[*] String found in .rodata section at address: " + foundAddress);
            }
            functionAddressPair = findFunctionReferences(foundAddress,".rodata");
            if(functionAddressPair == null){
                System.out.println("[-] Error in findFunctionReferences...");
                return new Pair<>(functions, referenceAddress);
            }
            functions.add(functionAddressPair.getFirst());
            referenceAddress = functionAddressPair.getSecond();
        }else{
            if(do_print_info_msg){
                System.err.println("[-] Unable to find pattern in .rodata section as well: "+foundAddress);
            }
        }
        
        return new Pair<>(functions, referenceAddress);
    }
    

    private String get_ida_address(Address ghidra_address){
        /*                                    
        The default base address in Ghidra is 0x00010000 for 32bit and 0x00100000 for 64bit and in IDA it is 
        just 0x0 therefore we just do the math here
        */
        long offset = 0x00010000; // offset 32bit
        String languageID = currentProgram.getLanguageID().toString();
        if(languageID.contains("64")){
            offset = 0x00100000;
        }
        
        // Subtract the offset from the Ghidra address
        Address ida_address = ghidra_address.subtract(offset);

        return ida_address.toString().toUpperCase();

    }

private boolean is_target_binary_a_rust_binary(){
    Memory memory = currentProgram.getMemory();
    for (MemoryBlock block : memory.getBlocks()) {
        String blockName = block.getName();
        if (blockName != null && (blockName.contains(".rustc") || blockName.contains("note.rustc"))) {
            return true;
        }
    }
    

    SymbolTable symbolTable = currentProgram.getSymbolTable();
        
        String[] rustSymbols = {
            "rust_eh_personality", 
            "core::panicking::panic_fmt",
            "alloc::alloc::alloc",
            "std::rt::lang_start",
            "_ZN3std2rt10lang_start",
            "DW.ref.rust_eh_personality"
        };
        
        for (Symbol symbol : symbolTable.getAllSymbols(true)) {
            for (String rustSymbol : rustSymbols) {
                if (symbol.getName().contains(rustSymbol)) {
                    System.out.println("[*] 🚀 Rust Binary Detected! Symbol found: " + symbol.getName());
                    return true; // Stop early if Rust is confirmed
                }
            }
        }

        List<String> rustStringMarkers = Arrays.asList(
        "rustls::record_layer",
            "Cargo.toml",
            "begin_panic",
            "panicked at",
            "core::"
        );

        for (String marker : rustStringMarkers) {
            boolean has_rust_String = is_string_in_binary(marker);
            if(has_rust_String){
                // we have a rust binary
                return true;
            }
        }

        for (String marker : rustStringMarkers) {
            boolean has_rust_String = isHexStringInRodata(marker);
            if(has_rust_String){
                // we have a rust binary
                return true;
            }
        }


        System.out.println("[*] None rust binary...");
        return false;
}

private String get_rustcall_mangled_function_name(Address targetAddress){
    SymbolTable symbolTable = currentProgram.getSymbolTable();

        for (Symbol symbol : symbolTable.getAllSymbols(false)) {
            Function function = getFunctionAt(symbol.getAddress());
            if (function != null) {
                if(targetAddress == symbol.getAddress() || function.getName().toLowerCase().contains("log_secret")){
                String mangledName = symbol.getName(); // Raw symbol name (likely mangled)

                // Only process symbols with "Rust" style mangling (_ZN...)
                if (mangledName.startsWith("_ZN")) {
                    return mangledName;
                }

                }
                
            }
        }
        return "";

}


/**
     * Returns the first function that calls the given function.
     * 
     * @param function The function whose caller is to be determined.
     * @return The caller function if found; otherwise, null.
     */
    private Function getFirstCaller(Function function) {
        // Get the entry point of the function.
        Address entry = function.getEntryPoint();
        // Retrieve all references to this address.
        ReferenceIterator refIter = currentProgram.getReferenceManager().getReferencesTo(entry);
        while (refIter.hasNext()) {
            Reference ref = refIter.next();
            // Check if the reference is a call.
            if (ref.getReferenceType().isCall()) {
                // Get the function containing the caller address.
                Function caller = getFunctionContaining(ref.getFromAddress());
                if (caller != null) {
                    return caller;
                }
            }
        }
        return null;
    }



// Function to extract function information
private void extractFunctionInfo(Function function, boolean is_rust_tls12_run) {
    Address entryPoint = function.getEntryPoint();
    String label = function.getName();

    // Get the memory object
    Memory memory = currentProgram.getMemory();

    // Ensure the memory block is valid and readable
    if (memory.getBlock(entryPoint) == null) {
        System.err.println("[-] Memory block not found for entry point: " + entryPoint);
        return;
    }

    // Determine the length of bytes until the first branch
    int numBytes = getLengthUntilBranch(function);

    if(numBytes == -42){
        System.out.println("[*] Couldn't find a branching instruction in current function...");
        Function callerFunction = getFirstCaller(function);
        if(callerFunction == null){
            System.err.println("[-] Unable to identify target calling function..");
        }else{
            System.out.println("[*] Using calling function as ssl_log()...");
            numBytes = getLengthUntilBranch(callerFunction);
            function = callerFunction;
            entryPoint = function.getEntryPoint();
            label = function.getName();
        }
        
    }

    // Use the custom readBytes function to read the dynamically determined length of bytes
    byte[] byteData = readBytes(memory, entryPoint, numBytes);

    // Convert the byte array into a formatted string of hex values
    StringBuilder bytePattern = new StringBuilder();
    for (byte b : byteData) {
        bytePattern.append(String.format("%02X ", b & 0xFF)); // Ensure uppercase hex values
    }

    // Print the function information to the terminal
    System.out.println();
    if(function.getCallingConventionName().contains("rust")){
        System.out.println("[!] Keep in mind that hooking function using the "+function.getCallingConventionName()+" with frida is a little bit tricky...");
        String mangled_target_function_name = get_rustcall_mangled_function_name(entryPoint);
        System.out.println("[*] Function label: " + label+  " ("+ mangled_target_function_name +")");

    }else{
        System.out.println("[*] Function label: " + label+  " ("+ function.toString() +")");
    }

    if(is_rust_tls12_run){
        System.out.println("\n");
        System.out.println("[*] TLS 1.2 RusTLS:");
        System.out.println("[*] Function label: " + label+  " ("+ function.toString() +")");
        System.out.println("[*] Function offset (Ghidra): " + entryPoint.toString().toUpperCase() + " (0x" + entryPoint.toString().toUpperCase() + ")");
        System.out.println("[*] Function offset (IDA with base 0x0): " + get_ida_address(entryPoint) + " (0x" + get_ida_address(entryPoint) + ")");
        System.out.println("[*] Byte pattern for frida (friTap): " + bytePattern.toString().trim());
        System.out.println();
        printTls13Info();
        return;
    }
    
    System.out.println("[*] Function offset (Ghidra): " + entryPoint.toString().toUpperCase() + " (0x" + entryPoint.toString().toUpperCase() + ")");
    System.out.println("[*] Function offset (IDA with base 0x0): " + get_ida_address(entryPoint) + " (0x" + get_ida_address(entryPoint) + ")");
    System.out.println("[*] Byte pattern for frida (friTap): " + bytePattern.toString().trim());
    System.out.println("");
    BoringSecretHunter.identified_pattern = bytePattern.toString().trim();

    BoringSecretHunter.identifiedTls13 = true;
    BoringSecretHunter.tls13GhidraOffset = entryPoint.toString().toUpperCase();
    BoringSecretHunter.tls13IdaOffset    = get_ida_address(entryPoint);
    BoringSecretHunter.tls13BytePattern  = bytePattern.toString().trim();
    BoringSecretHunter.tls13label = function;
}

// Helper function to read bytes from memory
private byte[] readBytes(Memory memory, Address address, int numBytes) {
    byte[] byteData = new byte[numBytes];
    try {
        memory.getBytes(address, byteData);
    } catch (MemoryAccessException e) {
        System.err.println("[-] Error reading bytes from memory at " + address + ": " + e.getMessage());
    }
    return byteData;
}

private Address findReferenceToStringAtAddress(Address referenceAddr, Function function) {
    System.out.println("[*] Analyzing reference at address: " + referenceAddr + " in function: "+function.getName());
    Listing listing = currentProgram.getListing();
    Instruction instruction = listing.getInstructionAt(referenceAddr);

    if (instruction == null) {
        System.err.println("[-] No instruction found at reference address: " + referenceAddr);
        return null;
    }

    // Look for the function containing this reference
    Function containingFunction = getFunctionContaining(referenceAddr);


    // Need to fix this in future releases - this is a temporary workaround for problems on ARM32
    if(isARM32()){
        return containingFunction.getEntryPoint();
    }
    
    
    
    if (containingFunction != null) {
        if(DEBUG_RUN){
        
            System.out.println("[!] Start analyzing the function at ref: "+containingFunction.getName());
        }
        while (instruction != null && !instruction.getFlowType().isCall()) {
            instruction = instruction.getNext();
        }

        if(containingFunction.getBody().contains(instruction.getAddress())){
            if(DEBUG_RUN){
                System.out.println("[!] Target address is part of the analyzed function");
            }
        }else{
            if(DEBUG_RUN){
                System.out.println("[!] Target address is not part of the analyzed function...");
            }
            return null;
        }

        if (instruction != null && instruction.getFlowType().isCall()) {
            Address[] flowRefs = instruction.getFlows(); // Get the flow references for function calls
            if (flowRefs.length > 0) {
                return flowRefs[0]; // Return the first flow reference as the called function address
            }else{
                if(DEBUG_RUN){
                    System.out.println("[!] flowRefs: "+flowRefs.length + " on instruction: "+instruction.toString());
                }
            }
        }
    }

    

    System.err.println("[-] No function call found near the string reference.");
    if(DEBUG_RUN){
        System.out.println("[!] instruction: "+instruction.toString());
    }
    return null;
}


    private int getLengthUntilBranch(Function function) {
        Address entryPoint = function.getEntryPoint();
        Listing listing = currentProgram.getListing();
        AddressSetView functionBody = function.getBody();
        // Get the first instruction at the entry point
        InstructionIterator instructions = listing.getInstructions(functionBody, true); 
        Instruction start_instruction = listing.getInstructionAt(entryPoint);
        int length = 0;
        boolean found_call = false;


        if (start_instruction == null) {
            println("[-] No instruction found at entry point: " + entryPoint);
            println("[-] Defaulting to 32 bytes");
            return 32; // Default to 32 if no instructions are found
        }

        while (instructions.hasNext()) {
            Instruction instruction = instructions.next();
            if (instruction == null) {
                break; // Break if there's no instruction at the current address
            }

            // Check if the instruction is a branch, jump, or call
            if (instruction.getFlowType().isJump() ||
            instruction.getFlowType().isConditional() ||
            instruction.getFlowType().isCall()) {
                // with that we ensure that we also count the length of the branch itself
                length += instruction.getLength();
                //instruction = listing.getInstructionAt(entryPoint);

                Address[] flows = instruction.getFlows();
                if (flows.length > 0) {
                    Address target_address_of_call_instruction = flows[0];
                    // is this function call still part of the analysed function
                    if (function.getBody().contains(target_address_of_call_instruction) && (target_address_of_call_instruction.subtract(instruction.getAddress()))< 10) {
                        continue;
                    } 
                }

                if(instruction.toString().toLowerCase().startsWith("call") && instruction.toString().toLowerCase().contains("$+")){
                    continue;
                }

                found_call = true;
                break;
            }
            
            //length += listing.getInstructionAt(entryPoint).getLength();
            length += instruction.getLength();
            //entryPoint = entryPoint.add(listing.getInstructionAt(entryPoint).getLength());
        }
        if(found_call){
            return length;
        }else{
            return -42; // indicates that we didn't identified a branch instruction in that function
        }
        
    }

    private String getBinaryInfos() {
        String binaryNameWithPath = currentProgram.getExecutablePath();
        String architecture = currentProgram.getLanguage().getProcessor().toString();

        if(architecture.contains("AARCH64")){
            architecture = "ARM64";
        }
        String binaryName = new java.io.File(binaryNameWithPath).getName();




        return "[*] Start analyzing binary " + binaryName + " (CPU Architecture: "+ architecture+"). This might take a while ...";
    }


private void processFoundFunctions(Pair<Set<Function>, Address> result, boolean is_rust_tls12_run) {
    Set<Function> functions = result.getFirst();
    Address referenceAddress = result.getSecond();

    Function firstFunction = functions.iterator().next();
    //int byteCount = getLengthUntilBranch(firstFunction);
    //System.out.println("[*] Function Found where the target string has been used: " + firstFunction.getName() + ", Byte Length: " + byteCount);

    Address calledFunctionAddr = findReferenceToStringAtAddress(referenceAddress, firstFunction);
    if (calledFunctionAddr != null) {
        Function calledFunction = getFunctionAt(calledFunctionAddr);
        if (calledFunction != null) {
            extractFunctionInfo(calledFunction, is_rust_tls12_run); // Extract and print function details
        } else {
            System.err.println("[-] No function found at address: " + calledFunctionAddr);
        }
    }else {
        
        int numberOfXrefs = countXRefs(firstFunction);
        if(DEBUG_RUN){
            System.out.println("[!] Target function has "+numberOfXrefs+" invocation(s)");
        }
        Function callerFunction = null;
        if(numberOfXrefs <= 1){
            System.out.println("[*] Trying to identify the calling function...");
            callerFunction = getFirstCaller(firstFunction);
        }else{
            System.out.println("[*] Using function with the identified label as ssl_log()...");
            extractFunctionInfo(firstFunction, is_rust_tls12_run);
            return;
        }
        
        if(callerFunction == null){
            System.err.println("[-] Unable to identify target calling function...");
        }else{
            System.out.println("[*] Using calling function as ssl_log()...");
            extractFunctionInfo(callerFunction, is_rust_tls12_run);
        }

    }
}

/**
 * Attempts to find the hex representation of a string in the .rodata section.
 */
private Pair<Set<Function>, Address> findHexStringInRodataWrapper(String stringToFind, boolean do_print_info_msg) {
    if(do_print_info_msg){
        System.out.println("[*] Searching for hex representation of: " + stringToFind);
    }
    return findHexStringInRodata(stringToFind, do_print_info_msg); // Assumes this method exists as per your script
}


private void do_analysis(String primaryString, String fallbackString){
    // Step 1: Look for the primary string
    System.out.println("[*] Looking for " + primaryString);
    Pair<Set<Function>, Address> result = findStringUsage(primaryString);

    // Step 2: If not found, fallback to the alternative string
    if (result.getSecond() == null) {
        System.out.println("[*] Trying fallback approach with String " + fallbackString);
        result = findStringUsage(fallbackString);
    }else{
        System.out.println("[*] Found string reference at address: "+result.getSecond());
    }

    // Step 3: Process the results
    if (!result.getFirst().isEmpty()) {
        processFoundFunctions(result, false);
    } else {
        // Fallback: Try looking for hex representation in .rodata
        System.out.println("[*] No string found. Searching for its hex representation...");
        result = findHexStringInRodataWrapper(primaryString, true);

        if (result.getSecond() == null) {
            System.out.println("[*] Trying fallback approach with hex representation of " + fallbackString);
            result = findHexStringInRodataWrapper(fallbackString, true);
        }

        if (!result.getFirst().isEmpty()) {
            processFoundFunctions(result, false);
        } else {
            System.err.println("[-] No functions found using the string or its hex representation.");
            System.err.println("[-] ssl_log_secret() function not found.");
        }
    }

}

private void set_debug_option(){
    // Retrieve the script arguments.
    String[] args = getScriptArgs();
    for (String arg : args) {
        // For example, if you pass "DEBUG_RUN=true" as an argument:
        if (arg.equalsIgnoreCase("DEBUG_RUN=true")) {
            DEBUG_RUN = true;
            break;
        }
    }
}


    @Override
protected void run() throws Exception {
    set_debug_option();
    printBoringSecretHunterLogo();
    String binInfoGreetings = getBinaryInfos();
    System.out.println(binInfoGreetings);

    String primaryString = "SERVER_HANDSHAKE_TRAFFIC_SECRET";
    String fallbackString = "CLIENT_RANDOM";
    do_analysis(primaryString,fallbackString);
    if(is_target_binary_a_rust_binary()){
        print_max_pattern();
        System.out.println("\n[*] Target binary is a Rust binary. Looking if RusTLS was used...");
        primaryString = "rustls";
        fallbackString = "not a loggable secret"; // 

        Pair<Set<Function>, Address> result = findStringUsage(primaryString);

        // Step 2: If not found, fallback to the alternative string
        if (result.getSecond() == null) {
            result = findHexStringInRodataWrapper(fallbackString, false);
            if (result.getFirst().isEmpty()) {
                result = findHexStringInRodataWrapper(primaryString, false);
                if (result.getFirst().isEmpty()) {
                    System.out.println("[*] No RusTLS detected. Keep using the BoringSSL hooks!");
                    return;
                }else{
                    System.out.println("[*] RusTLS detected. Try using the RusTLS hooks!");
                     System.out.println("\n[*] Previous pattern was only a TLS 1.3 pattern. Now looking for the TLS 1.2 pattern...");
                     result = findHexStringInRodataWrapper("master secret", false);
                     if(result.getFirst() != null && result.getSecond() != null){
                        // This should be the following function of RusTLS:
                        // https://github.com/rustls/rustls/blob/293f05e9d1011132a749b8b6e0435f701421fd01/rustls/src/tls12/mod.rs#L102
                        processFoundFunctions(result, true);
                     }
                     
                }
                
            }

        }
        System.out.println("\n[*] This binary contains 🚀 RusTLS try to use the RusTLS hooks for this pattern!");
        
    }
    

    
}



   }

