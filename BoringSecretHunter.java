import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
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
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;



public class BoringSecretHunter extends GhidraScript {

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


    private static final String VERSION = "0.9.5";
    private static final boolean DEBUG_RUN = false;

    private void printBoringSecretHunterLogo() {
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

    private Pair<Set<Function>, Address> findStringUsage(String stringToFind) {
        Set<Function> functions = new HashSet<>();
        Address referenceAddress = null;
    
        Listing listing = currentProgram.getListing();
        DataIterator dataIterator = listing.getDefinedData(true);
    
        while (dataIterator.hasNext()) {
            Data data = dataIterator.next();
            if (data.getDataType().getName().equals("string") && data.getValue().toString().contains(stringToFind)) {
                Reference[] references = getReferencesTo(data.getAddress());
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
                System.out.println("[*] Found pattern: " + byteArrayToHex(pattern) + " at: " + foundAddress);
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
                                    " at target address: " + currentAddress);
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
                System.out.println("[*] Found reference to "+sectionName+" at " + refAddress + " in function: " + function.getName());
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

        return functionAddressPairs.getFirst();
    }


    private Pair<Set<Function>, Address> findHexStringInRodata(String targetString) {
        Set<Function> functions = new HashSet<>();
        Pair<Function, Address> functionAddressPair;
        Address referenceAddress = null;

        byte[] targetBytes = targetString.getBytes(); // Convert the target string to bytes
        Memory memory = currentProgram.getMemory();
        MemoryBlock rodataBlock = memory.getBlock(".rodata"); // Locate the .rodata section

        if (rodataBlock == null) {
            System.out.println(".rodata section not found!");
            return new Pair<>(functions, null);
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
            if (foundAddress != null && DEBUG_RUN) {
                System.out.println("[*] Found big-endian pattern at: " + foundAddress);
    
            }

            if(foundAddress == null){
                // If not found, search for the little-endian pattern
                foundAddress = searchPatterns(memory, start, end,
                    new byte[][] {littleEndianWithNull, littleEndianWithSpace, littleEndianPattern});
                if (foundAddress != null && DEBUG_RUN) {
                    System.out.println("[*] Found little-endian pattern at: " + foundAddress);
                }
            }

        } catch (MemoryAccessException e) {
            System.err.println("Error accessing memory: " + e.getMessage());
        } catch (Exception e) {
            System.err.println("Error in pattern identification: " + e.getMessage());
        }


        if(foundAddress != null){
            System.out.println("[*] String found in .rodata section at address: " + foundAddress);
            functionAddressPair = findFunctionReferences(foundAddress,".rodata");
            functions.add(functionAddressPair.getFirst());
            referenceAddress = functionAddressPair.getSecond();
        }else{
            System.err.println("[-] Unable to find pattern in .rodata section as well: "+foundAddress);
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



// Function to extract function information
private void extractFunctionInfo(Function function) {
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
        System.out.println("[!] "+function.getCallingConventionName()+" calling convention detected.");
        System.out.println("[!] Keep in mind that hooking functions using the "+function.getCallingConventionName()+" calling convention with Frida can be tricky...");
        String mangled_target_function_name = get_rustcall_mangled_function_name(entryPoint);
        System.out.println("[*] Function label: " + label+  " ("+ mangled_target_function_name +")");

    }else{
        System.out.println("[*] Function label: " + label+  " ("+ function.toString() +")");
    }
    
    System.out.println("[*] Function offset (Ghidra): " + entryPoint.toString().toUpperCase() + " (0x" + entryPoint.toString().toUpperCase() + ")");
    System.out.println("[*] Function offset (IDA with base 0x0): " + get_ida_address(entryPoint) + " (0x" + get_ida_address(entryPoint) + ")");
    System.out.println("[*] Byte pattern for frida (friTap): " + bytePattern.toString().trim());
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

private Address findReferenceToStringAtAddress(Address referenceAddr) {
    System.out.println("[*] Analyzing reference at address: " + referenceAddr);
    Listing listing = currentProgram.getListing();
    Instruction instruction = listing.getInstructionAt(referenceAddr);

    if (instruction == null) {
        System.err.println("[-] No instruction found at reference address: " + referenceAddr);
        return null;
    }

    // Look for the function containing this reference
    Function containingFunction = getFunctionContaining(referenceAddr);
    if (containingFunction != null) {
        while (instruction != null && !instruction.getFlowType().isCall()) {
            instruction = instruction.getNext();
        }

        if (instruction != null && instruction.getFlowType().isCall()) {
            Address[] flowRefs = instruction.getFlows(); // Get the flow references for function calls
            if (flowRefs.length > 0) {
                return flowRefs[0]; // Return the first flow reference as the called function address
            }
        }
    }

    System.err.println("[-] No function call found near the string reference.");
    return null;
}


    private int getLengthUntilBranch(Function function) {
        Address entryPoint = function.getEntryPoint();
        Listing listing = currentProgram.getListing();
        Instruction instruction = listing.getInstructionAt(entryPoint);
        int length = 0;

        if (instruction == null) {
            println("[-] No instruction found at entry point: " + entryPoint);
            println("[-] Defaulting to 32 bytes");
            return 32; // Default to 32 if no instructions are found
        }

        while (true) {
            if (listing.getInstructionAt(entryPoint) == null) {
                break; // Break if there's no instruction at the current address
            }

            // Check if the instruction is a branch, jump, or call
            if (listing.getInstructionAt(entryPoint).getFlowType().isJump() ||
            listing.getInstructionAt(entryPoint).getFlowType().isConditional() ||
            listing.getInstructionAt(entryPoint).getFlowType().isCall()) {
                // with that we ensure that we also count the length of the branch itself
                length += listing.getInstructionAt(entryPoint).getLength();
                break;
            }
            length += listing.getInstructionAt(entryPoint).getLength();
            entryPoint = entryPoint.add(listing.getInstructionAt(entryPoint).getLength());
        }
        return length;
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


private void processFoundFunctions(Pair<Set<Function>, Address> result) {
    //Set<Function> functions = result.getFirst();
    Address referenceAddress = result.getSecond();

    //Function firstFunction = functions.iterator().next();
    //int byteCount = getLengthUntilBranch(firstFunction);
    //System.out.println("[*] Function Found where the target string has been used: " + firstFunction.getName() + ", Byte Length: " + byteCount);

    Address calledFunctionAddr = findReferenceToStringAtAddress(referenceAddress);
    if (calledFunctionAddr != null) {
        Function calledFunction = getFunctionAt(calledFunctionAddr);
        if (calledFunction != null) {
            extractFunctionInfo(calledFunction); // Extract and print function details
        } else {
            System.err.println("[-] No function found at address: " + calledFunctionAddr);
        }
    }
}

/**
 * Attempts to find the hex representation of a string in the .rodata section.
 */
private Pair<Set<Function>, Address> findHexStringInRodataWrapper(String stringToFind) {
    System.out.println("[*] Searching for hex representation of: " + stringToFind);
    return findHexStringInRodata(stringToFind); // Assumes this method exists as per your script
}


    @Override
protected void run() throws Exception {
    printBoringSecretHunterLogo();
    String binInfoGreetings = getBinaryInfos();
    System.out.println(binInfoGreetings);

    String primaryString = "SERVER_HANDSHAKE_TRAFFIC_SECRET";
    String fallbackString = "CLIENT_RANDOM";

    // Step 1: Look for the primary string
    System.out.println("[*] Looking for " + primaryString);
    Pair<Set<Function>, Address> result = findStringUsage(primaryString);

    // Step 2: If not found, fallback to the alternative string
    if (result.getSecond() == null) {
        System.out.println("[*] Trying fallback approach with String " + fallbackString);
        result = findStringUsage(fallbackString);
    }

    // Step 3: Process the results
    if (!result.getFirst().isEmpty()) {
        processFoundFunctions(result);
    } else {
        // Fallback: Try looking for hex representation in .rodata
        System.out.println("[*] No string found. Searching for its hex representation...");
        result = findHexStringInRodataWrapper(primaryString);

        if (result.getSecond() == null) {
            System.out.println("[*] Trying fallback approach with hex representation of " + fallbackString);
            result = findHexStringInRodataWrapper(fallbackString);
        }

        if (!result.getFirst().isEmpty()) {
            processFoundFunctions(result);
        } else {
            System.err.println("[-] No functions found using the string or its hex representation.");
            System.err.println("[-] ssl_log_secret() function not found.");
        }
    }
}



   }