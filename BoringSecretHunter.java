import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.listing.Instruction;
import java.util.HashSet;
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


    private static final String VERSION = "0.8";
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
    


// Function to extract function information
private void extractFunctionInfo(Function function) {
    Address entryPoint = function.getEntryPoint();
    String label = function.getName().toUpperCase();

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
    System.out.println("[*] Function label: " + label);
    System.out.println("[*] Function offset: " + entryPoint + " (0x" + entryPoint + ")");
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

    @Override
    protected void run() throws Exception {
        printBoringSecretHunterLogo();
        String binInfoGreetings = getBinaryInfos();
        System.out.println(binInfoGreetings);

        String stringToFind = "SERVER_HANDSHAKE_TRAFFIC_SECRET";
        System.out.println("[*] Looking for " + stringToFind);


        Pair<Set<Function>, Address> result = findStringUsage(stringToFind);
        Set<Function> functions = result.getFirst();
        Address referenceAddress = result.getSecond();
        if(referenceAddress == null){
            stringToFind = "CLIENT_RANDOM";
            System.out.println("[*] Trying fallback approach with String " + stringToFind);
            result = findStringUsage(stringToFind);
            functions = result.getFirst();
            referenceAddress = result.getSecond();
        }

        if (!functions.isEmpty()) {
            Function firstFunction = functions.iterator().next();
            int byteCount = getLengthUntilBranch(firstFunction);
            System.out.println("[*] Function Found: " + firstFunction.getName() + ", Byte Length: " + byteCount);

            Address calledFunctionAddr = findReferenceToStringAtAddress(referenceAddress);
            if (calledFunctionAddr != null) {
                //println("Called function address: " + calledFunctionAddr);
                Function calledFunction = getFunctionAt(calledFunctionAddr);
                if (calledFunction != null) {
                    // Pass the function to extractFunctionInfo to get its details and print the byte pattern
                    extractFunctionInfo(calledFunction);
                } else {
                    System.err.println("[-] No function found at address: " + calledFunctionAddr);
                }
            } 
        } else {
            System.err.println("[-] No functions found using the string.\nssl_log_secret() function not found.");
        }
    }
}

