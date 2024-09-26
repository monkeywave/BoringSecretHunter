# -*- coding: utf-8 -*-

# Ghidra script to identify ssl_log_secret() function

import ghidra.program.model.address.Address
from ghidra.program.model.pcode import PcodeOp
from ghidra.program.model.listing import Function
from ghidra.app.decompiler import DecompInterface
import sys
import os

# Redirect print output to stdout explicitly (optional)
sys.stdout = sys.__stdout__
__version__ = "0.6"
__debug_run__ = False

def print_BoringSecretHunter_logo():
    print(r"""
    				BoringSecretHunter
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣀⣀⣀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⠾⠛⢉⣉⣉⣉⡉⠛⠷⣦⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⠋⣠⣴⣿⣿⣿⣿⣿⡿⣿⣶⣌⠹⣷⡀⠀⠀⠀⠀⠀⠀⠀
 ⠀⠀⠀⠀⠀⠀⠀⠀⣼⠁⣴⣿⣿⣿⣿⣿⣿⣿⣿⣆⠉⠻⣧⠘⣷⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢰⡇⢰⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠀⠀⠈⠀⢹⡇⠀⠀⠀⠀⠀⠀   8 8 8 8                     ,ooo.⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢸⡇⢸⣿⠛⣿⣿⣿⣿⣿⣿⡿⠃⠀⠀⠀⠀⢸⡇⠀⠀⠀⠀⠀⠀  8a8 8a8       FUNCTION     oP   ?b⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠈⣷⠀⢿⡆⠈⠛⠻⠟⠛⠉⠀⠀⠀⠀⠀⠀⣾⠃⠀⠀⠀⠀⠀⠀d888a888zzzzzzzzzzzzzzzzzzzz8      8b⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⣧⡀⠻⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣼⠃⠀⠀⠀⠀⠀⠀⠀ `""^""'                    ?o____oP'⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢼⠿⣦⣄⠀⠀⠀⠀⠀⠀⠀⣀⣴⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⣠⣾⣿⣦⠀⠀⠈⠉⠛⠓⠲⠶⠖⠚⠋⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⣠⣾⣿⣿⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⣠⣾⣿⣿⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⣾⣿⣿⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣄⠈⠛⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
    """)
    print("Identifying the ssl_log_secret() function for extracting key material using Frida.")
    print "Version: {} by Daniel Baier\n".format(__version__)
    return


def find_string_usage(string_to_find):
    """Find the functions where the given string is used as the second parameter."""
    functions = set()
    
    # Iterate through all the data looking for string references
    listing = currentProgram.getListing()
    memory = currentProgram.getMemory()
    
    # Find string locations
    if __debug_run__:
        print("\n[!] Searching for string: '{}'".format(string_to_find))  # Debug print
    for data in listing.getDefinedData(True):
        if data.getDataType().getName() == "string" and string_to_find in str(data.value):
            if __debug_run__:
                print("\n[!] Found string {} at {}".format(string_to_find, data.getAddress()))  # Debug print
            
            # Get references to this string
            refs = getReferencesTo(data.getAddress())
            for ref in refs:
                if __debug_run__:
                    print("\t[!] Found reference at {}".format(ref.getFromAddress()))  # Debug print
                # Find the function containing this reference
                func = getFunctionContaining(ref.getFromAddress())
                if func:
                    if __debug_run__:
                        print("\t[!] Reference belongs to function: {}".format(func.getName()))  # Debug print
                    functions.add(func)

    if len(functions) == 0:
        print("\n[-] No functions found using the string.")  # Debug print
    return functions, ref.getFromAddress()


def find_reference_to_string_at_address(reference_addr):
    """Find the function to which the string reference at reference_addr is passed."""
    if __debug_run__:
        print("\n[*] Analyzing reference at address: {:08x}".format(int(reference_addr.getOffset())))  # Debug print
    listing = currentProgram.getListing()
    instruction = listing.getInstructionAt(reference_addr)
    
    if not instruction:
        print("[-] No instruction found at reference address: {:08x}".format(int(reference_addr.getOffset())))
        return None

    if __debug_run__:
        print("[!] Instruction at reference address: {}".format(instruction))  # Debug print

    # Look for the function containing this reference
    func = getFunctionContaining(reference_addr)
    if func:

        # Check if this instruction or nearby instructions involve a function call
        while instruction and not instruction.getFlowType().isCall():
            instruction = instruction.getNext()

        if instruction and instruction.getFlowType().isCall():
            flow_refs = instruction.getFlows()  # Get the flows (instead of getFlowRef)
            if flow_refs:
                return flow_refs[0]  # Return the first flow reference as the called function


    print("[-] No function call found near the string reference.")
    return None


def get_length_until_branch(function):
    """Identify the number of bytes until the first branch instruction."""
    entry_point = function.getEntryPoint()
    listing = currentProgram.getListing()
    instruction = listing.getInstructionAt(entry_point)

    if not instruction:
        print("[-] No instruction found at entry point: {}".format(entry_point))
        print("[-] Defaulting to 32")
        return 32  # Default to 32 if no instructions are found

    length = 0
    while instruction:
        flow_type = instruction.getFlowType()
        if flow_type.isJump() or flow_type.isConditional() or flow_type.isCall():
            length += instruction.getLength()
            if __debug_run__:
                print("[!] Branch instruction found at address: {}".format(instruction.getAddress()))
            break  # Stop at the first branch instruction

        length += instruction.getLength()
        instruction = instruction.getNext()

    if __debug_run__:
        print("[*] Dynamically calculated length: {}".format(length))
    return length


def extract_function_info(function):
    """Extract function offset, label, and first 32 bytes."""
    entry_point = function.getEntryPoint()
    label = function.getName()

    # Get the first 32 bytes of the function
    memory = currentProgram.getMemory()

    # Pre-allocate a byte array
    byte_data = []

    # Ensure the memory block is valid and readable
    if memory.getBlock(entry_point) is None:
        print("[-] Memory block not found for entry point: {}".format(entry_point))
        return entry_point, label, None

    # Determine the length of bytes until the first branch
    num_bytes = get_length_until_branch(function)

    # Use the custom read_bytes function to read the dynamically determined length of bytes
    byte_data = read_bytes(memory, entry_point, num_bytes)

    # Convert the byte array into a formatted string of hex values
    byte_pattern = ' '.join(["{:02X}".format(b & 0xff) for b in byte_data])  # Ensure uppercase
    
    return entry_point, label.upper(), byte_pattern

def read_bytes(memory, address, num_bytes):
    """Custom function to read memory byte by byte."""
    byte_data = []
    for i in range(num_bytes):
        try:
            byte = memory.getByte(address.add(i))
            byte_data.append(byte & 0xff)  # Mask to ensure unsigned bytes
        except Exception as e:
            print("[-] error reading byte at offset {}: {}".format(i, e))  # Debug print
            break
    return byte_data



def get_binary_infos():
    # Get the binary path
    binary_path = currentProgram.getExecutablePath()
    # Extract only the file name
    binary_name = os.path.basename(binary_path)

    # Get the language description, which includes the processor architecture
    language = currentProgram.getLanguage()

    # Extract the processor architecture (e.g., x86, ARM, MIPS, etc.)
    processor = language.getProcessor()

    # Get the default pointer size to differentiate between 32 and 64 bit
    default_address_space = currentProgram.getAddressFactory().getDefaultAddressSpace()
    pointer_size = default_address_space.getPointerSize()

    # Initialize architecture name
    architecture = processor.toString()

    # Check for x86/x86-64
    if processor.toString().lower() == "x86":
        if pointer_size == 8:
            architecture = "x86-64"
        elif pointer_size == 4:
            architecture = "x86"

    
    # Check for ARM/ARM64
    elif processor.toString().lower() == "arm":
        if pointer_size == 8:
            architecture = "ARM64"
        elif pointer_size == 4:
            architecture = "ARM"

    return binary_name, architecture


def main():
    print_BoringSecretHunter_logo()
    
    # Define the target string to search for
    string_to_find = "SERVER_HANDSHAKE_TRAFFIC_SECRET"

    binary_name, architecture = get_binary_infos()
    print("[*] Start analyzing binary {} (CPU Architecture: {}). This might take a while ...".format(binary_name, architecture))
    
    # Step 1: Find the functions that reference the string
    functions, reference_address = find_string_usage(string_to_find)

    if len(functions) == 0:
        print("[-] No functions found using the string.\nssl_log_secret() function not found.")
        return

    # Step 2: Find the function to which the string is passed
    called_function_addr = find_reference_to_string_at_address(reference_address)

    if called_function_addr:
        # Step 3: Get the function information
        called_function = getFunctionAt(called_function_addr)
        if called_function:
            entry_point, label, byte_pattern = extract_function_info(called_function)
            print("\n\n[*] Target function identified (ssl_log_secret):")
            print("\nFunction label: {}".format(label))
            print("Function offset: {:08X} (0X{:X})".format(int(entry_point.getOffset()), int(entry_point.getOffset())))
            print("Byte pattern for frida (friTap): {}".format(byte_pattern))
        else:
            print("[-] Function not found at address: {:08X}".format(int(called_function_addr.getOffset())))
    else:
        print("[-] ssl_log_secret() function not found.")


    print("\nThx for using BoringSecretHunter. Have a nice day :)")

    

# Run the main function
main()
