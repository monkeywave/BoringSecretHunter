/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
//Turns off Function ID and Library Identification analysis before
//auto-analysis whilst running headless Ghidra for import and ingest
//of programs (object files/libraries) for use in creating FID libraries
//@category FunctionID
import java.util.Map;

import ghidra.app.script.GhidraScript;

public class MinimalAnalysisOption extends GhidraScript {
	// must turn off FID and LID when analyzing libraries for FID
	// creation, in order to avoid corrupting names

	// also, it's important that your loaders have moved object file
	// sections to an appropriate height above 0x0 in order for the
	// scalar operand analyzer to run; we need to identify those
	// references to rule out scalar addresses!

	private static final String FUNCTION_ID_ANALYZER = "Function ID";
	private static final String LIBRARY_IDENTIFICATION = "Library Identification";
	private static final String DEMANGLER_MS_ANALYZER = "Demangler Microsoft";
	private static final String DEMANGLER_GNU_ANALYZER = "Demangler GNU";
	private static final String SCALAR_OPERAND_ANALYZER = "Scalar Operand References";
    private static final String DECOMPILER_SWITCH_ANALYSIS = "Decompiler Switch Analysis";
    private static final String STACK_ANALYSIS = "Stack";
    private static final String CONSTANT_PROPAGATION_ANALYSIS = "Basic Constant Reference Analyzer";
    private static final String DWARF_ANALYZER = "DWARF";

	@Override
	protected void run() throws Exception {
		Map<String, String> options = getCurrentAnalysisOptionsAndValues(currentProgram);
        /* 
        println(options.toString());

        {GCC Exception Handlers=true, 
            Variadic Function Signature Override=false, 
            Basic Constant Reference Analyzer.Stored Value Pointer analysis=true, 
            Data Reference.Relocation Table Guide=true, 
            ASCII Strings=true, 
            Shared Return Calls.Allow Conditional Jumps=false, 
            Create Address Tables.Allow Offcut References=false, 
            Reference.Unicode String References=true, 
            Decompiler Parameter ID.Analysis Decompiler Timeout (sec)=60, 
            Create Address Tables=true, 
            Function Start Search After Data.Bookmark Functions=false, 
            Basic Constant Reference Analyzer.Function parameter/return Pointer analysis=true, 
            Disassemble Entry Points.Respect Execute Flag=true, 
            Aggressive Instruction Finder=false,
             Function Start Search After Code.Search Data Blocks=false,
              Reference.Address Table Minimum Size=2, 
              DWARF=true, 
              ASCII Strings.Minimum String Length=LEN_5, 
              Reference.Minimum String Length=5, 
              Non-Returning Functions - Known.Create Analysis Bookmarks=true, 
              Reference.Ascii String References=true, 
              Stack.useNewFunctionStackAnalysis=true, 
              Reference.Relocation Table Guide=true, 
              Demangler GNU.Apply Function Signatures=true, 
              Variadic Function Signature Override.Create Analysis Bookmarks=false,
              Function Start Search=true, 
              Data Reference.Address Table Alignment=1, 
              Decompiler Parameter ID=false, 
              Non-Returning Functions - Discovered.Repair Flow Damage=true, 
              Apply Data Archives.Create Analysis Bookmarks=true, 
              Create Address Tables.Create Analysis Bookmarks=true, 
              Reference.References to Pointers=true, 
              Apply Data Archives.Archive Chooser=[Auto-Detect], 
              DWARF.Import Local Variable Info=true, 
              Basic Constant Reference Analyzer.Speculative reference max=512, 
              ELF Scalar Operand References=false, 
              Non-Returning Functions - Discovered=true,
              Apply Data Archives.User Project Archive Path=, 
              Create Address Tables.Relocation Table Guide=true, 
              Basic Constant Reference Analyzer=true, 
              Reference.Address Table Alignment=1, 
              Data Reference.Align End of Strings=false, 
              Basic Constant Reference Analyzer.Speculative reference min=1024, 
              DWARF.Output Source Info=false, 
              Apply Data Archives=true, 
              ASCII Strings.Create Strings Containing Existing Strings=true, 
              Basic Constant Reference Analyzer.Require pointer param data type=false, 
Data Reference.Create Address Tables=false, 
ASCII Strings.Force Model Reload=false, 
Data Reference.Ascii String References=true, 
Data Reference.Respect Execute Flag=true, 
DWARF.Output Source Line Info=false, 
Data Reference.Subroutine References=true, 
Shared Return Calls=true, 
Data Reference=true, 
Condense Filler Bytes=false, 
Reference=true, 
Subroutine References=true, 
ASCII Strings.Create Strings Containing References=true, 
Disassemble Entry Points=true, 
Aggressive Instruction Finder.Create Analysis Bookmarks=true, 
ELF Scalar Operand References.Relocation Table Guide=true, 
Demangler GNU=true, 
DWARF.Default Calling Convention=, 
Shared Return Calls.Assume Contiguous Functions Only=true, 
Data Reference.Switch Table References=false, 
Condense Filler Bytes.Filler Value=Auto, 
DWARF.Add Lexical Block Comments=false, 
Stack.Create Local Variables=true, 
Call Convention ID.Analysis Decompiler Timeout (sec)=60, 
Data Reference.Address Table Minimum Size=2, 
AARCH64 ELF PLT Thunks=true, 
Create Address Tables.Table Alignment=4, 
DWARF.Output DWARF DIE Info=false, 
Demangler GNU.Use Deprecated Demangler=false, 
GCC Exception Handlers.Create Try Catch Comments=true, 
Data Reference.Unicode String References=true, 
Embedded Media.Create Analysis Bookmarks=true, 
Decompiler Parameter ID.Prototype Evaluation=__cdecl, 
ASCII Strings.String Start Alignment=ALIGN_1, 
Decompiler Parameter ID.Analysis Clear Level=ANALYSIS, 
Basic Constant Reference Analyzer.Create Data from pointer=false, 
Decompiler Switch Analysis.Analysis Decompiler Timeout (sec)=60, 
ASCII Strings.Require Null Termination for String=true, 
Decompiler Parameter ID.Commit Data Types=true, ???
Create Address Tables.Minimum Table Size=2, 
Data Reference.References to Pointers=true, 
Demangler GNU.Apply Function Calling Conventions=true, 
Non-Returning Functions - Discovered.Create Analysis Bookmarks=true, 
Create Address Tables.Pointer Alignment=1, 
Function Start Search After Data=true, 
External Entry References=true, 
Basic Constant Reference Analyzer.Trust values read from writable memory=true, 
DWARF.Add Inlined Functions Comments=false, 
Reference.Respect Execute Flag=true, 
ASCII Strings.String end alignment=4, 
Basic Constant Reference Analyzer.Min absolute reference=4, 
Function Start Search After Data.Search Data Blocks=false, 
Function Start Search After Code.Bookmark Functions=false, 
Non-Returning Functions - Known=true, 
Stack=true, 
Reference.Align End of Strings=false, 
Non-Returning Functions - Discovered.Function Non-return Threshold=3, 
Reference.Subroutine References=true, 
Subroutine References.Create Thunks Early=true, 
Call Convention ID=true, 
Demangler GNU.Demangler Format=AUTO, 
Basic Constant Reference Analyzer.Max Threads=2, 
ASCII Strings.Search Only in Accessible Memory Blocks=true, 
Reference.Create Address Tables=false, 
ASCII Strings.Model File=StringModel.sng, 
Demangler GNU.Demangle Only Known Mangled Symbols=false, 
Embedded Media=true, 
Reference.Switch Table References=false, 
Data Reference.Minimum String Length=5, 
Create Address Tables.Minimum Pointer Address=4132, 
Function Start Search After Code=true, 
DWARF.Import Functions=true, 
Decompiler Switch Analysis=true, 
Decompiler Parameter ID.Commit Void Return Values=false, 
Function Start Search.Search Data Blocks=false, 
DWARF.Try To Pack Structs=true, 
Call-Fixup Installer=true, 
DWARF.Ignore Parameter Storage Info=false, 
DWARF.Import Data Types=true, 
Create Address Tables.Auto Label Table=false, 
Create Address Tables.Maxmimum Pointer Distance=16777215, 
DWARF.Create Function Signatures=true, 
Stack.Create Param Variables=true, 
Function Start Search.Bookmark Functions=false, 
Condclient_randomense Filler Bytes.Minimum number of sequential bytes=1, 
Demangler GNU.Use Standard Text Replacements=true}



Decompiler Switch Analysis=true, 
        */
		if (options.containsKey(FUNCTION_ID_ANALYZER)) {
			setAnalysisOption(currentProgram, FUNCTION_ID_ANALYZER, "false");
		}
		if (options.containsKey(LIBRARY_IDENTIFICATION)) {
			setAnalysisOption(currentProgram, LIBRARY_IDENTIFICATION, "false");
		}
		if (options.containsKey(DEMANGLER_MS_ANALYZER)) {
			setAnalysisOption(currentProgram, DEMANGLER_MS_ANALYZER, "true");
		}
		if (options.containsKey(DEMANGLER_GNU_ANALYZER)) {
			setAnalysisOption(currentProgram, DEMANGLER_GNU_ANALYZER, "true");
		}
		if (options.containsKey(SCALAR_OPERAND_ANALYZER)) {
			setAnalysisOption(currentProgram, SCALAR_OPERAND_ANALYZER, "false");
		}/* 
        // This analysis takes the most time, unfortunately it is in some occasions needed (e.g. PRF on BoringSSL) 
        if (options.containsKey(DECOMPILER_SWITCH_ANALYSIS)) {
			setAnalysisOption(currentProgram, DECOMPILER_SWITCH_ANALYSIS, "false");
		}*/
        /*if (options.containsKey(STACK_ANALYSIS)) {
			setAnalysisOption(currentProgram, STACK_ANALYSIS, "false");
		}/*
        if (options.containsKey(CONSTANT_PROPAGATION_ANALYSIS)) {
			setAnalysisOption(currentProgram, CONSTANT_PROPAGATION_ANALYSIS, "false");
		}*/
        if (options.containsKey(DWARF_ANALYZER)) {
			setAnalysisOption(currentProgram, DWARF_ANALYZER, "false");
		}

      
	}
}


