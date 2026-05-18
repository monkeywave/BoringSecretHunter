import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.util.task.TaskMonitor;

import java.util.function.Consumer;

/**
 * Context bridge that wraps GhidraScript-only methods via functional interfaces.
 * Only BoringSecretHunter extends GhidraScript; all helper classes receive this instead.
 */
public class GhidraContext {

    public final Program program;
    public final TaskMonitor monitor;
    public final java.util.function.Function<Address, Function> getFunctionContaining;
    public final java.util.function.Function<Address, Function> getFunctionAt;
    public final java.util.function.Function<Address, Data> getDataContaining;
    public final java.util.function.Function<Address, Reference[]> getReferencesTo;
    public final Consumer<String> println;

    public GhidraContext(
            Program program,
            TaskMonitor monitor,
            java.util.function.Function<Address, Function> getFunctionContaining,
            java.util.function.Function<Address, Function> getFunctionAt,
            java.util.function.Function<Address, Data> getDataContaining,
            java.util.function.Function<Address, Reference[]> getReferencesTo,
            Consumer<String> println) {
        this.program = program;
        this.monitor = monitor;
        this.getFunctionContaining = getFunctionContaining;
        this.getFunctionAt = getFunctionAt;
        this.getDataContaining = getDataContaining;
        this.getReferencesTo = getReferencesTo;
        this.println = println;
    }

    public int getPointerSize() {
        String languageID = program.getLanguageID().toString();
        if (languageID.contains("64")) {
            return 0x8;
        }
        return 0x4;
    }

    public String getIdaAddress(Address ghidraAddress) {
        long offset = 0x00010000; // offset 32bit
        String languageID = program.getLanguageID().toString();
        if (languageID.contains("64")) {
            offset = 0x00100000;
        }
        Address idaAddress = ghidraAddress.subtract(offset);
        return idaAddress.toString().toUpperCase();
    }

    public boolean isARM32() {
        String languageID = program.getLanguageID().toString().toUpperCase();
        return languageID.contains("ARM:LE:32");
    }

    public boolean isARM64() {
        String languageID = program.getLanguageID().toString().toUpperCase();
        return languageID.contains("AARCH64") || languageID.contains("ARM:LE:64");
    }

    /**
     * Generic Pair class shared by all files.
     */
    public static class Pair<K, V> {
        public final K first;
        public final V second;

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
}
