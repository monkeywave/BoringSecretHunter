import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;

import java.util.*;

/**
 * Function-level analysis helpers: xrefs, immediates, ERR_put_error, filtering.
 */
public class FunctionAnalysisUtils {

    private final GhidraContext ctx;
    private final boolean debugRun;

    public FunctionAnalysisUtils(GhidraContext ctx, boolean debugRun) {
        this.ctx = ctx;
        this.debugRun = debugRun;
    }

    public int countXRefs(Function function) {
        Address entry = function.getEntryPoint();
        ReferenceIterator refIter = ctx.program.getReferenceManager().getReferencesTo(entry);
        int count = 0;
        while (refIter.hasNext()) {
            Reference ref = refIter.next();
            if (ref.getReferenceType().isCall()) {
                count++;
            }
        }
        return count;
    }

    public Set<Function> getCalledFunctions(Function func) {
        Set<Function> called = new HashSet<>();
        AddressSetView body = func.getBody();
        InstructionIterator instIter = ctx.program.getListing().getInstructions(body, true);
        while (instIter.hasNext()) {
            Instruction inst = instIter.next();
            for (Reference ref : inst.getReferencesFrom()) {
                if (ref.getReferenceType().isCall()) {
                    Function target = ctx.getFunctionAt.apply(ref.getToAddress());
                    if (target != null) {
                        called.add(target);
                    }
                }
            }
        }
        return called;
    }

    public Set<Long> findImmediatesInBody(Function func, Set<Long> targetValues) {
        Set<Long> found = new HashSet<>();
        AddressSetView body = func.getBody();
        InstructionIterator instIter = ctx.program.getListing().getInstructions(body, true);
        while (instIter.hasNext()) {
            Instruction inst = instIter.next();
            for (int i = 0; i < inst.getNumOperands(); i++) {
                Object[] opObjects = inst.getOpObjects(i);
                for (Object obj : opObjects) {
                    if (obj instanceof ghidra.program.model.scalar.Scalar) {
                        long val = ((ghidra.program.model.scalar.Scalar) obj).getUnsignedValue();
                        if (targetValues.contains(val)) {
                            found.add(val);
                        }
                    }
                }
            }
            if (found.size() == targetValues.size()) break;
        }
        return found;
    }

    public Set<Function> findTopCalledFunctions(int n) {
        List<Function> allFunctions = new ArrayList<>();
        FunctionIterator funcIter = ctx.program.getFunctionManager().getFunctions(true);
        while (funcIter.hasNext()) {
            allFunctions.add(funcIter.next());
        }

        allFunctions.sort((a, b) -> Integer.compare(countXRefs(b), countXRefs(a)));

        Set<Function> topN = new HashSet<>();
        for (int i = 0; i < Math.min(n, allFunctions.size()); i++) {
            topN.add(allFunctions.get(i));
        }

        if (debugRun) {
            System.out.println("[!] NumericErrorCodeFP: top-" + n + " most-called functions:");
            for (Function f : topN) {
                System.out.println("[!]   " + f.getName() + " (xrefs=" + countXRefs(f) + ")");
            }
        }

        return topN;
    }

    public Function findERRPutErrorFunction() {
        Function bestMatch = null;
        int bestXrefs = 0;

        FunctionIterator funcIter = ctx.program.getFunctionManager().getFunctions(true);
        while (funcIter.hasNext()) {
            Function func = funcIter.next();
            long bodySize = func.getBody().getNumAddresses();
            if (bodySize >= 500) continue;

            int xrefs = countXRefs(func);
            if (xrefs < 20) continue;

            if (xrefs > bestXrefs) {
                bestXrefs = xrefs;
                bestMatch = func;
            }
        }

        if (bestMatch != null) {
            if (debugRun) {
                System.out.println("[!] ERRPutError: found ERR_put_error candidate: " +
                    bestMatch.getName() + " (xrefs=" + bestXrefs +
                    ", size=" + bestMatch.getBody().getNumAddresses() +
                    ", params=" + bestMatch.getParameterCount() + ")");
            }
        } else {
            if (debugRun) {
                System.out.println("[!] ERRPutError: could not find any function with 20+ xrefs and body < 500");
            }
        }

        return bestMatch;
    }

    public boolean isLikelyNonSSLFunction(Function func) {
        String rawName = func.getName();
        if (rawName.startsWith("__Z") || rawName.startsWith("_Z")) return true;

        String name = rawName.toUpperCase();
        String[] nonSSLPatterns = {"BN_", "RSA_", "EC_", "EVP_", "ASN1", "X509",
            "SHA", "MD5", "AES", "DES", "HMAC", "CRYPTO_", "CBS_", "CBB_",
            "OPENSSL_", "PEM_", "BIO_", "PKCS", "V2I_", "I2V_", "D2I_", "I2D_",
            "GENERAL_NAME", "CONF_", "NCONF_", "OBJ_", "NID_",
            "ERR_", "RAND_", "LHASH_", "STACK_", "SK_", "BUF_", "SSL_IS_",
            "SSL_SET_", "SSL_GET_", "SSL_CTX", "SSL_SESSION", "SSL_CIPHER",
            "SSL_NEW", "SSL_FREE", "SSL_DO_", "SSL_CONNECT", "SSL_ACCEPT",
            "SSL_SHUTDOWN", "SSL_PENDING", "SSL_HAS_", "SSL_IN_", "SSL_QUIC",
            "SSL_KEY_", "SSL_EXPORT_", "SSL_EARLY_",
            "DOREAD", "DOWRITE", "DOEXCHANGE", "DOSHUTDOWN", "DOCONNECTION"};
        for (String pattern : nonSSLPatterns) {
            if (name.contains(pattern)) return true;
        }
        return false;
    }

    public Set<Long> extractReasonCodesFromCaller(Function errPutError, Function caller) {
        Set<Long> reasonCodes = new HashSet<>();
        Address errEntry = errPutError.getEntryPoint();
        boolean isARM64 = ctx.isARM64();

        AddressSetView body = caller.getBody();
        InstructionIterator instIter = ctx.program.getListing().getInstructions(body, true);

        while (instIter.hasNext()) {
            Instruction inst = instIter.next();
            boolean isCallToErr = false;
            if (inst.getFlowType().isCall()) {
                for (Reference ref : inst.getReferencesFrom()) {
                    if (ref.getReferenceType().isCall() && ref.getToAddress().equals(errEntry)) {
                        isCallToErr = true;
                        break;
                    }
                }
            }

            if (!isCallToErr) continue;

            Instruction prev = inst.getPrevious();
            for (int step = 0; step < 10 && prev != null; step++) {
                if (!body.contains(prev.getAddress())) break;
                String mnemonic = prev.getMnemonicString().toLowerCase();

                if (isARM64) {
                    if ((mnemonic.equals("mov") || mnemonic.equals("movz") || mnemonic.equals("orr")) &&
                        prev.getNumOperands() >= 2) {
                        String op0 = prev.getDefaultOperandRepresentation(0).toLowerCase();
                        if (op0.equals("w2") || op0.equals("x2")) {
                            for (int opIdx = 1; opIdx < prev.getNumOperands(); opIdx++) {
                                Object[] opObjects = prev.getOpObjects(opIdx);
                                for (Object obj : opObjects) {
                                    if (obj instanceof ghidra.program.model.scalar.Scalar) {
                                        long val = ((ghidra.program.model.scalar.Scalar) obj).getUnsignedValue();
                                        if ((val & 0xFF000000L) != 0) {
                                            val = val & 0xFFF;
                                        }
                                        if (val > 0 && val < 0x1000) {
                                            reasonCodes.add(val);
                                        }
                                    }
                                }
                            }
                        }
                    }
                } else {
                    if (mnemonic.startsWith("mov") && prev.getNumOperands() >= 2) {
                        String op0 = prev.getDefaultOperandRepresentation(0).toLowerCase();
                        if (op0.equals("edx") || op0.equals("rdx")) {
                            for (int opIdx = 1; opIdx < prev.getNumOperands(); opIdx++) {
                                Object[] opObjects = prev.getOpObjects(opIdx);
                                for (Object obj : opObjects) {
                                    if (obj instanceof ghidra.program.model.scalar.Scalar) {
                                        long val = ((ghidra.program.model.scalar.Scalar) obj).getUnsignedValue();
                                        if ((val & 0xFF000000L) != 0) {
                                            val = val & 0xFFF;
                                        }
                                        if (val > 0 && val < 0x1000) {
                                            reasonCodes.add(val);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                prev = prev.getPrevious();
            }
        }

        return reasonCodes;
    }
}
