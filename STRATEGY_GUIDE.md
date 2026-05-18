# Strategy Guide — SSL_read / SSL_write Identification

BoringSecretHunter uses a chain of strategies to locate `SSL_read` and `SSL_write` inside BoringSSL binaries. Strategies are tried in order; the search stops once both functions are found.

## Strategies

| # | Strategy | Description |
|---|----------|-------------|
| 1 | `SymbolTableLookup` | Looks for `SSL_read` / `SSL_write` symbols in the symbol table. Works on non-stripped or partially-stripped binaries. |
| 2 | `ErrorStringFingerprinting` | Cross-references BoringSSL error strings (`UNINITIALIZED`, `BAD_LENGTH`, `SSL_HANDSHAKE_FAILURE`) to distinguish `SSL_write` from `ssl_read_impl`. |
| 3 | `NumericErrorCodeFingerprinting` | Searches for numeric BoringSSL error codes (e.g., `SSL_R_UNINITIALIZED = 276`) loaded as immediate constants. |
| 4 | `CallGraphTracing` | Follows call-graph relationships from already-identified functions (e.g., `ssl_log_secret`) to locate callers matching `SSL_read` / `SSL_write` signatures. |
| 5 | `AdjacentFunctionScanning` | Scans functions adjacent (by address) to already-identified candidates, exploiting the fact that related BoringSSL functions are often compiled contiguously. |
| 6 | `ConstantFingerprinting` | Matches known magic constants and struct-offset patterns characteristic of `SSL_read` / `SSL_write` implementations. |
| 7 | `FunctionSignatureAnalysis` | Analyzes function prototypes (parameter count, types, return type) to filter candidates that match the expected `SSL_read(SSL*, void*, int)` signature. |
| 8 | `ErrorCodeTableScan` | Scans for BoringSSL error-code tables in read-only data sections and traces references back to the calling functions. |

## CLI Flags

### `--no-symbols`

Skip the `SymbolTableLookup` strategy. This forces BoringSecretHunter to rely entirely on pattern-based detection — useful for verifying that pattern matching works correctly on a binary that still has symbols.

```bash
bsh analyze --no-symbols path/to/libssl.so
```

### `--strategy <name>`

Use only the specified strategy. All other strategies are skipped.

```bash
bsh analyze --strategy ErrorStringFingerprinting path/to/libssl.so
```

Valid strategy names (case-sensitive):

- `SymbolTableLookup`
- `ErrorStringFingerprinting`
- `NumericErrorCodeFingerprinting`
- `CallGraphTracing`
- `AdjacentFunctionScanning`
- `ConstantFingerprinting`
- `FunctionSignatureAnalysis`
- `ErrorCodeTableScan`

> **Note:** `--no-symbols` and `--strategy SymbolTableLookup` are mutually exclusive.

## Verification Workflow

To verify that pattern-based detection produces the same results as symbol-based detection:

1. **Baseline run** (uses symbols if available):
   ```bash
   bsh analyze -o baseline.json path/to/symbolized_libssl.so
   ```

2. **Pattern-only run** (skips symbols):
   ```bash
   bsh analyze --no-symbols -o patterns.json path/to/symbolized_libssl.so
   ```

3. **Compare** the byte patterns in both JSON outputs — they should match for the same binary.

4. **Single-strategy run** (test one strategy in isolation):
   ```bash
   bsh analyze --strategy NumericErrorCodeFingerprinting -o single.json path/to/libssl.so
   ```
