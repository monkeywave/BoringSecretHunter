# BoringSecretHunter Environment Validation Test

This document guides users through verifying that BoringSecretHunter runs properly on their system.  
By following these steps, every user should obtain the same (or very similar) output.

---

### Prerequisites

Before running the test, ensure you have the following:

- Docker installed and working (a simple `docker run hello-world` should succeed)  
- A built BoringSecretHunter Docker image (named `boringsecrethunter`)  
- The binary `libcronet.132.0.6779.0.so` (see below)

---

### Step 1 – Prepare the Binary

Create a `binary/` directory (if not present), then copy the test binary into it:

```bash
mkdir -p binary
cp /path/to/test/libcronet.132.0.6779.0.so binary/
```

### Step 2 – Run the Validation Container

From the project root, run:
```bash
docker run --rm \
    -v "$(pwd)/binary":/usr/local/src/binaries \
    -v "$(pwd)/results":/host_output \
    -e DEBUG_RUN=true \
    boringsecrethunter
```
This bind-mounts the binary into the container and enables debug output. Results (if any) will be written to results/ on your host and the terminal.


### Expected Output

If everything is working — you should see output highly similar to this:

```bash
[*] Debug mode enabled.
Analyzing libcronet.132.0.6779.0.so...
[!] BoringSecretHunter Environment infos: 
[!] Running on Java version: 21.0.7
[!] Current Ghidra version: 1

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

Identifying the ssl_log_secret() function for extracting key material using Frida.
Version: 1.0.6 by Daniel Baier

[*] Start analyzing binary libcronet.132.0.6779.0.so (CPU Architecture: ARM64). This might take a while ...
[*] Looking for EXPORTER_SECRET
[!] Found string"EXPORTER_SECRET"at location 0013b879 (IDA: 0x0003B879) with value EXPORTER_SECRET
[*] Found 1 function(s) using the string: EXPORTER_SECRET
Value of debug run: true
[!] Found 1 function(s) using the string: EXPORTER_SECRET
[*] Found string reference at address: 005136b8
[*] Analyzing reference at address: 005136b8 in function: FUN_005135ec
[!] Start analyzing the function at ref: FUN_005135ec
[!] Target address is part of the analyzed function

[*] Function label: FUN_0050788c (FUN_0050788c)
[*] Function offset (Ghidra): 0050788C (0x0050788C)
[*] Function offset (IDA with base 0x0): 0040788C (0x0040788C)
[*] Byte pattern for frida (friTap): 3F 23 03 D5 FF 03 02 D1 FD 7B 04 A9 F7 2B 00 F9 F6 57 06 A9 F4 4F 07 A9 FD 03 01 91 08 34 40 F9 08 15 41 F9 E8 0F 00 B4

[*] None rust binary...
=== Finished analyzing libcronet.132.0.6779.0.so ===
```

### Troubleshooting

If your output diverges from the expected:

1. Verify the binary’s filename and path — it must be binary/libcronet.132.0.6779.0.so.

2. Rebuild the Docker image after any code changes:
```bash
docker build -t boringsecrethunter .
```

3. Ensure correct file permissions on host-mounted volumes:
```bash
chmod -R 755 binary results
```

4. If issues persist, open an issue on GitHub and attach the binary if permitted. Having the same binary helps reproduce and fix the problem more easily.


### Reporting an Issue

Please use the GitHub issue tracker:
https://github.com/FKIE-CAD/BoringSecretHunter/issues