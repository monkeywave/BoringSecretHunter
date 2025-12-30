# BoringSecretHunter

A Ghidra-based tool designed to analyze binaries and identify the `ssl_log_secret()` function. The tool extracts and prints the byte pattern of this function, making it ready for use with Frida for efficient function hooking and TLS key extraction.
Its primary purpose is to analyze binaries with BoringSSL statically linked into them.

The extracted pattern can be used directly with [friTap](https://github.com/fkie-cad/friTap/blob/main/USAGE.md#1-dump-keys) to hook the `ssl_log_secret()` function in target applications.


## Building

Step 1: Build the Docker Image

Run the following command in the root of the BoringSecretHunter directory to build the Docker image:

```bash
docker build -t boringsecrethunter .
```

## Usage

Once the image is built, you can run the Docker container and provide the binary you want to analyze.

For example, if your binary is named libcrypto.so and is located in the binary/ folder, run:

```bash
docker run --rm -v "$(pwd)/binary":/usr/local/src/binaries -v "$(pwd)/results":/host_output boringsecrethunter


Analyzing libcronet.113.0.5672.61.so...
    	BoringSecretHunter
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣀⣀⣀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⠾⠛⢉⣉⣉⣉⡉⠛⠷⣦⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⠋⣠⣴⣿⣿⣿⣿⣿⡿⣿⣶⣌⠹⣷⡀⠀⠀⠀⠀⠀⠀⠀
 ⠀⠀⠀⠀⠀⠀⠀⠀⣼⠁⣴⣿⣿⣿⣿⣿⣿⣿⣿⣆⠉⠻⣧⠘⣷⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢰⡇⢰⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢸⡇⢸⣿⠛⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠈⣷⠀⢿⡆⠈⠛⠻⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⣧⡀⠻⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢼⠿⣦⣄⠀⠀⠀⠀⠀⠀⠀⣀⣴⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⣠⣾⣿⣦⠀⠀⠈⠉⠛⠓⠲⠶⠖⠚⠋⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⣠⣾⣿⣿⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⣠⣾⣿⣿⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⣾⣿⣿⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣄⠈⠛⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
    
Identifying the ssl_log_secret() function for extracting key material using Frida.
Version: 1.0.2 by Daniel Baier

[*] Start analyzing binary libcronet.113.0.5672.61.so (CPU Architecture: AARCH64). This might take a while ...


[*] Target function identified (ssl_log_secret):

Function label: FUN_00493BB0
Function offset: 00493BB0 (0X493BB0)
Byte pattern for frida (friTap): 3F 23 03 D5 FF C3 01 D1 FD 7B 04 A9 F6 57 05 A9 F4 4F 06 A9 FD 03 01 91 08 34 40 F9 08 11 41 F9 C8 07 00 B4
```

## 🔍 Debug Output

If you're experiencing issues, try running BoringSecretHunter with debug output enabled first::
```bash
$ docker run --rm -v "$(pwd)/binary":/usr/local/src/binaries -v "$(pwd)/results":/host_output -e DEBUG_RUN=true boringsecrethunter
```

## 🐞 Interactive Debugging

For deeper inspection or troubleshooting, you can start BoringSecretHunter in interactive mode and work directly with the [Headless Analyzer](https://static.grumpycoder.net/pixel/support/analyzeHeadlessREADME.html) of Ghidra invoking our script:
```bash
$ docker run -it --entrypoint /bin/bash  -v "$(pwd)/binary":/usr/local/src/binaries -v "$(pwd)/results":/host_output boringsecrethunter

# /opt/ghidra_11.1.2_PUBLIC/support/analyzeHeadless /tmp ghidra_project_$(date +%s) \
            -import "$bin" -scriptPath /usr/local/src/ -prescript /usr/local/src/MinimalAnalysisOption.java -postScript /usr/local/src/BoringSecretHunter.java DEBUG_RUN=true
```

## How to identify SSL/TLS libraries

A fast first step is to **scan the process’ mapped memory ranges** for key-log related strings (e.g., `CLIENT_RANDOM`). This works well on Android where multiple TLS stacks may be present (Conscrypt/BoringSSL, Cronet, app-bundled JNI libs, etc.). Then general approach should also work on other platforms but currently this script focues on Android

### Quick start: run the scanner
```bash
frida -U -n Signal -l scanner.js 
     ____
    / _  |   Frida 17.5.2 - A world-class dynamic instrumentation toolkit
   | (_| |
    > _  |   Commands:
   /_/ |_|       help      -> Displays the help system
   . . . .       object?   -> Display information about 'object'
   . . . .       exit/quit -> Exit
   . . . .
   . . . .   More info at https://frida.re/docs/home/
   . . . .
   . . . .   Connected to Pixel 7 (id=31041FDH2006EY)
Attaching...                                                            
[-] Starting Kernel-Level Discovery Scan...

[+] CANDIDATE FOUND: libssl.so
    |-- Match:      "CLIENT_RANDOM"
    |-- Segment:    r--
    |-- Address:    0x77cb0bfa5e
    |-- Offset:     0x15a5e
    |-- Path:       /apex/com.android.conscrypt/lib64/libssl.so

[+] CANDIDATE FOUND: stable_cronet_libssl.so
    |-- Match:      "CLIENT_RANDOM"
    |-- Segment:    r--
    |-- Address:    0x77bdd9207c
    |-- Offset:     0x1107c
    |-- Path:       /apex/com.android.tethering/lib64/stable_cronet_libssl.so

[+] CANDIDATE FOUND: libconscrypt_jni.so
    |-- Match:      "CLIENT_RANDOM"
    |-- Segment:    r-x
    |-- Address:    0x775f85b222
    |-- Offset:     0x198222
    |-- Path:       /data/app/~~_5EN8WxAdkxnS2z2qKiv5g==/org.thoughtcrime.securesms-iYfaztHsw0XGyVwHv3vlsg==/split_config.arm64_v8a.apk!/lib/arm64-v8a/libconscrypt_jni.so

[+] CANDIDATE FOUND: libsignal_jni.so
    |-- Match:      "CLIENT_RANDOM"
    |-- Segment:    r--
    |-- Address:    0x77744a7d53
    |-- Offset:     0x9fd53
    |-- Path:       /data/app/~~_5EN8WxAdkxnS2z2qKiv5g==/org.thoughtcrime.securesms-iYfaztHsw0XGyVwHv3vlsg==/split_config.arm64_v8a.apk!/lib/arm64-v8a/libsignal_jni.so

[+] CANDIDATE FOUND: libringrtc_rffi.so
    |-- Match:      "CLIENT_RANDOM"
    |-- Segment:    r-x
    |-- Address:    0x7744e87ff1
    |-- Offset:     0x3aff1
    |-- Path:       /data/app/~~_5EN8WxAdkxnS2z2qKiv5g==/org.thoughtcrime.securesms-iYfaztHsw0XGyVwHv3vlsg==/split_config.arm64_v8a.apk!/lib/arm64-v8a/libringrtc_rffi.so
[-] Scan Complete.
[Pixel 7::Signal ]-> exit

Thank you for using Frida!
```

### Why this approach works

The scanner relies on `Process.enumerateRanges()` to enumerate all mapped virtual memory ranges in the current process that match a given protection (e.g., `r--`, `r-x`). Frida returns each range’s base, size, protection, and—when available—file mapping details (`file.path`, `file.offset`, `file.size`). 
Frida

On Linux/Android, these ranges correspond closely to the process’ memory mappings as exposed by `/proc/self/maps` (same conceptual source of truth: the kernel’s memory manager view of the process’ VMAs).

*Key point:* we do not depend on “module enumeration”, ELF headers, exports, or section parsing. We ask:

“Which memory pages exist and are readable in this process right now?”
and then scan those pages for TLS related strings.

Under the hood (what `scanner.js` is doing)

1. Enumerate readable ranges
    - e.g., `Process.enumerateRanges({ protection: 'r--', coalesce: true })`
    - `coalesce: true` reduces noise by merging adjacent ranges with identical protection. 
2. Scan each range for one or more signatures
    - e.g., `CLIENT_RANDOM`, `SSLKEYLOGFILE`, `EXPORTER_SECRET`, etc.


Multiple candidates are normal on Android (Conscrypt, Cronet, app-bundled JNI, WebRTC, etc.). Treat discovery as a shortlisting step: once you know the likely .so, you can move to the next phase: extracting so file to your device e.g. with `python3 ./findBoringSSLLibsOnAndroid.py --pid <app target pid> --library <your target lib name>` and provide it to BoringSecretHunter.