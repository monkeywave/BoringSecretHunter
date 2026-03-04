# BoringSecretHunter

![version](https://img.shields.io/badge/version-1.2.0-blue) [![PyPI version](https://badge.fury.io/py/boring-secret-hunter.svg)](https://badge.fury.io/py/boring-secret-hunter) [![Publish status](https://github.com/monkeywave/BoringSecretHunter/actions/workflows/publish.yml/badge.svg?branch=main)](https://github.com/monkeywave/BoringSecretHunter/actions/workflows/publish.yml)
[![Lint](https://github.com/monkeywave/BoringSecretHunter/actions/workflows/lint.yml/badge.svg)](https://github.com/monkeywave/BoringSecretHunter/actions/workflows/lint.yml) [![Tests](https://github.com/monkeywave/BoringSecretHunter/actions/workflows/test.yml/badge.svg)](https://github.com/monkeywave/BoringSecretHunter/actions/workflows/test.yml) [![Docker](https://github.com/monkeywave/BoringSecretHunter/actions/workflows/docker.yml/badge.svg)](https://github.com/monkeywave/BoringSecretHunter/actions/workflows/docker.yml) 

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

## Installation (CLI)

BoringSecretHunter is also available as a pip-installable CLI tool called `bsh`. This requires a local Ghidra installation.

```bash
pip install boringsecrethunter
bsh analyze binary/libcronet.132.0.6779.0.so
```

For debug output:
```bash
bsh analyze -d binary/libcronet.132.0.6779.0.so
```

To simplify Ghidra installation, you can use [ghidractl](https://github.com/monkeywave/ghidractl), our tool designed to simplify and streamline the setup process.

## Supported Input Types

BoringSecretHunter accepts the following file types in the `binary/` folder:

- **ELF, Mach-O, PE32 binaries** — analyzed directly (e.g., `.so`, `.dylib`, `.dll`)
- **Raw binary data files** — memory dumps without proper headers (e.g., `.bin` files reported as `data` by `file`) are imported and analyzed as raw binaries
- **IPA files** — iOS app bundles; Mach-O binaries are extracted automatically before analysis
- **APK files** — Android app bundles; ELF `.so` files are extracted automatically before analysis

## Debug Output

If you're experiencing issues, try running BoringSecretHunter with debug output enabled. There are two ways:

**Option 1: Environment variable (recommended for Docker)**
```bash
$ docker run --rm -v "$(pwd)/binary":/usr/local/src/binaries -v "$(pwd)/results":/host_output -e DEBUG_RUN=true boringsecrethunter
```

**Option 2: Command-line flag**
```bash
$ docker run --rm -v "$(pwd)/binary":/usr/local/src/binaries -v "$(pwd)/results":/host_output boringsecrethunter -d
```

> **Note:** Do not combine both methods (e.g., `-e DEBUG_RUN=true ... boringsecrethunter -d`). Use one or the other.

### Raw Data Files (`DATA_PROCESSOR`)

When analyzing raw binary data files (e.g., memory dumps reported as `data` by `file`), BoringSecretHunter auto-detects the CPU architecture from sibling binaries in the same folder. To override the auto-detection, set the `DATA_PROCESSOR` environment variable:

```bash
$ docker run --rm -v "$(pwd)/binary":/usr/local/src/binaries -v "$(pwd)/results":/host_output \
    -e DATA_PROCESSOR="AARCH64:LE:64:v8A" boringsecrethunter
```

Supported processor values:
| Value | Architecture |
|---|---|
| `AARCH64:LE:64:v8A` | ARM 64-bit (default) |
| `ARM:LE:32:v8` | ARM 32-bit |
| `x86:LE:64:default` | x86-64 |
| `x86:LE:32:default` | x86 32-bit |

## Interactive Debugging

For deeper inspection or troubleshooting, you can start BoringSecretHunter in interactive mode and work directly with the [Headless Analyzer](https://static.grumpycoder.net/pixel/support/analyzeHeadlessREADME.html) of Ghidra invoking our script:
```bash
$ docker run -it --entrypoint /bin/bash  -v "$(pwd)/binary":/usr/local/src/binaries -v "$(pwd)/results":/host_output boringsecrethunter

# /opt/ghidra_12.0.3_PUBLIC/support/analyzeHeadless /tmp ghidra_project_$(date +%s) \
            -import "$bin" -scriptPath /usr/local/src/ -prescript /usr/local/src/MinimalAnalysisOption.java -postScript /usr/local/src/BoringSecretHunter.java DEBUG_RUN=true
```

## How to identify SSL/TLS libraries

To identify which SSL/TLS libraries a target application uses at runtime, see [tlsLibHunter](https://github.com/monkeywave/tlsLibHunter). It scans a process’ mapped memory ranges for TLS-related strings (e.g., `CLIENT_RANDOM`) and extracts the corresponding shared libraries from the device. This works well on Android where multiple TLS stacks may be present (Conscrypt/BoringSSL, Cronet, app-bundled JNI libs, etc.).

Once you have identified and extracted the target library, provide it to BoringSecretHunter for analysis.