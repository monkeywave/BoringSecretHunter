# BoringSecretHunter

A Ghidra-based tool designed to analyze binaries and identify the `ssl_log_secret()` function. The tool extracts and prints the byte pattern of this function, making it ready for use with Frida for efficient function hooking and TLS key extraction.


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
```

## Debugging

If you encounter any problems try to run BoringSecretHunter at first in interactive mode and work with the `.py` script:
```bash
docker run -it --entrypoint /bin/bash  -v "$(pwd)/binary":/usr/local/src/binaries -v "$(pwd)/results":/host_output boringsecrethunter
```
