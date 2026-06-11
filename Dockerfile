# Base image with Java (required for Ghidra)
FROM gradle:jdk25

# Install Python and dependencies
RUN apt-get update && \
    apt-get install -y python3 python3-pip wget git bison flex build-essential  unzip file && \
    rm -rf /var/lib/apt/lists/*

# Install Ghidra
WORKDIR /opt
RUN wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.0.3_build/ghidra_12.0.3_PUBLIC_20260210.zip -O ghidra.zip && \
    unzip ghidra.zip && \
    rm ghidra.zip

# Set Ghidra and Java environment paths
ENV GHIDRA_PATH=/opt/ghidra_12.0.3_PUBLIC
ENV JAVA_HOME=/opt/java/openjdk
ENV PATH="${JAVA_HOME}/bin:${PATH}"


# Build support for decompiler
RUN cd /opt/ghidra_12.0.3_PUBLIC/support/gradle && gradle buildNatives

# Raise the headless analyzer heap so large stripped libraries (e.g. Chrome's
# ~193 MB libmonochrome_64.so) can be analyzed. The default MAXMEM=2G lives in
# the analyzeHeadless launcher; launch.sh turns it into -Xmx.
RUN sed -i 's/^MAXMEM=2G/MAXMEM=5G/' /opt/ghidra_12.0.3_PUBLIC/support/analyzeHeadless

WORKDIR /usr/local/src
COPY ghidra_analysis.sh /usr/local/src/ghidra_analysis.sh
COPY custom_log4j.xml /usr/local/src/custom_log4j.xml
COPY src/boring_secret_hunter/ghidra_scripts/BoringSecretHunter.java /usr/local/src/BoringSecretHunter.java
COPY src/boring_secret_hunter/ghidra_scripts/MinimalAnalysisOption.java /usr/local/src/MinimalAnalysisOption.java
COPY src/boring_secret_hunter/ghidra_scripts/GhidraContext.java /usr/local/src/GhidraContext.java
COPY src/boring_secret_hunter/ghidra_scripts/FunctionAnalysisUtils.java /usr/local/src/FunctionAnalysisUtils.java
COPY src/boring_secret_hunter/ghidra_scripts/MemorySearchUtils.java /usr/local/src/MemorySearchUtils.java
COPY src/boring_secret_hunter/ghidra_scripts/SSLLogSecretFinder.java /usr/local/src/SSLLogSecretFinder.java
COPY src/boring_secret_hunter/ghidra_scripts/SSLReadFinder.java /usr/local/src/SSLReadFinder.java
COPY src/boring_secret_hunter/ghidra_scripts/SSLWriteFinder.java /usr/local/src/SSLWriteFinder.java
COPY src/boring_secret_hunter/ghidra_scripts/SSLReadWriteHelper.java /usr/local/src/SSLReadWriteHelper.java
COPY src/boring_secret_hunter/ghidra_scripts/QuicheFinder.java /usr/local/src/QuicheFinder.java
COPY src/boring_secret_hunter/ghidra_scripts/QuicSpdyStreamFinder.java /usr/local/src/QuicSpdyStreamFinder.java
COPY src/boring_secret_hunter/ghidra_scripts/QuicStreamSequencerFinder.java /usr/local/src/QuicStreamSequencerFinder.java
COPY src/boring_secret_hunter/ghidra_scripts/QuicChromiumClientStreamFinder.java /usr/local/src/QuicChromiumClientStreamFinder.java
COPY src/boring_secret_hunter/ghidra_scripts/QuicSpdySessionFinder.java /usr/local/src/QuicSpdySessionFinder.java

# Install the BoringSecretHunter Python package so the entrypoint can run
# `bsh export-patterns` to emit a friTap-consumable patterns.json. Ghidra is
# still launched directly by ghidra_analysis.sh; the package is used ONLY for
# the JSON export step, sharing the exact builder/parsers with the PyPi path.
COPY pyproject.toml /opt/bsh-src/pyproject.toml
COPY README.md /opt/bsh-src/README.md
COPY src /opt/bsh-src/src
RUN pip3 install --no-cache-dir --break-system-packages /opt/bsh-src

# Set the JVM options using the JAVA_TOOL_OPTIONS environment variable
ENV JAVA_TOOL_OPTIONS="-Dlog4j.configurationFile=/usr/local/src/custom_log4j.xml"

# Make the bash script executable
RUN chmod +x /usr/local/src/ghidra_analysis.sh

# Set default command to run the bash script
CMD ["/usr/local/src/ghidra_analysis.sh"]

# Set up a volume for copying logs back to the host
VOLUME /host_output
