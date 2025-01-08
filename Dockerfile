# Base image with Java (required for Ghidra)
FROM gradle:jdk21

# Install Python and dependencies
RUN apt-get update && \
    apt-get install -y python3 python3-pip wget git bison flex build-essential  unzip file && \
    rm -rf /var/lib/apt/lists/*

# Install Ghidra
WORKDIR /opt
RUN wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.1.2_build/ghidra_11.1.2_PUBLIC_20240709.zip -O ghidra.zip && \
    unzip ghidra.zip && \
    rm ghidra.zip

# Set Ghidra and Java environment paths
ENV GHIDRA_PATH=/opt/ghidra_11.1.2_PUBLIC
ENV JAVA_HOME=/opt/java/openjdk
ENV PATH="${JAVA_HOME}/bin:${PATH}"


# Build support for decompiler
RUN /opt/ghidra_11.1.2_PUBLIC/support/buildNatives

# Copy the Ghidra analysis script into the container
WORKDIR /usr/local/src
COPY boring_secret_hunter_jython.py /usr/local/src/boring_secret_hunter_jython.py
COPY boring_secret_hunter.py /usr/local/src/boring_secret_hunter.py
COPY BoringSecretHunter.java /usr/local/src/BoringSecretHunter.java
COPY MinimalAnalysisOption.java /usr/local/src/MinimalAnalysisOption.java
COPY custom_log4j.xml /usr/local/src/custom_log4j.xml
COPY ghidra_analysis.sh /usr/local/src/ghidra_analysis.sh

# Set the JVM options using the JAVA_TOOL_OPTIONS environment variable
ENV JAVA_TOOL_OPTIONS="-Dlog4j.configurationFile=/usr/local/src/custom_log4j.xml"


# Make the bash script executable
RUN chmod +x /usr/local/src/ghidra_analysis.sh

# Set default command to run the bash script
CMD ["/usr/local/src/ghidra_analysis.sh"]

# Set up a volume for copying logs back to the host
VOLUME /host_output
