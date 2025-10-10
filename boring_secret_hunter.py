import subprocess
import os
import time
import argparse

def generate_ghidra_project_name():
    # Get the current timestamp in seconds since epoch
    timestamp = int(time.time())
    
    # Create the project name with the timestamp
    project_name = f"ghidra_project_{timestamp}"
    
    return project_name

def run_ghidra_command(file_path):
    # Define the absolute path to your home directory
    #home_directory = os.path.expanduser("~")
    
    # create temporary project name
    tmp_project_name = generate_ghidra_project_name()


    # Construct the Ghidra command with the absolute path
    command = [
        '/opt/ghidra_11.1.2_PUBLIC/support/analyzeHeadless',
        '/usr/local/src/',
        tmp_project_name,
        '-import',
        file_path,
        '-scriptPath',
        '/usr/local/src/',
        '-prescript',
        '/usr/local/src/MinimalAnalysisOption.java',
        '-postScript',
        '/usr/local/src/BoringSecretHunter.java'
    ]


    # Initialize flags for when to start and stop printing
    start_printing = False
    stop_printing = False

    try:
        # Run the command using subprocess and capture the output in real-time
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        # Read the output line by line
        for line in process.stdout:
            # Check if the line contains the starting point
            if 'INFO  BoringSecretHunter.java>' in line:
                start_printing = True
                continue

            # Check if the line contains the stopping point
            if 'INFO  ANALYZING changes made by post scripts' in line:
                stop_printing = True

            # If we should be printing and haven't reached the stopping point, print the line
            if start_printing and not stop_printing:
                print(line.strip())

        # Wait for the process to complete
        process.wait()

        # Check for errors
        

    except Exception as e:
        print(f"An error occurred while running the Ghidra command: {e}")


if __name__ == '__main__':
    # Use argparse to get the file_path as a command-line argument
    parser = argparse.ArgumentParser(description='Run Ghidra headless with the given binary file.')
    parser.add_argument('file_path', type=str, help='The absolute path to the binary file.')

    # Parse the arguments
    args = parser.parse_args()

    # Run the Ghidra command with the file path provided
    run_ghidra_command(args.file_path)
