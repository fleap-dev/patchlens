#!/bin/bash

# -----------------------------------------------------------------------------
# This script runs a user-provided command on all .c files found
# in a given directory and then reports a summary.
#
# Usage: ./process_files.sh <command> [directory]
# Example: ./process_files.sh "python find_conditions.py" ./src
# -----------------------------------------------------------------------------

# --- Argument Validation ---

# Check if the command argument ($1) was provided.
if [[ -z "$1" ]]; then
    echo "Error: No command provided."
    echo "Usage: $0 <command_to_run> [directory_to_search]"
    exit 1
fi

# The command to execute for each file is the first argument.
command_to_run="$1"

# The search directory is the second argument ($2). Default to '.' if not provided.
search_dir=${2:-.}

# Check if the target directory actually exists.
if [[ ! -d "$search_dir" ]]; then
    echo "Error: Directory '$search_dir' not found."
    exit 1
fi

# --- Main Script ---

# Initialize counters
total_runs=0
failure_count=0

echo "🚀 Starting to process .c files in '$search_dir'..."
echo

# Find all .c files and process them one by one.
while IFS= read -r file; do
    # Increment the counter for every file processed
    ((total_runs++))

    # Print the file name header
    printf "%s: " "$file"

    # Execute the user-provided command on the file.
    # Note: The command is executed with the file path as its final argument.
    $command_to_run "$search_dir" "$file"

    # Check the exit code of the last command.
    if [[ $? -ne 0 ]]; then
        # If the script failed, increment the failure counter
        ((failure_count++))
    fi
done < <(find "$search_dir" -type f -name "*.c")

# --- Final Summary ---
echo
echo "-------------------------------------"
echo "✅ Processing Complete"
echo "-------------------------------------"
echo "Total files processed: $total_runs"
echo "Commands that failed: $failure_count"
