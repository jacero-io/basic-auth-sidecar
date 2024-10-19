#!/bin/sh

# Output file
output_file="concatenated_output.txt"

# Create or empty the output file
> "$output_file"

# Function to process files
process_files() {
  dir=$1
  find_command="find \"$dir\" -type f"
  
  # Apply exclude patterns
  old_IFS=$IFS
  IFS=','
  for pattern in $CONCAT_EXCLUDE_PATTERNS; do
    if echo "$pattern" | grep -q "/"; then
      find_command="$find_command ! -path \"*/$pattern\""
    else
      find_command="$find_command ! -name \"$pattern\""
    fi
  done
  
  # Apply include patterns
  if [ -n "$CONCAT_INCLUDE_PATTERNS" ]; then
    find_command="$find_command \("
    for pattern in $CONCAT_INCLUDE_PATTERNS; do
      if echo "$pattern" | grep -q "/"; then
        find_command="$find_command -path \"*/$pattern\" -o"
      else
        find_command="$find_command -name \"$pattern\" -o"
      fi
    done
    find_command=$(echo "$find_command" | sed 's/ -o$//')  # Remove the last -o
    find_command="$find_command \)"
  fi
  IFS=$old_IFS

  eval "$find_command"
}

# Process the specified directory
process_files "$CONCAT_DIRECTORY" | while read -r file; do
  # Get the relative path of the file
  relative_path=${file#$CONCAT_DIRECTORY}
  relative_path=${relative_path#/}  # Remove leading slash if present
  
  echo -e "\n# File: $relative_path\n" >> "$output_file"
  
  # Remove multiline comments and output the result
  sed '/\/\*/,/\*\//d' "$file" >> "$output_file"
  
  echo -e "\n#==== End of file: $relative_path ====\n" >> "$output_file"
done

echo "Concatenation complete. Output written to $output_file"
