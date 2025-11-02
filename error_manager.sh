#!/bin/bash
# Ashley Okoro sba25350 


# Color codes for output formatting
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Default input file
INPUT_FILE="${1:-logs.txt}"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
OUTPUT_FILE="error_report_${TIMESTAMP}.txt"

# Function: check_file_exists
# Description: Validates that the input log file exists and is readable
# Parameters: $1 - File path to check
# Returns: 0 if file exists, 1 otherwise
check_file_exists() {
    if [[ ! -f "$1" ]]; then
        echo -e "${RED}Error: File '$1' not found!${NC}" >&2
        return 1
    fi

    if [[ ! -r "$1" ]]; then
        echo -e "${RED}Error: File '$1' is not readable!${NC}" >&2
        return 1
    fi

    return 0
}

# Function: detect_errors
# Description: Searches for error patterns in log entries
# Patterns detected:
#   - Lines containing ERROR, FATAL, CRITICAL (case-insensitive)
#   - Exception traces
#   - Failed operations
# Parameters: $1 - Input log file
# Output: Writes errors to OUTPUT_FILE
detect_errors() {
    local log_file="$1"
    local error_count=0

    echo "ERROR DETECTION REPORT" > "$OUTPUT_FILE"
    echo "Generated: $(date)" >> "$OUTPUT_FILE"
    echo "Source: $log_file" >> "$OUTPUT_FILE"
    echo "" >> "$OUTPUT_FILE"

    # Detect ERROR level entries
    echo "ERROR ENTRIES" >> "$OUTPUT_FILE"
    while IFS= read -r line; do
        if echo "$line" | grep -iE "(ERROR|FATAL|CRITICAL|Exception|Failed)" > /dev/null; then
            echo "$line" >> "$OUTPUT_FILE"
            ((error_count++))
        fi
    done < "$log_file"

    echo "" >> "$OUTPUT_FILE"
    echo "Total errors found: $error_count" >> "$OUTPUT_FILE"

    return $error_count
}

# Function: validate_log_format
# Description: Detects malformed or invalid log entry patterns
# Valid format expected: [TIMESTAMP] LEVEL: Message
# Invalid patterns:
#   - Missing timestamp
#   - Missing log level
#   - Empty lines (excluded from validation)
# Parameters: $1 - Input log file
# Output: Appends invalid entries to OUTPUT_FILE
validate_log_format() {
    local log_file="$1"
    local invalid_count=0

    echo "" >> "$OUTPUT_FILE"
    echo "MALFORMED LOG ENTRIES" >> "$OUTPUT_FILE"

    local line_number=0
    while IFS= read -r line; do
        ((line_number++))

        # Skip empty lines
        [[ -z "$line" ]] && continue

        # Check for valid log format: [timestamp] LEVEL: message
        if ! echo "$line" | grep -E "^\[.+\]\s+(DEBUG|INFO|WARNING|ERROR|FATAL|CRITICAL):" > /dev/null; then
            echo "Line $line_number - INVALID FORMAT: $line" >> "$OUTPUT_FILE"
            ((invalid_count++))
        fi
    done < "$log_file"

    echo "" >> "$OUTPUT_FILE"
    echo "Total malformed entries: $invalid_count" >> "$OUTPUT_FILE"

    return $invalid_count
}

# MAIN EXECUTION FLOW

echo -e "${GREEN}=== Error Log Manager ===${NC}"
echo "Input file: $INPUT_FILE"
echo "Output file: $OUTPUT_FILE"
echo ""

# Step 1: Validate input file exists
echo -e "${YELLOW}[1/3] Validating input file...${NC}"
if ! check_file_exists "$INPUT_FILE"; then
    exit 1
fi
echo -e "${GREEN}✓ File validation passed${NC}"
echo ""

# Step 2: Detect errors
echo -e "${YELLOW}[2/3] Detecting error entries...${NC}"
detect_errors "$INPUT_FILE"
error_count=$?
echo -e "${GREEN}✓ Found $error_count error entries${NC}"
echo ""

# Step 3: Validate log format
echo -e "${YELLOW}[3/3] Validating log format...${NC}"
validate_log_format "$INPUT_FILE"
invalid_count=$?
echo -e "${GREEN}✓ Found $invalid_count malformed entries${NC}"
echo ""

# # Generate summary
# generate_summary

echo -e "${GREEN}=== Processing Complete ===${NC}"
echo "Report saved to: $OUTPUT_FILE"
echo ""
