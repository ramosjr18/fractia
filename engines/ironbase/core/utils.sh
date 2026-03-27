#!/bin/bash

# core/utils.sh
# Core utility functions for logging and output formatting.

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1" >&2
}

log_success() {
    echo -e "${GREEN}[OK]${NC} $1" >&2
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1" >&2
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to load a profile config (Mock/Simple grepper for v0)
# Usage: is_module_enabled "module_name" "profile_path"
is_module_enabled() {
    local module_name=$1
    local profile_path=$2
    
    # Check if profile exists
    if [[ ! -f "$profile_path" ]]; then
        return 1
    fi
    
    # Simple logic: check if "module_name" is present and NOT followed by "enabled: false"
    # This is a very basic parser for v0.
    # In a real scenario, use yq or similar.
    # We assume the structure:
    #   module_name:
    #     enabled: true
    
    # Check if module is explicitly disabled
    grep -A 2 "${module_name}:" "$profile_path" | grep "enabled: false" > /dev/null
    if [[ $? -eq 0 ]]; then
        return 1
    fi
    
    # Check if module is explicitly enabled
     grep -A 2 "${module_name}:" "$profile_path" | grep "enabled: true" > /dev/null
    if [[ $? -eq 0 ]]; then
         return 0
    fi
    
    # Default to false if not found?
    return 1
}

# Progress Bar Functions
PROGRESS_BAR_WIDTH=50
PROGRESS_CURRENT=0
PROGRESS_TOTAL=0
PROGRESS_CURRENT_NAME=""

# Initialize progress bar
# Usage: init_progress_bar "total_items"
init_progress_bar() {
    PROGRESS_TOTAL=$1
    PROGRESS_CURRENT=0
    PROGRESS_CURRENT_NAME=""
    
    if [[ $PROGRESS_TOTAL -eq 0 ]]; then
        return 0
    fi
    
    # Print initial empty progress bar
    printf "\n" >&2
    printf "${BLUE}Progress: [${NC}%${PROGRESS_BAR_WIDTH}s${BLUE}]${NC} 0/$PROGRESS_TOTAL (0%%)\n" "" >&2
    printf "\n" >&2
}

# Update progress bar
# Usage: update_progress "current_item" "item_name"
update_progress() {
    local current=$1
    local item_name="${2:-Processing...}"
    PROGRESS_CURRENT=$current
    PROGRESS_CURRENT_NAME="$item_name"
    
    if [[ $PROGRESS_TOTAL -eq 0 ]]; then
        return 0
    fi
    
    # Calculate percentage
    local percentage=0
    if [[ $PROGRESS_TOTAL -gt 0 ]]; then
        percentage=$(( (current * 100) / PROGRESS_TOTAL ))
    fi
    
    # Calculate filled and empty width
    local filled=$(( (current * PROGRESS_BAR_WIDTH) / PROGRESS_TOTAL ))
    local empty=$(( PROGRESS_BAR_WIDTH - filled ))
    
    # Build progress bar string
    local bar=""
    local i
    for ((i=0; i<filled; i++)); do
        bar="${bar}#"
    done
    for ((i=0; i<empty; i++)); do
        bar="${bar} "
    done
    
    # Move cursor up one line and clear it, then print updated progress
    printf "\033[A\033[K" >&2
    printf "${BLUE}Progress: [${GREEN}${bar}${BLUE}]${NC} %d/%d (%d%%) - ${YELLOW}%s${NC}\n" "$current" "$PROGRESS_TOTAL" "$percentage" "$item_name" >&2
    
    # Print blank line for next update if not complete
    if [[ $current -lt $PROGRESS_TOTAL ]]; then
        printf "\n" >&2
    fi
}

# Complete progress bar
complete_progress_bar() {
    if [[ $PROGRESS_TOTAL -eq 0 ]]; then
        return 0
    fi
    
    update_progress "$PROGRESS_TOTAL" "Complete"
    printf "\n" >&2
}
