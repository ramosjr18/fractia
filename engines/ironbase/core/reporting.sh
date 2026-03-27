#!/bin/bash

# core/reporting.sh
# Global Report System - Centralizes all findings and generates reports

# Global Report Storage
declare -a GLOBAL_MODULES=()
GLOBAL_RUN_ID=""
GLOBAL_RUN_DIR=""
GLOBAL_METADATA=""
GLOBAL_FINDINGS_FILE=""

# Initialize reporting system
# Sets up run directory and metadata
init_reporting() {
    local action="$1"
    local profile="$2"
    shift 2
    local flags="$@"
    
    # Generate run ID with timestamp
    GLOBAL_RUN_ID=$(date +"%Y-%m-%d_%H-%M-%S")
    
    # Create output directory structure
    # Use IRONBASE_ROOT from engine if available, otherwise calculate from BASH_SOURCE
    local root_dir="${IRONBASE_ROOT:-}"
    if [[ -z "$root_dir" ]]; then
        # Fallback: calculate from reporting.sh location
        local script_path="${BASH_SOURCE[0]}"
        root_dir="$(cd "$(dirname "$script_path")/.." && pwd)"
    fi
    local output_dir="$root_dir/output"
    GLOBAL_RUN_DIR="$output_dir/runs/$GLOBAL_RUN_ID"
    
    # Create directories
    mkdir -p "$GLOBAL_RUN_DIR" 2>/dev/null || {
        echo "Error: Cannot create output directory: $GLOBAL_RUN_DIR" >&2
        exit 1
    }
    
    # Create latest symlink (portable fallback if symlinks not supported)
    local latest_link="$output_dir/latest"
    if ln -sfn "$GLOBAL_RUN_DIR" "$latest_link" 2>/dev/null; then
        : # Symlink created
    elif [[ ! -L "$latest_link" ]]; then
        # Fallback: create a file with path if symlinks don't work
        echo "$GLOBAL_RUN_DIR" > "$latest_link.path" 2>/dev/null || true
    fi
    
    # Set metadata
    local hostname_val=$(hostname 2>/dev/null || echo "unknown")
    local timestamp_val=$(date -Iseconds 2>/dev/null || date +"%Y-%m-%d %H:%M:%S" || echo "unknown")
    
    GLOBAL_METADATA=$(cat <<EOF
{
  "run_id": "$GLOBAL_RUN_ID",
  "timestamp": "$timestamp_val",
  "hostname": "$hostname_val",
  "action": "$action",
  "profile": "$profile",
  "flags": "$flags",
  "version": "0.1.0"
}
EOF
)
    
    # Export for modules to use
    export IRONBASE_RUN_ID="$GLOBAL_RUN_ID"
    export IRONBASE_RUN_DIR="$GLOBAL_RUN_DIR"
    export IRONBASE_OUTPUT_DIR="$GLOBAL_RUN_DIR"
    
    # Initialize findings file (temporary, used for aggregation)
    GLOBAL_FINDINGS_FILE="$GLOBAL_RUN_DIR/.findings.tmp"
    touch "$GLOBAL_FINDINGS_FILE" 2>/dev/null || {
        echo "Error: Cannot create findings file: $GLOBAL_FINDINGS_FILE" >&2
        exit 1
    }
    
    # Write metadata
    echo "$GLOBAL_METADATA" > "$GLOBAL_RUN_DIR/metadata.json"
    
    echo "$GLOBAL_RUN_DIR"
}

# Register a module execution
register_module() {
    local module_name="$1"
    GLOBAL_MODULES+=("$module_name")
}

# Register a finding to global report
# Compatible with both add_finding (core) and add_vps_finding (vps modules)
register_finding() {
    local id="$1"
    local severity="$2"
    local status="${3:-}"
    local title="$4"
    local description="$5"
    local evidence="${6:-}"
    local remediation="${7:-}"
    local type="${8:-}"
    local origin="${9:-}"
    local category="${10:-}"
    
    # Defensive: Ensure GLOBAL_FINDINGS_FILE is set
    # Use IRONBASE_RUN_DIR if available (exported), otherwise use GLOBAL_RUN_DIR
    local run_dir="${IRONBASE_RUN_DIR:-${GLOBAL_RUN_DIR:-}}"
    if [[ -z "$GLOBAL_FINDINGS_FILE" ]]; then
        if [[ -n "$run_dir" ]] && [[ -d "$run_dir" ]]; then
            GLOBAL_FINDINGS_FILE="$run_dir/.findings.tmp"
        else
            # If no run directory, skip registration (standalone mode or not initialized)
            return 0
        fi
    fi
    
    # Ensure the findings file exists and is writable
    if [[ ! -f "$GLOBAL_FINDINGS_FILE" ]]; then
        touch "$GLOBAL_FINDINGS_FILE" 2>/dev/null || {
            # Silently fail if we can't create the file (non-critical)
            return 0
        }
    fi
    
    # Escape special characters for JSON
    escape_json() {
        echo "$1" | sed 's/\\/\\\\/g' | sed 's/"/\\"/g' | sed ':a;N;$!ba;s/\n/\\n/g' | sed 's/\t/\\t/g'
    }
    
    local id_escaped=$(escape_json "$id")
    local severity_escaped=$(escape_json "$severity")
    local status_escaped=$(escape_json "$status")
    local title_escaped=$(escape_json "$title")
    local desc_escaped=$(escape_json "$description")
    local evidence_escaped=$(escape_json "$evidence")
    local remediation_escaped=$(escape_json "$remediation")
    local type_escaped=$(escape_json "$type")
    local origin_escaped=$(escape_json "$origin")
    local category_escaped=$(escape_json "$category")
    local module_escaped="${GLOBAL_MODULES[-1]:-unknown}"
    local timestamp_escaped=$(date -Iseconds 2>/dev/null || date +"%Y-%m-%d %H:%M:%S")
    
    # Write finding to temporary file (one per line, pipe-delimited for parsing)
    # Format: ID|SEVERITY|STATUS|TITLE|DESCRIPTION|EVIDENCE|REMEDIATION|TYPE|ORIGIN|CATEGORY|MODULE|TIMESTAMP
    echo "${id_escaped}|${severity_escaped}|${status_escaped}|${title_escaped}|${desc_escaped}|${evidence_escaped}|${remediation_escaped}|${type_escaped}|${origin_escaped}|${category_escaped}|${module_escaped}|${timestamp_escaped}" >> "$GLOBAL_FINDINGS_FILE" 2>/dev/null || {
        # Silently fail if write fails (non-critical, findings will still appear in console)
        return 0
    }
}

# Generate final reports
# Returns exit code from summary (0=passed, 1=failed)
generate_reports() {
    # Use exported IRONBASE_RUN_DIR (always available if init_reporting was called)
    # Fallback to GLOBAL_RUN_DIR for backwards compatibility
    local run_dir="${IRONBASE_RUN_DIR:-${GLOBAL_RUN_DIR:-}}"
    
    if [[ -z "$run_dir" ]] || [[ ! -d "$run_dir" ]]; then
        echo "Error: Run directory not initialized. IRONBASE_RUN_DIR=$IRONBASE_RUN_DIR, GLOBAL_RUN_DIR=$GLOBAL_RUN_DIR" >&2
        return 1
    fi
    
    # Synchronize GLOBAL_RUN_DIR with IRONBASE_RUN_DIR (ensure consistency)
    GLOBAL_RUN_DIR="$run_dir"
    
    # Also ensure GLOBAL_FINDINGS_FILE is set correctly
    if [[ -z "$GLOBAL_FINDINGS_FILE" ]]; then
        GLOBAL_FINDINGS_FILE="$GLOBAL_RUN_DIR/.findings.tmp"
    fi
    
    # Generate JSON report
    generate_json_report
    
    # Generate text report
    generate_text_report
    
    # Generate summary (returns exit code)
    generate_summary
    return $?
}

# Generate JSON report (complete serialization)
generate_json_report() {
    # Use exported IRONBASE_RUN_DIR (always available if init_reporting was called)
    # Fallback to GLOBAL_RUN_DIR for backwards compatibility
    local run_dir="${IRONBASE_RUN_DIR:-${GLOBAL_RUN_DIR:-}}"
    
    if [[ -z "$run_dir" ]] || [[ ! -d "$run_dir" ]]; then
        echo "Error: Run directory not initialized. Cannot generate JSON report." >&2
        return 1
    fi
    
    # Synchronize GLOBAL_RUN_DIR with IRONBASE_RUN_DIR (ensure consistency)
    GLOBAL_RUN_DIR="$run_dir"
    
    # Ensure GLOBAL_FINDINGS_FILE is set correctly
    if [[ -z "$GLOBAL_FINDINGS_FILE" ]]; then
        GLOBAL_FINDINGS_FILE="$GLOBAL_RUN_DIR/.findings.tmp"
    fi
    
    local json_file="$GLOBAL_RUN_DIR/report.json"
    
    # Start JSON structure
    {
        echo "{"
        echo "  \"metadata\": $GLOBAL_METADATA,"
        echo "  \"modules\": ["
        
        local first_module=1
        for module in "${GLOBAL_MODULES[@]}"; do
            if [[ $first_module -eq 0 ]]; then
                echo ","
            fi
            echo -n "    \"$module\""
            first_module=0
        done
        
        echo ""
        echo "  ],"
        echo "  \"findings\": ["
        
        # Read findings from temporary file
        local first_finding=1
        if [[ -f "$GLOBAL_FINDINGS_FILE" ]]; then
            while IFS='|' read -r id sev status title desc evidence remediation type origin category module timestamp; do
                if [[ $first_finding -eq 0 ]]; then
                    echo ","
                fi
                echo -n "    {"
                echo -n "\"id\": \"$id\","
                echo -n "\"severity\": \"$sev\","
                echo -n "\"status\": \"$status\","
                echo -n "\"title\": \"$title\","
                echo -n "\"description\": \"$desc\","
                echo -n "\"evidence\": \"$evidence\","
                echo -n "\"remediation\": \"$remediation\","
                echo -n "\"type\": \"$type\","
                echo -n "\"origin\": \"$origin\","
                echo -n "\"category\": \"$category\","
                echo -n "\"module\": \"$module\","
                echo -n "\"timestamp\": \"$timestamp\""
                echo -n "}"
                first_finding=0
            done < "$GLOBAL_FINDINGS_FILE"
        fi
        
        echo ""
        echo "  ],"
        
        # Add summary statistics
        local counts=$(calculate_counts)
        echo "  \"summary\": $counts"
        
        echo "}"
    } > "$json_file"
}

# Generate text report (human-readable)
generate_text_report() {
    # Use exported IRONBASE_RUN_DIR (always available if init_reporting was called)
    # Fallback to GLOBAL_RUN_DIR for backwards compatibility
    local run_dir="${IRONBASE_RUN_DIR:-${GLOBAL_RUN_DIR:-}}"
    
    if [[ -z "$run_dir" ]] || [[ ! -d "$run_dir" ]]; then
        echo "Error: Run directory not initialized. Cannot generate text report." >&2
        return 1
    fi
    
    # Synchronize GLOBAL_RUN_DIR with IRONBASE_RUN_DIR (ensure consistency)
    GLOBAL_RUN_DIR="$run_dir"
    
    # Ensure GLOBAL_FINDINGS_FILE is set correctly
    if [[ -z "$GLOBAL_FINDINGS_FILE" ]]; then
        GLOBAL_FINDINGS_FILE="$GLOBAL_RUN_DIR/.findings.tmp"
    fi
    
    local text_file="$GLOBAL_RUN_DIR/report.txt"
    local tmp_file="$GLOBAL_RUN_DIR/.report_tmp.txt"
    
    {
        echo "IronBase Security Assessment Report"
        echo "===================================="
        echo ""
        # Parse metadata.json for header info
        if [[ -f "$GLOBAL_RUN_DIR/metadata.json" ]]; then
            local run_id=$(grep -o '"run_id": "[^"]*"' "$GLOBAL_RUN_DIR/metadata.json" | cut -d'"' -f4)
            local timestamp=$(grep -o '"timestamp": "[^"]*"' "$GLOBAL_RUN_DIR/metadata.json" | cut -d'"' -f4)
            local hostname=$(grep -o '"hostname": "[^"]*"' "$GLOBAL_RUN_DIR/metadata.json" | cut -d'"' -f4)
            local action=$(grep -o '"action": "[^"]*"' "$GLOBAL_RUN_DIR/metadata.json" | cut -d'"' -f4)
            echo "Run ID: $run_id"
            echo "Timestamp: $timestamp"
            echo "Hostname: $hostname"
            echo "Action: $action"
        fi
        echo ""
        echo "Modules Executed:"
        for module in "${GLOBAL_MODULES[@]}"; do
            echo "  - $module"
        done
        echo ""
        echo "===================================="
        echo "Findings"
        echo "===================================="
        echo ""
    } > "$text_file"
    
    # Group and print findings by severity
    if [[ -f "$GLOBAL_FINDINGS_FILE" ]]; then
        local crit_count=0 high_count=0 medium_count=0 low_count=0 info_count=0
        
        # Temporary files for grouping
        local crit_file="$tmp_file.crit"
        local high_file="$tmp_file.high"
        touch "$crit_file" "$high_file" 2>/dev/null || true
        
        # Parse findings: count and group by severity in single pass
        while IFS='|' read -r id sev status title desc evidence remediation type origin category module timestamp; do
            case "$sev" in
                "CRITICAL")
                    ((crit_count++))
                    echo "  [$sev] $title ($id) - Module: $module" >> "$crit_file"
                    echo "    Status: $status" >> "$crit_file"
                    echo "    Description: $desc" >> "$crit_file"
                    [[ -n "$evidence" ]] && echo "    Evidence: $evidence" >> "$crit_file"
                    [[ -n "$remediation" ]] && echo "    Remediation: $remediation" >> "$crit_file"
                    echo "" >> "$crit_file"
                    ;;
                "HIGH")
                    ((high_count++))
                    echo "  [$sev] $title ($id) - Module: $module" >> "$high_file"
                    echo "    Status: $status" >> "$high_file"
                    echo "    Description: $desc" >> "$high_file"
                    [[ -n "$evidence" ]] && echo "    Evidence: $evidence" >> "$high_file"
                    [[ -n "$remediation" ]] && echo "    Remediation: $remediation" >> "$high_file"
                    echo "" >> "$high_file"
                    ;;
                "MEDIUM") ((medium_count++)) ;;
                "LOW") ((low_count++)) ;;
                *) ((info_count++)) ;;
            esac
        done < "$GLOBAL_FINDINGS_FILE"
        
        # Append grouped findings to report
        if [[ $crit_count -gt 0 ]] && [[ -f "$crit_file" ]]; then
            echo "[CRITICAL] Findings: ($crit_count)" >> "$text_file"
            cat "$crit_file" >> "$text_file"
        fi
        
        if [[ $high_count -gt 0 ]] && [[ -f "$high_file" ]]; then
            echo "[HIGH] Findings: ($high_count)" >> "$text_file"
            cat "$high_file" >> "$text_file"
        fi
        
        # Print MEDIUM findings (summary only)
        if [[ $medium_count -gt 0 ]] || [[ $low_count -gt 0 ]] || [[ $info_count -gt 0 ]]; then
            echo "Other Findings:" >> "$text_file"
            echo "  Medium: $medium_count" >> "$text_file"
            echo "  Low: $low_count" >> "$text_file"
            echo "  Info: $info_count" >> "$text_file"
            echo "(See individual module logs for details)" >> "$text_file"
            echo "" >> "$text_file"
        fi
        
        # Cleanup temp files
        rm -f "$crit_file" "$high_file" 2>/dev/null || true
    else
        echo "No findings reported." >> "$text_file"
        echo "" >> "$text_file"
    fi
}


# Generate summary (short, for console/CI)
generate_summary() {
    # Use exported IRONBASE_RUN_DIR (always available if init_reporting was called)
    # Fallback to GLOBAL_RUN_DIR for backwards compatibility
    local run_dir="${IRONBASE_RUN_DIR:-${GLOBAL_RUN_DIR:-}}"
    
    if [[ -z "$run_dir" ]] || [[ ! -d "$run_dir" ]]; then
        echo "Error: Run directory not initialized. Cannot generate summary." >&2
        return 1
    fi
    
    # Synchronize GLOBAL_RUN_DIR with IRONBASE_RUN_DIR (ensure consistency)
    GLOBAL_RUN_DIR="$run_dir"
    
    # Extract Run ID from directory path if GLOBAL_RUN_ID is empty
    local run_id="${GLOBAL_RUN_ID:-}"
    if [[ -z "$run_id" ]]; then
        # Extract from run directory path (format: .../runs/YYYY-MM-DD_HH-MM-SS)
        run_id=$(basename "$run_dir")
    fi
    
    local summary_file="$GLOBAL_RUN_DIR/summary.txt"
    local counts=$(calculate_counts)
    
    # Extract counts from JSON (simple parsing)
    local crit=$(echo "$counts" | grep -o '"critical": [0-9]*' | grep -o '[0-9]*' || echo "0")
    local high=$(echo "$counts" | grep -o '"high": [0-9]*' | grep -o '[0-9]*' || echo "0")
    local medium=$(echo "$counts" | grep -o '"medium": [0-9]*' | grep -o '[0-9]*' || echo "0")
    local low=$(echo "$counts" | grep -o '"low": [0-9]*' | grep -o '[0-9]*' || echo "0")
    local info=$(echo "$counts" | grep -o '"info": [0-9]*' | grep -o '[0-9]*' || echo "0")
    local total=$(echo "$counts" | grep -o '"total": [0-9]*' | grep -o '[0-9]*' || echo "0")
    
    # Sanitize: ensure numeric values
    [[ "$crit" =~ ^[0-9]+$ ]] || crit=0
    [[ "$high" =~ ^[0-9]+$ ]] || high=0
    [[ "$medium" =~ ^[0-9]+$ ]] || medium=0
    [[ "$low" =~ ^[0-9]+$ ]] || low=0
    [[ "$info" =~ ^[0-9]+$ ]] || info=0
    [[ "$total" =~ ^[0-9]+$ ]] || total=0
    
    {
        echo "IronBase Security Assessment Summary"
        echo "===================================="
        echo ""
        echo "Run ID: $run_id"
        echo "Modules: ${#GLOBAL_MODULES[@]}"
        echo "Findings: $total"
        echo ""
        echo "By Severity:"
        echo "  Critical: $crit"
        echo "  High:     $high"
        echo "  Medium:   $medium"
        echo "  Low:      $low"
        echo "  Info:     $info"
        echo ""
        
        # Determine overall result
        local result="PASSED"
        local exit_code=0
        if [[ "$crit" -gt 0 ]] || [[ "$high" -gt 0 ]]; then
            result="FAILED"
            exit_code=1
        elif [[ "$medium" -gt 0 ]]; then
            result="PASSED WITH FINDINGS"
        fi
        
        echo "Result: $result"
        echo ""
        echo "Full reports available in: $GLOBAL_RUN_DIR"
        echo "  - report.json (machine-readable)"
        echo "  - report.txt (human-readable)"
        echo ""
    } > "$summary_file"
    
    # Return exit code (for engine to use)
    return $exit_code
}

# Calculate counts by severity
calculate_counts() {
    # Ensure GLOBAL_FINDINGS_FILE is set correctly
    local run_dir="${IRONBASE_RUN_DIR:-${GLOBAL_RUN_DIR:-}}"
    local findings_file="${GLOBAL_FINDINGS_FILE:-}"
    
    if [[ -z "$findings_file" ]] && [[ -n "$run_dir" ]] && [[ -d "$run_dir" ]]; then
        findings_file="$run_dir/.findings.tmp"
    fi
    
    local crit=0 high=0 medium=0 low=0 info=0
    
    if [[ -n "$findings_file" ]] && [[ -f "$findings_file" ]]; then
        while IFS='|' read -r id sev status title desc evidence remediation type origin category module timestamp; do
            case "$sev" in
                "CRITICAL") ((crit++)) ;;
                "HIGH") ((high++)) ;;
                "MEDIUM") ((medium++)) ;;
                "LOW") ((low++)) ;;
                *) ((info++)) ;;
            esac
        done < "$findings_file"
    fi
    
    local total=$((crit + high + medium + low + info))
    
    cat <<EOF
{
  "critical": $crit,
  "high": $high,
  "medium": $medium,
  "low": $low,
  "info": $info,
  "total": $total
}
EOF
}
