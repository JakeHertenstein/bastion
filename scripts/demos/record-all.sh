#!/bin/bash
# =============================================================================
# Bastion Demo Recording Script
# =============================================================================
# Records all 5 terminal demos using asciinema with simulated output
#
# PREREQUISITES:
#   1. asciinema installed: brew install asciinema
#   2. Bastion installed (only needed for --version check)
#
# The demos use simulated output, so no 1Password auth or YubiKey needed.
#
# USAGE:
#   ./record-all.sh              # Interactive mode (recommended)
#   ./record-all.sh --batch      # Non-interactive, runs all demos
#   ./record-all.sh 3            # Record only demo 3
#
# OUTPUT:
#   Creates demo-XX-name.cast files in scripts/demos/
#
# TIPS:
#   - Review with: asciinema play demo-XX-name.cast
#   - Upload with: asciinema upload demo-XX-name.cast
#   - Play at 2x: asciinema play -s 2 demo-XX-name.cast
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
OUTPUT_DIR="$SCRIPT_DIR"

# Demo definitions: number, filename, description, script
declare -a DEMOS=(
    "1|demo-01-initial-setup|Initial Setup|01-initial-setup.sh"
    "2|demo-02-daily-check|Daily Security Check|02-daily-check.sh"
    "3|demo-03-yubikey-mgmt|YubiKey Management|03-yubikey-mgmt.sh"
    "4|demo-04-username-gen|Username Generation|04-username-gen.sh"
    "5|demo-05-entropy-collect|Entropy Collection|05-entropy-collect.sh"
)

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_header() {
    echo -e "\n${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}  Bastion Terminal Demo Recorder${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}\n"
}

print_checklist() {
    echo -e "${YELLOW}Pre-Recording Checklist:${NC}"
    echo "  [ ] asciinema installed"
    echo "  [ ] 1Password CLI authenticated (op whoami)"
    echo "  [ ] Bastion installed (bsec --version)"
    echo "  [ ] YubiKey connected (for demos 3, 5)"
    echo "  [ ] Terminal sized to 80x24"
    echo "  [ ] Clean prompt set (export PS1='\$ ')"
    echo ""
}

check_prerequisites() {
    local errors=0
    
    echo -e "${YELLOW}Checking prerequisites...${NC}"
    
    # Check asciinema
    if command -v asciinema &> /dev/null; then
        echo -e "  ${GREEN}✓${NC} asciinema installed"
    else
        echo -e "  ${RED}✗${NC} asciinema not found (brew install asciinema)"
        ((errors++))
    fi
    
    # Check 1Password CLI
    if op whoami &> /dev/null; then
        echo -e "  ${GREEN}✓${NC} 1Password CLI authenticated"
    else
        echo -e "  ${RED}✗${NC} 1Password CLI not authenticated (op signin)"
        ((errors++))
    fi
    
    # Check Bastion
    if command -v bsec &> /dev/null; then
        echo -e "  ${GREEN}✓${NC} Bastion installed ($(bsec --version 2>/dev/null || echo 'version unknown'))"
    else
        echo -e "  ${RED}✗${NC} Bastion not found (pip install -e packages/bastion)"
        ((errors++))
    fi
    
    # Check YubiKey (optional warning)
    if ykman list 2>/dev/null | grep -q .; then
        echo -e "  ${GREEN}✓${NC} YubiKey detected"
    else
        echo -e "  ${YELLOW}⚠${NC} No YubiKey detected (needed for demos 3, 5)"
    fi
    
    echo ""
    
    if [ $errors -gt 0 ]; then
        echo -e "${RED}Please fix the above issues before recording.${NC}"
        exit 1
    fi
}

record_demo() {
    local num="$1"
    local filename="$2"
    local description="$3"
    local script="$4"
    
    local output_file="$OUTPUT_DIR/$filename.cast"
    local script_path="$SCRIPT_DIR/$script"
    
    echo -e "\n${BLUE}Recording Demo $num: $description${NC}"
    echo -e "Output: $output_file"
    echo -e "Script: $script_path"
    echo ""
    
    if [ -f "$output_file" ]; then
        echo -e "${YELLOW}Warning: $output_file already exists.${NC}"
        read -p "Overwrite? [y/N] " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            echo "Skipping demo $num"
            return 0
        fi
    fi
    
    echo -e "${GREEN}Starting recording...${NC}"
    echo -e "  - Executing: $script"
    echo ""
    
    # Record with asciinema, auto-executing the demo script
    # -c: command to run (the demo script)
    # --idle-time-limit: caps idle time in playback
    # --overwrite: replace existing file
    # Note: Use single quotes around the path to handle spaces
    asciinema rec \
        --title "Bastion Demo $num: $description" \
        --idle-time-limit 2 \
        --overwrite \
        -c "bash '$script_path'" \
        "$output_file"
    
    echo -e "\n${GREEN}✓ Demo $num recorded: $output_file${NC}"
}

show_menu() {
    echo "Available demos:"
    for demo in "${DEMOS[@]}"; do
        IFS='|' read -r num filename description script <<< "$demo"
        local status=""
        if [ -f "$OUTPUT_DIR/$filename.cast" ]; then
            status="${GREEN}[recorded]${NC}"
        else
            status="${YELLOW}[pending]${NC}"
        fi
        echo -e "  $num) $description $status"
    done
    echo "  a) Record all demos"
    echo "  q) Quit"
    echo ""
}

interactive_mode() {
    print_header
    print_checklist
    check_prerequisites
    
    while true; do
        show_menu
        read -p "Select demo to record (1-5, a, q): " choice
        
        case "$choice" in
            [1-5])
                for demo in "${DEMOS[@]}"; do
                    IFS='|' read -r num filename description script <<< "$demo"
                    if [ "$num" = "$choice" ]; then
                        record_demo "$num" "$filename" "$description" "$script"
                        break
                    fi
                done
                ;;
            a|A)
                for demo in "${DEMOS[@]}"; do
                    IFS='|' read -r num filename description script <<< "$demo"
                    record_demo "$num" "$filename" "$description" "$script"
                done
                ;;
            q|Q)
                echo "Exiting."
                exit 0
                ;;
            *)
                echo -e "${RED}Invalid choice.${NC}"
                ;;
        esac
    done
}

batch_mode() {
    print_header
    check_prerequisites
    
    echo -e "${YELLOW}Batch mode: Recording all demos...${NC}"
    
    for demo in "${DEMOS[@]}"; do
        IFS='|' read -r num filename description script <<< "$demo"
        record_demo "$num" "$filename" "$description" "$script"
    done
    
    echo -e "\n${GREEN}All demos recorded!${NC}"
}

single_demo() {
    local target="$1"
    
    print_header
    check_prerequisites
    
    for demo in "${DEMOS[@]}"; do
        IFS='|' read -r num filename description script <<< "$demo"
        if [ "$num" = "$target" ]; then
            record_demo "$num" "$filename" "$description" "$script"
            exit 0
        fi
    done
    
    echo -e "${RED}Demo $target not found.${NC}"
    exit 1
}

# Main
cd "$PROJECT_ROOT"

case "${1:-}" in
    --batch)
        batch_mode
        ;;
    [1-5])
        single_demo "$1"
        ;;
    --help|-h)
        echo "Usage: $0 [--batch | 1-5 | --help]"
        echo ""
        echo "Options:"
        echo "  (none)    Interactive mode - select demos from menu"
        echo "  --batch   Record all demos non-interactively"
        echo "  1-5       Record specific demo number"
        echo "  --help    Show this help"
        exit 0
        ;;
    "")
        interactive_mode
        ;;
    *)
        echo "Unknown option: $1"
        echo "Run with --help for usage."
        exit 1
        ;;
esac
