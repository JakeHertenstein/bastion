#!/bin/bash
# =============================================================================
# Bastion Demo Vault Setup
# =============================================================================
# Creates example items in the "Bastion DEMO" vault for demo recordings.
#
# PREREQUISITES:
#   1. 1Password CLI authenticated: op signin
#   2. Vault named "Bastion DEMO" exists: op vault create "Bastion DEMO"
#
# USAGE:
#   ./setup-demo-vault.sh          # Create all demo items
#   ./setup-demo-vault.sh --clean  # Remove all demo items first
#
# DEMO ITEMS CREATED:
#   - 6 Login items with various Bastion tags
#   - 1 YubiKey/Token item
#   - 1 Untagged item (for audit demos)
# =============================================================================

set -e

VAULT="Bastion DEMO"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_header() {
    echo -e "\n${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}  Bastion Demo Vault Setup${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}\n"
}

check_vault() {
    echo -e "${YELLOW}Checking vault...${NC}"
    if ! op vault get "$VAULT" &>/dev/null; then
        echo -e "${RED}Vault '$VAULT' not found!${NC}"
        echo "Create it with: op vault create $VAULT"
        exit 1
    fi
    echo -e "${GREEN}✓${NC} Vault '$VAULT' exists"
}

clean_vault() {
    echo -e "${YELLOW}Cleaning demo items from vault...${NC}"
    
    # Get all items in the vault and delete them
    items=$(op item list --vault "$VAULT" --format json 2>/dev/null | jq -r '.[].id' || true)
    
    if [ -n "$items" ]; then
        for item in $items; do
            echo "  Deleting $item..."
            op item delete "$item" --vault "$VAULT" 2>/dev/null || true
        done
        echo -e "${GREEN}✓${NC} Vault cleaned"
    else
        echo "  No items to clean"
    fi
}

create_items() {
    echo -e "\n${YELLOW}Creating demo items...${NC}\n"
    
    # =========================================================================
    # 1. ACME Bank - Bank, Money-Transfer, FIDO2+TOTP (overdue rotation)
    # =========================================================================
    echo "Creating: ACME Bank..."
    op item create \
        --category login \
        --vault "$VAULT" \
        --title "ACME Bank" \
        --url "https://www.acmebank.example.com" \
        --generate-password='letters,digits,symbols,32' \
        "username=demo_user_acme@example.com" \
        "Rotation Schedule.Rotation Period[text]=90 days" \
        "Rotation Schedule.Last Rotated[date]=2024-08-15" \
        --tags "Bastion/Type/Bank,Bastion/Capability/Money-Transfer,Bastion/2FA/FIDO2-Hardware,Bastion/2FA/TOTP" \
        >/dev/null
    echo -e "  ${GREEN}✓${NC} ACME Bank (overdue rotation, FIDO2+TOTP)"
    
    # =========================================================================
    # 2. SecureMail Pro - Email, Recovery, TOTP (recently rotated)
    # =========================================================================
    echo "Creating: SecureMail Pro..."
    op item create \
        --category login \
        --vault "$VAULT" \
        --title "SecureMail Pro" \
        --url "https://mail.securemail.example.com" \
        --generate-password='letters,digits,symbols,24' \
        "username=demouser@securemail.example.com" \
        "Rotation Schedule.Rotation Period[text]=180 days" \
        "Rotation Schedule.Last Rotated[date]=2025-11-01" \
        --tags "Bastion/Type/Email,Bastion/Capability/Recovery,Bastion/2FA/TOTP" \
        >/dev/null
    echo -e "  ${GREEN}✓${NC} SecureMail Pro (recently rotated, TOTP)"
    
    # =========================================================================
    # 3. CloudStore AWS - Cloud, FIDO2-Hardware (due soon)
    # =========================================================================
    echo "Creating: CloudStore AWS..."
    op item create \
        --category login \
        --vault "$VAULT" \
        --title "CloudStore AWS" \
        --url "https://console.cloudstore.example.com" \
        --generate-password='letters,digits,symbols,32' \
        "username=admin@cloudstore.example.com" \
        "Rotation Schedule.Rotation Period[text]=90 days" \
        "Rotation Schedule.Last Rotated[date]=2024-09-15" \
        --tags "Bastion/Type/Cloud,Bastion/2FA/FIDO2-Hardware,Bastion/Capability/Secrets" \
        >/dev/null
    echo -e "  ${GREEN}✓${NC} CloudStore AWS (due soon, FIDO2)"
    
    # =========================================================================
    # 4. MegaShop - Shopping, SMS only (WEAK 2FA - pre-baseline)
    # =========================================================================
    echo "Creating: MegaShop..."
    op item create \
        --category login \
        --vault "$VAULT" \
        --title "MegaShop" \
        --url "https://www.megashop.example.com" \
        --generate-password='letters,digits,20' \
        "username=shopper@example.com" \
        "Rotation Schedule.Rotation Period[text]=365 days" \
        "Rotation Schedule.Last Rotated[date]=2023-06-15" \
        --tags "Bastion/Type/Shopping,Bastion/2FA/SMS" \
        >/dev/null
    echo -e "  ${GREEN}✓${NC} MegaShop (pre-baseline, SMS only - weak)"
    
    # =========================================================================
    # 5. HealthPortal - Healthcare, Insurance, TOTP+Backup-Codes
    # =========================================================================
    echo "Creating: HealthPortal..."
    op item create \
        --category login \
        --vault "$VAULT" \
        --title "HealthPortal" \
        --url "https://patient.healthportal.example.com" \
        --generate-password='letters,digits,symbols,28' \
        "username=patient_12345@healthportal.example.com" \
        "Rotation Schedule.Rotation Period[text]=180 days" \
        "Rotation Schedule.Last Rotated[date]=2025-06-01" \
        --tags "Bastion/Type/Healthcare,Bastion/Type/Insurance,Bastion/2FA/TOTP,Bastion/Dependency/Backup-Codes" \
        >/dev/null
    echo -e "  ${GREEN}✓${NC} HealthPortal (Healthcare+Insurance, TOTP)"
    
    # =========================================================================
    # 6. DevHub GitHub - Cloud, Identity, FIDO2+TOTP+Passkey
    # =========================================================================
    echo "Creating: DevHub GitHub..."
    op item create \
        --category login \
        --vault "$VAULT" \
        --title "DevHub GitHub" \
        --url "https://github.example.com" \
        --generate-password='letters,digits,symbols,32' \
        "username=developer@example.com" \
        "Rotation Schedule.Rotation Period[text]=90 days" \
        "Rotation Schedule.Last Rotated[date]=2025-10-01" \
        --tags "Bastion/Type/Cloud,Bastion/Capability/Identity,Bastion/2FA/FIDO2-Hardware,Bastion/2FA/TOTP,Bastion/2FA/Passkey/Software" \
        >/dev/null
    echo -e "  ${GREEN}✓${NC} DevHub GitHub (multiple 2FA methods)"
    
    # =========================================================================
    # 7. YubiKey Demo Token
    # =========================================================================
    echo "Creating: YubiKey Demo Token..."
    op item create \
        --category "Secure Note" \
        --vault "$VAULT" \
        --title "YubiKey 5 NFC - Demo" \
        "Serial Number[text]=12345678" \
        "Firmware[text]=5.4.3" \
        "OATH Slots.Slot 1[text]=ACME Bank TOTP" \
        "OATH Slots.Slot 2[text]=SecureMail Pro TOTP" \
        "OATH Slots.Slot 3[text]=CloudStore AWS TOTP" \
        --tags "Bastion/YubiKey/Token" \
        >/dev/null
    echo -e "  ${GREEN}✓${NC} YubiKey 5 NFC - Demo (OATH slots)"
    
    # =========================================================================
    # 8. Untagged Item (for audit demo)
    # =========================================================================
    echo "Creating: Legacy Account (untagged)..."
    op item create \
        --category login \
        --vault "$VAULT" \
        --title "Legacy Account" \
        --url "https://legacy.example.com" \
        --generate-password='letters,digits,16' \
        "username=olduser@example.com" \
        >/dev/null
    echo -e "  ${GREEN}✓${NC} Legacy Account (no Bastion tags - for audit demo)"
    
    echo ""
}

show_summary() {
    echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}  Demo Vault Setup Complete!${NC}"
    echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}\n"
    
    echo "Items created in vault '$VAULT':"
    echo ""
    op item list --vault "$VAULT" --format json | jq -r '.[] | "  • \(.title)"'
    echo ""
    
    echo -e "${YELLOW}Next steps:${NC}"
    echo "  1. Sync the demo vault:  bsec 1p sync vault --vault $VAULT"
    echo "  2. Run demos:            ./record-all.sh"
    echo ""
}

# Main
print_header

case "${1:-}" in
    --clean)
        check_vault
        clean_vault
        create_items
        show_summary
        ;;
    --help|-h)
        echo "Usage: $0 [--clean | --help]"
        echo ""
        echo "Options:"
        echo "  (none)    Create demo items (fails if items exist)"
        echo "  --clean   Remove existing items first, then create"
        echo "  --help    Show this help"
        exit 0
        ;;
    "")
        check_vault
        create_items
        show_summary
        ;;
    *)
        echo "Unknown option: $1"
        exit 1
        ;;
esac
