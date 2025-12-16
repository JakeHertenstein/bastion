# 📸 Terminal Screenshot Development Guide

## 🎯 **Screenshot Strategy for Seed Card**

### **Essential Screenshots Needed**
1. **Basic token generation** - Core functionality demo
2. **Multiple seed types** - BIP-39, simple, SLIP-39 examples  
3. **CSV export workflow** - Professional data export
4. **Password pattern generation** - End-user practical example
5. **Verification workflow** - Security validation demo

## 🖥️ **Terminal Setup for Beautiful Screenshots**

### **1. Terminal Appearance Configuration**
```bash
# Set up attractive terminal theme
# Use a dark theme with good contrast (SF Mono font recommended on macOS)

# Window settings:
# - Font: SF Mono 14pt (or Menlo 13pt)
# - Theme: Dark background (#1d1f21 or similar)
# - Colors: Bright but not overwhelming
# - Window size: 100x30 (wide enough for output, tall enough for context)
```

### **2. Command Preparation Scripts**

Create demo scripts that generate clean, professional output:

```bash
#!/bin/bash
# demo_basic.sh - Basic functionality demonstration

echo "🎯 Seed Card - Deterministic Password Token Generator"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

echo "📝 Generating tokens from simple seed phrase..."
python3 seeder.py generate grid --simple "Banking Vault Alpha"
echo ""

echo "✅ Tokens generated successfully!"
echo "💡 Each coordinate (A0-J9) contains a 4-character cryptographic token"
```

### **3. Terminal Recording Tools**

#### **Option A: Built-in Screenshot (macOS)**
```bash
# Take screenshot of specific terminal window
# Cmd+Shift+4, then Spacebar, then click terminal window
# Saves to Desktop automatically

# For consistent sizing:
# 1. Resize terminal to standard size first
# 2. Clear screen: clear
# 3. Run demo command
# 4. Take screenshot when output is displayed
```

#### **Option B: Terminal Recording with ASCIINEMA**
```bash
# Install asciinema for terminal session recording
brew install asciinema

# Record terminal session
asciinema rec seed_card_demo.cast

# Convert to GIF for README
npm install -g svg-term-cli
cat seed_card_demo.cast | svg-term --out seed_card_demo.svg
```

#### **Option C: Cleaner Static Screenshots**
```bash
# Use CleanShot X (paid) or similar for professional screenshots
# Features: drop shadows, rounded corners, annotations
```

## 📝 **Screenshot Scenarios**

### **Screenshot 1: Basic Token Generation**
```bash
#!/bin/bash
# File: demo_basic.sh

clear
echo "$ python3 seeder.py generate grid --simple \"Banking Vault Alpha\""
echo ""
python3 seeder.py generate grid --simple "Banking Vault Alpha"
```

### **Screenshot 2: BIP-39 with Rich Output**
```bash
#!/bin/bash  
# File: demo_bip39.sh

clear
echo "$ python3 seeder.py generate grid --bip39 \"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about\""
echo ""
python3 seeder.py generate grid --bip39 "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
```

### **Screenshot 3: CSV Export Workflow**
```bash
#!/bin/bash
# File: demo_export.sh

clear
echo "$ python3 seeder.py export csv --simple \"Banking\" --id \"VAULT-2024-001\""
echo ""
python3 seeder.py export csv --simple "Banking" --id "VAULT-2024-001"
echo ""
echo "$ head -3 Seeds.csv"
head -3 Seeds.csv
```

### **Screenshot 4: Password Generation**
```bash
#!/bin/bash
# File: demo_password.sh

clear
echo "$ python3 seeder.py generate patterns --simple \"Banking\" --pattern \"A0 B1 C2 D3\""
echo ""
python3 seeder.py generate patterns --simple "Banking" --pattern "A0 B1 C2 D3"
```

### **Screenshot 5: Verification Demo**
```bash
#!/bin/bash
# File: demo_verify.sh

clear
echo "$ python3 seeder.py verify tokens --simple \"test\" --tokens \"#tJt r7q[ e5<:\""
echo ""
python3 seeder.py verify tokens --simple "test" --tokens "#tJt r7q[ e5<:"
```

## 🎨 **Screenshot Optimization**

### **Terminal Settings for Screenshots**
```bash
# Optimal terminal configuration:
# Width: 100-120 columns (fits GitHub README width)
# Height: 30-40 rows (shows context without scrolling)
# Font size: 14-16pt (readable in GitHub)
# Color scheme: High contrast (dark background, bright text)
```

### **Command for Consistent Screenshots**
```bash
#!/bin/bash
# setup_terminal.sh - Configure terminal for screenshots

# Set terminal size
printf '\e[8;35;120t'  # 35 rows, 120 columns

# Clear and prepare
clear
echo "Ready for screenshot - terminal configured to 120x35"
```

## 📋 **Screenshot Checklist**

### **Before Taking Screenshots**
- [ ] Terminal sized consistently (120x35 recommended)
- [ ] Font size appropriate (14-16pt)
- [ ] Clean workspace (close other windows)
- [ ] Demo commands prepared and tested
- [ ] Output fits in visible area (no scrolling needed)

### **During Screenshots**
- [ ] Commands shown with `$` prompt for clarity
- [ ] Output displayed completely
- [ ] No personal information visible
- [ ] Good contrast and readability

### **After Screenshots**
- [ ] Images saved in consistent format (PNG recommended)  
- [ ] File names descriptive (`seed_card_basic_demo.png`)
- [ ] Images optimized for web (reasonable file size)
- [ ] Alt text prepared for accessibility

## 🚀 **Implementation Commands**

### **Create Screenshot Session**
```bash
# Create demo scripts directory
mkdir -p docs/screenshots

# Make all demo scripts executable
chmod +x docs/screenshots/*.sh

# Run screenshot session
cd docs/screenshots
./demo_basic.sh    # Screenshot 1
./demo_bip39.sh    # Screenshot 2  
./demo_export.sh   # Screenshot 3
./demo_password.sh # Screenshot 4
./demo_verify.sh   # Screenshot 5
```

### **Embed in README**
```markdown
## 🎯 Quick Start Examples

### Basic Token Generation
![Basic Demo](docs/screenshots/seed_card_basic_demo.png)

### Password Pattern Generation  
![Password Demo](docs/screenshots/seed_card_password_demo.png)

### CSV Export for Card Generation
![Export Demo](docs/screenshots/seed_card_export_demo.png)
```

**Result**: Professional, consistent screenshots that demonstrate Seed Card's capabilities clearly and attractively in your README.