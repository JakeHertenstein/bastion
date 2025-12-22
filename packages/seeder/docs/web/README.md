# Seed Card Generator - Web Application

A modern single-page application (SPA) for generating deterministic password matrices from seed material. Built with Vite for optimal development experience and production builds.

## 🆕 Latest Features

### **Argon2id KDF Support**
- Memory-hard key derivation resistant to GPU/ASIC brute-force attacks
- Configurable memory (64MB-2GB), iterations (1-10), and parallelism (1-8)
- Safari-compatible WASM workers with 208MB memory limit per worker
- Parallel multi-core generation using Web Worker pool
- Graceful fallback to SHA-512 when Argon2 unavailable

### **Multi-Base Token Systems**
- **Base10**: 4-digit PIN codes (~13.3 bits/token) for numeric requirements
- **Base62**: Alphanumeric tokens (~23.8 bits/token) for balanced security
- **Base90**: Full special characters (~26.0 bits/token) for maximum entropy
- Select via dropdown in Configuration section

### **Nonce-Based Derivation**
- Auto-generated 48-bit nonces ensure unique card batches
- URL-safe Base64 encoding (A-Za-z0-9-_)
- Regenerate button for new nonce values
- Full v1 label format for reproducibility

### **Batch Generation Progress**
- Visual progress overlay with cancellation support
- Card button states: grey (pending), amber pulse (generating), green (complete)
- Persistent state tracking survives card selection changes

### **Click-to-Copy Token System**
- Click any token in any matrix to copy it to clipboard
- Visual hover effects with "Click to copy" tooltips
- Disabled text selection prevents accidental highlighting
- Unified status bar feedback for all copy operations

### **Enhanced Card Layouts**
- **Single cards**: Copy Matrix button positioned in header
- **Batch grids**: Unified header with centered title/hash, button on right
- **Modal cards**: Reuse exact single card layout and styling
- **Visual cohesion**: Header and grid appear as seamless joined elements

### **Improved User Experience**
- Fixed scroll positioning to properly account for navbar height
- Auto-close modals when switching between single/batch modes
- Eliminated duplicate status messages (blue popups removed)
- Graceful error handling for empty inputs during auto-generation

## �🏗️ Project Structure

```
docs/web/
├── src/                    # 🎯 Vite source directory
│   ├── index.html         # Main HTML (Vite entry point)
│   ├── main.js           # Vite entry point (CSS imports)
│   ├── spa-styles.css    # SPA-specific styles & UI components
│   └── styles/
│       └── main.css      # Main stylesheet
├── public/               # 📦 Static assets served by Vite
│   ├── app.js           # Main application logic
│   ├── crypto.js        # Cryptographic functions  
│   ├── generator.js     # Generator functionality
│   └── router.js        # SPA routing implementation
├── package.json          # Dependencies & scripts
├── vite.config.js        # Development configuration
├── vite.config.prod.js   # Production configuration  
├── .gitignore           # Git ignore rules
├── README.md            # Project documentation
└── ARCHITECTURE.md      # Architecture guide
```

## 🚀 Quick Start

### Development
```bash
npm install
npm run dev
```
Starts development server at `http://localhost:3000`

### Production Build
```bash
npm run build
```
Creates optimized single-file build in `dist/`

### Preview Production Build
```bash
npm run preview
```

## 📦 Available Scripts

- `npm run dev` - Start development server with hot reload
- `npm run build` - Create production build (single-file)
- `npm run build:dev` - Create development build (with sourcemaps)
- `npm run preview` - Preview production build locally
- `npm run clean` - Remove build artifacts
- `npm run release` - Clean build for production release

📋 **See [DEV_PROCESS.md](DEV_PROCESS.md) for complete development workflow**

- **[OFFLINE_SETUP.md](OFFLINE_SETUP.md)**: Complete guide for offline operation ✅ **COMPLETE**
- **[ACCESSIBILITY_AUDIT.md](ACCESSIBILITY_AUDIT.md)**: Detailed accessibility compliance report ✅ **WCAG 2.1 AA**
- **[../design.md](../design.md)**: Technical design and cryptographic specifications

## ✅ Fully Offline Ready

The web interface is now **completely self-contained** with no external dependencies:
- **System Fonts**: Uses browser's default font stack (no Google Fonts)
- **Unicode Icons**: Native symbols replace Font Awesome icons
- **Local Assets**: All CSS, JS, and resources included
- **Network Independent**: Works with internet completely disabled

Save the page locally for air-gapped operation - no additional setup required!

## 🏗️ Architecture

### Frontend Stack
- **Pure HTML/CSS/JavaScript** - No frameworks for maximum compatibility and auditability
- **Web Crypto API** - Native browser cryptography for PBKDF2, HMAC-SHA512
- **Client-Side Only** - All processing happens in the browser, no server communication
- **Offline Capable** - Save the page locally for air-gapped operation

### Core Features

#### 🔐 Seed Sources
- **Simple Phrases** - Argon2id by default (memory-hard), SHA-512 fallback
- **BIP-39 Mnemonics** - Standard cryptocurrency seed phrases with PBKDF2
- **SLIP-39 Shares** - Shamir's Secret Sharing reconstruction

#### ⚙️ Configuration Options
- **KDF Selection** - Choose Argon2id (recommended) or SHA-512 (legacy)
- **Memory Setting** - 64MB to 2GB for Argon2 (higher = more secure, slower)
- **Iterations** - 1-10 time cost parameter for Argon2
- **Parallelism** - 1-8 lanes for multi-threaded Argon2
- **Base System** - Base10 (PIN), Base62 (alphanumeric), Base90 (full)
- **Nonce Field** - Auto-generated or manual for unique derivation

#### 🎯 Generation Modes
- **Single Card** - Generate one password matrix
- **Card Lookup** - Generate specific card by ID (ABC.##.##)
- **Batch Generation** - Create up to 100 unique cards from one seed

#### 🔍 Password Management
- **Coordinate-Based Selection** - A0, B1, C2 style patterns
- **Pattern Examples** - Diagonal, row, column, scattered patterns
- **Memorized Components** - Pronounceable words for enhanced security
- **Export Options** - Copy, print, download matrices

## 🚀 Local Development

### Quick Start
```bash
# Clone the repository
git clone https://github.com/JakeHertenstein/bastion.git
cd bastion/packages/seeder/docs/web

# Serve locally (any HTTP server)
python -m http.server 8000
# or
npx serve .
# or
php -S localhost:8000

# Open browser
open http://localhost:8000
```

### File Structure
```
docs/web/
├── index.html          # Landing page with navigation
├── generator.html      # Main generator interface
├── styles.css          # Complete styling (offline-ready)
├── app.js              # Main application logic
└── README.md           # This file
```

### Navigation Features
- **Consistent Navbar**: Standardized navigation between index and generator pages
- **Smart Linking**: Site title always links appropriately (home/top)
- **Section Navigation**: Easy movement between generator sections
- **Accessibility**: Full keyboard navigation and screen reader support

## 🔒 Security Model

### Client-Side Processing
- **No Server Communication** - All cryptography happens locally
- **No Data Storage** - Nothing persists beyond the session
- **Auditable Code** - All source code visible and verifiable
- **Offline Operation** - Download page for air-gapped security

### Cryptographic Implementation
- **Argon2id KDF** - Memory-hard derivation (64MB-2GB configurable)
- **PBKDF2-HMAC-SHA512** - Standard key derivation for BIP-39 (2048+ iterations)
- **Deterministic Generation** - Same seed + nonce always produces identical output
- **Rejection Sampling** - Unbiased mapping to Base10/62/90 alphabets
- **Entropy Analysis** - ~13-26 bits per token depending on base system

### Threat Model
- **Rate-Limited Online Attacks** - Designed for services with lockout protection
- **2FA Required** - Always use multi-factor authentication for critical accounts
- **Not Offline-Resistant** - Insufficient entropy for unlimited brute force

## 📱 Usage Patterns

### Individual Password Management
1. Generate single card with memorable seed phrase
2. Use coordinate patterns for different services
3. Memorize patterns like "Banking: A0-B1-C2, Email: D3-E4-F5"

### Organizational Deployment
1. Generate 100 cards from organization seed
2. Distribute card IDs to users (SYS.01.02, WEB.03.15, etc.)
3. Users reconstruct matrices using organization seed + their card ID

### Air-Gapped Operation
1. Download complete website locally
2. Disconnect from internet
3. Generate cards on isolated system
4. Print or transcribe results

## 🛠️ Development Guidelines

### Code Organization
- **Modular Design** - Separate crypto, UI, and utility functions
- **No Dependencies** - Pure JavaScript for maximum auditability
- **Progressive Enhancement** - Works with JavaScript disabled (basic functionality)
- **Responsive Design** - Mobile-friendly interface

### Cryptographic Consistency
- **Python Compatibility** - Matches reference implementation exactly
- **Test Vectors** - Same seeds produce identical output across platforms
- **Standard Algorithms** - Uses well-established cryptographic primitives

### Security Reviews
- **Code Auditing** - All cryptographic code should be reviewed
- **Test Coverage** - Comprehensive testing of edge cases
- **Browser Compatibility** - Works across modern browsers
- **Performance Testing** - Batch generation performance validation

## 🔧 Deployment

### GitHub Pages Setup
1. Enable GitHub Pages in repository settings
2. Set source to `main` branch `/docs` folder
3. Custom domain optional: `seed-card.example.com`

### CDN Distribution
- Host on multiple CDNs for redundancy
- Include integrity hashes for security
- Provide downloadable archives for offline use

### Docker Container (Optional)
```dockerfile
FROM nginx:alpine
COPY docs/web/ /usr/share/nginx/html/
EXPOSE 80
```

## 📊 Analytics & Monitoring

### Privacy-Preserving Analytics
- **No Personal Data** - Only aggregate usage patterns
- **No Seed Material** - Never log cryptographic inputs
- **Client-Side Metrics** - Basic feature usage tracking

### Performance Monitoring
- **Generation Times** - Track crypto operation performance
- **Error Rates** - Monitor client-side errors
- **Browser Compatibility** - Track supported browser usage

## 🤝 Contributing

### Feature Additions
1. Maintain cryptographic compatibility with Python implementation
2. Add comprehensive tests for new features
3. Update documentation and examples
4. Consider security implications

### Security Improvements
1. Follow responsible disclosure for vulnerabilities
2. Provide detailed security analysis for changes
3. Maintain audit trail for cryptographic modifications

### UI/UX Enhancements
1. Preserve accessibility standards
2. Maintain mobile responsiveness
3. Keep interface intuitive and clear
4. Add comprehensive help documentation

## ♿ Accessibility Features

### ✅ WCAG 2.1 AA Compliance
The web interface meets **WCAG 2.1 AA accessibility standards** with comprehensive support for:

### Keyboard Navigation
- **Tab Order**: Logical flow through all interactive elements
- **Focus Management**: Clear visual focus indicators (2px blue outlines)
- **Skip Links**: Direct navigation to main content sections
- **Enter/Space**: All buttons respond to both Enter and Space keys
- **Section Navigation**: Smooth scrolling with proper navbar offset

### Screen Reader Support
- **Semantic HTML**: Proper heading hierarchy (h1 → h2 → h3) and landmarks
- **ARIA Labels**: Descriptive labels for all form controls and buttons
- **Live Regions**: Status updates announced for generation completion
- **Form Labels**: All inputs properly associated with descriptive labels
- **Role Attributes**: Proper navigation and menu semantics

### Visual Accessibility
- **High Contrast**: Color combinations exceed WCAG AA standards
- **Focus Indicators**: Visible 2px blue outlines for all interactive elements
- **Scalable Text**: Responsive font sizes work with browser zoom up to 200%
- **Color Independence**: Information not conveyed by color alone
- **System Fonts**: Respects user's preferred fonts and accessibility settings

### Motor Accessibility
- **Large Targets**: Buttons minimum 44px for touch accessibility
- **Adequate Spacing**: Proper spacing between interactive elements
- **No Time Limits**: Users can take as long as needed for operations
- **Error Prevention**: Real-time validation prevents invalid inputs

### Cognitive Accessibility
- **Clear Instructions**: Step-by-step guidance through the process
- **Progress Indication**: Clear section navigation shows current location
- **Error Recovery**: Clear error messages with guidance for fixes
- **Consistent Layout**: Predictable interface structure throughout
- **Intuitive Navigation**: Standardized navbar behavior across pages

### Browser Compatibility
- **Modern Browsers**: Chrome 70+, Firefox 65+, Safari 12+, Edge 79+
- **Mobile Support**: Responsive design for iOS and Android browsers
- **Assistive Technology**: Compatible with NVDA, JAWS, VoiceOver
- **Offline Operation**: Works in all browsers without network connectivity

### Accessibility Testing Results
✅ **Comprehensive testing completed with**:
- **Keyboard Only**: Full functionality without mouse
- **Screen Readers**: NVDA (Windows), VoiceOver (macOS/iOS)
- **Browser Zoom**: 200% zoom without horizontal scroll
- **Color Blindness**: Tested with color vision simulators
- **Focus Management**: Proper focus flow and visual indicators

### Future Improvements
- **Dark Mode**: High contrast dark theme option
- **Font Size Controls**: User-adjustable text sizing  
- **Reduced Motion**: Respect prefers-reduced-motion settings
- **Voice Navigation**: Enhanced support for voice control software

## 🛠️ Development Guidelines

### Code Organization
- **Modular Design**: Separate crypto, UI, and utility functions
- **No Dependencies**: Pure JavaScript for maximum auditability
- **Progressive Enhancement**: Works with JavaScript disabled (basic functionality)
- **Responsive Design**: Mobile-friendly interface
- **Offline First**: No external dependencies required

### Cryptographic Consistency
- **Python Compatibility**: Matches reference implementation exactly
- **Test Vectors**: Same seeds produce identical output across platforms
- **Standard Algorithms**: Uses well-established cryptographic primitives
- **Deterministic Output**: Consistent results across browsers and platforms

### UI/UX Standards
- **Accessibility First**: WCAG 2.1 AA compliance maintained
- **Consistent Navigation**: Standardized navbar behavior
- **Progressive Enhancement**: Core functionality works without JavaScript
- **Mobile Responsive**: Touch-friendly interface on all devices
- **Offline Operation**: Self-contained with no network dependencies

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](../../LICENSE) file for details.

## ⚠️ Security Notice

This tool generates passwords for online services with rate limiting protection. It provides ~41-45 bits of entropy, which is sufficient for services that lock out after multiple failed attempts. For maximum security:

- **Always use 2FA** for critical accounts
- **Use different patterns** for different service categories
- **Consider password managers** for very high-security requirements
- **Audit the code** before using in production environments

The web interface is designed for convenience and accessibility, but for maximum security, use the offline Python implementation on an air-gapped system.
