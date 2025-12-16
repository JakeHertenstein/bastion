# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### ⚠️ BREAKING CHANGES
- **HKDF-Expand Migration**: Token stream generation now uses standard RFC 5869 HKDF-Expand
  - Previous: Custom counter-mode HMAC (`HMAC(seed, info || counter_2byte)`)
  - New: Standard HKDF-Expand with chained blocks (`T(i) = HMAC(PRK, T(i-1) || info || i)`)
  - **All existing seed/nonce combinations will produce different tokens**
  - Recommendation: Regenerate cards after upgrade if you have existing cards
  - Rationale: Standard algorithm improves audit transparency and defense-in-depth

### Security
- **Offline-Only Web App**: Vendored all external dependencies for air-gapped operation
  - Argon2 WASM library now served from local `vendor/argon2/` directory
  - Removed all CDN references (`cdn.jsdelivr.net`)
  - Production builds include all dependencies - no network required after download
  - Files vendored: `argon2-bundled.min.js`, `argon2.wasm`, `argon2.js`, `argon2-lib.js` (~97KB total)
- **PWA Support**: Installable Progressive Web App for desktop and mobile
  - Cache-on-install service worker for complete offline operation after first visit
  - Web App Manifest with standalone display mode and theme colors
  - Apple device support (touch icons, web app meta tags)
  - No cookies or persistent storage - only uses Cache API for app shell
  - Safari-compatible (tested on macOS Safari)

### Added
- **HKDF Test Vectors**: Comprehensive test suite for cross-platform HKDF verification
  - `tests/test_hkdf.py` with 18 tests for RFC 5869 compliance
  - `tests/generate_hkdf_vectors.py` to generate JavaScript verification data
  - Chaining verification tests to ensure proper block linking
- **Security Analysis Document**: Comprehensive cryptographic review (`docs/SECURITY_ANALYSIS.md`)
  - Threat model with attack cost analysis
  - Entropy calculations for various password patterns
  - Implementation security review and recommendations
- **Argon2id KDF Support**: Memory-hard key derivation function resistant to GPU/ASIC attacks
  - Configurable memory (64MB-2GB), iterations (1-10), and parallelism (1-8) via web UI
  - Safari-compatible WASM loader with conservative 208MB memory limit per worker
  - Web Worker pool for parallel multi-core card generation (up to 4 workers on Safari)
  - Graceful fallback to SHA-512 when Argon2 unavailable or memory insufficient
- **Multi-Base Token Systems**: Support for Base10, Base62, and Base90 alphabets
  - Base10: 4-digit PIN codes (~13.3 bits/token) for numeric-only requirements
  - Base62: Alphanumeric tokens (~23.8 bits/token) for balanced security/usability
  - Base90: Full special character set (~26.0 bits/token) for maximum entropy
  - CLI `--base` flag and web UI selector for choosing token alphabet
- **Nonce-Based Derivation**: Auto-generated 48-bit nonces for unique card batches
  - URL-safe Base64 encoding (A-Za-z0-9-_) for label compatibility
  - Ensures different token grids even with identical seed + date + card ID
  - Regenerate button in web UI for new nonce generation
- **Label Format v1**: Complete derivation label for full reproducibility
  - Format: `v1|SEED_TYPE|KDF|KDF_PARAMS|BASE|DATE|NONCE|CARD_ID|CARD_INDEX`
  - Encodes all parameters needed to recreate identical token grid
  - Compact Argon2 params: `t3m1024p4` (3 iterations, 1024MB, 4 parallelism)
- **Batch Generation Progress UI**: Visual progress overlay with real-time status
  - Card button states: grey (pending), amber pulse (generating), green (complete)
  - Cancellable batch operations with progress percentage
  - Persistent state tracking survives card selection changes

### Changed
- **Coordinate System**: Switched from row-first (A0=row A, col 0) to spreadsheet convention
  - Now: letter=column (A-J), number=row (0-9) matching Excel/Google Sheets
  - A0=top-left, J0=top-right, A9=bottom-left, J9=bottom-right
- **KDF Label**: Changed from "ARGON2" to "ARGON2ID" for precision
  - Reflects actual algorithm variant (Argon2id = hybrid of Argon2i and Argon2d)
- **Settings Change Triggers**: Memory, iterations, and parallelism changes now regenerate cards
  - Automatically cancels in-progress generation and reinitializes worker pool
  - Provides visual feedback during reconfiguration
- **CSS Architecture**: Removed duplicate CSS files from `public/` folder
  - Source of truth is now exclusively `src/spa-styles.css` and `src/styles/main.css`
  - Vite serves CSS correctly without publicDir conflicts

### Fixed
- **Safari Web Workers**: Argon2 WASM now works in Safari with custom memory limits
  - Bypasses argon2-browser's 2GB allocation that crashes WebKit
  - Pre-configures `self.Module` with 208MB `WebAssembly.Memory` before loading
  - Tested on Safari 17+ desktop and iOS Safari
- **Card Button State Race Condition**: Persistent `cardGenerationStates` Map
  - DOM-based state tracking was unreliable during rapid parallel completions
  - Map tracks state by card index, survives selection changes and re-renders
- **Nonce Regeneration Trigger**: Fixed nonce input not dispatching change event
  - Added `dispatchEvent(new Event('input'))` after programmatic value change
- **Selected Card CSS Specificity**: `.token-index-btn.selected` no longer overrides generation states
  - Removed background color from `.selected`, now only adds outline styling
  - Green complete state properly shows on selected cards

### Removed
- **Debug Console Logs**: Cleaned up ~150+ debug console.log statements from web files
  - Removed emoji-prefixed debug logs (🔑, 📍, 🔧, etc.) from app.js, crypto.js
  - Removed worker lifecycle logs from argon2-worker-safe.js, argon2-loader.js
  - Kept only console.error for actual error conditions

### Technical
- **Modal System**: Fixed non-functional help modal buttons throughout the application
  - Token entropy help button (?) now properly displays entropy calculation details
  - Card compromise modal now shows correctly with proper overlay
  - Keyboard shortcuts modal (? key and navigation help button) now displays properly
  - All modals now have consistent styling, backdrop behavior, and close functionality
- **Keyboard Shortcuts Modal**: Comprehensive modal showing all available keyboard shortcuts
  - Accessible via ? key, F1 key, or navigation help button
  - Shows categorized shortcuts for Actions, Editing, Seed Modes, Navigation, and Security
- **Modal Architecture**: Improved modal initialization and event handling
  - Centralized modal setup in `initializeModals()` method
  - Consistent use of `.modal.show` CSS classes for visibility
  - Proper body overflow management to prevent background scrolling
  - Enhanced accessibility with focus management and keyboard navigation
