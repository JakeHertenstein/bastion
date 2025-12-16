/**
 * Safari-Compatible Argon2 WASM Loader
 * 
 * The bundled version of argon2-browser (argon2-bundled.min.js) fails on Safari 
 * because it allocates WebAssembly.Memory with maximum ~2GB (32,767 pages), 
 * which Safari/WebKit rejects.
 * 
 * This loader uses lib/argon2.js (the high-level wrapper) with custom hooks
 * to inject Safari-safe memory limits.
 * 
 * Key insight: lib/argon2.js provides these hooks:
 * - global.loadArgon2WasmBinary: Return Promise<ArrayBuffer> of WASM binary
 * - global.loadArgon2WasmModule: Return Promise<Module> with custom memory
 */

(function(global) {
    'use strict';
    
    // Local vendor path for offline operation (no CDN dependency)
    // Use absolute paths to work correctly with SPA routing
    const VENDOR_BASE = '/vendor/argon2';
    const DIST_URL = VENDOR_BASE + '/argon2.js';
    const WASM_URL = VENDOR_BASE + '/argon2.wasm';
    const LIB_URL = VENDOR_BASE + '/argon2-lib.js';
    
    // WASM page size is 64KB
    const WASM_PAGE_SIZE = 64 * 1024;
    const KB = 1024;
    const MB = 1024 * KB;
    
    // Safari-safe memory limits
    // Safari desktop: ~512MB max, iOS: ~256MB max
    // We use conservative limits to work across all WebKit browsers
    const SAFARI_SAFE_MAX_PAGES = 8192;   // 512MB maximum
    const IOS_SAFE_MAX_PAGES = 4096;      // 256MB maximum for iOS
    const INITIAL_PAGES = 256;            // 16MB initial
    
    // State
    let wasmBinary = null;
    let initPromise = null;
    let argon2Ready = false;
    
    /**
     * Detect if running in Safari/WebKit
     */
    function isSafari() {
        const ua = navigator.userAgent.toLowerCase();
        return ua.includes('safari') && !ua.includes('chrome') && !ua.includes('android');
    }
    
    /**
     * Detect if running on iOS (any browser on iOS uses WebKit)
     */
    function isIOS() {
        return /iPad|iPhone|iPod/.test(navigator.userAgent) ||
               (navigator.platform === 'MacIntel' && navigator.maxTouchPoints > 1);
    }
    
    /**
     * Get safe maximum pages for current browser
     */
    function getSafeMaxPages() {
        if (isIOS()) return IOS_SAFE_MAX_PAGES;    // 256MB for iOS
        if (isSafari()) return SAFARI_SAFE_MAX_PAGES; // 512MB for Safari desktop
        return 16384; // 1GB for Chrome/Firefox
    }
    
    /**
     * Fetch the WASM binary
     */
    async function fetchWasmBinary() {
        if (wasmBinary) return wasmBinary;
        
        const response = await fetch(WASM_URL);
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        wasmBinary = await response.arrayBuffer();
        return wasmBinary;
    }
    
    /**
     * Load the Argon2 wrapper script that provides argon2.hash()
     */
    function loadScript(url) {
        return new Promise((resolve, reject) => {
            const script = document.createElement('script');
            script.src = url;
            script.onload = () => resolve();
            script.onerror = (e) => reject(new Error(`Failed to load ${url}`));
            document.head.appendChild(script);
        });
    }
    
    /**
     * Initialize Argon2 with Safari-safe memory handling
     */
    async function initArgon2() {
        if (initPromise) return initPromise;
        
        initPromise = (async () => {
            
            // Pre-fetch WASM binary
            const binary = await fetchWasmBinary();
            
            // Calculate memory pages (208MB for Safari, more for others)
            const maxPages = getSafeMaxPages();
            
            // Set up hooks BEFORE loading lib/argon2.js
            // Hook 1: Provide the WASM binary
            global.loadArgon2WasmBinary = function() {
                return Promise.resolve(binary);
            };
            
            // Hook 2: Load the WASM module with custom memory
            global.loadArgon2WasmModule = function() {
                return new Promise((resolve, reject) => {
                    // Create Safari-safe WebAssembly.Memory
                    const wasmMemory = new WebAssembly.Memory({
                        initial: INITIAL_PAGES,
                        maximum: maxPages
                    });
                    
                    // Configure Module before loading dist/argon2.js
                    global.Module = {
                        wasmMemory: wasmMemory,
                        wasmBinary: binary,
                        locateFile: function(path) {
                            if (path.endsWith('.wasm')) {
                                return WASM_URL;
                            }
                            return CDN_BASE + '/dist/' + path;
                        },
                        onRuntimeInitialized: function() {
                        },
                        postRun: [function() {
                            resolve(global.Module);
                        }],
                        onAbort: function(what) {
                            console.error(`❌ Module aborted:`, what);
                            reject(new Error('Argon2 module aborted: ' + what));
                        }
                    };
                    
                    // Load the Emscripten runtime (dist/argon2.js)
                    const script = document.createElement('script');
                    script.src = DIST_URL;
                    script.onerror = function() {
                        reject(new Error('Failed to load Emscripten runtime'));
                    };
                    document.head.appendChild(script);
                });
            };
            
            // Now load the high-level wrapper (lib/argon2.js)
            // This wrapper will use our hooks to get WASM binary and Module
            await loadScript(LIB_URL);
            
            // Verify the wrapper loaded successfully
            if (typeof global.argon2 === 'undefined') {
                throw new Error('argon2 object not available after loading wrapper');
            }
            
            if (typeof global.argon2.hash !== 'function') {
                throw new Error('argon2.hash is not a function');
            }
            
            argon2Ready = true;
            return true;
        })();
        
        return initPromise;
    }
    
    /**
     * High-level hash function - ensures init then delegates to argon2.hash
     */
    async function hash(params) {
        if (!argon2Ready) {
            await initArgon2();
        }
        return global.argon2.hash(params);
    }
    
    // Create safe argon2 interface
    const safeArgon2 = {
        ArgonType: {
            Argon2d: 0,
            Argon2i: 1,
            Argon2id: 2
        },
        hash: hash,
        init: initArgon2,
        isSafari: isSafari,
        isIOS: isIOS
    };
    
    // Expose globally
    global.argon2Safe = safeArgon2;
    
    // Auto-initialize on load (non-blocking)
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', function() {
            initArgon2().catch(function(e) {
                console.error('❌ Argon2 auto-init failed:', e);
            });
        });
    } else {
        // DOM already loaded
        initArgon2().catch(function(e) {
            console.error('❌ Argon2 auto-init failed:', e);
        });
    }
    
})(typeof window !== 'undefined' ? window : typeof self !== 'undefined' ? self : this);
