/**
 * Safari-Safe Argon2 Web Worker
 * 
 * Directly uses dist/argon2.js (Emscripten Module) with custom WebAssembly.Memory
 * to avoid the 2GB memory allocation that crashes Safari.
 * 
 * This bypasses lib/argon2.js because its hooks don't give us enough control
 * over memory allocation timing.
 */

// Local vendor path for offline operation (no CDN dependency)
const VENDOR_BASE = './vendor/argon2';
const WASM_URL = VENDOR_BASE + '/argon2.wasm';
const JS_URL = VENDOR_BASE + '/argon2.js';

// Safari-safe memory limits (in WebAssembly pages, 64KB each)
// These are defaults; can be overridden via init params
let SAFE_MEMORY_PAGES = 3328;  // 208MB max (default)
const INITIAL_PAGES = 256;       // 16MB initial

// Maximum safe pages for Safari (208MB is conservative for parallel workers)
const MAX_SAFE_PAGES = 3328;

// Argon2 type constants
const ArgonType = {
    Argon2d: 0,
    Argon2i: 1,
    Argon2id: 2
};

let moduleReady = false;
let modulePromise = null;

/**
 * Initialize the Emscripten Module with Safari-safe memory
 */
async function initModule() {
    if (modulePromise) return modulePromise;
    
    modulePromise = (async () => {
        
        // Create Safari-safe WebAssembly.Memory FIRST
        const wasmMemory = new WebAssembly.Memory({
            initial: INITIAL_PAGES,
            maximum: SAFE_MEMORY_PAGES
        });
        
        // Fetch the WASM binary
        const wasmResponse = await fetch(WASM_URL);
        if (!wasmResponse.ok) {
            throw new Error(`Failed to fetch WASM: ${wasmResponse.status}`);
        }
        const wasmBinary = new Uint8Array(await wasmResponse.arrayBuffer());
        
        // Set up Module configuration BEFORE loading the JS
        // This is the key - we configure Module before Emscripten runs
        await new Promise((resolve, reject) => {
            self.Module = {
                wasmBinary: wasmBinary,
                wasmMemory: wasmMemory,
                locateFile: (path) => {
                    if (path.endsWith('.wasm')) return WASM_URL;
                    return CDN_BASE + '/dist/' + path;
                },
                onRuntimeInitialized: () => {
                },
                postRun: [() => {
                    moduleReady = true;
                    resolve();
                }],
                onAbort: (what) => {
                    console.error('[Worker] Module aborted:', what);
                    reject(new Error('Module aborted: ' + what));
                }
            };
            
            // Load the Emscripten JS - it will use our pre-configured Module
            try {
                importScripts(JS_URL);
            } catch (e) {
                console.error('[Worker] Failed to load dist/argon2.js:', e);
                reject(e);
            }
        });
        
        // Verify the Module has the required functions
        if (typeof Module._argon2_hash !== 'function') {
            throw new Error('Module._argon2_hash not available');
        }
        
        return true;
    })();
    
    return modulePromise;
}

/**
 * Allocate a UTF-8 string in WASM memory
 */
function allocateString(str) {
    const encoder = new TextEncoder();
    const bytes = encoder.encode(str);
    const ptr = Module._malloc(bytes.length + 1);
    Module.HEAPU8.set(bytes, ptr);
    Module.HEAPU8[ptr + bytes.length] = 0; // null terminator
    return { ptr, length: bytes.length };
}

/**
 * Allocate bytes in WASM memory
 */
function allocateBytes(data) {
    const bytes = data instanceof Uint8Array ? data : new TextEncoder().encode(data);
    const ptr = Module._malloc(bytes.length);
    Module.HEAPU8.set(bytes, ptr);
    return { ptr, length: bytes.length };
}

/**
 * Compute Argon2 hash using the low-level Module API
 */
async function computeHash(pass, salt, time, mem, hashLen, parallelism, type) {
    if (!moduleReady) {
        await initModule();
    }
    
    // Convert inputs to bytes if needed
    const passBytes = pass instanceof Uint8Array ? pass : new TextEncoder().encode(pass);
    const saltBytes = salt instanceof Uint8Array ? salt : new TextEncoder().encode(salt);
    
    // Allocate memory for inputs
    const passAlloc = allocateBytes(passBytes);
    const saltAlloc = allocateBytes(saltBytes);
    const hashPtr = Module._malloc(hashLen);
    const encodedPtr = Module._malloc(512); // Buffer for encoded string
    
    try {
        // Call _argon2_hash
        // int argon2_hash(uint32_t t_cost, uint32_t m_cost, uint32_t parallelism,
        //                 const void *pwd, size_t pwdlen,
        //                 const void *salt, size_t saltlen,
        //                 void *hash, size_t hashlen,
        //                 char *encoded, size_t encodedlen,
        //                 argon2_type type, uint32_t version)
        const result = Module._argon2_hash(
            time,           // t_cost (iterations)
            mem,            // m_cost (memory in KB)
            parallelism,    // parallelism
            passAlloc.ptr,  // password pointer
            passAlloc.length, // password length
            saltAlloc.ptr,  // salt pointer
            saltAlloc.length, // salt length
            hashPtr,        // hash output pointer
            hashLen,        // hash length
            encodedPtr,     // encoded output pointer
            512,            // encoded buffer length
            type,           // argon2 type (0=d, 1=i, 2=id)
            0x13            // version (0x13 = 1.3)
        );
        
        if (result !== 0) {
            // Get error message
            const errorMsg = Module.UTF8ToString(Module._argon2_error_message(result));
            throw new Error(`Argon2 error ${result}: ${errorMsg}`);
        }
        
        // Read the hash output
        const hash = new Uint8Array(hashLen);
        hash.set(Module.HEAPU8.subarray(hashPtr, hashPtr + hashLen));
        
        // Read the encoded string
        const encoded = Module.UTF8ToString(encodedPtr);
        
        // Convert hash to hex
        const hashHex = Array.from(hash).map(b => b.toString(16).padStart(2, '0')).join('');
        
        return { hash, hashHex, encoded };
        
    } finally {
        // Free allocated memory
        Module._free(passAlloc.ptr);
        Module._free(saltAlloc.ptr);
        Module._free(hashPtr);
        Module._free(encodedPtr);
    }
}

/**
 * Handle messages from the main thread
 */
self.onmessage = async function(e) {
    const { id, type, params } = e.data;
    
    try {
        if (type === 'init') {
            // Allow init params to specify memory limit
            if (params && params.memoryMb) {
                // Calculate pages needed: memoryMb * 1024KB / 64KB per page
                // Add some headroom for Argon2's internal allocations
                const requestedPages = Math.ceil((params.memoryMb * 1024) / 64) + 256;
                SAFE_MEMORY_PAGES = Math.min(requestedPages, MAX_SAFE_PAGES);
            }
            await initModule();
            self.postMessage({ id, type: 'ready', argon2Loaded: true });
            return;
        }
        
        if (type === 'hash') {
            
            // Support both naming conventions
            const pass = params.pass || params.phrase;
            const salt = params.salt;
            const time = params.time || params.timeCost || 3;
            const mem = params.mem || (params.memoryMb ? params.memoryMb * 1024 : 65536);
            const hashLen = params.hashLen || params.hashLength || 64;
            const parallelism = params.parallelism || 1;
            const argonType = params.argonType ?? params.type ?? ArgonType.Argon2id;
            
            
            const result = await computeHash(pass, salt, time, mem, hashLen, parallelism, argonType);
            
            self.postMessage({
                id,
                type: 'result',
                result: {
                    hash: result.hash,
                    hashHex: result.hashHex,
                    encoded: result.encoded
                }
            });
        }
    } catch (error) {
        console.error('[Worker] Error:', error);
        self.postMessage({
            id,
            type: 'error',
            error: error.message || String(error)
        });
    }
};

// Signal that worker script has loaded and send pending message
self.postMessage({ type: 'pending' });
