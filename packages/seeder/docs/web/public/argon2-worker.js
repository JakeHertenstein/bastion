/**
 * Argon2 Web Worker
 * Offloads Argon2 computation to background thread for UI responsiveness
 * 
 * Used by Argon2WorkerPool for TRUE parallel computation:
 * Each worker instance runs Argon2 independently, allowing
 * multi-core utilization when processing batches.
 */

// Track if argon2 library loaded successfully
let argon2Loaded = false;
let loadError = null;

// Import argon2-browser library with error handling (local vendor for offline operation)
try {
    importScripts('./vendor/argon2/argon2-bundled.min.js');
    argon2Loaded = typeof argon2 !== 'undefined';
    if (!argon2Loaded) {
        loadError = 'argon2 object not defined after import';
    }
} catch (e) {
    loadError = e.message;
    console.error('Failed to load argon2-browser in worker:', e);
}

// Send ready signal immediately after loading
self.postMessage({ 
    type: 'ready', 
    argon2Loaded, 
    loadError 
});

/**
 * Handle messages from main thread
 */
self.onmessage = async function(event) {
    const { id, type, params } = event.data;
    
    // Check if argon2 is available
    if (!argon2Loaded && type !== 'ping' && type !== 'status') {
        self.postMessage({ 
            id, 
            type: 'error', 
            error: `Argon2 library not loaded in worker: ${loadError || 'unknown error'}`
        });
        return;
    }
    
    try {
        switch (type) {
            case 'hash':
                const result = await computeArgon2(params);
                self.postMessage({ id, type: 'success', result });
                break;
                
            case 'test':
                const testResult = await testMemory(params.memoryMb);
                self.postMessage({ id, type: 'success', result: testResult });
                break;
                
            case 'ping':
                self.postMessage({ id, type: 'success', result: 'pong' });
                break;
                
            case 'status':
                self.postMessage({ 
                    id, 
                    type: 'success', 
                    result: { 
                        argon2Loaded, 
                        loadError,
                        ready: argon2Loaded 
                    }
                });
                break;
                
            default:
                throw new Error(`Unknown message type: ${type}`);
        }
    } catch (error) {
        self.postMessage({ 
            id, 
            type: 'error', 
            error: error.message || 'Unknown error in worker'
        });
    }
};

/**
 * Compute Argon2id hash
 * @param {Object} params - Argon2 parameters
 * @returns {Object} Hash result with timing info
 */
async function computeArgon2(params) {
    const { 
        phrase, 
        salt, 
        timeCost = 3, 
        memoryMb = 512, 
        parallelism = 8,
        hashLength = 64 
    } = params;
    
    const encoder = new TextEncoder();
    const phraseBytes = encoder.encode(phrase);
    const saltBytes = encoder.encode(salt);
    const memoryKb = memoryMb * 1024;
    
    const startTime = performance.now();
    
    try {
        const result = await argon2.hash({
            pass: phraseBytes,
            salt: saltBytes,
            time: timeCost,
            mem: memoryKb,
            parallelism: parallelism,
            hashLen: hashLength,
            type: argon2.ArgonType.Argon2id
        });
        
        const elapsed = performance.now() - startTime;
        
        return {
            hash: Array.from(result.hash), // Convert Uint8Array to regular array for transfer
            elapsed: elapsed,
            params: { timeCost, memoryMb, parallelism }
        };
    } catch (error) {
        // Re-throw with more context
        throw new Error(`Argon2 ${memoryMb}MB: ${error.message}`);
    }
}

/**
 * Test if a specific memory size works
 * @param {number} memoryMb - Memory size in MB
 * @returns {Object} Test result
 */
async function testMemory(memoryMb) {
    const testPhrase = 'memory-test';
    const testSalt = 'test-salt-12345678';
    const memoryKb = memoryMb * 1024;
    
    const startTime = performance.now();
    
    try {
        await argon2.hash({
            pass: new TextEncoder().encode(testPhrase),
            salt: new TextEncoder().encode(testSalt),
            time: 1,
            mem: memoryKb,
            parallelism: 1,
            hashLen: 32,
            type: argon2.ArgonType.Argon2id
        });
        
        const elapsed = performance.now() - startTime;
        return { success: true, memoryMb, elapsed };
    } catch (error) {
        return { success: false, memoryMb, error: error.message };
    }
}

// Signal that worker is ready (with status)
self.postMessage({ 
    type: 'ready', 
    argon2Loaded,
    loadError 
});
