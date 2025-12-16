/**
 * Seed Card Cryptographic Functions
 * JavaScript implementation of the Python crypto module
 */

// Configuration constants
const CONFIG = {
    TOKENS_WIDE: 10,
    TOKENS_TALL: 10,
    CHARS_PER_TOKEN: 4,
    DEFAULT_PBKDF2_ITERATIONS: 2048,
    HMAC_LABEL_TOKENS: 'SEEDER-TOKENS',
    HMAC_LABEL_DIGEST: 'SEEDER-DIGEST',
    STREAM_BUFFER_SIZE: 4096,
    
    // Argon2 configuration (browser-safe defaults)
    ARGON2_TIME_COST: 3,
    ARGON2_MEMORY_COST_MB: 64, // 64MB default (browser-safe)
    ARGON2_PARALLELISM: 8, // Default 8 lanes
    ARGON2_HASH_LENGTH: 64,
    
    // Nonce configuration
    NONCE_BYTES: 6, // 48 bits = 8 Base64 characters
    LABEL_VERSION: 'v1',
    
    // Base90 alphabet (excludes problematic characters)
    ALPHABET: [
        ...'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
        ...'abcdefghijklmnopqrstuvwxyz',
        ...'0123456789',
        ...'!#$%&()*+,-./:;<=>?@[]^_{|}~'
    ]
};

// Memory test options (ordered from highest to lowest)
// Includes very low options (8MB) for severely constrained browsers
const MEMORY_OPTIONS = [2048, 1024, 512, 256, 128, 64, 32, 16, 8];

// Base system configurations
const BASE_CONFIGS = {
    base10: {
        alphabet: ['0','1','2','3','4','5','6','7','8','9'],
        name: "Base10 (Digits)",
        description: "PIN codes using digits 0-9"
    },
    base62: {
        alphabet: ['0','1','2','3','4','5','6','7','8','9',
                  'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z',
                  'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z'],
        name: "Base62 (Alphanumeric)",
        description: "Tokens using digits and letters (case-sensitive)"
    },
    base90: {
        alphabet: CONFIG.ALPHABET,
        name: "Base90 (Mixed)",
        description: "Full 90-character alphabet including special characters"
    }
};

/**
 * Memory testing utilities for Argon2
 * Tests browser's memory allocation capability
 */
class MemoryUtils {
    /**
     * Test if a specific memory size works with Argon2
     * @param {number} memoryMb - Memory size in MB to test
     * @returns {Promise<boolean>} True if test passed
     */
    static async testArgon2Memory(memoryMb) {
        // Check for Safari-safe loader first
        const hasSafeLoader = typeof argon2Safe !== 'undefined' && typeof argon2Safe.init === 'function';
        const hasArgon2 = typeof argon2 !== 'undefined' && typeof argon2.hash === 'function';
        
        // Try to initialize Safari-safe loader if bundled version isn't available
        if (!hasArgon2 && hasSafeLoader) {
            try {
                await argon2Safe.init(memoryMb * 1024);
            } catch (initError) {
                console.warn(`⚠️ Safari-safe Argon2 init failed:`, initError.message);
                return false;
            }
        }
        
        // Final check
        if (typeof argon2 === 'undefined' || typeof argon2.hash !== 'function') {
            console.warn('Argon2 library not available, skipping memory test');
            return false;
        }
        
        const testPhrase = 'memory-test';
        const testSalt = 'test-salt-12345678';
        const memoryKb = memoryMb * 1024;
        
        try {
            const startTime = performance.now();
            
            // Shorter timeout - if it takes this long on main thread, it's not practical
            // Safari especially struggles with main thread + workers competing
            const timeoutMs = 3000; // 3 seconds max
            const hashPromise = argon2.hash({
                pass: new TextEncoder().encode(testPhrase),
                salt: new TextEncoder().encode(testSalt),
                time: 1, // Minimum iterations for speed
                mem: memoryKb,
                parallelism: 1, // Single thread for test
                hashLen: 32, // Small output for speed
                type: argon2.ArgonType.Argon2id
            });
            
            const timeoutPromise = new Promise((_, reject) => 
                setTimeout(() => reject(new Error('Memory test timeout')), timeoutMs)
            );
            
            await Promise.race([hashPromise, timeoutPromise]);
            
            const elapsed = ((performance.now() - startTime) / 1000).toFixed(2);
            return true;
        } catch (error) {
            console.warn(`❌ ${memoryMb}MB test failed:`, error.message, error.name);
            return false;
        }
    }
    
    /**
     * Probe available memory by testing from highest to lowest
     * @returns {Promise<{maxMemory: number, tested: Object, argon2Broken: boolean}>} Max working memory, test results, and broken flag
     */
    static async probeMaxMemory() {
        const tested = {};
        let maxMemory = 0; // Start at 0, will be set if any test passes
        let anyTestPassed = false;
        
        
        // When Web Workers are available, skip main-thread memory probe entirely
        // The probe competes with workers for CPU/memory, causing timeouts
        // Workers handle their own memory allocation with configured limits
        const workersAvailable = typeof Worker !== 'undefined';
        
        // Detect browser type for logging
        const isSafari = /^((?!chrome|android).)*safari/i.test(navigator.userAgent);
        const isFirefox = /firefox/i.test(navigator.userAgent);
        const browserName = isSafari ? 'Safari' : isFirefox ? 'Firefox' : 'Chrome';
        
        if (workersAvailable) {
            // Workers handle memory allocation - default to a safe value for UI
            // Users can still select higher memory from dropdown if needed
            const defaultMemory = isSafari ? 64 : 512; // Safari is more constrained
            return { 
                maxMemory: defaultMemory, 
                tested: { [defaultMemory]: true }, 
                argon2Broken: false,
                skippedProbe: true
            };
        }
        
        // Fallback: No workers, must use main thread - run probe
        const startAt = MEMORY_OPTIONS[0]; // Start at highest (512MB)
        const testOptions = MEMORY_OPTIONS.filter(mb => mb <= startAt);
        
        // Test from highest to lowest, stop when one works
        for (const mb of testOptions) {
            const success = await this.testArgon2Memory(mb);
            tested[mb] = success;
            
            if (success) {
                maxMemory = mb;
                anyTestPassed = true;
                break; // Found the max, no need to test lower
            }
        }
        
        // If no test passed, Argon2 WASM is completely broken
        if (!anyTestPassed) {
            console.error('❌ Argon2 WASM is completely broken - ALL memory tests failed!');
            maxMemory = 0; // Signal that Argon2 is unusable
        }
        
        return { maxMemory, tested, argon2Broken: !anyTestPassed };
    }
    
    /**
     * Get recommended memory based on max available
     * @param {number} maxMemory - Maximum available memory in MB
     * @returns {number} Recommended memory setting
     */
    static getRecommendedMemory(maxMemory) {
        // Recommend one step below max for stability
        const idx = MEMORY_OPTIONS.indexOf(maxMemory);
        if (idx >= 0 && idx < MEMORY_OPTIONS.length - 1) {
            return MEMORY_OPTIONS[idx + 1]; // One level safer
        }
        return maxMemory; // Use max if it's already the minimum
    }
    
    /**
     * Detect number of logical CPU cores
     * @returns {number} Number of cores (defaults to 8 if detection fails)
     */
    static detectCPUCores() {
        // Use navigator.hardwareConcurrency if available
        if (typeof navigator !== 'undefined' && navigator.hardwareConcurrency) {
            const cores = navigator.hardwareConcurrency;
            return cores;
        }
        // Fallback to reasonable default
        return 8;
    }
    
    /**
     * Get recommended parallelism based on CPU cores.
     * Note: This is just a default - Argon2 parallelism (lanes) is a crypto
     * parameter that can exceed CPU cores. More lanes = more memory-hard,
     * but slower if lanes > cores (simulated in software).
     * @returns {number} Recommended parallelism (matches cores, capped at 16)
     */
    static getRecommendedParallelism() {
        const cores = this.detectCPUCores();
        // Use detected cores, but cap at 16 for reasonable default
        return Math.min(cores, 16);
    }
}

/**
 * Argon2 Web Worker Manager
 * Manages a pool of web workers for non-blocking Argon2 computation
 */
class Argon2Worker {
    static instance = null;
    static pendingRequests = new Map();
    static requestId = 0;
    static workerReady = false;
    static workerArgon2Loaded = false;
    static workerSupported = null;
    static workerFailed = false; // Track if worker has permanently failed
    
    /**
     * Check if Web Workers are supported
     * @returns {boolean} True if workers are available
     */
    static isSupported() {
        if (this.workerSupported === null) {
            this.workerSupported = typeof Worker !== 'undefined';
        }
        // Don't use worker if it has failed
        return this.workerSupported && !this.workerFailed;
    }
    
    /**
     * Get or create the worker instance
     * @returns {Worker|null} Worker instance or null if not supported
     */
    static getWorker() {
        if (!this.isSupported()) {
            return null;
        }
        
        if (!this.instance) {
            try {
                // Use absolute path for worker to avoid MIME type issues
                const workerUrl = new URL('/argon2-worker-safe.js', window.location.origin).href;
                this.instance = new Worker(workerUrl);
                this.instance.onmessage = this.handleMessage.bind(this);
                this.instance.onerror = this.handleError.bind(this);
            } catch (error) {
                console.warn('Failed to create Web Worker:', error.message);
                this.workerSupported = false;
                return null;
            }
        }
        
        return this.instance;
    }
    
    /**
     * Handle messages from worker
     */
    static handleMessage(event) {
        const { id, type, result, error, argon2Loaded, loadError } = event.data;
        
        // Handle pending signal - worker loaded and needs init
        if (type === 'pending') {
            const initId = ++this.requestId;
            this.pendingRequests.set(initId, {
                resolve: () => {
                    this.workerReady = true;
                    this.workerArgon2Loaded = true;
                },
                reject: (err) => {
                    console.warn('⚠️ Argon2 Web Worker init failed:', err.message);
                    this.workerFailed = true;
                }
            });
            // Send init with default memory (64MB is safe for single worker)
            this.instance.postMessage({ id: initId, type: 'init', params: { memoryMb: 64 } });
            return;
        }
        
        // Handle ready signal with status
        if (type === 'ready') {
            this.workerReady = true;
            this.workerArgon2Loaded = argon2Loaded !== false;
            if (!argon2Loaded) {
                console.warn('⚠️ Argon2 Web Worker ready but argon2 failed to load:', loadError);
                this.workerFailed = true; // Mark worker as unusable
            }
            return;
        }
        
        // Handle request responses
        if (id === undefined) {
            // Ignore messages without id (like initial pending signal)
            return;
        }
        const pending = this.pendingRequests.get(id);
        if (!pending) {
            console.warn('Received response for unknown request:', id);
            return;
        }
        
        this.pendingRequests.delete(id);
        
        if (type === 'error') {
            pending.reject(new Error(error));
        } else {
            pending.resolve(result);
        }
    }
    
    /**
     * Handle worker errors
     */
    static handleError(error) {
        console.error('Web Worker error:', error);
        
        // Reject all pending requests
        for (const [id, pending] of this.pendingRequests) {
            pending.reject(new Error('Worker error: ' + (error.message || 'unknown')));
        }
        this.pendingRequests.clear();
        
        // Mark worker as failed after repeated errors
        this.workerFailed = true;
        this.terminate();
        
        console.warn('⚠️ Web Worker disabled, using main thread fallback');
    }
    
    /**
     * Send a request to the worker
     * @param {string} type - Message type
     * @param {Object} params - Parameters
     * @returns {Promise} Promise resolving to result
     */
    static sendRequest(type, params) {
        return new Promise((resolve, reject) => {
            const worker = this.getWorker();
            
            if (!worker) {
                reject(new Error('Web Worker not available'));
                return;
            }
            
            const id = ++this.requestId;
            this.pendingRequests.set(id, { resolve, reject });
            
            worker.postMessage({ id, type, params });
        });
    }
    
    /**
     * Compute Argon2 hash using Web Worker
     * @param {string} phrase - Input phrase
     * @param {string} salt - Salt string
     * @param {number} timeCost - Time cost parameter
     * @param {number} memoryMb - Memory in MB
     * @param {number} parallelism - Parallelism lanes
     * @param {number} hashLength - Output hash length
     * @returns {Promise<Uint8Array>} Hash result
     */
    static async hash(phrase, salt, timeCost = 3, memoryMb = 512, parallelism = 8, hashLength = 64) {
        const result = await this.sendRequest('hash', {
            phrase,
            salt,
            timeCost,
            memoryMb,
            parallelism,
            hashLength
        });
        
        
        // Convert array back to Uint8Array
        return new Uint8Array(result.hash);
    }
    
    /**
     * Test memory allocation in worker
     * @param {number} memoryMb - Memory size to test
     * @returns {Promise<Object>} Test result
     */
    static async testMemory(memoryMb) {
        return this.sendRequest('test', { memoryMb });
    }
    
    /**
     * Check if worker is ready and functional
     * @returns {Promise<boolean>} True when ready and argon2 is loaded
     */
    static async waitForReady(timeout = 5000) {
        // Already failed, don't wait
        if (this.workerFailed) return false;
        
        // Already ready, check if argon2 loaded
        if (this.workerReady) {
            return this.workerArgon2Loaded;
        }
        
        const worker = this.getWorker();
        if (!worker) return false;
        
        return new Promise((resolve) => {
            const startTime = Date.now();
            const checkReady = () => {
                if (this.workerFailed) {
                    resolve(false);
                } else if (this.workerReady) {
                    resolve(this.workerArgon2Loaded);
                } else if (Date.now() - startTime > timeout) {
                    console.warn('Worker ready timeout');
                    resolve(false);
                } else {
                    setTimeout(checkReady, 50);
                }
            };
            checkReady();
        });
    }
    
    /**
     * Terminate the worker
     */
    static terminate() {
        if (this.instance) {
            this.instance.terminate();
            this.instance = null;
            this.workerReady = false;
            this.workerArgon2Loaded = false;
        }
    }
    
    /**
     * Reset worker state (allows retry after failure)
     */
    static reset() {
        this.terminate();
        this.workerFailed = false;
    }
}

/**
 * Parallel Argon2 Worker Pool
 * Spawns multiple Web Workers for true parallel Argon2 computation
 * Each worker runs a separate Argon2 hash, enabling multi-core utilization
 * 
 * Uses non-bundled argon2-browser with custom WebAssembly.Memory limits
 * to work across all browsers including Safari/iOS.
 */
class Argon2WorkerPool {
    static workers = [];
    static workerCount = 0;
    static pendingRequests = new Map();
    static requestId = 0;
    static initialized = false;
    static initPromise = null;
    static memoryMb = 64; // Memory setting for workers
    
    /**
     * Initialize the worker pool with specified number of workers
     * @param {number} count - Number of workers (defaults to CPU cores)
     * @param {number} memoryMb - Memory in MB for Argon2 (for worker initialization)
     * @returns {Promise<boolean>} True if pool initialized successfully
     */
    static async initialize(count = null, memoryMb = 64) {
        const memoryChanged = this.memoryMb !== memoryMb;
        
        
        // If memory setting changed, must reinitialize workers
        if (memoryChanged && this.initialized) {
            this.terminate();
        }
        
        this.memoryMb = memoryMb;
        
        // If already initialized with enough workers, reuse
        if (this.initialized && this.workerCount > 0) {
            const targetCount = count || Math.min(MemoryUtils.detectCPUCores(), 8);
            if (this.workerCount >= targetCount) {
                return true;
            }
            // Need more workers, terminate and reinitialize
            this.terminate();
        }
        
        // Clear any stale promise from failed initialization
        if (this.initPromise && !this.initialized) {
            this.initPromise = null;
        }
        
        if (this.initPromise) return this.initPromise;
        
        this.initPromise = this._doInitialize(count, memoryMb);
        return this.initPromise;
    }
    
    static async _doInitialize(count, memoryMb) {
        if (this.initialized) return true;
        
        // Default to number of CPU cores, capped at 8
        const targetCount = count || Math.min(MemoryUtils.detectCPUCores(), 8);
        
        
        const workerPromises = [];
        
        for (let i = 0; i < targetCount; i++) {
            workerPromises.push(this._createWorker(i, memoryMb));
        }
        
        const results = await Promise.allSettled(workerPromises);
        const successCount = results.filter(r => r.status === 'fulfilled' && r.value).length;
        
        if (successCount === 0) {
            console.error('❌ Failed to create any workers for pool');
            return false;
        }
        
        this.workerCount = successCount;
        this.initialized = true;
        
        return true;
    }
    
    /**
     * Create a single worker and wait for it to be ready
     * Uses Safari-safe worker that doesn't allocate 2GB on startup
     */
    static async _createWorker(index, memoryMb = 64) {
        return new Promise((resolve) => {
            try {
                // Use absolute path for worker to avoid MIME type issues in Safari
                // Safari can misresolve relative paths in certain contexts
                const workerUrl = new URL('/argon2-worker-safe.js', window.location.origin).href;
                const worker = new Worker(workerUrl);
                let ready = false;
                let initSent = false;
                
                worker.onmessage = (event) => {
                    const { id, type, result, error, argon2Loaded } = event.data;
                    
                    // Handle pending signal - worker loaded but needs init
                    if (type === 'pending' && !initSent) {
                        initSent = true;
                        const initId = ++this.requestId;
                        this.pendingRequests.set(initId, {
                            isInit: true, // Mark as init request (not cancelled by cancelPendingRequests)
                            resolve: () => {
                                ready = true;
                                this.workers.push({ worker, busy: false, index });
                                resolve(true);
                            },
                            reject: (err) => {
                                console.warn(`[Pool] Worker ${index} init failed:`, err.message);
                                worker.terminate();
                                resolve(false);
                            }
                        });
                        worker.postMessage({ id: initId, type: 'init', params: { memoryMb } });
                        return;
                    }
                    
                    // Handle legacy ready signal (from old worker)
                    if (type === 'ready') {
                        if (argon2Loaded) {
                            ready = true;
                            this.workers.push({ worker, busy: false, index });
                            resolve(true);
                        } else {
                            worker.terminate();
                            resolve(false);
                        }
                        return;
                    }
                    
                    // Handle request responses
                    const pending = this.pendingRequests.get(id);
                    if (pending) {
                        this.pendingRequests.delete(id);
                        // Mark worker as available
                        const workerInfo = this.workers.find(w => w.worker === worker);
                        if (workerInfo) workerInfo.busy = false;
                        
                        if (type === 'error') {
                            pending.reject(new Error(error));
                        } else {
                            pending.resolve(result);
                        }
                    }
                };
                
                worker.onerror = (error) => {
                    console.warn(`Worker ${index} error:`, error.message);
                    if (!ready) resolve(false);
                };
                
                // Timeout after 10 seconds (increased for Safari WASM loading)
                setTimeout(() => {
                    if (!ready) {
                        console.warn(`Worker ${index} timed out`);
                        worker.terminate();
                        resolve(false);
                    }
                }, 10000);
                
            } catch (e) {
                console.warn(`Failed to create worker ${index}:`, e.message);
                resolve(false);
            }
        });
    }
    
    /**
     * Get an available worker from the pool and mark it busy atomically
     * @returns {Object|null} Worker info or null if none available
     */
    static getAvailableWorker() {
        const worker = this.workers.find(w => !w.busy);
        if (worker) {
            worker.busy = true; // Mark busy immediately to prevent race conditions
        }
        return worker || null;
    }
    
    /**
     * Queue a hash job and return when complete
     * @param {Object} params - Hash parameters
     * @returns {Promise<Uint8Array>} Hash result
     */
    static async hash(params) {
        if (!this.initialized) {
            await this.initialize();
        }
        
        // Wait for an available worker (already marked busy)
        const workerInfo = await this._waitForWorker();
        
        return new Promise((resolve, reject) => {
            const id = ++this.requestId;
            
            this.pendingRequests.set(id, { 
                resolve: (result) => resolve(new Uint8Array(result.hash)),
                reject 
            });
            
            workerInfo.worker.postMessage({ id, type: 'hash', params });
        });
    }
    
    /**
     * Wait for a worker to become available
     */
    static _waitForWorker() {
        return new Promise((resolve) => {
            const check = () => {
                const available = this.getAvailableWorker();
                if (available) {
                    resolve(available);
                } else {
                    // Use shorter poll interval for responsiveness
                    setTimeout(check, 1);
                }
            };
            check();
        });
    }
    
    /**
     * Process multiple hash jobs in parallel
     * @param {Array} jobs - Array of {params, onComplete, onError} objects
     * @param {Function} onProgress - Called with (completed, total) after each completion
     * @returns {Promise<Array>} Array of results in same order as jobs
     */
    static async hashBatch(jobs, onProgress = null) {
        if (!this.initialized) {
            await this.initialize();
        }
        
        const results = new Array(jobs.length).fill(null);
        let completed = 0;
        
        const startTime = performance.now();
        
        // Create promises for all jobs
        const jobPromises = jobs.map((job, index) => {
            return this.hash(job.params).then(result => {
                results[index] = result;
                completed++;
                if (onProgress) onProgress(completed, jobs.length);
                if (job.onComplete) job.onComplete(result, index);
                return result;
            }).catch(error => {
                completed++;
                if (onProgress) onProgress(completed, jobs.length);
                if (job.onError) job.onError(error, index);
                throw error;
            });
        });
        
        // Wait for all to complete
        await Promise.allSettled(jobPromises);
        
        const elapsed = ((performance.now() - startTime) / 1000).toFixed(2);
        
        return results;
    }
    
    /**
     * Get pool status
     */
    static getStatus() {
        const busyCount = this.workers.filter(w => w.busy).length;
        return {
            initialized: this.initialized,
            totalWorkers: this.workerCount,
            busyWorkers: busyCount,
            availableWorkers: this.workerCount - busyCount,
            pendingRequests: this.pendingRequests.size
        };
    }
    
    /**
     * Terminate all workers in the pool
     */
    static terminate() {
        for (const { worker } of this.workers) {
            worker.terminate();
        }
        this.workers = [];
        this.workerCount = 0;
        this.initialized = false;
        this.initPromise = null;
        this.pendingRequests.clear();
    }
    
    /**
     * Cancel all pending requests without terminating workers.
     * Use this when settings change and old results are no longer valid.
     * Only cancels hash requests, not worker init requests.
     */
    static cancelPendingRequests() {
        let count = 0;
        // Only cancel hash requests (id > this.workerCount * 2 to skip init IDs)
        // OR check if it's a hash request by looking at the pending object
        for (const [id, pending] of this.pendingRequests) {
            // Skip init requests - they don't have a 'hash' marker
            if (pending.isInit) continue;
            pending.reject(new Error('Cancelled: settings changed'));
            this.pendingRequests.delete(id);
            count++;
        }
        
        // Clear busy flags on all workers since their pending requests were cancelled
        // The workers are still computing but we don't care about their results
        for (const workerInfo of this.workers) {
            workerInfo.busy = false;
        }
    }
}

/**
 * Label building utilities (matches Python crypto.py)
 */
class LabelUtils {
    
    // ========== Luhn Mod-36 Check Digit ==========
    
    // Luhn mod-36 alphabet: 0-9, A-Z (uppercase)
    static LUHN_ALPHABET = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    static LUHN_BASE = 36;
    
    /**
     * Compute Luhn mod-36 check digit for a label body.
     * Uses the Luhn mod N algorithm with N=36 and alphabet [0-9A-Z].
     * 
     * @param {string} body - Label string to compute check digit for
     * @returns {string} Single character check digit from LUHN_ALPHABET
     */
    static luhnMod36Check(body) {
        const bodyUpper = body.toUpperCase();
        
        // Map character to value
        const charToValue = (c) => {
            const idx = this.LUHN_ALPHABET.indexOf(c);
            if (idx >= 0) return idx;
            return c.charCodeAt(0) % this.LUHN_BASE;
        };
        
        let total = 0;
        // Process from right to left, doubling every second digit
        const chars = [...bodyUpper].reverse();
        for (let i = 0; i < chars.length; i++) {
            let value = charToValue(chars[i]);
            if (i % 2 === 1) {
                // Double and sum digits if >= base
                value *= 2;
                if (value >= this.LUHN_BASE) {
                    value = Math.floor(value / this.LUHN_BASE) + (value % this.LUHN_BASE);
                }
            }
            total += value;
        }
        
        // Check digit makes total divisible by base
        const checkValue = (this.LUHN_BASE - (total % this.LUHN_BASE)) % this.LUHN_BASE;
        return this.LUHN_ALPHABET[checkValue];
    }
    
    /**
     * Validate and strip Luhn mod-36 check digit from a label.
     * 
     * @param {string} label - Full label string, optionally with |CHECK suffix
     * @returns {{valid: boolean, body: string}} Validation result and body without check
     */
    static luhnMod36Validate(label) {
        if (!label.includes('|')) {
            // No check digit, return as-is (unverified but valid format)
            return { valid: true, body: label };
        }
        
        // Find the last | which separates body from check digit
        const lastPipe = label.lastIndexOf('|');
        const body = label.substring(0, lastPipe);
        const check = label.substring(lastPipe + 1);
        
        // Check digit should be single character
        if (check.length !== 1) {
            return { valid: false, body };
        }
        
        const expected = this.luhnMod36Check(body);
        return { valid: check.toUpperCase() === expected, body };
    }
    
    /**
     * Append Luhn mod-36 check digit to a label body.
     * 
     * @param {string} body - Label body (colon-separated fields)
     * @returns {string} Complete label with |CHECK suffix
     */
    static buildLabelWithCheck(body) {
        const check = this.luhnMod36Check(body);
        return `${body}|${check}`;
    }
    
    // ========== Coordinate Conversion Helpers ==========
    
    /**
     * Convert numeric index (0-99) to grid coordinate (A0-J9)
     * Spreadsheet convention: letter=column (A-J), number=row (0-9)
     * @param {number} index - Index from 0 to 99
     * @returns {string} Grid coordinate like "A0", "E5", "J9"
     */
    static indexToCoord(index) {
        if (index < 0 || index > 99) {
            throw new Error(`Index must be 0-99, got ${index}`);
        }
        const row = Math.floor(index / 10); // 0-9 (numeric part)
        const col = index % 10;              // 0-9 (letter part: A-J)
        return `${String.fromCharCode(65 + col)}${row}`; // Column letter + Row number
    }
    
    /**
     * Convert grid coordinate (A0-J9) to numeric index (0-99)
     * Spreadsheet convention: letter=column (A-J), number=row (0-9)
     * @param {string} coord - Grid coordinate like "A0", "E5", "J9"
     * @returns {number} Index from 0 to 99
     */
    static coordToIndex(coord) {
        if (!coord || coord.length !== 2) {
            throw new Error(`Invalid coordinate format: ${coord}`);
        }
        const colChar = coord[0].toUpperCase(); // Letter = column
        const rowChar = coord[1];                // Number = row
        
        if (colChar < 'A' || colChar > 'J') {
            throw new Error(`Invalid column: ${colChar}`);
        }
        if (rowChar < '0' || rowChar > '9') {
            throw new Error(`Invalid row: ${rowChar}`);
        }
        
        const col = colChar.charCodeAt(0) - 65; // A=0, J=9
        const row = parseInt(rowChar);
        return row * 10 + col;
    }
    
    // ========== Argon2 Parameter Encoding ==========
    
    /**
     * Encode Argon2 parameters in Bastion URL-style format: TIME=3&MEMORY=64&PARALLELISM=8
     */
    static encodeArgon2Params(timeCost = CONFIG.ARGON2_TIME_COST,
                               memoryMb = CONFIG.ARGON2_MEMORY_COST_MB,
                               parallelism = CONFIG.ARGON2_PARALLELISM) {
        return `TIME=${timeCost}&MEMORY=${memoryMb}&PARALLELISM=${parallelism}`;
    }
    
    /**
     * Decode Argon2 params from Bastion URL-style format
     * 
     * Format: TIME=3&MEMORY=64&PARALLELISM=8
     */
    static decodeArgon2Params(encoded) {
        if (!encoded.includes('=')) {
            throw new Error(`Invalid Argon2 params format (expected URL-style): ${encoded}`);
        }
        
        const params = {};
        for (const part of encoded.split('&')) {
            if (part.includes('=')) {
                const [key, value] = part.split('=');
                params[key.toUpperCase()] = value;
            }
        }
        
        if (params.TIME && params.MEMORY && params.PARALLELISM) {
            return {
                timeCost: parseInt(params.TIME),
                memoryMb: parseInt(params.MEMORY),
                parallelism: parseInt(params.PARALLELISM)
            };
        }
        throw new Error(`Missing required Argon2 params (TIME, MEMORY, PARALLELISM) in: ${encoded}`);
    }
    
    /**
     * Generate URL-safe Base64 nonce
     */
    static generateNonce(numBytes = CONFIG.NONCE_BYTES) {
        const randomBytes = new Uint8Array(numBytes);
        crypto.getRandomValues(randomBytes);
        // Convert to URL-safe Base64 without padding
        let base64 = btoa(String.fromCharCode(...randomBytes));
        // Make URL-safe: replace + with -, / with _
        return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    }
    
    // ========== Argon2 Salt Label (per-card) ==========
    
    /**
     * Build complete Argon2 salt label string (Bastion Format)
     * Format: Bastion/TOKEN/ALGO:IDENT:DATE#PARAMS|CHECK
     * 
     * Uses URL-style parameter encoding with & separator and = assignment.
     * Parameter order is canonical: VERSION, TIME, MEMORY, PARALLELISM, NONCE, ENCODING
     * 
     * Example: Bastion/TOKEN/SIMPLE-ARGON2ID:banking.A0:2025-11-28#VERSION=1&TIME=64&MEMORY=64&PARALLELISM=8&NONCE=Kx7mQ9bL&ENCODING=90|X
     * 
     * @param {string} seedType - Seed source type (SIMPLE, BIP39, SLIP39)
     * @param {string} kdf - KDF type (ARGON2ID)
     * @param {string} kdfParams - Encoded KDF params (TIME=3&MEMORY=512&PARALLELISM=4)
     * @param {string} base - Output alphabet (BASE90, BASE62, BASE10)
     * @param {string} date - Card date (YYYY-MM-DD or empty)
     * @param {string} nonce - Random batch nonce
     * @param {string} cardId - User's card identifier (e.g., "Banking")
     * @param {string} cardIndex - Card index as grid coordinate (A0-J9)
     * @returns {string} Complete label with Luhn check digit
     */
    static buildLabel(seedType, kdf = 'ARGON2ID', kdfParams = null, base = 'BASE90',
                      date = null, nonce = null, cardId = null, cardIndex = null) {
        if (!kdfParams) {
            kdfParams = this.encodeArgon2Params();
        }
        if (!nonce) {
            nonce = this.generateNonce();
        }
        
        // Parse params (Bastion URL-style format only)
        const params = this.decodeArgon2Params(kdfParams);
        
        // Build ALGO: SEED_TYPE-KDF (e.g., SIMPLE-ARGON2ID)
        const algo = `${seedType.toUpperCase()}-${kdf.toUpperCase()}`;
        
        // Build IDENT: {card_id}.{card_index} (lowercase card_id)
        const ident = `${(cardId || 'card').toLowerCase()}.${cardIndex || 'A0'}`;
        
        // Extract encoding number from base (BASE90 -> 90)
        const encoding = base.toUpperCase().replace('BASE', '');
        
        // Build PARAMS in Bastion canonical order using URL-style format
        // Order: VERSION, TIME, MEMORY, PARALLELISM, NONCE, ENCODING
        const paramsStr = `VERSION=1&TIME=${params.timeCost}&MEMORY=${params.memoryMb}&PARALLELISM=${params.parallelism}&NONCE=${nonce}&ENCODING=${encoding}`;
        
        // Build body: Bastion/TOKEN/ALGO:IDENT:DATE#PARAMS
        const body = `Bastion/TOKEN/${algo}:${ident}:${date || ''}#${paramsStr}`;
        
        // Append Luhn check digit
        return this.buildLabelWithCheck(body);
    }
    
    /**
     * Parse a label string (Bastion format only)
     */
    static parseLabel(label) {
        if (!label.startsWith('Bastion/')) {
            throw new Error(`Invalid label format: expected 'Bastion/' prefix, got: ${label}`);
        }
        return this._parseNewBastionLabel(label);
    }
    
    /**
     * Parse Bastion format label
     * Format: Bastion/TOKEN/ALGO:IDENT:DATE#PARAMS|CHECK
     */
    static _parseNewBastionLabel(label) {
        // Validate and strip Luhn check digit
        const { valid, body } = this.luhnMod36Validate(label);
        if (!valid) {
            throw new Error(`Invalid Luhn check digit in label: ${label}`);
        }
        
        // Split on # to separate metadata from params
        if (!body.includes('#')) {
            throw new Error(`Invalid Bastion label format: missing # params separator`);
        }
        
        const [metadata, paramsStr] = body.split('#');
        
        // Parse metadata: Bastion/TOKEN/ALGO:IDENT:DATE
        const slashParts = metadata.split('/');
        if (slashParts.length < 3) {
            throw new Error(`Invalid Bastion label format: expected Tool/TYPE/ALGO prefix`);
        }
        
        const tool = slashParts[0];
        const labelType = slashParts[1];
        
        // Everything after second / contains ALGO:IDENT:DATE
        const algoAndRest = slashParts.slice(2).join('/');
        const colonParts = algoAndRest.split(':');
        
        if (colonParts.length !== 3) {
            throw new Error(`Invalid Bastion label format: expected ALGO:IDENT:DATE`);
        }
        
        const [algo, ident, date] = colonParts;
        
        // Parse ALGO: SEED_TYPE-KDF
        const algoParts = algo.split('-');
        if (algoParts.length < 2) {
            throw new Error(`Invalid ALGO format: ${algo}`);
        }
        const seedType = algoParts[0];
        const kdf = algoParts.slice(1).join('-');
        
        // Parse IDENT: {card_id}.{card_index}
        const lastDot = ident.lastIndexOf('.');
        if (lastDot === -1) {
            throw new Error(`Invalid IDENT format: ${ident}`);
        }
        const cardId = ident.substring(0, lastDot);
        const cardIndex = ident.substring(lastDot + 1);
        
        // Parse PARAMS (URL-style)
        const paramsDict = this._parseUrlParams(paramsStr);
        
        // Build base from encoding
        const encoding = paramsDict.encoding || '90';
        const base = `BASE${encoding}`;
        
        return {
            version: String(paramsDict.version || '1'),
            type: labelType,
            tool,
            seedType: seedType.toUpperCase(),
            kdf: kdf.toUpperCase(),
            kdfParams: `TIME=${paramsDict.time || 3}&MEMORY=${paramsDict.memory || 64}&PARALLELISM=${paramsDict.parallelism || 8}`,
            base,
            date: date || null,
            nonce: paramsDict.nonce || '',
            cardId: cardId.toUpperCase() || 'CARD',
            cardIndex: cardIndex.toUpperCase() || 'A0',
            argon2Time: paramsDict.time || 3,
            argon2MemoryMb: paramsDict.memory || 64,
            argon2Parallelism: paramsDict.parallelism || 8
        };
    }
    
    /**
     * Parse URL-style parameters
     * Format: KEY=value&KEY=value&...
     */
    static _parseUrlParams(paramsStr) {
        const result = {};
        
        for (const part of paramsStr.split('&')) {
            if (!part.includes('=')) continue;
            const [key, value] = part.split('=');
            const keyLower = key.toLowerCase();
            
            // Convert numeric values
            if (['version', 'time', 'memory', 'parallelism', 'encoding'].includes(keyLower)) {
                result[keyLower] = parseInt(value) || value;
            } else {
                result[keyLower] = value;
            }
        }
        
        return result;
    }
    
    // ========== HMAC Info Label (per-token) ==========
    
    /**
     * Build HMAC info label for per-token domain separation (Bastion Format)
     * Format: Bastion/TOKEN/HMAC:IDENT:#VERSION=1|CHECK
     * 
     * Example: Bastion/TOKEN/HMAC:A0.B3:#VERSION=1|Y
     * 
     * @param {string} cardIndex - Card index as grid coordinate (A0-J9)
     * @param {string} tokenCoord - Token coordinate (A0-J9)
     * @returns {string} HMAC info label with Luhn check digit
     */
    static buildHmacLabel(cardIndex, tokenCoord) {
        // Build IDENT: {card_index}.{token_coord}
        const ident = `${cardIndex || 'A0'}.${tokenCoord}`;
        
        // Build body: Bastion/TOKEN/HMAC:IDENT:#VERSION=1
        // Note: DATE field is empty for HMAC labels
        const body = `Bastion/TOKEN/HMAC:${ident}:#VERSION=1`;
        
        return this.buildLabelWithCheck(body);
    }
    
    /**
     * Parse an HMAC info label (Bastion format only)
     */
    static parseHmacLabel(label) {
        if (!label.startsWith('Bastion/')) {
            throw new Error(`Invalid HMAC label format: expected 'Bastion/' prefix, got: ${label}`);
        }
        
        // Validate and strip Luhn check digit
        const { valid, body } = this.luhnMod36Validate(label);
        if (!valid) {
            throw new Error(`Invalid Luhn check digit in label: ${label}`);
        }
        
        // Parse: Bastion/TOKEN/HMAC:IDENT:#VERSION=1
        if (!body.includes('#')) {
            throw new Error(`Invalid Bastion HMAC label format: missing # params`);
        }
        
        const [metadata, paramsStr] = body.split('#');
        
        // Parse metadata: Bastion/TOKEN/HMAC:IDENT:
        const slashParts = metadata.split('/');
        if (slashParts.length < 3) {
            throw new Error(`Invalid Bastion HMAC label: missing Tool/TYPE/ALGO`);
        }
        
        // Get algo and rest after second slash
        const algoAndRest = slashParts.slice(2).join('/');
        const colonParts = algoAndRest.split(':');
        
        if (colonParts.length < 2 || colonParts[0] !== 'HMAC') {
            throw new Error(`Invalid HMAC label format: ${label}`);
        }
        
        const ident = colonParts[1];
        const identParts = ident.split('.');
        if (identParts.length !== 2) {
            throw new Error(`Invalid HMAC label IDENT: ${ident}`);
        }
        
        // Parse version from params
        const paramsDict = this._parseUrlParams(paramsStr);
        
        return {
            version: String(paramsDict.version || '1'),
            cardIndex: identParts[0],
            tokenCoord: identParts[1]
        };
    }
}

/**
 * Core cryptographic operations for deterministic token generation
 */
class SeedCardCrypto {
    
    /**
     * HKDF-Expand function per RFC 5869.
     * 
     * Expands a pseudorandom key (PRK) into output keying material using
     * HMAC-SHA512. This is the standard HKDF expand phase with chained blocks.
     * 
     * @param {Uint8Array} prk - Pseudorandom key (should be at least 64 bytes)
     * @param {Uint8Array} info - Context/application-specific info
     * @param {number} length - Desired output length in bytes
     * @returns {Promise<Uint8Array>} Output keying material
     */
    static async hkdfExpand(prk, info, length) {
        const hashLen = 64; // SHA-512 output size
        const maxLength = 255 * hashLen;
        
        if (length > maxLength) {
            throw new Error(`HKDF-Expand length ${length} exceeds maximum ${maxLength}`);
        }
        
        // Number of blocks needed
        const n = Math.ceil(length / hashLen);
        
        const okm = [];
        let t = new Uint8Array(0); // T(0) = empty
        
        // Import PRK as HMAC key
        const key = await crypto.subtle.importKey(
            'raw',
            prk,
            { name: 'HMAC', hash: 'SHA-512' },
            false,
            ['sign']
        );
        
        for (let i = 1; i <= n; i++) {
            // T(i) = HMAC(PRK, T(i-1) || info || i)
            // Each block chains the previous block's output
            const message = new Uint8Array([...t, ...info, i]);
            const signature = await crypto.subtle.sign('HMAC', key, message);
            t = new Uint8Array(signature);
            okm.push(...t);
        }
        
        return new Uint8Array(okm.slice(0, length));
    }
    
    /**
     * Generate deterministic byte stream using standard HKDF-Expand (RFC 5869).
     * 
     * Note: We skip HKDF-Extract because our seed is already a uniformly random
     * 64-byte value from Argon2id (which produces indistinguishable-from-random output).
     * Using the Argon2 output directly as PRK is cryptographically safe.
     * 
     * @param {Uint8Array} seedBytes - 64-byte seed from Argon2id (used directly as PRK)
     * @param {string} infoLabel - Context label for domain separation
     * @param {number} neededBytes - Number of bytes to generate
     * @returns {Promise<Uint8Array>} Deterministic byte stream
     */
    static async hkdfLikeStream(seedBytes, infoLabel, neededBytes) {        
        if (seedBytes.length !== 64) {
            throw new Error(`Expected 64-byte seed, got ${seedBytes.length} bytes`);
        }
        
        const info = new TextEncoder().encode(infoLabel);
        return SeedCardCrypto.hkdfExpand(seedBytes, info, neededBytes);
    }
    
    /**
     * Map byte value to alphabet index using rejection sampling
     */
    static byteToSymbol(byteValue, alphabetSize) {
        if (byteValue < 0 || byteValue > 255) {
            throw new Error(`Byte value must be 0-255, got ${byteValue}`);
        }
        
        // Calculate maximum usable value to avoid modulo bias
        const maxUsable = Math.floor(256 / alphabetSize) * alphabetSize;
        
        if (byteValue < maxUsable) {
            return byteValue % alphabetSize;
        } else {
            return null; // Reject this byte
        }
    }
    
    /**
     * Generate a single token from byte stream using rejection sampling
     */
    static generateTokenFromStream(byteStreamIterator, alphabet = null) {
        if (alphabet === null) {
            alphabet = CONFIG.ALPHABET;
        }
        
        const tokenChars = [];
        const alphabetSize = alphabet.length;
        
        while (tokenChars.length < CONFIG.CHARS_PER_TOKEN) {
            const next = byteStreamIterator.next();
            if (next.done) {
                throw new Error("Out of entropy bytes unexpectedly");
            }
            
            const symbolIndex = this.byteToSymbol(next.value, alphabetSize);
            if (symbolIndex !== null) {
                tokenChars.push(alphabet[symbolIndex]);
            }
        }
        
        return tokenChars.join('');
    }
    
    /**
     * Generate complete token matrix with per-token HMAC labels
     * 
     * @param {Uint8Array} seedBytes - 64-byte seed from Argon2
     * @param {string} cardIndex - Card index as grid coordinate (A0-J9)
     * @param {string} base - Output alphabet (base90, base62, base10)
     * @returns {Object} Matrix and metadata
     */
    static async generateTokenMatrix(seedBytes, cardIndex = 'A0', base = 'base90') {
        // Get alphabet for selected base
        const alphabet = BASE_CONFIGS[base]?.alphabet || CONFIG.ALPHABET;
        
        // Generate matrix with per-token HMAC labels
        const matrix = [];
        
        for (let row = 0; row < CONFIG.TOKENS_TALL; row++) {
            const matrixRow = [];
            for (let col = 0; col < CONFIG.TOKENS_WIDE; col++) {
                // Build per-token HMAC label: v1|{cardIndex}|TOKEN|{tokenCoord}
                // Spreadsheet convention: letter=column (A-J), number=row (0-9)
                const tokenCoord = `${String.fromCharCode(65 + col)}${row}`; // A0, B0, ..., J0, A1, ..., J9
                const hmacLabel = LabelUtils.buildHmacLabel(cardIndex, tokenCoord);
                
                // Generate byte stream for this specific token
                const byteStream = await this.hkdfLikeStream(
                    seedBytes,
                    hmacLabel,
                    64 // Only need ~20 bytes per token, 64 is plenty with rejection sampling
                );
                
                // Create iterator for this token
                let byteIndex = 0;
                const byteStreamIterator = {
                    next() {
                        if (byteIndex >= byteStream.length) {
                            return { done: true };
                        }
                        return { value: byteStream[byteIndex++], done: false };
                    }
                };
                
                const token = this.generateTokenFromStream(byteStreamIterator, alphabet);
                matrixRow.push(token);
            }
            matrix.push(matrixRow);
        }
        
        return {
            matrix: matrix,
            cardIndex: cardIndex,
            hmacLabelFormat: 'v1|{cardIndex}|TOKEN|{tokenCoord}'
        };
    }
    
    /**
     * Safely decode a label with fallback
     */
    static safeDecodeLabel(labelBytes) {
        try {
            if (!labelBytes) return 'SEEDER-TOKENS';
            if (typeof labelBytes === 'string') return labelBytes;
            if (labelBytes instanceof Uint8Array || labelBytes instanceof ArrayBuffer) {
                return new TextDecoder().decode(labelBytes);
            }
            return 'SEEDER-TOKENS';
        } catch (error) {
            console.warn('Failed to decode label bytes:', error);
            return 'SEEDER-TOKENS';
        }
    }
    
    /**
     * Generate integrity hash for verification
     */
    static async generateDigest(seedBytes) {
        const digestStream = await this.hkdfLikeStream(
            seedBytes,
            CONFIG.HMAC_LABEL_DIGEST,
            64
        );
        
        // Convert to hex string
        return Array.from(digestStream)
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    }
    
    /**
     * Get coordinate-based token from matrix
     * Spreadsheet convention: letter=column (A-J), number=row (0-9)
     */
    static getTokenAtCoordinate(matrix, coordinate) {
        if (coordinate.length !== 2) {
            throw new Error(`Invalid coordinate format: ${coordinate}`);
        }
        
        const colChar = coordinate[0].toUpperCase(); // Letter = column
        const rowChar = coordinate[1];                // Number = row
        
        if (colChar < 'A' || colChar > 'J') {
            throw new Error(`Invalid column: ${colChar}`);
        }
        
        if (rowChar < '0' || rowChar > '9') {
            throw new Error(`Invalid row: ${rowChar}`);
        }
        
        const col = colChar.charCodeAt(0) - 'A'.charCodeAt(0);
        const row = parseInt(rowChar);
        
        return matrix[row][col];
    }
    
    /**
     * Generate password from pattern coordinates
     */
    static generatePasswordFromPattern(matrix, pattern, separators = true) {
        const tokens = pattern.split(' ').map(coord => 
            this.getTokenAtCoordinate(matrix, coord.trim())
        );
        
        return separators ? tokens.join('-') : tokens.join('');
    }
}

/**
 * Seed source processing functions
 */
class SeedSources {
    
    /**
     * Simple SHA-512 seed derivation (legacy)
     */
    static async simpleToSeed(phrase) {
        const encoder = new TextEncoder();
        const data = encoder.encode(phrase);
        const hashBuffer = await crypto.subtle.digest('SHA-512', data);
        return new Uint8Array(hashBuffer);
    }
    
    /**
     * Argon2id seed derivation using Web Worker (preferred) or main thread fallback
     * 
     * @param {string} phrase - Input phrase
     * @param {string} salt - Salt string (typically the v1 label)
     * @param {number} timeCost - Iterations (default 3)
     * @param {number} memoryMb - Memory in MB (default 512MB)
     * @param {number} parallelism - Parallelism lanes (default 8)
     * @param {boolean} useWorker - Try to use Web Worker (default true)
     * @returns {Uint8Array} 64-byte seed
     */
    static async argon2ToSeed(phrase, salt, timeCost = CONFIG.ARGON2_TIME_COST, 
                               memoryMb = CONFIG.ARGON2_MEMORY_COST_MB,
                               parallelism = CONFIG.ARGON2_PARALLELISM,
                               useWorker = true) {
        
        // Try Web Worker first for non-blocking UI
        if (useWorker && Argon2Worker.isSupported()) {
            try {
                const isReady = await Argon2Worker.waitForReady(2000);
                if (isReady) {
                    return await Argon2Worker.hash(
                        phrase, salt, timeCost, memoryMb, parallelism, CONFIG.ARGON2_HASH_LENGTH
                    );
                }
            } catch (workerError) {
                console.warn('Web Worker Argon2 failed, falling back to main thread:', workerError.message);
            }
        }
        
        // Fallback to main thread
        return this.argon2ToSeedMainThread(phrase, salt, timeCost, memoryMb, parallelism);
    }
    
    /**
     * Argon2id seed derivation on main thread (blocks UI)
     * Used as fallback when Web Worker is not available
     * Includes automatic memory fallback for browser limitations
     * Uses Safari-safe loader when available
     */
    static async argon2ToSeedMainThread(phrase, salt, timeCost = CONFIG.ARGON2_TIME_COST, 
                               memoryMb = CONFIG.ARGON2_MEMORY_COST_MB,
                               parallelism = CONFIG.ARGON2_PARALLELISM) {
        // Check for Safari-safe loader first, then bundled argon2
        const hasArgon2 = typeof argon2 !== 'undefined' && typeof argon2.hash === 'function';
        const hasSafeLoader = typeof argon2Safe !== 'undefined' && typeof argon2Safe.init === 'function';
        
        
        // Try to initialize Safari-safe loader if bundled version isn't available
        if (!hasArgon2 && hasSafeLoader) {
            try {
                await argon2Safe.init(memoryMb * 1024);
            } catch (initError) {
                console.error(`❌ Safari-safe Argon2 init failed:`, initError);
                throw new Error('Failed to initialize Argon2 library: ' + initError.message);
            }
        }
        
        // Final check - at this point argon2 should be available
        if (typeof argon2 === 'undefined' || typeof argon2.hash !== 'function') {
            throw new Error('Argon2 library not loaded. Please include argon2-browser or argon2-loader.js');
        }
        
        const encoder = new TextEncoder();
        const phraseBytes = encoder.encode(phrase);
        const saltBytes = encoder.encode(salt);
        
        // Memory fallback sequence: try requested, then progressively lower
        const memoryFallbacks = [memoryMb];
        for (const fallback of MEMORY_OPTIONS) {
            if (fallback < memoryMb && !memoryFallbacks.includes(fallback)) {
                memoryFallbacks.push(fallback);
            }
        }
        
        let lastError = null;
        
        for (const tryMemoryMb of memoryFallbacks) {
            const memoryKb = tryMemoryMb * 1024;
            
            const startTime = performance.now();
            
            try {
                const result = await argon2.hash({
                    pass: phraseBytes,
                    salt: saltBytes,
                    time: timeCost,
                    mem: memoryKb,
                    parallelism: parallelism,
                    hashLen: CONFIG.ARGON2_HASH_LENGTH,
                    type: argon2.ArgonType.Argon2id
                });
                
                const elapsed = ((performance.now() - startTime) / 1000).toFixed(2);
                
                if (tryMemoryMb !== memoryMb) {
                    console.warn(`⚠️ Argon2 succeeded with reduced memory: ${tryMemoryMb}MB (requested ${memoryMb}MB)`);
                }
                
                return new Uint8Array(result.hash);
            } catch (error) {
                const elapsed = ((performance.now() - startTime) / 1000).toFixed(2);
                lastError = error;
                
                // Check if this is a memory error - catch RangeError and any memory-related message
                const errorName = error.name || '';
                const errorMsg = error.message || '';
                const isMemoryError = 
                    errorName === 'RangeError' ||
                    errorMsg.toLowerCase().includes('memory') || 
                    errorMsg.toLowerCase().includes('range') ||
                    errorMsg.toLowerCase().includes('out of');
                
                console.warn(`⚠️ Argon2 ${tryMemoryMb}MB failed (${elapsed}s): [${errorName}] ${errorMsg}`);
                
                if (isMemoryError && tryMemoryMb > 8) {
                    // Small delay to let browser release memory
                    await new Promise(r => setTimeout(r, 100));
                    continue;
                }
                
                console.error(`❌ Argon2 failed (non-recoverable):`, error);
                break;
            }
        }
        
        throw new Error(`Argon2 derivation failed even at minimum memory: ${lastError?.message || 'unknown error'}`);
    }
    
    /**
     * BIP-39 mnemonic to seed (simplified PBKDF2)
     */
    static async bip39ToSeed(mnemonic, passphrase = '', iterations = CONFIG.DEFAULT_PBKDF2_ITERATIONS) {
        const encoder = new TextEncoder();
        const mnemonicBytes = encoder.encode(mnemonic.normalize('NFKD'));
        const salt = encoder.encode('mnemonic' + passphrase.normalize('NFKD'));
        
        // Import password as key
        const keyMaterial = await crypto.subtle.importKey(
            'raw',
            mnemonicBytes,
            'PBKDF2',
            false,
            ['deriveBits']
        );
        
        // Derive 64 bytes using PBKDF2
        const derived = await crypto.subtle.deriveBits(
            {
                name: 'PBKDF2',
                salt: salt,
                iterations: iterations,
                hash: 'SHA-512'
            },
            keyMaterial,
            512 // 64 bytes * 8 bits
        );
        
        return new Uint8Array(derived);
    }
    
    /**
     * Basic SLIP-39 reconstruction (simplified)
     */
    static async slip39ToSeed(shares) {
        if (shares.length < 2) {
            throw new Error('At least 2 shares required for reconstruction');
        }
        
        // For now, just combine and hash the shares
        // Real SLIP-39 requires proper Shamir's Secret Sharing
        const combined = shares.join(' ');
        return this.simpleToSeed(combined);
    }
}

/**
 * Word generation for memorized components
 */
class WordGenerator {
    static CONSONANTS = 'bcdfghjklmnpqrstvwxyz';
    static VOWELS = 'aeiou';
    
    static PATTERNS = {
        3: ['CVC'],
        4: ['CVCV', 'CVCC'],
        5: ['CVCVC', 'CCVCV', 'CVCCC'],
        6: ['CVCVCV', 'CCVCVC', 'CVCVCC']
    };
    
    /**
     * Generate pronounceable word from seed
     */
    static async generateWord(seedBytes, length, wordIndex = 0) {
        const patterns = this.PATTERNS[length] || ['CVC'];
        const patternIndex = wordIndex % patterns.length;
        const pattern = patterns[patternIndex];
        
        // Generate deterministic stream for this word
        const wordSeed = new Uint8Array(seedBytes.length + 4);
        wordSeed.set(seedBytes, 0);
        
        // Add word index as 4 bytes
        const indexBytes = new Uint8Array(4);
        for (let i = 0; i < 4; i++) {
            indexBytes[i] = (wordIndex >> (i * 8)) & 0xFF;
        }
        wordSeed.set(indexBytes, seedBytes.length);
        
        // Hash the combined seed+index back to 64 bytes for hkdfLikeStream
        const hashedSeed = new Uint8Array(await crypto.subtle.digest('SHA-512', wordSeed));
        
        const stream = await SeedCardCrypto.hkdfLikeStream(hashedSeed, 'WORDS', 64);
        
        let word = '';
        let streamPos = 0;
        
        for (const char of pattern) {
            let charSet, charIdx;
            
            if (char === 'C') {
                charSet = this.CONSONANTS;
            } else if (char === 'V') {
                charSet = this.VOWELS;
            } else {
                continue;
            }
            
            charIdx = stream[streamPos] % charSet.length;
            word += charSet[charIdx];
            streamPos++;
        }
        
        return word.charAt(0).toUpperCase() + word.slice(1);
    }
    
    /**
     * Generate list of words
     */
    static async generateWordList(seedBytes, length, count = 10) {
        const words = [];
        for (let i = 0; i < count; i++) {
            words.push(await this.generateWord(seedBytes, length, i));
        }
        return words;
    }
}

/**
 * Pattern generation for password examples
 */
class PatternGenerator {
    // Spreadsheet convention: letter=column (A-J), number=row (0-9)
    // A0=top-left, J0=top-right, A9=bottom-left, J9=bottom-right
    static BASIC_PATTERNS = [
        { pattern: 'A0 B1 C2 D3', description: 'Diagonal down-right' },
        { pattern: 'A0 B0 C0 D0', description: 'Top row (columns A-D)' },
        { pattern: 'A0 A1 A2 A3', description: 'Left column (rows 0-3)' }
    ];
    
    static SECURE_PATTERNS = [
        { pattern: 'B3 F7 D1 H5', description: 'High security spread' },
        { pattern: 'J0 I1 H2 G3', description: 'Diagonal from top-right' },
        { pattern: 'C3 G8 A5 F1 J9', description: 'Extended 5-token spread' }
    ];
    
    static MEMORABLE_PATTERNS = [
        { pattern: 'A0 B1 C2', description: '3-token diagonal' },
        { pattern: 'A9 B9 C9 D9', description: 'Bottom row (columns A-D)' },
        { pattern: 'A0 J0 A9 J9', description: 'Four corners' }
    ];
    
    /**
     * Generate password examples for given matrix
     */
    static generateExamples(matrix, patterns) {
        return patterns.map(({ pattern, description }) => ({
            pattern,
            description,
            password: SeedCardCrypto.generatePasswordFromPattern(matrix, pattern, true),
            passwordNoSep: SeedCardCrypto.generatePasswordFromPattern(matrix, pattern, false)
        }));
    }

    /**
     * Memory cleanup utilities for sensitive data
     */
    static secureZeroFill(array) {
        if (array && array.fill) {
            array.fill(0);
        }
    }

    static cleanupByteArrays(...arrays) {
        arrays.forEach(array => {
            if (array instanceof Uint8Array || array instanceof ArrayBuffer) {
                SeedCardCrypto.secureZeroFill(new Uint8Array(array));
            }
        });
    }

    static cleanupMatrix(matrix) {
        if (Array.isArray(matrix)) {
            matrix.forEach(row => {
                if (Array.isArray(row)) {
                    row.fill('');
                }
            });
            matrix.length = 0;
        }
    }
}

/**
 * Password entropy analysis utilities
 */
class EntropyAnalyzer {
    
    /**
     * Calculate bits of entropy per token
     */
    static calculateTokenEntropy(alphabetSize = null) {
        if (alphabetSize === null) {
            alphabetSize = CONFIG.ALPHABET.length;
        }
        return Math.log2(Math.pow(alphabetSize, CONFIG.CHARS_PER_TOKEN));
    }
    
    /**
     * Calculate total entropy for a password with given number of tokens
     */
    static calculatePasswordEntropy(numTokens, alphabetSize = null) {
        const tokenEntropy = this.calculateTokenEntropy(alphabetSize);
        return tokenEntropy * numTokens;
    }
    
    /**
     * Calculate entropy for coordinate pattern selection
     */
    static calculatePatternEntropy(coordinates) {
        if (!coordinates || coordinates.length === 0) return 0;
        
        const numTokens = coordinates.length;
        const totalPositions = CONFIG.TOKENS_WIDE * CONFIG.TOKENS_TALL; // 100
        
        // Entropy from choosing specific coordinates
        // This is the entropy of selecting specific positions, not the token values themselves
        if (numTokens === 1) {
            return Math.log2(totalPositions);
        } else {
            // For multiple tokens, consider combinations (order matters for passwords)
            // Using permutations: P(n,r) = n!/(n-r)!
            let arrangements = 1;
            for (let i = 0; i < numTokens; i++) {
                arrangements *= (totalPositions - i);
            }
            return Math.log2(arrangements);
        }
    }
    
    /**
     * Calculate entropy for memorized word component
     */
    static calculateMemorizedWordEntropy(wordLength, charsetSize = 26) {
        if (wordLength <= 0) return 0;
        return Math.log2(Math.pow(charsetSize, wordLength));
    }
    
    /**
     * Calculate entropy for PIN/numeric code component
     */
    static calculatePINEntropy(pinLength) {
        if (pinLength <= 0) return 0;
        return Math.log2(Math.pow(10, pinLength)); // 10 possible digits per position
    }
    
    /**
     * Calculate total memorized components entropy (word + PIN + punctuation + order)
     */
    static calculateMemorizedComponentsEntropy(wordLength = 6, pinLength = 4, punctuationCount = 1) {
        const wordEntropy = this.calculateMemorizedWordEntropy(wordLength, 26);
        const pinEntropy = this.calculatePINEntropy(pinLength);
        const punctuationEntropy = this.calculatePunctuationEntropy(punctuationCount, 32);
        const orderEntropy = Math.log2(6); // Basic ordering variations
        
        return {
            word: wordEntropy,
            pin: pinEntropy, 
            punctuation: punctuationEntropy,
            order: orderEntropy,
            total: wordEntropy + pinEntropy + punctuationEntropy + orderEntropy
        };
    }
    
    /**
     * Calculate entropy for a string based on character set size and length
     */
    static calculateStringEntropy(str, charsetSize = null) {
        if (!str || str.length === 0) return 0;
        
        // Auto-detect charset size if not provided
        if (charsetSize === null) {
            const uniqueChars = new Set(str.toLowerCase()).size;
            
            // Estimate charset based on content
            const hasDigits = /\d/.test(str);
            const hasLower = /[a-z]/.test(str);
            const hasUpper = /[A-Z]/.test(str);
            const hasSpecial = /[^a-zA-Z0-9]/.test(str);
            
            // Conservative charset size estimation
            let estimatedCharset = 0;
            if (hasDigits) estimatedCharset += 10;
            if (hasLower) estimatedCharset += 26;
            if (hasUpper) estimatedCharset += 26;
            if (hasSpecial) estimatedCharset += 32; // Common punctuation
            
            charsetSize = Math.max(estimatedCharset, uniqueChars);
        }
        
        return Math.log2(Math.pow(charsetSize, str.length));
    }
    
    /**
     * Calculate entropy for punctuation separators
     */
    static calculatePunctuationEntropy(numPunctuation, charsetSize = 32) {
        if (numPunctuation <= 0) return 0;
        return Math.log2(Math.pow(charsetSize, numPunctuation));
    }
    
    /**
     * Calculate rolling token entropy (time-based uncertainty)
     */
    static calculateRollingTokenEntropy(rotationPeriodDays = 90) {
        // Conservative estimate: attacker knows approximate time period
        const timeUncertaintyBits = Math.log2(rotationPeriodDays / 7); // Weekly uncertainty
        return Math.max(1.0, timeUncertaintyBits); // Minimum 1 bit
    }
    
    /**
     * Analyze coordinate pattern entropy
     */
    static analyzeCoordinatePattern(coordinates) {
        if (!coordinates || coordinates.length === 0) {
            return {
                token_entropy: 0,
                pattern_entropy: 0,
                effective_entropy: 0,
                security_level: 'NONE',
                security_color: 'gray',
                num_tokens: 0
            };
        }
        
        const numTokens = coordinates.length;
        const tokenEntropy = this.calculatePasswordEntropy(numTokens);
        const patternEntropy = this.calculatePatternEntropy(coordinates);
        
        // Effective entropy is the minimum of token and pattern entropy
        // (pattern entropy is usually much larger, so token entropy dominates)
        const effectiveEntropy = Math.min(tokenEntropy, patternEntropy);
        
        // Security classification (RFC 4086 compliant)
        let securityLevel, securityColor;
        if (effectiveEntropy < 29) {
            securityLevel = 'INSUFFICIENT';
            securityColor = 'red';
        } else if (effectiveEntropy < 48) {
            securityLevel = 'BASIC';
            securityColor = 'orange';
        } else if (effectiveEntropy < 64) {
            securityLevel = 'GOOD';
            securityColor = 'green';
        } else if (effectiveEntropy < 80) {
            securityLevel = 'STRONG';
            securityColor = 'darkgreen';
        } else {
            securityLevel = 'EXCELLENT';
            securityColor = 'blue';
        }
        
        return {
            token_entropy: Math.round(tokenEntropy * 10) / 10,
            pattern_entropy: Math.round(patternEntropy * 10) / 10,
            effective_entropy: Math.round(effectiveEntropy * 10) / 10,
            security_level: securityLevel,
            security_color: securityColor,
            num_tokens: numTokens,
            alphabet_size: CONFIG.ALPHABET.length,
            chars_per_token: CONFIG.CHARS_PER_TOKEN
        };
    }
    
    /**
     * Analyze composite password (tokens + memorized + separators)
     */
    static analyzeCompositePassword(options = {}) {
        const {
            numFixedTokens = 2,
            numRollingTokens = 1,
            memorizedWordLength = 6,
            numSeparators = 4,
            rotationDays = 90,
            includeOrderEntropy = true
        } = options;
        
        // Calculate individual components
        const fixedTokenEntropy = this.calculatePasswordEntropy(numFixedTokens);
        const rollingTokenEntropy = this.calculatePasswordEntropy(numRollingTokens);
        const rollingTimeEntropy = this.calculateRollingTokenEntropy(rotationDays);
        const memorizedEntropy = this.calculateMemorizedWordEntropy(memorizedWordLength);
        const separatorEntropy = this.calculatePunctuationEntropy(numSeparators);
        
        // Component ordering entropy
        const totalComponents = 3 + (memorizedWordLength > 0 ? 1 : 0); // tokens + rolling + memorized + separators
        const orderEntropy = includeOrderEntropy ? Math.log2(this.factorial(totalComponents)) : 0;
        
        // Total entropy is sum of independent components
        const totalEntropy = fixedTokenEntropy + rollingTokenEntropy + rollingTimeEntropy + 
                           memorizedEntropy + separatorEntropy + orderEntropy;
        
        // Security classification
        let securityLevel, securityColor;
        if (totalEntropy < 29) {
            securityLevel = 'INSUFFICIENT';
            securityColor = 'red';
        } else if (totalEntropy < 48) {
            securityLevel = 'BASIC';
            securityColor = 'orange';
        } else if (totalEntropy < 64) {
            securityLevel = 'GOOD';
            securityColor = 'green';
        } else if (totalEntropy < 80) {
            securityLevel = 'STRONG';
            securityColor = 'darkgreen';
        } else {
            securityLevel = 'EXCELLENT';
            securityColor = 'blue';
        }
        
        return {
            fixed_token_entropy: Math.round(fixedTokenEntropy * 10) / 10,
            rolling_token_entropy: Math.round(rollingTokenEntropy * 10) / 10,
            rolling_time_entropy: Math.round(rollingTimeEntropy * 10) / 10,
            memorized_word_entropy: Math.round(memorizedEntropy * 10) / 10,
            separator_entropy: Math.round(separatorEntropy * 10) / 10,
            order_entropy: Math.round(orderEntropy * 10) / 10,
            total_entropy: Math.round(totalEntropy * 10) / 10,
            security_level: securityLevel,
            security_color: securityColor,
            num_fixed_tokens: numFixedTokens,
            num_rolling_tokens: numRollingTokens,
            memorized_word_length: memorizedWordLength,
            num_separators: numSeparators,
            rotation_days: rotationDays,
            include_order_entropy: includeOrderEntropy
        };
    }
    
    /**
     * Helper function to calculate factorial
     */
    static factorial(n) {
        if (n <= 1) return 1;
        return n * this.factorial(n - 1);
    }
    
    /**
     * Format entropy for display
     */
    static formatEntropy(entropy, label = '') {
        const rounded = Math.round(entropy * 10) / 10;
        return label ? `${label}: ${rounded} bits` : `${rounded} bits`;
    }
    
    /**
     * Get security level badge HTML
     */
    static getSecurityBadge(securityLevel, securityColor) {
        const colorMap = {
            'red': '#dc3545',
            'orange': '#fd7e14', 
            'green': '#28a745',
            'darkgreen': '#155724',
            'blue': '#007bff',
            'gray': '#6c757d'
        };
        
        const color = colorMap[securityColor] || '#6c757d';
        return `<span class="security-badge" style="background-color: ${color}; color: white; padding: 2px 6px; border-radius: 3px; font-size: 0.8em; font-weight: bold;">${securityLevel}</span>`;
    }
}

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        SeedCardCrypto,
        SeedSources,
        WordGenerator,
        PatternGenerator,
        EntropyAnalyzer,
        LabelUtils,
        MemoryUtils,
        Argon2Worker,
        Argon2WorkerPool,
        CONFIG,
        BASE_CONFIGS,
        MEMORY_OPTIONS
    };
} else {
    // Browser globals
    window.SeedCardCrypto = SeedCardCrypto;
    window.SeedSources = SeedSources;
    window.WordGenerator = WordGenerator;
    window.PatternGenerator = PatternGenerator;
    window.EntropyAnalyzer = EntropyAnalyzer;
    window.LabelUtils = LabelUtils;
    window.MemoryUtils = MemoryUtils;
    window.Argon2Worker = Argon2Worker;
    window.Argon2WorkerPool = Argon2WorkerPool;
    window.CONFIG = CONFIG;
    window.BASE_CONFIGS = BASE_CONFIGS;
    window.MEMORY_OPTIONS = MEMORY_OPTIONS;
}
