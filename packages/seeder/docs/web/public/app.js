/**
 * Seed Card Web Application
 * Main application logic and UI handling
 */

/* ============================================
 * CONSTANTS AND CONFIGURATION
 * ============================================ */

const UI_CONSTANTS = {
    ANIMATION_DURATION: 300,
    DEBOUNCE_DELAY: 500,
    SCROLL_OFFSET: 80,
    PROGRESS_UPDATE_INTERVAL: 50,
    AUTO_GENERATION_DELAY: 800,
    BATCH_CHUNK_SIZE: 10,
    MAX_RETRY_ATTEMPTS: 3
};

/* ============================================
 * SECURITY UTILITIES
 * ============================================ */

/**
 * Security utility class for input validation and sanitization
 */
class SecurityUtils {
    /**
     * Sanitize HTML to prevent XSS attacks
     * @param {string} input - Raw input string
     * @returns {string} - Sanitized string
     */
    static sanitizeHTML(input) {
        if (typeof input !== 'string') return '';
        
        return input
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#x27;')
            .replace(/\//g, '&#x2F;');
    }
    
    /**
     * Validate seed input (simple phrase)
     * @param {string} input - Seed phrase
     * @returns {object} - Validation result
     */
    static validateSeedPhrase(input) {
        if (typeof input !== 'string') {
            return { valid: false, error: 'Input must be a string' };
        }
        
        const trimmed = input.trim();
        if (trimmed.length < 1) {
            return { valid: false, error: 'Seed phrase cannot be empty' };
        }
        
        if (trimmed.length > 1000) {
            return { valid: false, error: 'Seed phrase too long (max 1000 characters)' };
        }
        
        // Check for suspicious patterns
        if (/<script/i.test(trimmed) || /javascript:/i.test(trimmed)) {
            return { valid: false, error: 'Invalid characters detected' };
        }
        
        return { valid: true, sanitized: trimmed };
    }
    
    /**
     * Validate BIP-39 mnemonic
     * @param {string} input - Mnemonic phrase
     * @returns {object} - Validation result
     */
    static validateBIP39Mnemonic(input) {
        if (typeof input !== 'string') {
            return { valid: false, error: 'Input must be a string' };
        }
        
        const trimmed = input.trim().toLowerCase();
        const words = trimmed.split(/\s+/).filter(word => word.length > 0);
        
        if (words.length === 0) {
            return { valid: false, error: 'Mnemonic cannot be empty' };
        }
        
        if (words.length % 3 !== 0 || words.length < 12 || words.length > 24) {
            return { valid: false, error: 'Mnemonic must be 12-24 words (multiple of 3)' };
        }
        
        // Basic word validation - check for common issues
        for (const word of words) {
            if (word.length > 50 || !/^[a-z]+$/.test(word)) {
                return { valid: false, error: 'Invalid word format in mnemonic' };
            }
        }
        
        return { valid: true, sanitized: words.join(' ') };
    }
    
    /**
     * Validate domain input
     * @param {string} input - Domain string
     * @returns {object} - Validation result
     */
    static validateDomain(input) {
        if (typeof input !== 'string') {
            return { valid: false, error: 'Domain must be a string' };
        }
        
        const trimmed = input.trim();
        if (trimmed.length === 0) {
            return { valid: true, sanitized: 'SYS' }; // Default fallback
        }
        
        if (trimmed.length > 100) {
            return { valid: false, error: 'Domain too long (max 100 characters)' };
        }
        
        // Allow alphanumeric, dots, hyphens, and @ for email-style domains
        if (!/^[a-zA-Z0-9@._-]+$/.test(trimmed)) {
            return { valid: false, error: 'Domain contains invalid characters' };
        }
        
        return { valid: true, sanitized: trimmed };
    }
    
    /**
     * Validate card date input for flexible labeling
     * @param {string} input - Card date string
     * @returns {object} - Validation result
     */
    static validateCardDate(input) {
        if (typeof input !== 'string') {
            return { valid: false, error: 'Card date must be a string' };
        }
        
        const trimmed = input.trim();
        if (trimmed.length === 0) {
            return { valid: true, sanitized: '' }; // Empty is allowed (optional field)
        }
        
        if (trimmed.length > 50) {
            return { valid: false, error: 'Card date too long (max 50 characters)' };
        }
        
        // Sanitize to ASCII alphanumeric + safe characters (hyphens, underscores)
        const sanitized = trimmed.replace(/[^a-zA-Z0-9\-_]/g, '-').replace(/-+/g, '-').replace(/^-|-$/g, '');
        
        if (sanitized.length === 0) {
            return { valid: false, error: 'Card date contains no valid characters' };
        }
        
        if (sanitized.length < 4) {
            return { valid: false, error: 'Card date too short (minimum 4 characters)' };
        }
        
        return { valid: true, sanitized: sanitized };
    }
    
    /**
     * Rate limiting utility
     * @param {string} operation - Operation identifier
     * @param {number} maxAttempts - Maximum attempts allowed
     * @param {number} windowMs - Time window in milliseconds
     * @returns {boolean} - Whether operation is allowed
     */
    static checkRateLimit(operation, maxAttempts = 10, windowMs = 60000) {
        const now = Date.now();
        const key = `rateLimit_${operation}`;
        
        try {
            const stored = localStorage.getItem(key);
            let attempts = stored ? JSON.parse(stored) : { count: 0, firstAttempt: now };
            
            // Reset if window has passed
            if (now - attempts.firstAttempt > windowMs) {
                attempts = { count: 1, firstAttempt: now };
            } else {
                attempts.count++;
            }
            
            localStorage.setItem(key, JSON.stringify(attempts));
            
            return attempts.count <= maxAttempts;
        } catch (error) {
            console.warn('Rate limiting storage error:', error);
            return true; // Allow on storage errors
        }
    }
    
    /**
     * Clear sensitive data from memory
     * @param {Object|Array} obj - Object to clear
     */
    static secureClear(obj) {
        if (!obj) return;
        
        try {
            if (typeof obj === 'string') {
                // Can't actually clear string in JS, but we can overwrite references
                return '';
            }
            
            if (Array.isArray(obj)) {
                for (let i = 0; i < obj.length; i++) {
                    obj[i] = null;
                }
                obj.length = 0;
            } else if (typeof obj === 'object') {
                for (const key in obj) {
                    if (obj.hasOwnProperty(key)) {
                        try {
                            obj[key] = null;
                            delete obj[key];
                        } catch (e) {
                            // Property might not be configurable, just set to null
                            try {
                                obj[key] = null;
                            } catch (e2) {
                                // Property is completely protected, skip it
                            }
                        }
                    }
                }
            }
        } catch (error) {
            // Ignore cleanup errors - object might be frozen/sealed
        }
    }
    
    /**
     * Generate a cryptographically secure random ID
     * @param {number} length - Length of the ID
     * @returns {string} - Random ID
     */
    static generateSecureId(length = 16) {
        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
        let result = '';
        
        // Use crypto.getRandomValues if available
        if (window.crypto && window.crypto.getRandomValues) {
            const array = new Uint8Array(length);
            window.crypto.getRandomValues(array);
            for (let i = 0; i < length; i++) {
                result += chars[array[i] % chars.length];
            }
        } else {
            // Fallback to Math.random (less secure)
            console.warn('Crypto API not available, using less secure random generation');
            for (let i = 0; i < length; i++) {
                result += chars[Math.floor(Math.random() * chars.length)];
            }
        }
        
        return result;
    }
}

/* ============================================
 * ENTROPY ANALYSIS UTILITIES
 * ============================================ */

// EntropyAnalyzer is imported from crypto.js

/* ============================================
 * UTILITY FUNCTIONS
 * ============================================ */

/**
 * Announce status to screen readers
 * @param {string} message - Message to announce
 * @param {boolean} isAlert - Whether this is an alert (assertive) or status (polite)
 */
function announceToScreenReader(message, isAlert = false) {
    const regionId = isAlert ? 'alert-live-region' : 'status-live-region';
    const region = document.getElementById(regionId);
    if (region) {
        region.textContent = message;
        // Clear after announcing to allow repeat announcements
        setTimeout(() => region.textContent = '', 1000);
    }
}

/**
 * Show visual feedback for keyboard shortcuts
 * @param {string} action - Description of the action performed
 */
function showShortcutFeedback(action) {
    // Visual feedback
    const feedback = document.createElement('div');
    feedback.className = 'shortcut-feedback';
    feedback.textContent = action;
    feedback.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        background: rgba(37, 99, 235, 0.9);
        color: white;
        padding: 8px 16px;
        border-radius: 6px;
        font-size: 14px;
        font-weight: 500;
        z-index: 10000;
        animation: shortcutSlideIn 0.3s ease-out;
        pointer-events: none;
    `;
    
    document.body.appendChild(feedback);
    
    // Remove after animation
    setTimeout(() => {
        feedback.style.animation = 'shortcutSlideOut 0.3s ease-in';
        setTimeout(() => feedback.remove(), 300);
    }, 1500);
    
    // Announce to screen readers
    announceToScreenReader(action.replace(/[🎯📋✏️🌐🔄🔑]/g, '').trim());
}

/**
 * Show progress indicator for long operations
 * @param {string} message - Progress message
 * @param {number} progress - Progress percentage (0-100)
 */
function showProgress(message, progress = 0) {
    let progressContainer = document.getElementById('progress-container');
    if (!progressContainer) {
        progressContainer = document.createElement('div');
        progressContainer.id = 'progress-container';
        progressContainer.className = 'progress-container';
        document.body.appendChild(progressContainer);
    }
    
    progressContainer.innerHTML = `
        <div class="progress-modal">
            <div class="progress-content">
                <div class="progress-message">${message}</div>
                <div class="progress-bar">
                    <div class="progress-fill" style="width: ${progress}%"></div>
                </div>
                <div class="progress-percentage">${Math.round(progress)}%</div>
            </div>
        </div>
    `;
    progressContainer.style.display = 'block';
}

/**
 * Hide progress indicator
 */
function hideProgress() {
    const progressContainer = document.getElementById('progress-container');
    if (progressContainer) {
        progressContainer.style.display = 'none';
    }
}

/**
 * Validate input and provide visual feedback
 * @param {HTMLElement} input - Input element to validate
 * @param {Function} validator - Validation function
 * @param {string} errorMessage - Error message to display
 */
function validateInput(input, validator, errorMessage) {
    const isValid = validator(input.value.trim());
    const feedbackElement = input.parentElement.querySelector('.input-feedback') || createInputFeedback(input);
    
    // Remove existing classes
    input.classList.remove('valid', 'invalid');
    feedbackElement.classList.remove('feedback-success', 'feedback-error');
    
    if (input.value.trim() === '') {
        // Empty input - neutral state
        feedbackElement.textContent = '';
        feedbackElement.style.display = 'none';
    } else if (isValid) {
        // Valid input
        input.classList.add('valid');
        feedbackElement.classList.add('feedback-success');
        feedbackElement.innerHTML = '<span class="feedback-icon">✓</span> Valid';
        feedbackElement.style.display = 'block';
    } else {
        // Invalid input
        input.classList.add('invalid');
        feedbackElement.classList.add('feedback-error');
        feedbackElement.innerHTML = `<span class="feedback-icon">⚠</span> ${SecurityUtils.sanitizeHTML(errorMessage)}`;
        feedbackElement.style.display = 'block';
    }
}

/**
 * Create input feedback element
 * @param {HTMLElement} input - Input element
 */
function createInputFeedback(input) {
    const feedback = document.createElement('div');
    feedback.className = 'input-feedback';
    input.parentElement.appendChild(feedback);
    return feedback;
}

/**
 * Validators for different input types
 */
const validators = {
    simplePhrase: (value) => value.length >= 3,
    bip39Mnemonic: (value) => {
        const words = value.split(/\s+/).filter(w => w.length > 0);
        return words.length >= 12 && words.length <= 24 && words.length % 3 === 0;
    },
    slip39Share: (value) => {
        const words = value.split(/\s+/).filter(w => w.length > 0);
        return words.length === 20 || words.length === 33;
    },
    sha512Hash: (value) => /^[a-fA-F0-9]{128}$/.test(value),
    cardDomain: (value) => /^[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9]$/.test(value) && value.length >= 2 && value.length <= 50,
    cardDate: (value) => {
        if (value.length === 0) return true; // Optional field
        const sanitized = value.replace(/[^a-zA-Z0-9\-_]/g, '-').replace(/-+/g, '-').replace(/^-|-$/g, '');
        return sanitized.length >= 4 && sanitized.length <= 50;
    }
};

class SeedCardApp {
    constructor() {
        // Initialize the application
        this.currentMatrix = null;
        this.currentSeedBytes = null;
        this.currentCardId = null;
        this.isGenerating = false;
        this.lastAutoGenerationTime = 0;
        this.statusTimeout = null; // For auto-expiring status messages
        
        // Security: Track sensitive data for cleanup
        this.sensitiveData = new Set();
        
        // Initialize localStorage and preferences
        this.preferences = this.loadPreferences();
        
        this.initializeEventListeners();
        this.initializeDemoMode();
        this.initializeInputValidation();
        this.initializeKeyboardShortcuts();
        this.initializeScrollNavigation();
        this.initializeRouting(); // Add route handling
        this.updateNavigationMenu(); // Set up initial navigation menu
        this.restoreUserPreferences();
        this.initializeStatusIndicator();
        this.initializeSecurityFeatures();
        this.initializeModals(); // Initialize modal functionality
        
        // Show initial security status
        setTimeout(() => this.showSecurityStatus(), 1000);
        
        // Trigger initial entropy calculations
        setTimeout(() => {
            this.performInitialValidation();
            this.updatePasswordEntropySummary();
        }, 500);
        
        // Probe memory limits before enabling generation
        setTimeout(() => this.initializeMemoryLimits(), 100);
        
        // Generate initial demo card (after memory probe completes)
        setTimeout(() => this.generateInitialCard(), 2500);
    }
    
    /**
     * Probe browser memory limits and configure Argon2 memory dropdown
     */
    async initializeMemoryLimits() {
        const memorySelect = document.getElementById('argon2-memory');
        const probeStatus = document.getElementById('memory-probe-status');
        
        if (!memorySelect) {
            console.warn('Memory selector not found');
            return;
        }
        
        // Show that we're testing memory
        if (probeStatus) {
            probeStatus.textContent = '(testing limits...)';
            probeStatus.style.color = '#f59e0b'; // Warning yellow
        }
        this.updateStatus('Testing browser memory limits...', 'info');
        
        try {
            // Probe available memory
            const { maxMemory, tested, argon2Broken, skippedProbe } = await MemoryUtils.probeMaxMemory();
            
            // Store max memory for reference
            this.maxArgon2Memory = maxMemory;
            this.argon2Broken = argon2Broken;
            
            // When probe is skipped (workers available), show appropriate status
            if (skippedProbe) {
                const isSafari = /^((?!chrome|android).)*safari/i.test(navigator.userAgent);
                const statusText = isSafari ? '(Safari: 64MB/worker)' : `(default: ${maxMemory}MB)`;
                if (probeStatus) {
                    probeStatus.textContent = statusText;
                    probeStatus.style.color = '#22c55e'; // Success green
                }
                this.updateStatus(`Memory: ${maxMemory}MB (Web Workers enabled)`, 'success', 3000);
                this.initializeParallelismSelector();
                return;
            }
            
            // If Argon2 is completely broken, log warning but don't auto-switch
            if (argon2Broken) {
                console.error('🚨 Argon2 WASM completely broken - ALL memory tests failed!');
                console.error('🔍 This may indicate a WASM initialization issue or browser incompatibility');
                
                // Update status to warn user
                if (probeStatus) {
                    probeStatus.textContent = '(WASM broken!)';
                    probeStatus.style.color = '#ef4444'; // Error red
                }
                this.updateStatus('⚠️ Argon2 WASM failed to initialize - check console for details', 'error', 10000);
                
                // Initialize parallelism selector anyway
                this.initializeParallelismSelector();
                return;
            }
            
            // Disable options that exceed max memory and mark the max
            const options = memorySelect.querySelectorAll('option');
            options.forEach(option => {
                const mb = parseInt(option.value);
                if (mb > maxMemory) {
                    option.disabled = true;
                    // Add "exceeds limit" indicator
                    if (!option.textContent.includes('exceeds')) {
                        option.textContent = option.textContent + ' - exceeds limit';
                    }
                } else if (mb === maxMemory) {
                    // Mark the max available option
                    if (!option.textContent.includes('max')) {
                        option.textContent = option.textContent + ' (max)';
                    }
                }
            });
            
            // Get recommended memory (one step below max for stability)
            const recommendedMemory = MemoryUtils.getRecommendedMemory(maxMemory);
            
            // Set the dropdown to recommended value if current selection exceeds max
            const currentValue = parseInt(memorySelect.value);
            if (currentValue > maxMemory) {
                memorySelect.value = recommendedMemory.toString();
            }
            
            // Update probe status
            if (probeStatus) {
                probeStatus.textContent = `(max: ${maxMemory}MB)`;
                probeStatus.style.color = '#22c55e'; // Success green
            } else {
                console.warn('⚠️ memory-probe-status element not found for update');
            }
            
            // Update status with result
            this.updateStatus(`Memory limit: ${maxMemory}MB max available`, 'success', 3000);
            
        } catch (error) {
            console.error('Memory probe failed:', error);
            if (probeStatus) {
                probeStatus.textContent = '(using defaults)';
                probeStatus.style.color = '#f59e0b'; // Warning yellow
            }
            this.updateStatus('Memory probe failed - using defaults', 'warning', 3000);
        }
        
        // Initialize CPU parallelism selector
        this.initializeParallelismSelector();
    }
    
    /**
     * Initialize CPU parallelism selector based on detected cores
     * Note: Argon2 parallelism (lanes) is a cryptographic parameter that affects
     * the hash output. It can exceed CPU cores - Argon2 will simulate multiple
     * lanes on fewer cores, just slower. We show cores for reference only.
     */
    initializeParallelismSelector() {
        const parallelismSelect = document.getElementById('argon2-parallelism');
        const parallelismStatus = document.getElementById('parallelism-status');
        
        if (!parallelismSelect) {
            console.warn('Parallelism selector not found');
            return;
        }
        
        const detectedCores = MemoryUtils.detectCPUCores();
        this.detectedCores = detectedCores;
        
        // Update option labels to show relationship to cores (but don't disable!)
        // Argon2 parallelism is a crypto param - higher values are valid, just slower
        const parallelismOptions = parallelismSelect.querySelectorAll('option');
        parallelismOptions.forEach(option => {
            const lanes = parseInt(option.value);
            // Remove any previous annotations
            option.textContent = option.value + (lanes === 1 ? ' lane' : ' lanes');
            if (lanes === detectedCores) {
                option.textContent += ' (= cores)';
            } else if (lanes > detectedCores) {
                option.textContent += ' (> cores)';
            }
            // Don't disable - all values are valid for Argon2
            option.disabled = false;
        });
        
        // Default to cores or 8, whichever is lower (good balance)
        const recommendedParallelism = Math.min(detectedCores, 8);
        parallelismSelect.value = recommendedParallelism.toString();
        
        if (parallelismStatus) {
            parallelismStatus.textContent = `(${detectedCores} cores detected)`;
            parallelismStatus.style.color = '#22c55e';
        }
        
    }
    
    /**
     * Initialize security features including cleanup handlers
     */
    initializeSecurityFeatures() {
        // Add page unload handler for secure cleanup
        window.addEventListener('beforeunload', () => {
            this.secureCleanup();
        });
        
        // Add page hide handler for mobile/tab switching
        window.addEventListener('pagehide', () => {
            this.secureCleanup();
        });
        
        // Add visibility change handler
        document.addEventListener('visibilitychange', () => {
            if (document.visibilityState === 'hidden') {
                this.secureCleanup();
            }
        });
        
        // Periodic cleanup every 5 minutes
        setInterval(() => {
            this.periodicCleanup();
        }, 5 * 60 * 1000);
    }
    
    /**
     * Register sensitive data for cleanup
     * @param {any} data - Sensitive data to track
     */
    registerSensitiveData(data) {
        this.sensitiveData.add(data);
    }
    
    /**
     * Initialize modal functionality
     */
    initializeModals() {
        // Setup token entropy modal
        const tokenModal = document.getElementById('token-entropy-modal');
        if (tokenModal) {
            tokenModal.classList.remove('show');
            tokenModal.style.display = 'none'; // Force hide initially
            
            // Close modal when clicking outside of it
            tokenModal.addEventListener('click', (event) => {
                if (event.target === tokenModal) {
                    this.hideTokenEntropyModal();
                }
            });
            
            // Set up close button
            const closeBtn = tokenModal.querySelector('.close-btn');
            if (closeBtn) {
                closeBtn.addEventListener('click', (e) => {
                    e.preventDefault();
                    e.stopPropagation();
                    this.hideTokenEntropyModal();
                });
            }
        }
        
        // Setup password entropy modal
        const passwordModal = document.getElementById('password-entropy-modal');
        if (passwordModal) {
            passwordModal.classList.remove('show');
            passwordModal.style.display = 'none'; // Force hide initially
            
            // Close modal when clicking outside of it
            passwordModal.addEventListener('click', (event) => {
                if (event.target === passwordModal) {
                    this.hidePasswordEntropyModal();
                }
            });
            
            // Set up close button
            const closeBtn = passwordModal.querySelector('.close-btn');
            if (closeBtn) {
                closeBtn.addEventListener('click', (e) => {
                    e.preventDefault();
                    e.stopPropagation();
                    this.hidePasswordEntropyModal();
                });
            }
        }
        
        // Close modals with Escape key
        document.addEventListener('keydown', (event) => {
            if (event.key === 'Escape') {
                this.hideTokenEntropyModal();
                this.hidePasswordEntropyModal();
            }
        });
        
        // Set up help button click handler
        const helpButton = document.getElementById('token-entropy-help-btn');
        if (helpButton) {
            helpButton.addEventListener('click', (e) => {
                e.preventDefault();
                e.stopPropagation();
                this.showTokenEntropyModal();
            });
        }
        
        // Set up navigation buttons (replace inline onclick handlers for CSP compliance)
        this.initializeNavigationButtons();
        
        // Set up threat analysis buttons
        this.initializeThreatAnalysisButtons();
    }
    
    /**
     * Initialize navigation buttons to replace inline onclick handlers
     */
    initializeNavigationButtons() {
        // Seed section -> Domain section
        document.querySelectorAll('.next-btn').forEach(btn => {
            const section = btn.closest('.form-section, .section-navigation');
            if (section) {
                const sectionId = section.closest('[id]')?.id || section.id;
                if (sectionId === 'seed-section' || section.closest('#seed-section')) {
                    btn.addEventListener('click', () => {
                        if (window.router) router.navigate('/config/domain');
                        else this.navigateToRoute('/config/domain');
                    });
                } else if (sectionId === 'domain-section' || section.closest('#domain-section')) {
                    // Domain next button - handled separately with ID
                } else if (sectionId === 'results' || section.closest('#results')) {
                    btn.addEventListener('click', () => {
                        if (window.router) router.navigate('/examples');
                        else this.navigateToRoute('/examples');
                    });
                }
            }
        });
        
        document.querySelectorAll('.prev-btn').forEach(btn => {
            const section = btn.closest('.form-section, .section-navigation');
            if (section) {
                const sectionId = section.closest('[id]')?.id || section.id;
                if (sectionId === 'domain-section' || section.closest('#domain-section')) {
                    btn.addEventListener('click', () => {
                        if (window.router) router.navigate('/config/seed');
                        else this.navigateToRoute('/config/seed');
                    });
                } else if (sectionId === 'results' || section.closest('#results')) {
                    btn.addEventListener('click', () => {
                        if (window.router) router.navigate('/config/domain');
                        else this.navigateToRoute('/config/domain');
                    });
                } else if (sectionId === 'password-examples' || section.closest('#password-examples')) {
                    btn.addEventListener('click', () => {
                        if (window.router) router.navigate('/tokens');
                        else this.navigateToRoute('/tokens');
                    });
                }
            }
        });
        
        // Domain next button (Generate Hash) - special handling
        const domainNextBtn = document.getElementById('domain-next-btn');
        if (domainNextBtn) {
            domainNextBtn.addEventListener('click', async () => {
                try {
                    await this.handleGenerate();
                    if (window.router) router.navigate('/tokens');
                    else this.navigateToRoute('/tokens');
                } catch (err) {
                    console.error('Generation failed:', err);
                    if (window.router) router.navigate('/tokens');
                    else this.navigateToRoute('/tokens');
                }
            });
        }
        
        // Card compromise help button
        const cardCompromiseBtn = document.getElementById('card-compromise-help-btn');
        if (cardCompromiseBtn) {
            cardCompromiseBtn.addEventListener('click', () => {
                if (window.showCardCompromiseModal) showCardCompromiseModal();
            });
        }
        
        // Password entropy help buttons (using data-example attribute)
        document.querySelectorAll('.entropy-help-btn[data-example]').forEach(btn => {
            const exampleId = btn.getAttribute('data-example');
            if (exampleId) {
                btn.addEventListener('click', () => {
                    if (window.showPasswordEntropyForExample) showPasswordEntropyForExample(exampleId);
                });
            }
        });
    }
    
    /**
     * Initialize threat analysis buttons
     */
    initializeThreatAnalysisButtons() {
        const resetBtn = document.getElementById('reset-threat-btn');
        if (resetBtn) {
            resetBtn.addEventListener('click', () => {
                if (window.resetThreatAnalysis) resetThreatAnalysis();
            });
        }
        
        document.querySelectorAll('.preset-btn[data-preset]').forEach(btn => {
            const preset = btn.getAttribute('data-preset');
            if (preset) {
                btn.addEventListener('click', () => {
                    if (window.setPreset) setPreset(preset);
                });
            }
        });
    }
    
    /**
     * Show token entropy modal
     */
    showTokenEntropyModal() {
        const modal = document.getElementById('token-entropy-modal');
        if (modal) {
            modal.style.display = 'block';
            modal.classList.add('show');
            document.body.style.overflow = 'hidden';
        }
    }
    
    /**
     * Hide token entropy modal
     */
    hideTokenEntropyModal() {
        const modal = document.getElementById('token-entropy-modal');
        if (modal) {
            modal.classList.remove('show');
            modal.style.display = 'none';
            document.body.style.overflow = 'auto';
        }
    }
    
    /**
     * Hide password entropy modal
     */
    hidePasswordEntropyModal() {
        const modal = document.getElementById('password-entropy-modal');
        if (modal) {
            modal.classList.remove('show');
            modal.style.display = 'none';
            document.body.style.overflow = 'auto';
        }
    }
    
    /**
     * Perform secure cleanup of sensitive data
     */
    secureCleanup() {
        try {
            // Clear current sensitive data
            if (this.currentSeedBytes) {
                SecurityUtils.secureClear(this.currentSeedBytes);
                this.currentSeedBytes = null;
            }
            
            if (this.currentMatrix) {
                SecurityUtils.secureClear(this.currentMatrix);
                this.currentMatrix = null;
            }
            
            // Clear tracked sensitive data
            for (const data of this.sensitiveData) {
                SecurityUtils.secureClear(data);
            }
            this.sensitiveData.clear();
            
            // Clear input fields that might contain sensitive data
            const sensitiveInputs = document.querySelectorAll(
                '#simple-phrase, #bip39-mnemonic, #bip39-passphrase, .slip39-share'
            );
            sensitiveInputs.forEach(input => {
                if (input.value) {
                    input.value = '';
                }
            });
            
            // Force garbage collection if available
            if (window.gc && typeof window.gc === 'function') {
                window.gc();
            }
        } catch (error) {
            // Silently ignore cleanup errors - they're not critical
        }
    }
    
    /**
     * Periodic cleanup of old sensitive data
     */
    periodicCleanup() {
        // Clear old rate limiting data
        try {
            const now = Date.now();
            for (let i = 0; i < localStorage.length; i++) {
                const key = localStorage.key(i);
                if (key && key.startsWith('rateLimit_')) {
                    const data = JSON.parse(localStorage.getItem(key));
                    if (now - data.firstAttempt > 3600000) { // 1 hour
                        localStorage.removeItem(key);
                    }
                }
            }
        } catch (error) {
            console.warn('Error during periodic cleanup:', error);
        }
    }
    
    /**
     * Load user preferences from localStorage
     */
    loadPreferences() {
        try {
            const saved = localStorage.getItem('seedcard-preferences');
            return saved ? JSON.parse(saved) : {
                lastSeedType: 'simple',
                lastGenerationMode: 'single',
                domainHistory: [],
                maxHistoryItems: 10,
                showAdvancedOptions: false,
                preferredCardFormat: 'standard'
            };
        } catch (error) {
            console.warn('Failed to load preferences:', error);
            return {
                lastSeedType: 'simple',
                lastGenerationMode: 'single',
                domainHistory: [],
                maxHistoryItems: 10,
                showAdvancedOptions: false,
                preferredCardFormat: 'standard'
            };
        }
    }
    
    /**
     * Save user preferences to localStorage
     */
    savePreferences() {
        try {
            localStorage.setItem('seedcard-preferences', JSON.stringify(this.preferences));
        } catch (error) {
            console.warn('Failed to save preferences:', error);
        }
    }
    
    /**
     * Restore user preferences to UI
     */
    restoreUserPreferences() {
        // Restore seed type
        const seedTypeRadio = document.querySelector(`input[name="seedType"][value="${this.preferences.lastSeedType}"]`);
        if (seedTypeRadio) {
            seedTypeRadio.checked = true;
            this.handleSeedTypeChange({ target: seedTypeRadio });
        }
        
        // Restore generation mode
        const genModeRadio = document.querySelector(`input[name="genMode"][value="${this.preferences.lastGenerationMode}"]`);
        if (genModeRadio) {
            genModeRadio.checked = true;
            this.handleGenModeChange({ target: genModeRadio });
        }
        
        // Setup domain history autocomplete
        this.setupDomainAutocomplete();
    }
    
    /**
     * Handle mode changes for UI updates
     */
    handleModeChange() {
        const checkedMode = document.querySelector('input[name="seedType"]:checked');
        if (checkedMode) {
            this.handleSeedTypeChange({ target: checkedMode });
        }
    }
    
    /**
     * Add domain to history and save preferences
     */
    addToHistory(domain) {
        if (!domain || domain.trim() === '') return;
        
        const cleanDomain = domain.trim().toLowerCase();
        
        // Remove if already exists
        this.preferences.domainHistory = this.preferences.domainHistory.filter(d => d !== cleanDomain);
        
        // Add to beginning
        this.preferences.domainHistory.unshift(cleanDomain);
        
        // Limit history size
        if (this.preferences.domainHistory.length > this.preferences.maxHistoryItems) {
            this.preferences.domainHistory = this.preferences.domainHistory.slice(0, this.preferences.maxHistoryItems);
        }
        
        this.savePreferences();
        this.setupDomainAutocomplete();
    }
    
    /**
     * Setup domain autocomplete functionality
     */
    setupDomainAutocomplete() {
        const domainInput = document.getElementById('card-domain');
        if (!domainInput || this.preferences.domainHistory.length === 0) return;
        
        // Create datalist if it doesn't exist
        let datalist = document.getElementById('domain-history');
        if (!datalist) {
            datalist = document.createElement('datalist');
            datalist.id = 'domain-history';
            domainInput.parentNode.insertBefore(datalist, domainInput.nextSibling);
            domainInput.setAttribute('list', 'domain-history');
        }
        
        // Update datalist options
        datalist.innerHTML = this.preferences.domainHistory
            .map(domain => `<option value="${domain}"></option>`)
            .join('');
    }
    
    initializeKeyboardShortcuts() {
        // Initialize keyboard shortcuts
        // Add immediate capture to see if events are reaching us at all
        window.addEventListener('keydown', (event) => {
        }, true); // Use capture phase
        
        document.addEventListener('keydown', (event) => {
            const isInInput = event.target.tagName === 'INPUT' || event.target.tagName === 'TEXTAREA';
            
            // Allow certain navigation shortcuts even in input fields
            const allowInInputs = [
                'ArrowUp', 'ArrowDown', 'Escape', 'F1'
            ];
            
            // Handle special cases for input fields
            if (isInInput) {
                // Allow Escape to exit input fields
                if (event.key === 'Escape') {
                    event.target.blur();
                    return;
                }
                
                // Skip other shortcuts unless they're navigation shortcuts
                if (!allowInInputs.includes(event.key) && 
                    !(event.key === '?' && !event.ctrlKey && !event.metaKey)) {
                    return;
                }
            }
            
            // Ctrl/Cmd + Enter: Generate cards
            if ((event.ctrlKey || event.metaKey) && event.key === 'Enter') {
                event.preventDefault();
                showShortcutFeedback('🎯 Generating...');
                this.handleGenerate(false);
                return;
            }
            
            // Ctrl/Cmd + C: Copy matrix (when visible)
            if ((event.ctrlKey || event.metaKey) && event.key === 'c' && this.currentMatrix) {
                event.preventDefault();
                this.handleCopyMatrix();
                return;
            }
            
            // Ctrl/Cmd + E: Edit seed (focus seed input)
            if ((event.ctrlKey || event.metaKey) && event.key === 'e') {
                event.preventDefault();
                showShortcutFeedback('✏️ Editing seed...');
                this.focusOnSeedInput();
                return;
            }
            
            // Ctrl/Cmd + D: Focus domain input
            if ((event.ctrlKey || event.metaKey) && event.key === 'd') {
                event.preventDefault();
                showShortcutFeedback('🌐 Editing domain...');
                const domainInput = document.getElementById('card-domain');
                if (domainInput) {
                    domainInput.focus();
                    domainInput.select();
                }
                return;
            }
            
            // Escape: Close modals/clear errors
            if (event.key === 'Escape') {
                this.closeModalsAndErrors();
                return;
            }
            
            // ? or F1: Show keyboard shortcuts help modal
            if (event.key === '?' || event.key === 'F1') {
                event.preventDefault();
                this.showKeyboardShortcuts();
                return;
            }
            
            // n: Regenerate nonce
            if (event.key === 'n' && !event.ctrlKey && !event.metaKey && !event.shiftKey && !event.altKey) {
                event.preventDefault();
                this.regenerateNonce();
                return;
            }
            
            // Ctrl/Cmd + Shift + S: Show security status
            if ((event.ctrlKey || event.metaKey) && event.shiftKey && event.key === 'S') {
                event.preventDefault();
                showShortcutFeedback('🔒 Security audit...');
                this.showSecurityStatus();
                return;
            }
            
            // Number keys 1-3: Switch seed mode
            if (event.key >= '1' && event.key <= '3' && !event.ctrlKey && !event.metaKey) {
                event.preventDefault();
                const modes = ['simple', 'bip39', 'slip39'];
                const modeIndex = parseInt(event.key) - 1;
                if (modes[modeIndex]) {
                    const radio = document.querySelector(`input[name="seedType"][value="${modes[modeIndex]}"]`);
                    if (radio) {
                        radio.checked = true;
                        this.handleSeedTypeChange({ target: radio });
                    }
                }
                return;
            }
            
            // Arrow keys: Navigate sections (only without modifier keys)
            if ((event.key === 'ArrowDown' || event.key === 'ArrowUp') && 
                !event.ctrlKey && !event.metaKey && !event.shiftKey && !event.altKey) {
                
                
                // Handle textarea navigation
                if (isInInput && event.target.tagName === 'TEXTAREA') {
                    // Allow section navigation for SHA-512 hash input and any single-line textareas
                    if (event.target.id === 'seed-hash-value') {
                        // Always allow section navigation for SHA-512 hash
                        // But skip to next/previous section instead of trying to focus within current section
                        event.preventDefault();
                        const sections = ['seed-section', 'domain-section', 'results', 'password-examples'];
                        const currentIndex = 0; // seed-section is always index 0
                        const nextIndex = event.key === 'ArrowDown' ? 1 : 0; // Down goes to domain, Up stays at seed but focuses differently
                        
                        if (event.key === 'ArrowUp' && currentIndex === 0) {
                            // If going up from first section, stay in seed section but don't refocus hash field
                            // Instead, try to focus on a seed type radio or other element
                            const seedTypeRadio = document.querySelector('input[name="seedType"]:checked');
                            if (seedTypeRadio && seedTypeRadio.offsetParent !== null) {
                                seedTypeRadio.focus();
                                return;
                            }
                        }
                        
                        // Navigate to next section
                        const targetSection = sections[Math.min(nextIndex, sections.length - 1)];
                        const element = document.getElementById(targetSection);
                        if (element) {
                            element.scrollIntoView({ behavior: 'smooth', block: 'start' });
                            
                            // Focus on appropriate element in target section
                            setTimeout(() => {
                                if (targetSection === 'domain-section') {
                                    const dateInput = document.querySelector('#card-date');
                                    if (dateInput) {
                                        if (dateInput.offsetParent !== null) {
                                            dateInput.focus();
                                        } else {
                                            // Try to find any visible input in domain section
                                            const domainSection = document.getElementById('domain-section');
                                            if (domainSection) {
                                                const fallbackInput = domainSection.querySelector('input:not([disabled]), textarea:not([disabled])');
                                                if (fallbackInput && fallbackInput.offsetParent !== null) {
                                                    fallbackInput.focus();
                                                }
                                            }
                                        }
                                    } else {
                                    }
                                }
                            }, 300);
                        }
                        return;
                    } else if (event.target.id === 'slip39-shares') {
                        // Only prevent for SLIP-39 shares textarea where multiline editing is important
                        return; // Let textarea handle text navigation
                    }
                    // For other textareas, allow section navigation by default
                    event.preventDefault();
                    this.navigateSections(event.key === 'ArrowDown');
                    return;
                }
                
                // For all other inputs and general page navigation, allow section navigation
                event.preventDefault();
                this.navigateSections(event.key === 'ArrowDown');
                return;
            }
            
            // Tab: Cycle through interactive elements in current section
            // Let default Tab behavior handle this naturally
        });
    }
    
    /**
     * Initialize scroll-based navigation highlighting
     */
    initializeScrollNavigation() {
        let scrollTimeout;
        
        // Debounced scroll handler for performance
        const handleScroll = () => {
            if (scrollTimeout) {
                clearTimeout(scrollTimeout);
            }
            
            scrollTimeout = setTimeout(() => {
                this.updateActiveNavLink();
            }, 10); // Small debounce for smooth updates
        };
        
        // Add scroll listener
        window.addEventListener('scroll', handleScroll, { passive: true });
        
        // Initial call to set active link on page load
        setTimeout(() => this.updateActiveNavLink(), 100);
    }
    
    /**
     * Update the active navigation link based on current scroll position
     */
    updateActiveNavLink() {
        const currentSection = this.getCurrentSection();
        
        // Update navigation menu for current route
        this.updateNavigationMenu(currentSection);
    }

    /**
     * Initialize simple routing system
     */
    initializeRouting() {
        // Handle navigation link clicks
        document.addEventListener('click', (e) => {
            const link = e.target.closest('a[data-route]');
            if (link) {
                e.preventDefault();
                const route = link.getAttribute('data-route');
                this.navigateToRoute(route, true); // true = push to history
            }
        });
        
        // Handle browser back/forward buttons
        window.addEventListener('popstate', () => {
            const route = this.getRouteFromUrl();
            this.navigateToRoute(route, false); // false = don't push to history
        });
        
        // Set initial route from URL (handles page refresh)
        this.handleInitialRoute();
    }
    
    /**
     * Get route from current URL
     */
    getRouteFromUrl() {
        const pathname = window.location.pathname;
        // Handle trailing slashes
        const route = pathname === '' ? '/' : pathname.replace(/\/$/, '') || '/';
        return route;
    }
    
    /**
     * Handle initial route on page load
     */
    handleInitialRoute() {
        const route = this.getRouteFromUrl();
        // Navigate without pushing to history (already at this URL)
        this.navigateToRoute(route, false);
    }
    
    /**
     * Navigate to a specific route
     * @param {string} route - The route to navigate to
     * @param {boolean} pushHistory - Whether to push to browser history
     */
    navigateToRoute(route, pushHistory = true) {
        // Hide all route views
        const routeViews = document.querySelectorAll('.route-view');
        routeViews.forEach(view => {
            view.style.display = 'none';
        });
        
        // Show the appropriate view
        let viewToShow = null;
        let resolvedRoute = route;
        
        if (route === '/' || route === '/home') {
            viewToShow = document.getElementById('home-view');
            resolvedRoute = '/';
        } else if (route === '/generator' || route.startsWith('/config') || route === '/tokens' || route === '/examples') {
            viewToShow = document.getElementById('generator-view');
            
            // For generator sub-routes, scroll to the appropriate section
            if (route === '/config/seed') {
                setTimeout(() => scrollToSection('seed-section'), 100);
            } else if (route === '/config/domain') {
                setTimeout(() => scrollToSection('domain-section'), 100);
            } else if (route === '/tokens') {
                setTimeout(() => scrollToSection('results'), 100);
            } else if (route === '/examples') {
                setTimeout(() => scrollToSection('password-examples'), 100);
            }
        } else {
            // Unknown route - redirect to home
            viewToShow = document.getElementById('home-view');
            resolvedRoute = '/';
        }
        
        if (viewToShow) {
            viewToShow.style.display = 'block';
        }
        
        // Update browser URL if requested
        if (pushHistory && window.location.pathname !== resolvedRoute) {
            window.history.pushState({ route: resolvedRoute }, '', resolvedRoute);
        } else if (!pushHistory && window.location.pathname !== resolvedRoute) {
            // Replace state for fallback routes (e.g., unknown routes -> home)
            window.history.replaceState({ route: resolvedRoute }, '', resolvedRoute);
        }
        
        // Update navigation menu after route change
        setTimeout(() => {
            this.updateNavigationMenu();
        }, 50);
    }
    
    /**
     * Set initial route based on current state (legacy - now handled by handleInitialRoute)
     */
    setInitialRoute() {
        // Handled by handleInitialRoute() in initializeRouting()
    }

    /**
     * Update navigation menu based on current route
     */
    updateNavigationMenu(currentRoute = null) {
        const navList = document.getElementById('nav-list');
        if (!navList) {
            return;
        }
        
        // Get current route if not provided
        if (!currentRoute) {
            const currentSection = this.getCurrentSection();
            // Map section IDs to route names
            const sectionToRoute = {
                'seed-section': 'config/seed',
                'domain-section': 'config/domain', 
                'results': 'tokens',
                'password-examples': 'examples',
                'home': 'home',
                'generator': 'generator'
            };
            currentRoute = sectionToRoute[currentSection] || 'generator';
        }
        
        // Update body class for route-specific styling
        document.body.className = document.body.className.replace(/route-\w+/g, '');
        if (currentRoute === 'home') {
            document.body.classList.add('route-home');
        } else if (currentRoute.startsWith('config')) {
            document.body.classList.add('route-config');
        } else {
            document.body.classList.add(`route-${currentRoute}`);
        }
        
        // Clear existing navigation items
        navList.innerHTML = '';
        
        // Clear existing help button from nav-actions
        const navActions = document.querySelector('.nav-help-status');
        if (navActions) {
            const existingHelpBtn = navActions.querySelector('.nav-help-btn');
            if (existingHelpBtn) {
                existingHelpBtn.remove();
            }
        }
        
        // Define navigation items for different routes
        const navigationConfig = {
            'home': [
                { href: '/generator', text: 'Generator', route: '/generator' }
            ],
            'generator': [
                { href: '/config/seed', text: 'Seed', symbol: '🔑', route: '/config/seed' },
                { href: '/config/domain', text: 'Settings', symbol: '⚙️', route: '/config/domain' },
                { href: '/tokens', text: 'Card', symbol: '🃏', route: '/tokens' },
                { href: '/examples', text: 'Examples', symbol: '🔐', route: '/examples' }
            ],
            'config/seed': [
                { href: '/config/seed', text: 'Seed', symbol: '🔑', route: '/config/seed' },
                { href: '/config/domain', text: 'Settings', symbol: '⚙️', route: '/config/domain' },
                { href: '/tokens', text: 'Card', symbol: '🃏', route: '/tokens' },
                { href: '/examples', text: 'Examples', symbol: '🔐', route: '/examples' }
            ],
            'config/domain': [
                { href: '/config/seed', text: 'Seed', symbol: '🔑', route: '/config/seed' },
                { href: '/config/domain', text: 'Settings', symbol: '⚙️', route: '/config/domain' },
                { href: '/tokens', text: 'Card', symbol: '🃏', route: '/tokens' },
                { href: '/examples', text: 'Examples', symbol: '🔐', route: '/examples' }
            ],
            'tokens': [
                { href: '/config/seed', text: 'Seed', symbol: '🔑', route: '/config/seed' },
                { href: '/config/domain', text: 'Settings', symbol: '⚙️', route: '/config/domain' },
                { href: '/tokens', text: 'Card', symbol: '🃏', route: '/tokens' },
                { href: '/examples', text: 'Examples', symbol: '🔐', route: '/examples' }
            ],
            'examples': [
                { href: '/config/seed', text: 'Seed', symbol: '🔑', route: '/config/seed' },
                { href: '/config/domain', text: 'Settings', symbol: '⚙️', route: '/config/domain' },
                { href: '/tokens', text: 'Card', symbol: '🃏', route: '/tokens' },
                { href: '/examples', text: 'Examples', symbol: '🔐', route: '/examples' }
            ]
        };
        
        // Get navigation items for current route (default to generator if not found)
        const navItems = navigationConfig[currentRoute] || navigationConfig['generator'];
        
        // Create navigation items
        navItems.forEach(item => {
            const li = document.createElement('li');
            const link = document.createElement('a');
            link.href = item.href;
            link.className = 'nav-link';
            link.setAttribute('data-route', item.route);
            
            // Create content with symbol and text for responsive design
            if (item.symbol) {
                link.innerHTML = `<span class="nav-symbol">${item.symbol}</span><span class="nav-text">${item.text}</span>`;
            } else {
                link.textContent = item.text;
            }
            
            // Mark active link
            if (item.route === `/${currentRoute}`) {
                link.classList.add('active');
            }
            
            li.appendChild(link);
            navList.appendChild(li);
        });
        
        // Always add help button to nav-actions area
        if (navActions) {
            const helpButton = document.createElement('button');
            helpButton.className = 'nav-help-btn';
            helpButton.setAttribute('aria-label', 'Show keyboard shortcuts');
            helpButton.setAttribute('title', 'Keyboard shortcuts (Press ? or F1)');
            helpButton.onclick = () => {
                if (window.app && window.app.showKeyboardShortcuts) {
                    window.app.showKeyboardShortcuts();
                } else {
                    // Simple fallback
                    alert('Keyboard shortcuts:\n\n? or F1: Show help\nCtrl/Cmd+C: Copy matrix\nEscape: Close modals');
                }
            };
            helpButton.innerHTML = '<span aria-hidden="true">?</span>';
            
            navActions.appendChild(helpButton);
        }
    }

    /**
     * Focus on the appropriate seed input based on current mode
     */
    focusOnSeedInput() {
        const currentMode = document.querySelector('input[name="seedType"]:checked')?.value || 'simple';
        let inputElement;
        
        switch (currentMode) {
            case 'simple':
                inputElement = document.getElementById('simple-phrase');
                break;
            case 'bip39':
                inputElement = document.getElementById('bip39-mnemonic');
                break;
            case 'slip39':
                inputElement = document.getElementById('slip39-shares');
                break;
        }
        
        if (inputElement) {
            inputElement.focus();
            inputElement.select();
            // Scroll to the seed section
            scrollToSection('seed-section');
        }
    }
    
    closeModalsAndErrors() {
        // Close any open modals
        const modals = document.querySelectorAll('.modal');
        modals.forEach(modal => {
            modal.style.display = 'none';
            modal.remove();
        });
        document.body.style.overflow = 'auto';
        
        // Hide error messages
        const errorContainer = document.getElementById('error-container');
        if (errorContainer) errorContainer.style.display = 'none';
        
        // Hide progress indicators
        hideProgress();
    }
    
    /**
     * Regenerate the nonce with a new random value
     */
    regenerateNonce() {
        const nonceInput = document.getElementById('card-nonce');
        if (nonceInput && window.LabelUtils) {
            nonceInput.value = window.LabelUtils.generateNonce();
            // Dispatch input event to trigger auto-regeneration
            nonceInput.dispatchEvent(new Event('input', { bubbles: true }));
            this.updateStatus('🎲 Nonce generated', 'success');
        } else if (nonceInput) {
            // Fallback if LabelUtils not loaded yet
            const bytes = new Uint8Array(6);
            crypto.getRandomValues(bytes);
            // URL-safe Base64 encoding
            const base64 = btoa(String.fromCharCode(...bytes))
                .replace(/\+/g, '-')
                .replace(/\//g, '_')
                .replace(/=+$/, '');
            nonceInput.value = base64;
            nonceInput.dispatchEvent(new Event('input', { bubbles: true }));
            this.updateStatus('🎲 Nonce generated', 'success');
        }
    }
    
    navigateSections(down = true) {
        const sections = ['seed-section', 'domain-section', 'results', 'password-examples'];
        const currentSection = this.getCurrentSection();
        const currentIndex = sections.indexOf(currentSection);
        
        let nextIndex;
        if (currentIndex !== -1) {
            nextIndex = down ? 
                Math.min(currentIndex + 1, sections.length - 1) : 
                Math.max(currentIndex - 1, 0);
                
                
            // Don't navigate if already at the boundary
            if (nextIndex === currentIndex) {
                // Briefly flash the current navbar link to indicate boundary
                this.flashCurrentNavbarLink(currentSection);(`� ${boundaryMessage}`);
                return;
            }
        } else {
            // If no current section found, go to first section
            nextIndex = 0;
        }
        
        const targetSection = sections[nextIndex];
        
        // Smooth scroll with improved timing
        const element = document.getElementById(targetSection);
        if (element) {
            // Get actual navbar height dynamically - same logic as scrollToSection
            const navbar = document.querySelector('.navbar');
            let navbarHeight = 80; // Default fallback
            
            if (navbar) {
                navbarHeight = navbar.getBoundingClientRect().height;
            }
            
            // Calculate position accounting for navbar with extra padding
            const elementPosition = element.getBoundingClientRect().top + window.pageYOffset;
            const offsetPosition = elementPosition - navbarHeight - 20; // Extra 20px padding
            
            window.scrollTo({
                top: offsetPosition,
                behavior: 'smooth'
            });
            
            // Update status with delay to avoid conflicts
            setTimeout(() => {
                this.highlightNavbarLink(targetSection);
                this.focusFirstElementInSection(targetSection);
            }, 100);
        }
    }

    /**
     * Focus the first interactive element in a section
     */
    focusFirstElementInSection(sectionId) {
        const section = document.getElementById(sectionId);
        if (!section) {
            return;
        }

        // Define section-specific focus targets for better UX
        const sectionFocusMap = {
            'seed-section': this.getCurrentSeedInputSelector(), // Dynamic based on current seed type
            'domain-section': '#card-date', // Date input (first in domain section)
            'results': '.card-index-item', // First card index item
            'password-examples': '.password-example' // First password example
        };

        // Try section-specific focus target first
        const specificTarget = sectionFocusMap[sectionId];
        if (specificTarget) {
            const element = section.querySelector(specificTarget) || document.querySelector(specificTarget);
            if (element && this.isElementFocusable(element)) {
                element.focus();
                return;
            }
        }

        // Fallback: find first focusable element in section
        const focusableSelectors = [
            'input:not([disabled]):not([type="hidden"])',
            'textarea:not([disabled])',
            'button:not([disabled])',
            'select:not([disabled])',
            '[tabindex]:not([tabindex="-1"])',
            'a[href]'
        ];

        for (const selector of focusableSelectors) {
            const element = section.querySelector(selector);
            if (element && this.isElementFocusable(element)) {
                element.focus();
                return;
            }
        }
        
    }

    /**
     * Get the selector for the currently active seed input
     */
    getCurrentSeedInputSelector() {
        const checkedRadio = document.querySelector('input[name="seedType"]:checked');
        const seedType = checkedRadio ? checkedRadio.value : 'simple';
        
        let selector;
        switch (seedType) {
            case 'simple':
                selector = '#simple-phrase';
                break;
            case 'bip39':
                selector = '#bip39-mnemonic';
                break;
            case 'slip39':
                selector = '.slip39-share'; // First SLIP-39 share input
                break;
            default:
                selector = '#simple-phrase';
        }
        
        // Check if the selected input is actually visible
        const element = document.querySelector(selector);
        if (element && this.isElementFocusable(element)) {
            return selector;
        }
        
        // Fallback: if the intended input is hidden, look for the visible SHA-512 hash field
        const hashElement = document.querySelector('#seed-hash-value');
        if (hashElement && this.isElementFocusable(hashElement)) {
            return '#seed-hash-value';
        }
        
        // Last fallback: return the original selector anyway
        return selector;
    }

    /**
     * Check if an element is actually focusable (visible and not disabled)
     */
    isElementFocusable(element) {
        if (!element) {
            return false;
        }
        
        // Check if element is visible
        const style = window.getComputedStyle(element);
        if (style.display === 'none' || style.visibility === 'hidden') {
            return false;
        }
        
        // Check if element or parent is hidden
        let parent = element.parentElement;
        while (parent) {
            const parentStyle = window.getComputedStyle(parent);
            if (parentStyle.display === 'none' || parentStyle.visibility === 'hidden') {
                return false;
            }
            parent = parent.parentElement;
        }
        
        return true;
    }
    
    /**
     * Get the currently visible section based on scroll position
     */
    getCurrentSection() {
        // For navigation purposes, we need to detect which section within the generator view is active
        // First check if we're in the generator view at all
        const generatorView = document.getElementById('generator-view');
        if (generatorView) {
            const style = window.getComputedStyle(generatorView);
            if (style.display !== 'none') {
                // We're in generator view, now determine which section is active
                // Check sections in reverse order (bottom to top) to find the topmost visible section
                const sections = ['seed-section', 'domain-section', 'results', 'password-examples'];
                const navbar = document.querySelector('.navbar');
                let navbarHeight = 80; // Default fallback
                
                if (navbar) {
                    navbarHeight = navbar.getBoundingClientRect().height;
                }
                
                // Find the section that's most prominently in view
                for (let i = sections.length - 1; i >= 0; i--) {
                    const section = document.getElementById(sections[i]);
                    if (section) {
                        const rect = section.getBoundingClientRect();
                        // Consider a section active if its top is above the navbar + some threshold
                        const threshold = navbarHeight + 100; // 100px threshold
                        if (rect.top <= threshold && rect.bottom > navbarHeight) {
                            // Debug logging disabled - too noisy during scroll
                            // console.log('📍 Found active section:', sections[i], 'rect.top:', rect.top, 'threshold:', threshold);
                            return sections[i]; // Return section ID directly
                        }
                    }
                }
                
                // If no section is clearly in view, default to seed-section
                // Debug logging disabled - too noisy during scroll
                // console.log('📍 No clear section found, defaulting to seed-section');
                return 'seed-section';
            }
        }
        
        // Check other views (home, etc.) and return route names for those
        const routeViews = [
            { id: 'home-view', route: 'home' }
        ];
        
        for (const view of routeViews) {
            const element = document.getElementById(view.id);
            if (element) {
                const style = window.getComputedStyle(element);
                if (style.display !== 'none') {
                    return view.route;
                }
            }
        }
        
        // Final fallback
        return 'generator';
    }
    
    /**
     * Get user-friendly section name
     */
    getSectionName(sectionId) {
        const names = {
            'seed-section': 'Seed Input',
            'domain-section': 'Domain Settings', 
            'options-section': 'Generation Options',
            'results': 'Card',
            'password-examples': 'Password Examples'
        };
        return names[sectionId] || sectionId;
    }
    
    /**
     * Highlight the navbar link corresponding to the section being navigated to
     */
    highlightNavbarLink(sectionId) {
        // Clear any existing highlights
        const navLinks = document.querySelectorAll('.nav-menu a');
        navLinks.forEach(link => {
            link.classList.remove('nav-highlight');
        });
        
        // Find and highlight the corresponding navbar link
        const targetLink = document.querySelector(`.nav-menu a[onclick*="'${sectionId}'"]`);
        if (targetLink) {
            // Temporarily clear active state during highlight
            const wasActive = targetLink.classList.contains('nav-active');
            targetLink.classList.remove('nav-active');
            targetLink.classList.add('nav-highlight');
            
            // Remove highlight and restore active state after 1.5 seconds
            setTimeout(() => {
                targetLink.classList.remove('nav-highlight');
                if (wasActive) {
                    targetLink.classList.add('nav-active');
                }
                // Refresh active state in case scroll position changed
                this.updateActiveNavLink();
            }, 1500);
        }
    }
    
    /**
     * Flash the current navbar link to indicate navigation boundary
     */
    flashCurrentNavbarLink(sectionId) {
        const targetLink = document.querySelector(`.nav-menu a[onclick*="'${sectionId}'"]`);
        if (targetLink) {
            // Add flash class
            targetLink.classList.add('nav-flash');
            
            // Remove flash after 0.6 seconds (shorter than highlight)
            setTimeout(() => {
                targetLink.classList.remove('nav-flash');
            }, 600);
        }
    }
    
    showKeyboardShortcuts() {
        const modal = document.createElement('div');
        modal.className = 'modal keyboard-shortcuts-modal show';
        modal.innerHTML = `
            <div class="modal-content">
                <div class="modal-header">
                    <h3>⌨️ Keyboard Shortcuts</h3>
                    <button class="modal-close">&times;</button>
                </div>
                <div class="modal-body">
                    <div class="shortcuts-grid">
                        <div class="shortcut-group">
                            <h4>🎯 Actions</h4>
                            <div class="shortcut-item">
                                <kbd>Ctrl/Cmd</kbd> + <kbd>C</kbd>
                                <span>Copy Matrix</span>
                            </div>
                            <div class="shortcut-item">
                                <kbd>Escape</kbd>
                                <span>Close Modals/Errors</span>
                            </div>
                        </div>
                        
                        <div class="shortcut-group">
                            <h4>✏️ Editing</h4>
                            <div class="shortcut-item">
                                <kbd>Ctrl/Cmd</kbd> + <kbd>E</kbd>
                                <span>Edit Seed</span>
                            </div>
                            <div class="shortcut-item">
                                <kbd>Ctrl/Cmd</kbd> + <kbd>D</kbd>
                                <span>Edit Label</span>
                            </div>
                        </div>
                        
                        <div class="shortcut-group">
                            <h4>🔑 Seed Modes</h4>
                            <div class="shortcut-item">
                                <kbd>1</kbd>
                                <span>Simple Seed</span>
                            </div>
                            <div class="shortcut-item">
                                <kbd>2</kbd>
                                <span>BIP-39 Mnemonic</span>
                            </div>
                            <div class="shortcut-item">
                                <kbd>3</kbd>
                                <span>SLIP-39 Shares</span>
                            </div>
                        </div>
                        
                        <div class="shortcut-group">
                            <h4>🧭 Navigation</h4>
                            <div class="shortcut-item">
                                <kbd>↑</kbd> / <kbd>↓</kbd>
                                <span>Navigate Sections</span>
                            </div>
                            <div class="shortcut-item">
                                <kbd>Tab</kbd>
                                <span>Cycle Inputs</span>
                            </div>
                            <div class="shortcut-item">
                                <kbd>?</kbd> / <kbd>F1</kbd>
                                <span>Show This Help</span>
                            </div>
                        </div>
                        
                        <div class="shortcut-group">
                            <h4>🔒 Security</h4>
                            <div class="shortcut-item">
                                <kbd>n</kbd>
                                <span>Regenerate Nonce</span>
                            </div>
                            <div class="shortcut-item">
                                <kbd>Ctrl/Cmd</kbd> + <kbd>Shift</kbd> + <kbd>S</kbd>
                                <span>Security Status</span>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        `;
        
        // Add click outside to close
        modal.addEventListener('click', (e) => {
            if (e.target === modal) {
                modal.remove();
                document.body.style.overflow = 'auto';
            }
        });
        
        // Close on Escape
        const closeOnEscape = (e) => {
            if (e.key === 'Escape') {
                modal.remove();
                document.body.style.overflow = 'auto';
                document.removeEventListener('keydown', closeOnEscape);
            }
        };
        document.addEventListener('keydown', closeOnEscape);
        
        document.body.appendChild(modal);
        
        // Ensure modal is visible
        modal.style.display = 'block';
        document.body.style.overflow = 'hidden';
        
        // Focus the close button for accessibility and add click handler
        const closeButton = modal.querySelector('.modal-close');
        if (closeButton) {
            closeButton.addEventListener('click', () => {
                modal.remove();
                document.body.style.overflow = 'auto';
            });
            closeButton.focus();
        }
    }
    
    /**
     * Initialize status indicator for user feedback
     */
    initializeStatusIndicator() {
        // Status indicator is already in HTML - just set initial status
        this.updateStatus('Ready');
    }
    
    /**
     * Update status indicator
     */
    updateStatus(message, type = 'info') {
        // Update the desktop status indicator
        const statusText = document.querySelector('#status-text');
        if (statusText) {
            statusText.textContent = message;
            
            // Update color based on type (no background bubbles)
            statusText.style.removeProperty('background');
            statusText.style.removeProperty('padding');
            statusText.style.removeProperty('border-radius');
            
            if (type === 'error') {
                statusText.style.color = '#dc2626';
            } else if (type === 'warning') {
                statusText.style.color = '#d97706';
            } else if (type === 'success') {
                statusText.style.color = '#059669';
            } else {
                statusText.style.color = '#059669'; // Default to green for info
            }
            
            // Auto-expire success messages and some info messages after 3 seconds
            if (type === 'success' || (type === 'info' && message.includes('copied') || message.includes('generated'))) {
                // Clear any existing timeout
                if (this.statusTimeout) {
                    clearTimeout(this.statusTimeout);
                }
                
                // Set new timeout to revert to "Ready" after 3 seconds
                this.statusTimeout = setTimeout(() => {
                    if (statusText && statusText.textContent === message) {
                        statusText.textContent = 'Ready';
                        statusText.style.color = '#059669';
                    }
                }, 3000);
            }
        }
        
        // Also announce to screen readers
        announceToScreenReader(message, type === 'error');
    }
    
    /**
     * Show security status in the UI
     */
    showSecurityStatus() {
        const features = [];
        
        // Check if we're running in a secure context
        if (window.isSecureContext) {
            features.push('🔒 Secure');
        } else {
            features.push('⚠️ Insecure');
        }
        
        // Check if crypto API is available
        if (window.crypto && window.crypto.getRandomValues) {
            features.push('🔐 Crypto');
        } else {
            features.push('⚠️ Limited');
        }
        
        // Check if we're offline
        if (!navigator.onLine) {
            features.push('🌐 Offline');
        } else {
            features.push('🌍 Online');
        }
        
        // CSP Status
        features.push('🛡️ CSP');
        
        this.updateStatus(features.join(' | '), 'info');
    }
    
    initializeInputValidation() {
        // Add real-time validation to key inputs
        const simplePhrase = document.getElementById('simple-phrase');
        if (simplePhrase) {
            simplePhrase.addEventListener('input', () => {
                validateInput(simplePhrase, validators.simplePhrase, 'Phrase must be at least 3 characters');
            });
        }
        
        const bip39Mnemonic = document.getElementById('bip39-mnemonic');
        if (bip39Mnemonic) {
            bip39Mnemonic.addEventListener('input', () => {
                validateInput(bip39Mnemonic, validators.bip39Mnemonic, 'Must be 12-24 words (multiple of 3)');
            });
        }
        
        const hashInput = document.getElementById('seed-hash-value');
        if (hashInput) {
            hashInput.addEventListener('input', () => {
                validateInput(hashInput, validators.sha512Hash, 'Must be exactly 128 hex characters');
            });
        }
        
        // Validate domain input
        const domainInput = document.getElementById('card-domain');
        if (domainInput) {
            domainInput.addEventListener('input', () => {
                validateInput(domainInput, validators.cardDomain, 'Invalid domain format (2-50 chars, alphanumeric with dots/hyphens)');
            });
        }
        
        // Validate card date input
        const cardDateInput = document.getElementById('card-date');
        if (cardDateInput) {
            cardDateInput.addEventListener('input', () => {
                validateInput(cardDateInput, validators.cardDate, 'Invalid date format (4-50 chars, letters/numbers/hyphens)');
                // Trigger label entropy update when date changes
                this.updateLabelEntropyDisplay();
            });
        }
        
        // Validate card ID input
        const cardIdInput = document.getElementById('card-id');
        if (cardIdInput) {
            cardIdInput.addEventListener('input', () => {
                // Trigger label entropy update when card ID changes
                this.updateLabelEntropyDisplay();
            });
        }
        
        // Validate SLIP-39 shares dynamically
        document.addEventListener('input', (event) => {
            if (event.target.classList.contains('slip39-share')) {
                validateInput(event.target, validators.slip39Share, 'Must be exactly 20 or 33 words');
            }
        });
        
        // Perform initial validation of default values
        setTimeout(() => {
            this.performInitialValidation();
        }, 100);
    }
    
    performInitialValidation() {
        // Validate all inputs with default values
        const inputsToValidate = [
            { id: 'simple-phrase', validator: validators.simplePhrase, message: 'Phrase must be at least 3 characters' },
            { id: 'bip39-mnemonic', validator: validators.bip39Mnemonic, message: 'Must be 12-24 words (multiple of 3)' },
            { id: 'seed-hash-value', validator: validators.sha512Hash, message: 'Must be exactly 128 hex characters' },
            { id: 'card-domain', validator: validators.cardDomain, message: 'Invalid domain format' },
            { id: 'card-date', validator: validators.cardDate, message: 'Invalid date format' }
        ];
        
        inputsToValidate.forEach(({ id, validator, message }) => {
            const element = document.getElementById(id);
            if (element && element.value.trim()) {
                validateInput(element, validator, message);
            }
        });
        
        // Update label entropy with initial values
        this.updateLabelEntropyDisplay();
    }
    
    initializeEventListeners() {
        // Seed type selection
        const seedTypeRadios = document.querySelectorAll('input[name="seedType"]');
        seedTypeRadios.forEach(radio => {
            radio.addEventListener('change', this.handleSeedTypeChange.bind(this));
        });
        
        // Generation mode selection - Auto-generate on change
        const genModeRadios = document.querySelectorAll('input[name="genMode"]');
        genModeRadios.forEach(radio => {
            radio.addEventListener('change', this.handleGenModeChange.bind(this));
        });
        
        // Auto-generation setup for form inputs
        // Triggers regeneration when settings change (KDF params, base system, etc.)
        this.setupAutoGeneration();
        
        // Demo button
        const demoBtn = document.getElementById('demo-generate');
        if (demoBtn) {
            demoBtn.addEventListener('click', this.handleDemoGenerate.bind(this));
        }
        
        // Action buttons
        const printBtn = document.getElementById('print-cards');
        if (printBtn) {
            printBtn.addEventListener('click', this.handlePrint.bind(this));
        }
        
        // Change seed button
        const changeSeedBtn = document.getElementById('change-seed-btn');
        if (changeSeedBtn) {
            changeSeedBtn.addEventListener('click', this.handleChangeSeed.bind(this));
        }
        
        // Generate hash button
        const generateHashBtn = document.getElementById('generate-hash-btn');
        if (generateHashBtn) {
            generateHashBtn.addEventListener('click', this.handleGenerateHash.bind(this));
        }
        
        // Hash input validation on change (automatic)
        const hashInput = document.getElementById('seed-hash-value');
        if (hashInput) {
            hashInput.addEventListener('input', this.handleHashInput.bind(this));
            hashInput.addEventListener('paste', () => {
                // Delay validation slightly for paste events
                setTimeout(() => this.handleHashInput(), 10);
            });
        }
        
        const downloadBtn = document.getElementById('download-cards');
        if (downloadBtn) {
            downloadBtn.addEventListener('click', this.handleDownload.bind(this));
        }
        
        // SLIP-39 share management
        const addShareBtn = document.getElementById('add-slip39-share');
        if (addShareBtn) {
            addShareBtn.addEventListener('click', this.handleAddSlip39Share.bind(this));
        }
        
        // Cancel generation and restart when critical settings change
        const argon2MemorySelect = document.getElementById('argon2-memory');
        if (argon2MemorySelect) {
            argon2MemorySelect.addEventListener('change', () => {
                const newMemory = parseInt(argon2MemorySelect.value);
                
                // Always terminate pool when memory changes - workers have wrong memory setting
                if (typeof Argon2WorkerPool !== 'undefined') {
                    const status = Argon2WorkerPool.getStatus();
                    if (status.initialized) {
                        Argon2WorkerPool.terminate();
                    }
                }
                
                // Cancel any in-progress generation
                const wasGenerating = this.isGenerating;
                if (wasGenerating) {
                    this.generationCancelled = true;
                    this.updateStatus('Generation cancelled - memory changed', 'warning');
                }
                
                // Clear cached seed bytes since Argon2 params changed
                this.currentSeedBytes = null;
                
                // Schedule regeneration (debounced to handle rapid changes)
                // Use longer delay if generation was in progress to let it fully stop
                clearTimeout(this.memoryChangeTimeout);
                const delay = wasGenerating ? 300 : 150;
                this.memoryChangeTimeout = setTimeout(() => {
                    // Force isGenerating to false - the old generation is dead
                    // (pool terminated, cancellation flag set)
                    if (wasGenerating) {
                        this.isGenerating = false;
                    }
                    this.handleGenerate(true);
                }, delay);
            });
        }
        
        // Cancel on KDF type change
        const kdfTypeRadios = document.querySelectorAll('input[name="kdfType"]');
        kdfTypeRadios.forEach(radio => {
            radio.addEventListener('change', () => {
                if (this.isGenerating) {
                    this.generationCancelled = true;
                    this.updateStatus('Generation cancelled - settings changed', 'warning');
                    setTimeout(() => {
                        this.handleGenerate(true);
                    }, 100);
                }
            });
        });
        
        // Cancel on base system change
        const baseSystemRadios = document.querySelectorAll('input[name="baseSystem"]');
        baseSystemRadios.forEach(radio => {
            radio.addEventListener('change', () => {
                if (this.isGenerating) {
                    this.generationCancelled = true;
                    this.updateStatus('Generation cancelled - settings changed', 'warning');
                    setTimeout(() => {
                        this.handleGenerate(true);
                    }, 100);
                }
            });
        });
    }
    
    initializeDemoMode() {
        // Auto-generate demo matrix on page load
        if (document.getElementById('demo-matrix')) {
            this.generateDemoMatrix();
        }
        
        // Load sample seed hash on page load
        this.loadSampleSeed();
    }
    
    async loadSampleSeed() {
        try {
            // Generate seed from default test phrase
            const testPhrase = "test phrase";
            const encoder = new TextEncoder();
            const data = encoder.encode(testPhrase);
            const hashBuffer = await crypto.subtle.digest('SHA-512', data);
            const hashArray = new Uint8Array(hashBuffer);
            
            // Convert to hex string
            const hashHex = Array.from(hashArray)
                .map(b => b.toString(16).padStart(2, '0'))
                .join('')
                .toUpperCase();
            
            // Set the hash value
            const hashInput = document.getElementById('seed-hash-value');
            
            if (hashInput) {
                hashInput.value = hashHex;
                hashInput.classList.add('valid');
                // Update stats for the initial hash
                this.updateHashStats(hashHex);
            }
            
            // Store the seed bytes for generation
            this.currentSeedBytes = hashArray;
            
            // Automatically generate a single card with default domain
            await this.generateInitialCard();
            
        } catch (error) {
            console.error('Failed to load sample seed:', error);
        }
    }
    
    async generateInitialCard() {
        try {
            if (!this.currentSeedBytes) {
                console.warn('No seed bytes available for initial card generation');
                return;
            }
            
            // Generate the initial card (A0 = first card)
            const baseCardId = this.buildCardId();
            const cardIndex = 'A0'; // First card in batch
            const cardDate = this.getCardDate();
            const base = this.getSelectedBase();
            
            const result = await SeedCardCrypto.generateTokenMatrix(this.currentSeedBytes, cardIndex, base);
            const digest = await SeedCardCrypto.generateDigest(this.currentSeedBytes);
            
            this.currentMatrix = result.matrix;
            this.currentCardId = `${baseCardId}.${cardIndex}`; // Combined ID for display
            
            // Register sensitive data for cleanup
            this.registerSensitiveData(result.matrix);
            this.registerSensitiveData(digest);
            
            // Display the enhanced label information for transparency
            if (cardDate) {
                this.displayLabelInfo(result.label, cardDate);
            }
            
            // Add domain to history on successful generation
            const domainInput = document.getElementById('card-domain');
            if (domainInput?.value.trim()) {
                this.addToHistory(domainInput.value.trim());
            }
            
            this.displaySingleCard(result.matrix, this.currentCardId, digest, result.label);
            this.generatePasswordExamples(result.matrix);
            this.showResults();
            
        } catch (error) {
            console.error('Failed to generate initial card:', error);
        }
    }
    
    handleSeedTypeChange(event) {
        // Save seed type preference
        const selectedType = event.target.value;
        this.preferences.lastSeedType = selectedType;
        this.savePreferences();
        
        // Hide all seed input sections
        const seedInputs = document.querySelectorAll('.seed-input');
        seedInputs.forEach(input => input.classList.remove('active'));
        
        // Show selected seed input
        const targetInput = document.getElementById(`${selectedType}-input`);
        if (targetInput) {
            targetInput.classList.add('active');
        }
        
        // Clear cached seed bytes - user must click "Generate Hash" button
        // Do NOT auto-generate when changing seed type - wait for explicit action
        this.currentSeedBytes = null;
        this.hideAutoGenCountdown();
    }
    
    setupAutoGeneration() {
        // Auto-generation is DISABLED for seed inputs - user must click "Generate Hash"
        // Only settings changes (KDF, base system, etc.) trigger auto-generation
        // 
        // EXCLUDED (require explicit Generate Hash click):
        // - All seed inputs (simple phrase, BIP-39 mnemonic, SLIP-39 shares)
        // - Seed type radio buttons
        // - Seed hash textarea
        //
        // INCLUDED (auto-generate on change):
        // - KDF type selection
        // - Base system selection  
        // - Argon2 parameters (time, parallelism)
        // - Card ID, date, nonce (settings)
        //
        // NOTE: argon2-memory is NOT included here - it has a dedicated handler
        // that terminates the worker pool (workers have memory baked in)
        
        const settingsInputs = [
            document.getElementById('card-id'),
            document.getElementById('card-date'),
            document.getElementById('card-nonce'),
            ...document.querySelectorAll('input[name="kdfType"]'),
            ...document.querySelectorAll('input[name="baseSystem"]'),
            document.getElementById('argon2-time'),
            document.getElementById('argon2-parallelism')
        ].filter(Boolean);
        
        settingsInputs.forEach(input => {
            input.addEventListener('input', () => this.scheduleAutoGeneration());
            input.addEventListener('change', () => this.scheduleAutoGeneration());
        });
        
        // NO initial auto-generation - user must click "Generate Hash" first
        // This ensures seed material is explicitly confirmed before card generation
    }
    
    scheduleAutoGeneration() {
        // Debounce auto-generation to avoid excessive calls
        clearTimeout(this.autoGenerationTimeout);
        clearInterval(this.countdownInterval);
        
        // Cancel any in-progress generation when inputs change
        const wasGenerating = this.isGenerating;
        if (wasGenerating) {
            this.generationCancelled = true;
            
            // Cancel pending worker requests - old results are invalid
            if (typeof Argon2WorkerPool !== 'undefined') {
                Argon2WorkerPool.cancelPendingRequests();
            }
        }
        
        // Clear cached seed bytes to force re-derivation
        this.currentSeedBytes = null;
        
        // Use 2 second delay with visual countdown
        const delay = wasGenerating ? 500 : 2000;
        
        // Show countdown indicator
        this.showAutoGenCountdown(delay);
        
        this.autoGenerationTimeout = setTimeout(() => {
            // Force isGenerating to false if we cancelled a generation
            // The old generation is dead (cancellation flag set)
            if (wasGenerating) {
                this.isGenerating = false;
            }
            this.hideAutoGenCountdown();
            this.handleGenerate(true); // Pass true to indicate auto-generation
        }, delay);
    }
    
    showAutoGenCountdown(delayMs) {
        const countdownEl = document.getElementById('auto-gen-countdown');
        const countdownValue = document.getElementById('countdown-value');
        if (!countdownEl || !countdownValue) return;
        
        countdownEl.style.display = 'flex';
        countdownEl.classList.remove('countdown-cancelled');
        
        // Calculate remaining time and update display
        let remaining = Math.ceil(delayMs / 1000);
        countdownValue.textContent = `${remaining}s`;
        
        this.countdownInterval = setInterval(() => {
            remaining--;
            if (remaining > 0) {
                countdownValue.textContent = `${remaining}s`;
            } else {
                countdownValue.textContent = 'now';
            }
        }, 1000);
    }
    
    hideAutoGenCountdown() {
        clearInterval(this.countdownInterval);
        const countdownEl = document.getElementById('auto-gen-countdown');
        if (countdownEl) {
            countdownEl.style.display = 'none';
        }
    }
    
    handleGenModeChange(event) {
        const selectedMode = event.target.value;
        
        // Save mode preference
        this.preferences.lastGenerationMode = selectedMode;
        this.savePreferences();
        
        // Update description display
        document.querySelectorAll('.desc-content').forEach(desc => {
            desc.style.display = 'none';
        });
        const selectedDesc = document.getElementById(`desc-${selectedMode}`);
        if (selectedDesc) {
            selectedDesc.style.display = 'block';
        }
        
        // Automatically trigger generation when mode changes
        this.handleGenerate(false); // false = not auto-generation
    }
    
    async handleGenerate(isAutoGeneration = false) {
        if (this.isGenerating) {
            return;
        }

        
        try {
            this.isGenerating = true;
            this.generationCancelled = false; // Reset cancellation flag for new generation
            this.updateStatus('Generating...', 'info');
            
            // For auto-generation, don't show loading state for very quick operations
            if (!isAutoGeneration) {
                this.showLoadingState();
            }
            
            // Get seed bytes based on selected type
            const seedBytes = await this.getSeedBytes(isAutoGeneration);
            if (!seedBytes) {
                if (isAutoGeneration) {
                    // Silently fail for auto-generation when inputs are incomplete
                    this.updateStatus('Ready');
                    return;
                }
                throw new Error('Failed to generate seed bytes. Please check your input.');
            }
            
            this.currentSeedBytes = seedBytes;
            
            // Always generate 100 cards (removed single card option)
            await this.generateBatchCards();
            this.updateStatus('100 cards generated!', 'success');
            
        } catch (error) {
            console.error('Generation error:', error);
            this.updateStatus('Generation failed', 'error');
            if (!isAutoGeneration) {
                // Use status bar instead of modal for error display
                this.updateStatus(`Generation failed: ${error.message}`, 'error');
            }
            // Silently fail for auto-generation
        } finally {
            this.isGenerating = false;
            if (!isAutoGeneration) {
                this.hideLoadingState();
            }
        }
    }
    
    async handleDemoGenerate() {
        try {
            // Get seed phrase from input, fallback to default if empty or not found
            let seedPhrase = 'test phrase'; // Default
            const seedInput = document.getElementById('demo-seed');
            if (seedInput && seedInput.value.trim()) {
                seedPhrase = seedInput.value.trim();
            }
            
            const seedBytes = await SeedSources.simpleToSeed(seedPhrase);
            const base = this.getSelectedBase();
            const result = await SeedCardCrypto.generateTokenMatrix(seedBytes, 'A0', base);
            
            this.displayDemoMatrix(result.matrix);
        } catch (error) {
            console.error('Demo generation failed:', error);
            this.showError('Failed to generate demo matrix: ' + error.message);
        }
    }
    
    /**
     * Generate seed bytes using Argon2 with a v1 label.
     * This is the new secure method for simple seeds.
     * 
     * @param {string} phrase - The seed phrase
     * @param {string} cardId - Card identifier (base name only, e.g., "Banking")
     * @param {string} cardIndex - Card index as grid coordinate (A0-J9)
     * @param {string} cardDate - Card date (YYYY-MM-DD)
     * @param {string} base - Base system (base10, base62, base90)
     * @param {string|null} nonce - Optional nonce (auto-generated if null)
     * @param {number} memoryMb - Argon2 memory in MB (default 512MB)
     * @returns {Object} { seedBytes, label }
     */
    async deriveArgon2Seed(phrase, cardId, cardIndex, cardDate, base, nonce = null, memoryMb = CONFIG.ARGON2_MEMORY_COST_MB) {
        // Check if Argon2 is available
        if (typeof argon2 === 'undefined') {
            console.warn('Argon2 not available, falling back to SHA-512');
            const seedBytes = await SeedSources.simpleToSeed(phrase);
            const fallbackLabel = `legacy|SIMPLE|SHA512|${base.toUpperCase()}|${cardDate}|${cardId}|${cardIndex}`;
            return { seedBytes, label: fallbackLabel };
        }
        
        // Build v1 label with new format: v1|TYPE|KDF|PARAMS|BASE|DATE|NONCE|CARDID|INDEX
        const timeCost = parseInt(document.getElementById('argon2-time')?.value || CONFIG.ARGON2_TIME_COST);
        const parallelism = parseInt(document.getElementById('argon2-parallelism')?.value || CONFIG.ARGON2_PARALLELISM);
        const kdfParams = LabelUtils.encodeArgon2Params(timeCost, memoryMb, parallelism);
        const label = LabelUtils.buildLabel(
            'SIMPLE',
            'ARGON2ID',
            kdfParams,
            base.toUpperCase(),
            cardDate,
            nonce,
            cardId,
            cardIndex
        );
        
        // Derive seed using Argon2 with label as salt
        const seedBytes = await SeedSources.argon2ToSeed(phrase, label, 
            timeCost, memoryMb, parallelism);
        
        return { seedBytes, label };
    }
    
    async getSeedBytes(isAutoGeneration = false) {
        // Check rate limiting for generation operations
        if (!SecurityUtils.checkRateLimit('generation', 20, 60000)) {
            throw new Error('Rate limit exceeded. Please wait before generating more cards.');
        }
        
        // First check if we have valid seed bytes from hash input
        if (this.currentSeedBytes) {
            return this.currentSeedBytes;
        }
        
        const seedType = document.querySelector('input[name="seedType"]:checked').value;
        
        // Get KDF selection (default to Argon2)
        const kdfType = document.querySelector('input[name="kdfType"]:checked')?.value || 'argon2';
        
        let seedBytes;
        let label = null;
        
        switch (seedType) {
            case 'simple':
                const simplePhrase = document.getElementById('simple-phrase').value || '';
                
                // For auto-generation, silently return null if input is empty
                if (isAutoGeneration && !simplePhrase.trim()) {
                    return null;
                }
                
                const simplePhraseValidation = SecurityUtils.validateSeedPhrase(simplePhrase);
                if (!simplePhraseValidation.valid) {
                    throw new Error(`Invalid seed phrase: ${simplePhraseValidation.error}`);
                }
                
                // Use Argon2 or SHA-512 based on KDF selection
                if (kdfType === 'argon2' && typeof argon2 !== 'undefined') {
                    // Build v1 label for Argon2 derivation
                    const cardId = this.buildCardId() || 'CARD';
                    const cardIndex = 'A0'; // Single card generation defaults to A0
                    const cardDate = this.getCardDate();
                    const base = this.getSelectedBase();
                    const nonce = document.getElementById('card-nonce')?.value.trim() || LabelUtils.generateNonce();
                    const memoryMb = parseInt(document.getElementById('argon2-memory')?.value || CONFIG.ARGON2_MEMORY_COST_MB);
                    const parallelism = parseInt(document.getElementById('argon2-parallelism')?.value || CONFIG.ARGON2_PARALLELISM);
                    const timeCost = parseInt(document.getElementById('argon2-time')?.value || CONFIG.ARGON2_TIME_COST);
                    
                    // Build label with new format: v1|TYPE|KDF|PARAMS|BASE|DATE|NONCE|CARDID|INDEX
                    const kdfParams = LabelUtils.encodeArgon2Params(timeCost, memoryMb, parallelism);
                    label = LabelUtils.buildLabel('SIMPLE', 'ARGON2ID', kdfParams, base.toUpperCase(), cardDate, nonce, cardId, cardIndex);
                    
                    seedBytes = await SeedSources.argon2ToSeed(
                        simplePhraseValidation.sanitized,
                        label,
                        timeCost,
                        memoryMb,
                        parallelism
                    );
                    
                    // Store the label for display
                    this.currentLabel = label;
                } else {
                    // Fallback to SHA-512
                    seedBytes = await SeedSources.simpleToSeed(simplePhraseValidation.sanitized);
                    this.currentLabel = null;
                }
                break;
                
            case 'bip39':
                const mnemonic = document.getElementById('bip39-mnemonic').value || '';
                
                // For auto-generation, silently return null if input is empty
                if (isAutoGeneration && !mnemonic.trim()) {
                    return null;
                }
                
                const mnemonicValidation = SecurityUtils.validateBIP39Mnemonic(mnemonic);
                if (!mnemonicValidation.valid) {
                    throw new Error(`Invalid BIP-39 mnemonic: ${mnemonicValidation.error}`);
                }
                
                const passphrase = document.getElementById('bip39-passphrase').value || '';
                const passphraseValidation = SecurityUtils.validateSeedPhrase(passphrase);
                if (!passphraseValidation.valid && passphrase.length > 0) {
                    throw new Error(`Invalid passphrase: ${passphraseValidation.error}`);
                }
                
                // Use Argon2 or PBKDF2 based on KDF selection
                if (kdfType === 'argon2' && typeof argon2 !== 'undefined') {
                    // First derive BIP-39 seed, then apply Argon2
                    const bip39Iterations = parseInt(document.getElementById('bip39-iterations').value) || 2048;
                    const bip39Seed = await SeedSources.bip39ToSeed(
                        mnemonicValidation.sanitized,
                        passphraseValidation.sanitized || '',
                        bip39Iterations
                    );
                    
                    // Build v1 label for Argon2 derivation
                    const bip39CardId = this.buildCardId() || 'CARD';
                    const bip39CardIndex = 'A0';
                    const bip39CardDate = this.getCardDate();
                    const bip39Base = this.getSelectedBase();
                    const bip39Nonce = document.getElementById('card-nonce')?.value.trim() || LabelUtils.generateNonce();
                    const bip39MemoryMb = parseInt(document.getElementById('argon2-memory')?.value || CONFIG.ARGON2_MEMORY_COST_MB);
                    const bip39Parallelism = parseInt(document.getElementById('argon2-parallelism')?.value || CONFIG.ARGON2_PARALLELISM);
                    const bip39TimeCost = parseInt(document.getElementById('argon2-time')?.value || CONFIG.ARGON2_TIME_COST);
                    
                    const bip39KdfParams = LabelUtils.encodeArgon2Params(bip39TimeCost, bip39MemoryMb, bip39Parallelism);
                    label = LabelUtils.buildLabel('BIP-39', 'ARGON2ID', bip39KdfParams, bip39Base.toUpperCase(), bip39CardDate, bip39Nonce, bip39CardId, bip39CardIndex);
                    
                    // Use the BIP-39 seed hex as input to Argon2
                    const bip39SeedHex = Array.from(bip39Seed).map(b => b.toString(16).padStart(2, '0')).join('');
                    seedBytes = await SeedSources.argon2ToSeed(
                        bip39SeedHex,
                        label,
                        bip39TimeCost,
                        bip39MemoryMb,
                        bip39Parallelism
                    );
                    this.currentLabel = label;
                } else {
                    // Fallback to standard BIP-39 PBKDF2
                    const iterations = parseInt(document.getElementById('bip39-iterations').value) || 2048;
                    if (iterations < 1000 || iterations > 100000) {
                        throw new Error('Iterations must be between 1000 and 100000');
                    }
                    seedBytes = await SeedSources.bip39ToSeed(
                        mnemonicValidation.sanitized, 
                        passphraseValidation.sanitized || '',
                        iterations
                    );
                    this.currentLabel = null;
                }
                break;
                
            case 'slip39':
                const shareInputs = document.querySelectorAll('.slip39-share');
                const shares = [];
                
                for (const input of shareInputs) {
                    const shareValue = input.value || '';
                    if (shareValue.trim().length > 0) {
                        const shareValidation = SecurityUtils.validateSeedPhrase(shareValue);
                        if (!shareValidation.valid) {
                            throw new Error(`Invalid SLIP-39 share: ${shareValidation.error}`);
                        }
                        shares.push(shareValidation.sanitized);
                    }
                }
                
                // For auto-generation, silently return null if insufficient shares
                if (isAutoGeneration && shares.length < 2) {
                    return null;
                }
                
                if (shares.length < 2) {
                    throw new Error('At least 2 SLIP-39 shares are required');
                }
                
                if (shares.length > 10) {
                    throw new Error('Too many SLIP-39 shares (maximum 10)');
                }
                
                // Use Argon2 or SHA-512 based on KDF selection
                if (kdfType === 'argon2' && typeof argon2 !== 'undefined') {
                    // Combine shares into deterministic input
                    const combinedShares = shares.join(' ');
                    
                    // Build v1 label for Argon2 derivation
                    const slip39CardId = this.buildCardId() || 'CARD';
                    const slip39CardIndex = 'A0';
                    const slip39CardDate = this.getCardDate();
                    const slip39Base = this.getSelectedBase();
                    const slip39Nonce = document.getElementById('card-nonce')?.value.trim() || LabelUtils.generateNonce();
                    const slip39MemoryMb = parseInt(document.getElementById('argon2-memory')?.value || CONFIG.ARGON2_MEMORY_COST_MB);
                    const slip39Parallelism = parseInt(document.getElementById('argon2-parallelism')?.value || CONFIG.ARGON2_PARALLELISM);
                    const slip39TimeCost = parseInt(document.getElementById('argon2-time')?.value || CONFIG.ARGON2_TIME_COST);
                    
                    const slip39KdfParams = LabelUtils.encodeArgon2Params(slip39TimeCost, slip39MemoryMb, slip39Parallelism);
                    label = LabelUtils.buildLabel('SLIP-39', 'ARGON2ID', slip39KdfParams, slip39Base.toUpperCase(), slip39CardDate, slip39Nonce, slip39CardId, slip39CardIndex);
                    
                    seedBytes = await SeedSources.argon2ToSeed(
                        combinedShares,
                        label,
                        slip39TimeCost,
                        slip39MemoryMb,
                        slip39Parallelism
                    );
                    this.currentLabel = label;
                } else {
                    // Fallback to simple hash of combined shares
                    seedBytes = await SeedSources.slip39ToSeed(shares);
                    this.currentLabel = null;
                }
                break;
                
            default:
                throw new Error('Invalid seed type selected');
        }
        
        // Register sensitive data for cleanup
        this.registerSensitiveData(seedBytes);
        
        // Show seed hash and collapse seed options
        this.showSeedHash(seedBytes);
        
        return seedBytes;
    }
    
    showSeedHash(seedBytes) {
        const seedHashDisplay = document.getElementById('seed-hash-display');
        const seedOptions = document.getElementById('seed-options');
        const seedHashValue = document.getElementById('seed-hash-value');
        const generateCardsBtn = document.getElementById('generate-cards-btn');
        
        if (seedHashDisplay && seedHashValue && seedOptions) {
            // Convert to hex string for display
            const hashHex = Array.from(seedBytes)
                .map(byte => byte.toString(16).padStart(2, '0'))
                .join('')
                .toUpperCase();
            
            seedHashValue.value = hashHex;
            seedHashValue.classList.remove('invalid');
            seedHashValue.classList.add('valid');
            
            // Update stats
            this.updateHashStats(hashHex);
            
            seedHashDisplay.style.display = 'block';
            seedOptions.style.display = 'none';
            
            // Enable generate cards button
            if (generateCardsBtn) {
                generateCardsBtn.disabled = false;
                generateCardsBtn.classList.remove('btn-disabled');
            }
        }
    }
    
    async handleValidateHash() {
        const hashInput = document.getElementById('seed-hash-value');
        const generateCardsBtn = document.getElementById('generate-cards-btn');
        
        if (!hashInput) return;
        
        const hashValue = hashInput.value.trim();
        
        // Validate SHA-512 format (128 hex characters)
        const isValid = this.validateSHA512Hash(hashValue);
        
        if (isValid) {
            hashInput.classList.remove('invalid');
            hashInput.classList.add('valid');
            
            // Convert hex string to bytes
            const hashBytes = new Uint8Array(hashValue.match(/.{2}/g).map(byte => parseInt(byte, 16)));
            this.currentSeedBytes = hashBytes;
            
            // Enable generate cards button
            if (generateCardsBtn) {
                generateCardsBtn.disabled = false;
                generateCardsBtn.classList.remove('btn-disabled');
            }
        } else {
            hashInput.classList.remove('valid');
            hashInput.classList.add('invalid');
            
            // Disable generate cards button
            if (generateCardsBtn) {
                generateCardsBtn.disabled = true;
                generateCardsBtn.classList.add('btn-disabled');
            }
        }
        
        return isValid;
    }
    
    handleHashInput() {
        const hashInput = document.getElementById('seed-hash-value');
        if (!hashInput) return;
        
        const hashValue = hashInput.value.trim();
        
        // Update character/byte/bit counts
        this.updateHashStats(hashValue);
        
        // Automatic validation
        const isValid = this.validateSHA512Hash(hashValue);
        const generateCardsBtn = document.getElementById('generate-cards-btn');
        
        if (isValid) {
            hashInput.classList.remove('invalid');
            hashInput.classList.add('valid');
            
            // Convert hex string to bytes
            const hashBytes = new Uint8Array(hashValue.match(/.{2}/g).map(byte => parseInt(byte, 16)));
            this.currentSeedBytes = hashBytes;
            
            // Enable generate cards button
            if (generateCardsBtn) {
                generateCardsBtn.disabled = false;
                generateCardsBtn.classList.remove('btn-disabled');
            }
        } else {
            hashInput.classList.remove('valid');
            if (hashValue.length > 0) {
                hashInput.classList.add('invalid');
            }
            
            // Clear stored seed bytes
            this.currentSeedBytes = null;
            
            // Disable generate cards button
            if (generateCardsBtn) {
                generateCardsBtn.disabled = true;
                generateCardsBtn.classList.add('btn-disabled');
            }
        }
    }
    
    updateHashStats(hashValue) {
        const charCount = hashValue.length;
        const byteCount = Math.floor(charCount / 2);
        const bitCount = byteCount * 8;
        const isValidFormat = this.validateSHA512Hash(hashValue);
        
        // Calculate actual seed entropy based on source input
        const seedEntropy = this.calculateActualSeedEntropy();
        
        // Update stat displays
        const charCountEl = document.getElementById('char-count');
        const byteCountEl = document.getElementById('byte-count');
        const bitCountEl = document.getElementById('bit-count');
        const formatStatusEl = document.getElementById('format-status');
        const seedEntropyEl = document.getElementById('seed-entropy');
        
        if (charCountEl) {
            charCountEl.textContent = `Characters: ${charCount}`;
            charCountEl.className = `hash-stat ${charCount === 128 ? 'valid' : (charCount > 128 ? 'invalid' : '')}`;
        }
        
        if (byteCountEl) {
            byteCountEl.textContent = `Bytes: ${byteCount}`;
            byteCountEl.className = `hash-stat ${byteCount === 64 ? 'valid' : (byteCount > 64 ? 'invalid' : '')}`;
        }
        
        if (bitCountEl) {
            bitCountEl.textContent = `Bits: ${bitCount}`;
            bitCountEl.className = `hash-stat ${bitCount === 512 ? 'valid' : (bitCount > 512 ? 'invalid' : '')}`;
        }
        
        if (formatStatusEl) {
            formatStatusEl.textContent = `Format: ${isValidFormat ? 'Valid SHA-512' : (charCount === 0 ? 'Empty' : 'Invalid')}`;
            formatStatusEl.className = `hash-stat ${isValidFormat ? 'valid' : 'invalid'}`;
        }
        
        if (seedEntropyEl) {
            const entropyDisplay = seedEntropy > 0 ? `${Math.round(seedEntropy * 10) / 10} bits` : '0 bits';
            seedEntropyEl.textContent = `Seed Entropy: ${entropyDisplay}`;
            seedEntropyEl.className = `hash-stat ${seedEntropy > 0 ? 'valid' : 'invalid'}`;
        }
    }
    
    /**
     * Calculate actual seed entropy based on current input
     */
    calculateActualSeedEntropy() {
        const seedType = document.querySelector('input[name="seedType"]:checked')?.value || 'simple';
        
        switch (seedType) {
            case 'simple':
                const simplePhrase = document.getElementById('simple-phrase')?.value?.trim() || '';
                if (!simplePhrase) return 0;
                
                // Calculate entropy based on phrase characteristics
                const hasLower = /[a-z]/.test(simplePhrase);
                const hasUpper = /[A-Z]/.test(simplePhrase);
                const hasDigits = /[0-9]/.test(simplePhrase);
                const hasSpecial = /[^a-zA-Z0-9\s]/.test(simplePhrase);
                const hasSpaces = /\s/.test(simplePhrase);
                
                let charsetSize = 0;
                if (hasLower) charsetSize += 26;
                if (hasUpper) charsetSize += 26;
                if (hasDigits) charsetSize += 10;
                if (hasSpecial) charsetSize += 32; // Estimate
                if (hasSpaces) charsetSize += 1;
                
                charsetSize = Math.max(charsetSize, 10); // Minimum charset
                
                // Account for common patterns and dictionary words (reduce effective entropy)
                const effectiveLength = Math.max(simplePhrase.length * 0.6, 1); // Conservative estimate
                return Math.log2(Math.pow(charsetSize, effectiveLength));
                
            case 'bip39':
                const mnemonicWords = document.getElementById('bip39-mnemonic')?.value?.trim().split(/\s+/) || [];
                const validWordCount = mnemonicWords.filter(w => w.length > 0).length;
                if (validWordCount === 0) return 0;
                
                // BIP39 entropy: 11 bits per word (2048 word list), minus checksum
                // 12 words = 128 bits, 15 words = 160 bits, 18 words = 192 bits, 21 words = 224 bits, 24 words = 256 bits
                const wordEntropy = validWordCount * 11;
                const checksumBits = Math.floor(validWordCount / 3);
                const actualEntropy = wordEntropy - checksumBits;
                
                // Common configurations: 12 words (128 bits), 24 words (256 bits)
                return Math.max(actualEntropy, 0);
                
            case 'slip39':
                // SLIP39 shares typically represent 128-256 bits of entropy
                const shares = document.querySelectorAll('.slip39-share');
                let validShares = 0;
                shares.forEach(share => {
                    if (share.value.trim()) validShares++;
                });
                if (validShares < 2) return 0;
                return 128; // Conservative estimate for SLIP39
                
            default:
                return 0;
        }
    }
    
    /**
     * Update matrix entropy display
     */
    updateMatrixEntropy() {
        // Calculate Base90 token entropy
        const tokenEntropy = EntropyAnalyzer.calculateTokenEntropy();
        const matrixTotalEntropy = tokenEntropy * 100; // 100 tokens in 10x10 matrix
        const singlePasswordEntropy = tokenEntropy * 4; // 4 tokens typical password
        
        // Update displays
        const tokenEntropyEl = document.getElementById('token-entropy');
        const singlePasswordEntropyEl = document.getElementById('single-password-entropy');
        const matrixEntropyInfo = document.getElementById('matrix-entropy-info');
        
        if (tokenEntropyEl) {
            tokenEntropyEl.textContent = `Per Token: ${Math.round(tokenEntropy * 10) / 10} bits`;
        }
        
        if (singlePasswordEntropyEl) {
            singlePasswordEntropyEl.textContent = `Single Password (4 tokens): ${Math.round(singlePasswordEntropy * 10) / 10} bits`;
        }
        
        // Show the entropy info section
        if (matrixEntropyInfo) {
            matrixEntropyInfo.style.display = 'block';
        }
    }
    
    validateSHA512Hash(hashString) {
        // Check if it's exactly 128 hex characters
        const hexRegex = /^[A-Fa-f0-9]{128}$/;
        return hexRegex.test(hashString);
    }
    
    handleChangeSeed() {
        const seedHashDisplay = document.getElementById('seed-hash-display');
        const seedOptions = document.getElementById('seed-options');
        const hashInput = document.getElementById('seed-hash-value');
        const simplePhraseInput = document.getElementById('simple-phrase');
        
        if (seedHashDisplay && seedOptions) {
            seedHashDisplay.style.display = 'none';
            seedOptions.style.display = 'block';
            
            // Clear hash input validation
            if (hashInput) {
                hashInput.classList.remove('valid', 'invalid');
            }
            
            // Focus on the simple phrase input and select all text for easy editing
            if (simplePhraseInput) {
                setTimeout(() => {
                    simplePhraseInput.focus();
                    simplePhraseInput.select();
                }, 100);
            }
        }
    }
    
    async handleGenerateHash() {
        try {
            // Cancel any in-progress generation first
            if (this.isGenerating) {
                this.generationCancelled = true;
                
                // Cancel pending worker requests
                if (typeof Argon2WorkerPool !== 'undefined') {
                    Argon2WorkerPool.cancelPendingRequests();
                }
                
                // Force reset the generating flag so we can start fresh
                this.isGenerating = false;
                this.updateStatus('Restarting generation...', 'info');
            }
            
            // Validate input based on seed type
            const seedType = document.querySelector('input[name="seedType"]:checked').value;
            
            if (seedType === 'simple') {
                const phrase = document.getElementById('simple-phrase').value.trim();
                if (!phrase) {
                    alert('Please enter a seed phrase');
                    return;
                }
            } else if (seedType === 'bip39') {
                const mnemonic = document.getElementById('bip39-mnemonic').value.trim();
                if (!mnemonic) {
                    alert('Please enter a BIP-39 mnemonic');
                    return;
                }
            } else if (seedType === 'slip39') {
                const shares = Array.from(document.querySelectorAll('.slip39-share'))
                    .map(textarea => textarea.value.trim())
                    .filter(share => share.length > 0);
                if (shares.length < 2) {
                    alert('Please enter at least 2 SLIP-39 shares');
                    return;
                }
            }
            
            // Get seed bytes
            const seedBytes = await this.getSeedBytes(false); // Not auto-generation when manually generating hash
            
            // Store for later use
            this.currentSeedBytes = seedBytes;
            
            // Generate and show hash
            this.showSeedHash(seedBytes);
            
            // Trigger card generation after hash is generated
            await this.handleGenerate(false);
            
        } catch (error) {
            console.error('Failed to generate hash:', error);
            alert('Failed to generate hash: ' + error.message);
        }
    }
    
    buildCardId() {
        const cardIdInput = document.getElementById('card-id');
        const cardIdValue = cardIdInput?.value || '';
        
        // Validate and sanitize the card ID
        const cardIdValidation = SecurityUtils.validateDomain(cardIdValue);
        if (!cardIdValidation.valid) {
            throw new Error(`Invalid card ID: ${cardIdValidation.error}`);
        }
        
        return cardIdValidation.sanitized;
    }
    
    getCardDate() {
        const cardDateInput = document.getElementById('card-date');
        const cardDateValue = cardDateInput?.value?.trim() || '';
        
        if (cardDateValue.length === 0) {
            return null; // Optional field
        }
        
        // Validate and sanitize card date
        const dateValidation = SecurityUtils.validateCardDate(cardDateValue);
        if (!dateValidation.valid) {
            throw new Error(`Invalid card date: ${dateValidation.error}`);
        }
        
        return dateValidation.sanitized;
    }
    
    getSelectedBase() {
        const baseRadio = document.querySelector('input[name="baseSystem"]:checked');
        return baseRadio?.value || 'base90';
    }
    
    displayLabelInfo(label, cardDate) {
        // Display label information in the console and potentially in the UI
        
        // Could add UI display here if needed
        // const labelDisplay = document.getElementById('label-display');
        // if (labelDisplay) {
        //     labelDisplay.innerHTML = `<div class="label-info">
        //         <div>📅 Card Date: <code>${cardDate}</code></div>
        //         <div>🏷️ HMAC Label: <code>${label}</code></div>
        //     </div>`;
        // }
    }
    
    async generateSingleCard() {
        if (!this.currentSeedBytes) {
            console.error('No seed bytes available for card generation');
            alert('Please generate a hash first in the Seed Configuration section.');
            return;
        }
        
        try {
            const baseCardId = this.buildCardId();
            const cardIndex = 'A0'; // Single card is always A0
            const cardDate = this.getCardDate();
            const base = this.getSelectedBase();
            const result = await SeedCardCrypto.generateTokenMatrix(this.currentSeedBytes, cardIndex, base);
            const digest = await SeedCardCrypto.generateDigest(this.currentSeedBytes);
            
            this.currentMatrix = result.matrix;
            this.currentCardId = `${baseCardId}.${cardIndex}`; // Combined ID for display
            
            // Register sensitive data for cleanup
            this.registerSensitiveData(result.matrix);
            this.registerSensitiveData(digest);
            
            // Display the enhanced label information for transparency
            if (cardDate) {
                this.displayLabelInfo(result.label, cardDate);
            }
            
            // Add domain to history on successful generation
            const domainInput = document.getElementById('card-domain');
            if (domainInput?.value.trim()) {
                this.addToHistory(domainInput.value.trim());
            }
            
            this.displaySingleCard(result.matrix, cardId, digest, result.label);
            this.generatePasswordExamples(result.matrix);
            this.showResults();
            
        } catch (error) {
            console.error('Error in generateSingleCard:', error);
            alert('Failed to generate card: ' + error.message);
        }
    }
    
    async generateBatchCards() {
        const batchSize = 100; // Generate 100 cards indexed A0-J9 (spreadsheet convention)
        const cards = [];
        
        // Reset cancel flag
        this.generationCancelled = false;
        
        try {
            this.updateStatus('Preparing secure generation...', 'info');
            
            // Get base ID from domain + suffix combination
            const baseCardId = this.buildCardId();
            const base = this.getSelectedBase();
            const cardDate = this.getCardDate();
            
            // Get KDF settings
            const kdfType = document.querySelector('input[name="kdfType"]:checked')?.value || 'argon2';
            const memorySelector = document.getElementById('argon2-memory');
            const memorySelectorValue = memorySelector?.value;
            let memoryMb = parseInt(memorySelectorValue || CONFIG.ARGON2_MEMORY_COST_MB);
            const nonce = document.getElementById('card-nonce')?.value.trim() || LabelUtils.generateNonce();
            
            // Debug: log memory configuration
            
            // Get phrase for Argon2 per-card derivation
            const phrase = this.getCurrentPhrase();
            
            // Determine if we can proceed:
            // - If we have a phrase, use Argon2 per-card derivation
            // - If we have cached seed bytes (from SHA-512 hash), use those directly
            // - If neither, we can't generate
            const useArgon2PerCard = phrase && kdfType === 'argon2' && typeof argon2 !== 'undefined';
            const useCachedSeedBytes = !phrase && this.currentSeedBytes;
            
            if (!phrase && !this.currentSeedBytes) {
                // No phrase and no cached seed bytes - can't generate
                return;
            }
            
            // Check if using parallel workers (only for Argon2)
            const useParallelWorkers = useArgon2PerCard && typeof Argon2WorkerPool !== 'undefined';
            
            // Initialize button states
            this.initializeCardButtonStates(batchSize);
            
            // Initialize batchCards array for live updates
            this.batchCards = new Array(batchSize).fill(null);
            this.selectedCardIndex = null;
            
            // Show results section early so we can display cards as they generate
            this.showResults();
            
            if (useCachedSeedBytes) {
                // CACHED SEED BYTES - use currentSeedBytes directly (SHA-512 hash mode)
                await this.generateBatchFromCachedSeed(batchSize, cards, baseCardId, base, cardDate, nonce);
            } else if (useParallelWorkers) {
                // PARALLEL GENERATION using worker pool
                await this.generateBatchParallel(batchSize, cards, phrase, baseCardId, base, cardDate, nonce, memoryMb);
            } else {
                // SEQUENTIAL GENERATION (fallback)
                await this.generateBatchSequential(batchSize, cards, phrase, baseCardId, base, cardDate, nonce, memoryMb, useArgon2PerCard);
            }
            
            // Check if generation was cancelled - exit early without errors
            if (this.generationCancelled) {
                return;
            }
            
            // Filter out any null/undefined entries (failed or incomplete cards)
            const successfulCards = cards.filter(c => c != null);
            
            if (successfulCards.length === 0) {
                throw new Error('Failed to generate any cards');
            }
            
            this.displayBatchCards(successfulCards);
            // Add domain to history on successful generation
            const domainInput = document.getElementById('card-domain');
            if (domainInput?.value.trim()) {
                this.addToHistory(domainInput.value.trim());
            }
            
            // Generate password examples using the first card in the grid (card .A0)
            if (cards.length > 0) {
                const firstCard = cards.find(card => card.id.endsWith('.A0')) || cards[0];
                this.currentMatrix = firstCard.matrix;
                this.currentCardId = firstCard.id;
                await this.generatePasswordExamples(firstCard.matrix);
            }
            
            // Final status update
            this.updateStatus(`✅ Successfully generated ${successfulCards.length} cards`, 'success');
            
        } catch (error) {
            console.error('Batch generation failed:', error);
            this.updateStatus(`Batch generation failed: ${error.message}`, 'error');
        }
    }
    
    /**
     * PARALLEL batch generation using Argon2WorkerPool
     * Runs multiple Argon2 hashes simultaneously across CPU cores
     */
    async generateBatchParallel(batchSize, cards, phrase, baseCardId, base, cardDate, nonce, memoryMb) {
        const parallelism = parseInt(document.getElementById('argon2-parallelism')?.value || CONFIG.ARGON2_PARALLELISM);
        const timeCost = parseInt(document.getElementById('argon2-time')?.value || CONFIG.ARGON2_TIME_COST);
        
        // Calculate worker count based on memory setting
        // Safari has lower total memory limits than Chrome/Firefox
        // Account for ~16MB WASM overhead per worker on top of Argon2 memory
        const isSafari = /^((?!chrome|android).)*safari/i.test(navigator.userAgent);
        const wasmOverhead = 16; // MB overhead per worker for WASM module
        const effectiveMemoryPerWorker = memoryMb + wasmOverhead;
        const totalMemoryBudget = isSafari ? 384 : 2048; // Safari: 384MB, others: 2GB
        const maxSafeWorkers = Math.max(1, Math.floor(totalMemoryBudget / effectiveMemoryPerWorker));
        const cpuCores = typeof navigator !== 'undefined' && navigator.hardwareConcurrency 
            ? navigator.hardwareConcurrency : 8;
        const workerCount = Math.min(cpuCores, maxSafeWorkers, 8);
        
        this.updateStatus(`Initializing ${workerCount} parallel workers...`, 'info');
        
        // Pass memoryMb to pool so workers know how much memory to allocate
        const poolInitialized = await Argon2WorkerPool.initialize(workerCount, memoryMb);
        const poolStatus = Argon2WorkerPool.getStatus();
        
        // If pool failed to initialize, fall back to sequential
        if (poolStatus.totalWorkers === 0) {
            console.warn('⚠️ Worker pool failed to initialize, falling back to sequential generation');
            this.updateStatus('Using sequential generation (single thread)...', 'info');
            return this.generateBatchSequential(batchSize, cards, phrase, baseCardId, base, cardDate, nonce, memoryMb, true);
        }
        
        const startTime = performance.now();
        let completed = 0;
        
        // Build all jobs
        const jobs = [];
        for (let i = 0; i < batchSize; i++) {
            const cardIndex = LabelUtils.indexToCoord(i);
            const kdfParams = LabelUtils.encodeArgon2Params(timeCost, memoryMb, parallelism);
            const label = LabelUtils.buildLabel(
                'SIMPLE', 'ARGON2ID', kdfParams,
                base.toUpperCase(), cardDate, nonce, baseCardId, cardIndex
            );
            
            jobs.push({
                index: i,
                cardIndex,
                label,
                params: {
                    phrase,
                    salt: label,
                    timeCost,
                    memoryMb,
                    parallelism, // Use UI-selected lanes (crypto parameter, affects hash output)
                    hashLength: 64
                }
            });
        }
        
        // Shuffle jobs for random visual order (Fisher-Yates)
        for (let i = jobs.length - 1; i > 0; i--) {
            const j = Math.floor(Math.random() * (i + 1));
            [jobs[i], jobs[j]] = [jobs[j], jobs[i]];
        }
        
        // Mark all as pending (grey) - they'll turn to 'generating' when actually processed
        for (let i = 0; i < batchSize; i++) {
            this.updateCardButtonState(i, 'pending');
        }
        
        this.updateStatus(`🚀 Parallel generation: ${batchSize} cards across ${poolStatus.totalWorkers} cores`, 'info');
        
        // Process jobs in chunks to limit memory pressure
        // Each chunk processes workerCount jobs concurrently
        const chunkSize = poolStatus.totalWorkers;
        
        for (let chunkStart = 0; chunkStart < jobs.length; chunkStart += chunkSize) {
            // Check for cancellation between chunks
            if (this.generationCancelled) {
                return;
            }
            
            const chunkEnd = Math.min(chunkStart + chunkSize, jobs.length);
            const chunk = jobs.slice(chunkStart, chunkEnd);
            
            // Process this chunk in parallel
            const chunkPromises = chunk.map(async (job) => {
                // Check cancellation before each job
                if (this.generationCancelled) {
                    return; // Skip this job
                }
                
                // Mark as generating (pulsing) when actually starting
                this.updateCardButtonState(job.index, 'generating');
                
                try {
                    const seedBytes = await Argon2WorkerPool.hash(job.params);
                    
                    // Check cancellation after hash (in case it was cancelled mid-computation)
                    if (this.generationCancelled) {
                        seedBytes.fill(0);
                        return;
                    }
                    
                    // Generate token matrix from seed
                    const result = await SeedCardCrypto.generateTokenMatrix(seedBytes, job.cardIndex, base);
                    const combinedHash = await this.computeCardHash(job.label, seedBytes);
                    
                    // Clear seedBytes immediately after use
                    seedBytes.fill(0);
                    
                    const row = Math.floor(job.index / 10);
                    const col = job.index % 10;
                    const displayCardId = `${baseCardId}.${job.cardIndex}`;
                    
                    cards[job.index] = {
                        id: displayCardId,
                        cardIndex: job.cardIndex,
                        matrix: result.matrix,
                        digest: combinedHash.substring(0, 8),
                        position: { row, col },
                        label: job.label,
                        cardDate: cardDate
                    };
                    
                    this.batchCards[job.index] = cards[job.index];
                    this.displayCardLive(cards[job.index], job.index);
                    this.updateCardButtonState(job.index, 'complete');
                    
                    completed++;
                    const elapsed = (performance.now() - startTime) / 1000;
                    const rate = completed / elapsed;
                    const remaining = batchSize - completed;
                    const etaSeconds = Math.round(remaining / rate);
                    const timeStr = etaSeconds > 60 ? `${Math.floor(etaSeconds/60)}m ${etaSeconds%60}s` : `${etaSeconds}s`;
                    this.updateStatus(`⚡ Parallel: ${completed}/${batchSize} (~${timeStr} left)`, 'info');
                    
                } catch (error) {
                    // Silently handle cancellation - it's expected when settings change
                    if (error.message?.includes('Cancelled')) {
                        // Don't log or mark as error - just skip
                        return;
                    }
                    console.error(`Card ${job.index} failed:`, error);
                    this.updateCardButtonState(job.index, 'error');
                    completed++;
                }
            });
            
            // Wait for this chunk to complete before starting next
            await Promise.all(chunkPromises);
            
            // Brief yield to allow GC between chunks
            await new Promise(r => setTimeout(r, 10));
        }
        
        const totalTime = ((performance.now() - startTime) / 1000).toFixed(2);
        
        // Keep worker pool alive for reuse - only terminate if memory pressure detected
        // Workers will be reused on next batch generation
    }
    
    /**
     * SEQUENTIAL batch generation (fallback when workers unavailable)
     */
    async generateBatchSequential(batchSize, cards, phrase, baseCardId, base, cardDate, nonce, memoryMb, useArgon2PerCard) {
        let totalTime = 0;
        let cardsGenerated = 0;
        const startTime = performance.now();
        
        
        // Build index array and shuffle for random visual order
        const indices = Array.from({ length: batchSize }, (_, i) => i);
        for (let i = indices.length - 1; i > 0; i--) {
            const j = Math.floor(Math.random() * (i + 1));
            [indices[i], indices[j]] = [indices[j], indices[i]];
        }
        
        // Mark all as pending first
        for (let i = 0; i < batchSize; i++) {
            this.updateCardButtonState(i, 'pending');
        }
        
        for (let idx = 0; idx < indices.length; idx++) {
            const i = indices[idx]; // Process in random order
            
            if (this.generationCancelled) {
                this.updateCardButtonState(i, 'cancelled');
                this.updateStatus('Generation cancelled', 'warning');
                return;
            }
            
            this.updateCardButtonState(i, 'generating');
            const cardStartTime = performance.now();
            
            try {
                const cardIndex = LabelUtils.indexToCoord(i);
                let seedBytes, label;
                
                if (useArgon2PerCard) {
                    const parallelism = parseInt(document.getElementById('argon2-parallelism')?.value || CONFIG.ARGON2_PARALLELISM);
                    const timeCost = parseInt(document.getElementById('argon2-time')?.value || CONFIG.ARGON2_TIME_COST);
                    const kdfParams = LabelUtils.encodeArgon2Params(timeCost, memoryMb, parallelism);
                    
                    label = LabelUtils.buildLabel(
                        'SIMPLE', 'ARGON2ID', kdfParams,
                        base.toUpperCase(), cardDate, nonce, baseCardId, cardIndex
                    );
                    
                    seedBytes = await SeedSources.argon2ToSeedMainThread(
                        phrase, label, timeCost, memoryMb, parallelism
                    );
                } else {
                    seedBytes = this.currentSeedBytes;
                    label = `legacy|SIMPLE|SHA512|${base.toUpperCase()}|${cardDate}|${baseCardId}|${cardIndex}`;
                }
                
                const result = await SeedCardCrypto.generateTokenMatrix(seedBytes, cardIndex, base);
                const combinedHash = await this.computeCardHash(label, seedBytes);
                
                const row = Math.floor(i / 10);
                const col = i % 10;
                const displayCardId = `${baseCardId}.${cardIndex}`;
                
                cards[i] = {
                    id: displayCardId,
                    cardIndex: cardIndex,
                    matrix: result.matrix,
                    digest: combinedHash.substring(0, 8),
                    position: { row, col },
                    label: label,
                    cardDate: cardDate
                };
                
                this.batchCards[i] = cards[i];
                this.displayCardLive(cards[i], i);
                this.updateCardButtonState(i, 'complete');
                cardsGenerated++;
                
                if (useArgon2PerCard && seedBytes) {
                    seedBytes.fill(0);
                }
                
            } catch (cardError) {
                console.error(`Error generating card ${i}:`, cardError);
                this.updateCardButtonState(i, 'error');
            }
            
            // Progress update
            const elapsed = performance.now() - cardStartTime;
            totalTime += elapsed;
            const avgTimePerCard = totalTime / cardsGenerated;
            const remaining = batchSize - cardsGenerated;
            const eta = Math.round((avgTimePerCard * remaining) / 1000);
            const timeStr = eta > 60 ? `${Math.floor(eta/60)}m ${eta%60}s` : `${eta}s`;
            this.updateStatus(`🔐 Sequential: ${cardsGenerated}/${batchSize} (~${timeStr} left)`, 'info');
            
            // Small delay for GC
            if (cardsGenerated % 10 === 0) {
                await new Promise(r => setTimeout(r, 100));
            }
        }
        
        const totalSeconds = ((performance.now() - startTime) / 1000).toFixed(2);
    }
    
    /**
     * FAST batch generation using cached seed bytes (SHA-512 hash mode)
     * This is used when user has entered a hash directly instead of a phrase
     */
    async generateBatchFromCachedSeed(batchSize, cards, baseCardId, base, cardDate, nonce) {
        const startTime = performance.now();
        
        // Mark all as generating (this will be fast)
        for (let i = 0; i < batchSize; i++) {
            this.updateCardButtonState(i, 'generating');
        }
        
        for (let i = 0; i < batchSize; i++) {
            if (this.generationCancelled) {
                this.updateCardButtonState(i, 'cancelled');
                return;
            }
            
            try {
                const cardIndex = LabelUtils.indexToCoord(i);
                const seedBytes = this.currentSeedBytes;
                const label = `legacy|SIMPLE|SHA512|${base.toUpperCase()}|${cardDate}|${nonce}|${baseCardId}|${cardIndex}`;
                
                const result = await SeedCardCrypto.generateTokenMatrix(seedBytes, cardIndex, base);
                const combinedHash = await this.computeCardHash(label, seedBytes);
                
                const row = Math.floor(i / 10);
                const col = i % 10;
                const displayCardId = `${baseCardId}.${cardIndex}`;
                
                cards[i] = {
                    id: displayCardId,
                    cardIndex: cardIndex,
                    matrix: result.matrix,
                    digest: combinedHash.substring(0, 8),
                    position: { row, col },
                    label: label,
                    cardDate: cardDate
                };
                
                this.batchCards[i] = cards[i];
                this.updateCardButtonState(i, 'complete');
                
            } catch (cardError) {
                console.error(`Error generating card ${i}:`, cardError);
                this.updateCardButtonState(i, 'error');
            }
        }
        
        // Display the first card live
        if (cards[0]) {
            this.displayCardLive(cards[0], 0);
        }
        
        const totalMs = performance.now() - startTime;
        this.updateStatus(`✅ Generated ${batchSize} cards in ${totalMs.toFixed(0)}ms`, 'success');
    }
    
    /**
     * Initialize all card button states to pending (grey)
     */
    initializeCardButtonStates(count) {
        // Initialize persistent state map (avoids race conditions with parallel workers)
        this.cardGenerationStates = new Map();
        for (let i = 0; i < count; i++) {
            this.cardGenerationStates.set(i, 'pending');
        }
        
        // Find all existing token-index-btn elements in the matrix
        const allButtons = document.querySelectorAll('.token-index-btn');
        allButtons.forEach((btn, idx) => {
            btn.classList.remove('gen-generating', 'gen-complete', 'gen-error', 'gen-cancelled');
            btn.classList.add('gen-pending');
        });
    }
    
    /**
     * Update a single card button's visual state
     */
    updateCardButtonState(index, state) {
        // Update persistent state map first (source of truth)
        if (this.cardGenerationStates) {
            this.cardGenerationStates.set(index, state);
        }
        
        const allButtons = document.querySelectorAll('.token-index-btn');
        const btn = allButtons[index];
        if (!btn) return;
        
        // Remove all generation state classes
        btn.classList.remove('gen-pending', 'gen-generating', 'gen-complete', 'gen-error', 'gen-cancelled');
        
        // Add new state class
        switch (state) {
            case 'generating':
                btn.classList.add('gen-generating');
                break;
            case 'complete':
                btn.classList.add('gen-complete');
                break;
            case 'error':
                btn.classList.add('gen-error');
                break;
            case 'cancelled':
                btn.classList.add('gen-cancelled');
                break;
            default:
                btn.classList.add('gen-pending');
        }
    }
    
    /**
     * Display a card's matrix live during batch generation
     * Preserves generation state classes on buttons
     */
    displayCardLive(card, index) {
        this.selectedCardIndex = index;
        
        // Show the inline card display
        const cardDisplay = document.getElementById('selected-card-display');
        if (cardDisplay) {
            cardDisplay.style.display = 'block';
            
            // Update card header
            const cardIdElement = cardDisplay.querySelector('.selected-card-id');
            if (cardIdElement) {
                cardIdElement.textContent = `Card Label: ${card.label || card.id}`;
            }
            
            const cardHashElement = cardDisplay.querySelector('.selected-card-hash')
            if (cardHashElement) {
                cardHashElement.textContent = card.digest.substring(0, 12).toUpperCase();
            }
            
            // Update matrix
            const matrixTable = document.getElementById('selected-matrix');
            if (matrixTable) {
                const isGeneratorView = document.getElementById('generator-view')?.style.display !== 'none';
                this.renderMatrixTable(matrixTable, card.matrix, true, isGeneratorView);
                
                // Restore generation states from persistent map (avoids race conditions)
                const newButtons = document.querySelectorAll('.token-index-btn');
                newButtons.forEach((btn, i) => {
                    const state = this.cardGenerationStates?.get(i) || 'pending';
                    if (state === 'complete') btn.classList.add('gen-complete');
                    else if (state === 'generating') btn.classList.add('gen-generating');
                    else if (state === 'error') btn.classList.add('gen-error');
                    else if (state === 'cancelled') btn.classList.add('gen-cancelled');
                    else btn.classList.add('gen-pending');
                    
                    // Add selected class to current card
                    if (i === index) {
                        btn.classList.add('selected');
                    }
                });
            }
        }
        
        // Update current matrix for password examples
        this.currentMatrix = card.matrix;
        this.currentCardId = card.id;
    }
    
    /**
     * Get current phrase from selected seed type input.
     * Returns empty for SLIP-39 since it uses pre-derived seed bytes.
     */
    getCurrentPhrase() {
        const seedType = document.querySelector('input[name="seedType"]:checked')?.value || 'simple';
        switch (seedType) {
            case 'simple':
                return document.getElementById('simple-phrase')?.value?.trim() || '';
            case 'bip39':
                return document.getElementById('bip39-mnemonic')?.value?.trim() || '';
            case 'slip39':
                // For SLIP-39, we need the seed bytes from share reconstruction
                // These are stored in currentSeedBytes after "Generate Hash" is clicked
                // Return hex-encoded seed bytes as the "phrase" for Argon2
                if (this.currentSeedBytes && this.currentSeedBytes.length === 64) {
                    return Array.from(this.currentSeedBytes)
                        .map(b => b.toString(16).padStart(2, '0'))
                        .join('');
                }
                return '';
            default:
                return '';
        }
    }

    /**
     * Show batch progress overlay with time estimate and cancel button
     */
    showBatchProgress(completed, total, estimatedSecondsRemaining, memoryMb = 2048) {
        const parallelism = parseInt(document.getElementById('argon2-parallelism')?.value || CONFIG.ARGON2_PARALLELISM);
        let progressContainer = document.getElementById('batch-progress');
        
        if (!progressContainer) {
            // Create progress container
            progressContainer = document.createElement('div');
            progressContainer.id = 'batch-progress';
            progressContainer.className = 'batch-progress-overlay';
            progressContainer.innerHTML = `
                <div class="batch-progress-content">
                    <div class="progress-icon">🔐</div>
                    <div class="progress-title">Generating Secure Cards</div>
                    <div class="progress-subtitle">Running Argon2id (${memoryMb}MB, ${parallelism} threads) per card</div>
                    <div class="progress-bar-container">
                        <div class="progress-bar" id="progress-bar-fill"></div>
                    </div>
                    <div class="progress-text">
                        <span id="progress-count">Card 0 of ${total}</span>
                        <span id="progress-time">Calculating...</span>
                    </div>
                    <div class="progress-note">
                        ⚠️ Each card runs Argon2 independently for maximum security.<br>
                        This takes several minutes but protects against GPU attacks.
                    </div>
                    <button type="button" class="btn btn-secondary progress-cancel-btn" id="cancel-generation-btn">
                        Cancel Generation
                    </button>
                </div>
            `;
            document.body.appendChild(progressContainer);
            
            // Add cancel button handler
            document.getElementById('cancel-generation-btn').addEventListener('click', () => {
                this.generationCancelled = true;
            });
        }
        
        const progressBar = document.getElementById('progress-bar-fill');
        const progressCount = document.getElementById('progress-count');
        const progressTime = document.getElementById('progress-time');
        
        const percentage = Math.round((completed / total) * 100);
        
        if (progressBar) progressBar.style.width = `${percentage}%`;
        if (progressCount) progressCount.textContent = `Card ${completed} of ${total}`;
        if (progressTime) {
            if (completed === 0) {
                progressTime.textContent = 'Starting...';
            } else if (estimatedSecondsRemaining > 60) {
                const minutes = Math.floor(estimatedSecondsRemaining / 60);
                const seconds = estimatedSecondsRemaining % 60;
                progressTime.textContent = `~${minutes}m ${seconds}s remaining`;
            } else {
                progressTime.textContent = `~${estimatedSecondsRemaining}s remaining`;
            }
        }
        
        progressContainer.style.display = 'flex';
    }
    
    /**
     * Hide batch progress overlay
     */
    hideBatchProgress() {
        const progressContainer = document.getElementById('batch-progress');
        if (progressContainer) {
            progressContainer.style.display = 'none';
        }
    }
    
    displaySingleCard(matrix, cardId, digest, label = null) {
        // Show results area
        const resultsArea = document.getElementById('results');
        if (resultsArea) {
            resultsArea.style.display = 'block';
        }
        
        // Update section title with card ID
        const sectionTitle = document.getElementById('card-section-title');
        if (sectionTitle && cardId) {
            sectionTitle.innerHTML = `<span class="section-icon">🃏</span> Card: ${SecurityUtils.sanitizeHTML(cardId)}`;
        }
        
        // Wait a moment for DOM updates, then find elements
        setTimeout(() => {
            // NOW: Update card header (elements should exist after showSingleCardDisplay)
            const cardIdDisplay = document.querySelector('.card-id-display');
            const cardDate = document.querySelector('.card-date');
            const cardHash = document.querySelector('.card-hash');
            
            if (cardIdDisplay) {
                cardIdDisplay.textContent = `Card Label: ${label || cardId}`;
                
                // Add click-to-copy functionality for card label
                cardIdDisplay.classList.add('clickable-id');
                cardIdDisplay.style.cursor = 'copy';
                cardIdDisplay.title = 'Click to copy card label';
                cardIdDisplay.onclick = (e) => {
                    e.preventDefault();
                    this.copyCardId(label || cardId);
                };
            }
            if (cardDate) cardDate.textContent = new Date().toISOString().split('T')[0];
            if (cardHash) {
                // Compute hash of seed+label+counter instead of just seed hash
                this.computeCardHash(label).then(combinedHash => {
                    const displayHash = combinedHash.substring(0, 12).toUpperCase();
                    cardHash.textContent = displayHash;
                    
                    // Add click-to-copy functionality
                    cardHash.classList.add('clickable-hash');
                    cardHash.style.cursor = 'copy';
                    cardHash.title = 'Click to copy full hash';
                    cardHash.onclick = (e) => {
                        e.preventDefault();
                        this.copyHash(combinedHash);
                    };
                }).catch(err => {
                    console.error('Failed to compute card hash:', err);
                    const fallbackHash = digest.substring(0, 12).toUpperCase();
                    cardHash.textContent = fallbackHash;
                    
                    // Add click-to-copy functionality for fallback too
                    cardHash.classList.add('clickable-hash');
                    cardHash.style.cursor = 'copy';
                    cardHash.title = 'Click to copy hash';
                    cardHash.onclick = (e) => {
                        e.preventDefault();
                        this.copyHash(digest);
                    };
                });
            }
            
            // FINALLY: Generate matrix table (should exist after showSingleCardDisplay)
            const selectedCard = document.getElementById('selected-card-display');
            const matrixTable = selectedCard?.querySelector('.password-matrix') || document.querySelector('#selected-matrix');
            
            if (matrixTable) {
                // Enable phone keypad letters for generator view
                const isGeneratorView = document.getElementById('generator-view')?.style.display !== 'none';
                this.renderMatrixTable(matrixTable, matrix, true, isGeneratorView);
            } else {
                // Try to create the missing matrix table
                const matrixContainer = selectedCard?.querySelector('.matrix-container');
                if (matrixContainer) {
                    const newTable = document.createElement('table');
                    newTable.className = 'password-matrix';
                    matrixContainer.innerHTML = ''; // Clear existing content
                    matrixContainer.appendChild(newTable);
                    
                    // Try again with the new table
                    const isGeneratorView = document.getElementById('generator-view')?.style.display !== 'none';
                    this.renderMatrixTable(newTable, matrix, true, isGeneratorView);
                    
                    // Update entropy information after matrix is rendered
                    this.updateMatrixEntropy();
                } else {
                    // Matrix container not found - DOM might not be ready yet
                }
            }
            
        }, 50); // Small delay to ensure DOM is ready
    }
    
    /*
    showSingleCardDisplay() {
        
        const singleCard = document.getElementById('single-card');
        const batchCards = document.getElementById('batch-cards');
        const resultsArea = document.getElementById('results');
        const resultsHeader = resultsArea?.querySelector('.section-header-nav');
        
        // Hide batch display
        if (batchCards) {
            batchCards.style.display = 'none';
        }
        
        // Show single card
        if (singleCard) {
            singleCard.style.display = 'block';
        } else {
            console.error('ERROR: single-card element not found!');
            
            // Try to find it with a more specific selector after loading indicator is removed
            setTimeout(() => {
                const singleCardAlt = document.getElementById('single-card');
                
                if (singleCardAlt) {
                    singleCardAlt.style.display = 'block';
                } else {
                    console.error('CRITICAL: Cannot find single-card element anywhere!'); // Debug logging
                }
            }, 10);
        }
        
        // Clear any loading states and show results area
        if (resultsArea) {
            const loadingIndicator = resultsArea.querySelector('.loading-indicator');
            if (loadingIndicator) {
                loadingIndicator.remove();
            }
            
            // Show the header and other elements that were hidden during loading
            const header = resultsArea.querySelector('.section-header-nav');
            const passwordExamples = resultsArea.querySelector('.password-examples');
            
            if (header) {
                header.style.display = 'flex'; // Results header uses flex
            }
            if (passwordExamples) {
                passwordExamples.style.display = 'block';
            }
            
            resultsArea.style.display = 'block';
        } else {
            console.error('ERROR: results element not found!'); // Debug logging
        }
        
        // Final check: Header state after all changes
        const finalHeader = resultsArea?.querySelector('.section-header-nav');
        
        // Try alternative selectors
        const headerByTag = resultsArea?.querySelector('h2');
        const headerByIcon = resultsArea?.querySelector('.fas.fa-table');
        
        if (finalHeader) {
            
            // Force header to be visible
            finalHeader.style.display = 'flex'; // Use flex for section-header-nav
            finalHeader.style.visibility = 'visible';
            finalHeader.style.opacity = '1';
        } else {
            console.error('ERROR: Header not found after showSingleCardDisplay!');
        }
    }
    */

    /**
     * Compute hash of seed+label+counter for card display
     * @param {string} label - The HMAC label used for token generation
     * @returns {Promise<string>} - Hex hash string
     */
    async computeCardHash(label, seedBytes = null) {
        // Use provided seedBytes or fall back to instance variable
        const seed = seedBytes || this.currentSeedBytes;
        if (!seed) {
            throw new Error('No seed bytes available for hash computation');
        }
        
        // Create combined data: seed + label + counter
        const labelBytes = new TextEncoder().encode(label || 'SEEDER-TOKENS');
        const counterBytes = new Uint8Array(4); // 4-byte counter, initialized to 0
        
        // Combine all parts
        const combinedLength = seed.length + labelBytes.length + counterBytes.length;
        const combinedData = new Uint8Array(combinedLength);
        
        let offset = 0;
        combinedData.set(seed, offset);
        offset += seed.length;
        combinedData.set(labelBytes, offset);
        offset += labelBytes.length;
        combinedData.set(counterBytes, offset);
        
        // Compute SHA-512 hash
        const hashBuffer = await crypto.subtle.digest('SHA-512', combinedData);
        const hashArray = new Uint8Array(hashBuffer);
        
        // Convert to hex string
        return Array.from(hashArray)
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    }
    
    displayBatchCards(cards) {
        // Store cards for access throughout the app
        this.batchCards = cards;
        this.selectedCardIndex = null;
        
        // Update status for successful completion
        this.updateStatus(`Successfully generated ${cards.length} cards`, 'success');
        
        // Hide the separate index grid since we're embedding indices in the matrix
        const cardGrid = document.getElementById('card-index-grid');
        if (cardGrid) {
            cardGrid.style.display = 'none';
        }
        
        // Auto-select the first card (00) to show the inline display
        this.selectCard(0);
    }

    /**
     * Select and display a specific card by index
     */
    selectCard(index) {
        if (!this.batchCards || index >= this.batchCards.length) {
            console.error('Invalid card index or no cards available');
            return;
        }

        // Update selected index
        this.selectedCardIndex = index;

        // Get the selected card
        const card = this.batchCards[index];
        
        // Show the inline card display
        const cardDisplay = document.getElementById('selected-card-display');
        if (cardDisplay) {
            cardDisplay.style.display = 'block';
            
            // Update card header
            const cardIdElement = cardDisplay.querySelector('.selected-card-id');
            const cardHashElement = cardDisplay.querySelector('.selected-card-hash');
            
            if (cardIdElement) {
                cardIdElement.textContent = `Card Label: ${card.label || card.id}`;
                // Add click-to-copy functionality
                cardIdElement.style.cursor = 'copy';
                cardIdElement.onclick = (e) => {
                    e.preventDefault();
                    this.copyCardId(card.label || card.id);
                };
            }
            
            if (cardHashElement) {
                // Use the pre-computed digest from generation (more reliable than re-computing)
                const displayHash = card.digest.substring(0, 12).toUpperCase();
                cardHashElement.textContent = displayHash;
                
                // Add click-to-copy functionality
                cardHashElement.style.cursor = 'copy';
                cardHashElement.onclick = (e) => {
                    e.preventDefault();
                    this.copyHash(card.digest);
                };
            }
            
            // Update matrix
            const matrixTable = document.getElementById('selected-matrix');
            if (matrixTable) {
                // Enable phone keypad letters for generator view
                const isGeneratorView = document.getElementById('generator-view')?.style.display !== 'none';
                this.renderMatrixTable(matrixTable, card.matrix, true, isGeneratorView);
                
                // Restore generation states from persistent map (avoids race conditions)
                const newButtons = document.querySelectorAll('.token-index-btn');
                newButtons.forEach((btn, i) => {
                    const state = this.cardGenerationStates?.get(i) || 'pending';
                    if (state === 'complete') btn.classList.add('gen-complete');
                    else if (state === 'generating') btn.classList.add('gen-generating');
                    else if (state === 'error') btn.classList.add('gen-error');
                    else if (state === 'cancelled') btn.classList.add('gen-cancelled');
                    else btn.classList.add('gen-pending');
                    
                    // Add selected class to current card
                    if (i === index) {
                        btn.classList.add('selected');
                    }
                });
                
                // Update entropy information after matrix is rendered
                this.updateMatrixEntropy();
            }
        }

        // Update current matrix for password examples
        this.currentMatrix = card.matrix;
        this.currentCardId = card.id;
    }
    

    

    

    

    

    

    

    

    
    renderMatrixTable(table, matrix, showIndexButtons = true, showPhoneKeypadLetters = false) {
        // Clear existing content
        table.innerHTML = '';
        
        // Create header row
        const headerRow = table.createTHead().insertRow();
        
        // Top-left corner: Copy entire matrix button
        const cornerCell = headerRow.insertCell();
        cornerCell.innerHTML = '<button class="matrix-copy-btn" title="Copy entire matrix">📋</button>';
        cornerCell.className = 'matrix-corner-cell';
        const copyBtn = cornerCell.querySelector('button');
        copyBtn.addEventListener('click', (e) => {
            e.preventDefault();
            this.copyEntireMatrix(matrix);
        });
        
        // Add matrix highlighting on hover
        copyBtn.addEventListener('mouseenter', () => {
            table.classList.add('matrix-highlighted');
        });
        copyBtn.addEventListener('mouseleave', () => {
            table.classList.remove('matrix-highlighted');
        });
        
        // Phone keypad letter mapping for columns 0-9
        const phoneKeypadLetters = {
            0: '', // No letters for 0 and 1 on phone keypad
            1: '',
            2: 'ABC',
            3: 'DEF',
            4: 'GHI',
            5: 'JKL',
            6: 'MNO',
            7: 'PQRS',
            8: 'TUV',
            9: 'WXYZ'
        };
        
        // Column headers (A-J letters) - spreadsheet convention
        // clickable to copy columns
        for (let col = 0; col < CONFIG.TOKENS_WIDE; col++) {
            const th = document.createElement('th');
            const colLetter = String.fromCharCode('A'.charCodeAt(0) + col);
            
            if (showPhoneKeypadLetters) {
                // Create a container for letter and phone keypad info
                const headerContainer = document.createElement('div');
                headerContainer.className = 'coord-header-container';
                
                const letterDiv = document.createElement('div');
                letterDiv.className = 'coord-number';
                letterDiv.textContent = colLetter;
                
                const phoneDiv = document.createElement('div');
                phoneDiv.className = 'coord-letters';
                phoneDiv.textContent = phoneKeypadLetters[col] || '';
                
                headerContainer.appendChild(letterDiv);
                headerContainer.appendChild(phoneDiv);
                th.appendChild(headerContainer);
                th.className = 'coord-header coord-header-clickable coord-header-with-letters';
            } else {
                th.textContent = colLetter;
                th.className = 'coord-header coord-header-clickable';
            }
            
            th.title = `Copy column ${colLetter}`;
            th.addEventListener('click', (e) => {
                e.preventDefault();
                this.copyColumn(matrix, col);
            });
            
            // Add column highlighting on hover
            th.addEventListener('mouseenter', () => {
                const colCells = table.querySelectorAll(`td[data-col="${col}"]`);
                colCells.forEach(cell => cell.classList.add('col-highlighted'));
            });
            th.addEventListener('mouseleave', () => {
                const colCells = table.querySelectorAll(`td[data-col="${col}"]`);
                colCells.forEach(cell => cell.classList.remove('col-highlighted'));
            });
            
            headerRow.appendChild(th);
        }
        
        // Create body with data rows
        const tbody = table.createTBody();
        for (let row = 0; row < CONFIG.TOKENS_TALL; row++) {
            const tr = tbody.insertRow();
            
            // Row header (0-9 numbers) - spreadsheet convention
            // clickable to copy rows
            const rowHeader = document.createElement('th');
            
            if (showPhoneKeypadLetters) {
                // Show row number with optional letter mapping
                const rowLetter = String.fromCharCode('A'.charCodeAt(0) + row);
                rowHeader.textContent = `${row}/${rowLetter}`;
            } else {
                rowHeader.textContent = row.toString();
            }
            
            rowHeader.className = 'coord-header coord-header-clickable';
            rowHeader.title = `Copy row ${row}`;
            rowHeader.addEventListener('click', (e) => {
                e.preventDefault();
                this.copyRow(matrix, row);
            });
            
            // Add row highlighting on hover
            rowHeader.addEventListener('mouseenter', () => {
                tr.classList.add('row-highlighted');
            });
            rowHeader.addEventListener('mouseleave', () => {
                tr.classList.remove('row-highlighted');
            });
            
            tr.appendChild(rowHeader);
            
            // Token cells
            for (let col = 0; col < CONFIG.TOKENS_WIDE; col++) {
                const td = tr.insertCell();
                const token = matrix[row][col];
                
                // Calculate the card index for this cell (row * 10 + col)
                const cardIndex = row * 10 + col;
                const cardCoord = LabelUtils.indexToCoord(cardIndex); // Convert to grid coordinate (A0-J9)
                
                // Create container for index button and token
                const cellContainer = document.createElement('div');
                cellContainer.className = 'token-cell-container';
                
                // Create index button (only if showIndexButtons is true)
                if (showIndexButtons) {
                    const indexBtn = document.createElement('button');
                    indexBtn.className = 'token-index-btn';
                    indexBtn.textContent = cardCoord; // Display as grid coordinate
                    indexBtn.title = `Select card ${cardCoord}`;
                    indexBtn.addEventListener('click', (e) => {
                        e.preventDefault();
                        e.stopPropagation();
                        if (this.batchCards && cardIndex < this.batchCards.length) {
                            this.selectCard(cardIndex);
                        }
                    });
                    cellContainer.appendChild(indexBtn);
                }
                
                // Create token display
                const tokenSpan = document.createElement('span');
                tokenSpan.className = 'token-text';
                tokenSpan.textContent = token;
                
                // Add click handler to copy token
                tokenSpan.addEventListener('click', (e) => {
                    e.preventDefault();
                    e.stopPropagation();
                    this.copyToken(token, row, col);
                });
                
                // Assemble cell
                cellContainer.appendChild(tokenSpan);
                td.appendChild(cellContainer);
                
                // Add data attributes for styling
                td.setAttribute('data-row', row);
                td.setAttribute('data-col', col);
                td.setAttribute('data-token', token);
                td.setAttribute('data-card-index', cardIndex);
            }
        }
    }
    
    copyToken(token, row, col) {
        navigator.clipboard.writeText(token).then(() => {
            this.updateStatus('Token copied to clipboard!', 'success');
        }).catch(err => {
            console.error('Copy failed:', err);
            this.updateStatus('Copy failed', 'error');
        });
    }
    
    copyRow(matrix, rowIndex) {
        const rowTokens = matrix[rowIndex].join('  ');
        navigator.clipboard.writeText(rowTokens).then(() => {
            this.updateStatus(`Row ${rowIndex} copied to clipboard!`, 'success');
        }).catch(err => {
            console.error('Copy failed:', err);
            this.updateStatus('Copy failed', 'error');
        });
    }
    
    copyColumn(matrix, colIndex) {
        const columnTokens = matrix.map(row => row[colIndex]).join('  ');
        const colLetter = String.fromCharCode('A'.charCodeAt(0) + colIndex);
        navigator.clipboard.writeText(columnTokens).then(() => {
            this.updateStatus(`Column ${colLetter} copied to clipboard!`, 'success');
        }).catch(err => {
            console.error('Copy failed:', err);
            this.updateStatus('Copy failed', 'error');
        });
    }
    
    copyEntireMatrix(matrix) {
        const matrixText = matrix.map(row => row.join('  ')).join('\n');
        navigator.clipboard.writeText(matrixText).then(() => {
            this.updateStatus('Matrix copied to clipboard!', 'success');
        }).catch(err => {
            console.error('Copy failed:', err);
            this.updateStatus('Copy failed', 'error');
        });
    }
    
    copyHash(fullHash) {
        navigator.clipboard.writeText(fullHash).then(() => {
            this.updateStatus('Hash copied to clipboard!', 'success');
        }).catch(err => {
            console.error('Copy failed:', err);
            this.updateStatus('Copy failed', 'error');
        });
    }
    
    copyCardId(cardId) {
        navigator.clipboard.writeText(cardId).then(() => {
            this.updateStatus('Card ID copied to clipboard!', 'success');
        }).catch(err => {
            console.error('Copy failed:', err);
            this.updateStatus('Copy failed', 'error');
        });
    }
    
    updatePasswordEntropySummary() {
        try {
            // Base entropy components (your formula: H_seed + H_label + H_card + coordinates * (H_coordinate + H_token) + H_memorized + H_punctuation + H_order)
            
            // 1. H_seed: Entropy from the seed phrase itself - based on ACTUAL seed type
            const seedEntropy = this.calculateActualSeedEntropy();
            
            // 2. H_label: Entropy from label components (now returns object with breakdown)
            const labelEntropyObj = this.calculateCurrentLabelEntropy();
            const labelEntropy = labelEntropyObj.total; // Use total for calculations
            
            // 3. H_card: Already included in labelEntropyObj.cardIndex
            const cardSelectionEntropy = labelEntropyObj.cardIndex; // ~6.64 bits
            
            // 4. Per-coordinate entropy components (show individual calculation)
            const coordinateSelectionEntropy = Math.log2(100); // ~6.64 bits per coordinate selected from 10x10 grid
            const tokenValueEntropy = EntropyAnalyzer.calculateTokenEntropy(); // ~25.9 bits per token (if seed sufficient)
            const perCoordinateEntropy = coordinateSelectionEntropy + Math.min(tokenValueEntropy, seedEntropy/4); // Token entropy limited by seed quality
            
            // 5. H_memorized: Entropy from memorized components (word + PIN + punctuation + order)
            const memorizedComponents = EntropyAnalyzer.calculateMemorizedComponentsEntropy(6, 4, 1);
            const memorizedWordEntropy = memorizedComponents.word; // ~28.2 bits per word
            const pinEntropy = memorizedComponents.pin; // ~13.3 bits for 4-digit PIN
            const punctuationEntropy = memorizedComponents.punctuation; // ~5.0 bits per punctuation
            const orderEntropy = memorizedComponents.order; // ~2.6 bits (ordering variations)
            
            // 6. H_numbers: Entropy from numeric components (separate from PIN)
            const digitEntropy = Math.log2(10); // ~3.32 bits per digit
            
            // Example calculations with different coordinate counts and memorized components
            const calculateTotalEntropy = (numCoordinates, numWords = 1, numPunctuation = 1, numDigits = 0) => {
                const coordinateContribution = numCoordinates * perCoordinateEntropy;
                const memorizedContribution = numWords * memorizedWordEntropy;
                const punctuationContribution = numPunctuation * punctuationEntropy;
                const numberContribution = numDigits * digitEntropy;
                
                return seedEntropy + labelEntropy + 
                       coordinateContribution + memorizedContribution + 
                       punctuationContribution + numberContribution + orderEntropy;
            };
            
            // Special case: Seed compromised scenario (only non-seed components remain)
            const calculateSeedCompromisedEntropy = (numCoordinates, numWords = 1, numPunctuation = 1, numDigits = 0) => {
                // When seed is known, only coordinate SELECTION entropy remains (not token values)
                const remainingCoordinateEntropy = numCoordinates * coordinateSelectionEntropy;
                const memorizedContribution = numWords * memorizedWordEntropy;
                const punctuationContribution = numPunctuation * punctuationEntropy;
                const numberContribution = numDigits * digitEntropy;
                
                return labelEntropy + remainingCoordinateEntropy + 
                       memorizedContribution + punctuationContribution + numberContribution + orderEntropy;
            };
            
            // Calculate scenarios for specific examples
            const fullSecurity2Token = calculateTotalEntropy(2, 1, 1, 0); // 2 coordinates, 1 word, 1 punctuation
            const fullSecurity3Token = calculateTotalEntropy(3, 1, 1, 0); // 3 coordinates, 1 word, 1 punctuation
            const fullSecurityWithNumbers = calculateTotalEntropy(2, 1, 1, 3); // 2 coordinates, 1 word, 1 punctuation, 3 digits
            
            const seedCompromised2Token = calculateSeedCompromisedEntropy(2, 1, 1, 0);
            const seedCompromised3Token = calculateSeedCompromisedEntropy(3, 1, 1, 0);
            const seedCompromisedWithNumbers = calculateSeedCompromisedEntropy(2, 1, 1, 3);
            
            // Sample password generation with entropy breakdown
            const dictionaryWords = ["forest", "ocean", "bridge", "castle", "garden", "thunder", "crystal", "shadow", "winter", "summer"];
            const randomWord = dictionaryWords[Math.floor(Math.random() * dictionaryWords.length)];
            const fullTokens = ["tJt3", "r7q[", "tH9v"]; // Example tokens from matrix
            const coordinates = ["A0", "B1", "C2"];
            
            // Enhanced punctuation with ordering variety
            const punctuations = ["!", "@", "#", "$", "%", "&", "*", "+"];
            const randomPunct1 = punctuations[Math.floor(Math.random() * punctuations.length)];
            const randomPunct2 = punctuations[Math.floor(Math.random() * punctuations.length)];
            const randomPunct3 = punctuations[Math.floor(Math.random() * punctuations.length)];
            
            // Different ordering patterns (contributing to H_order)
            const password1 = `${fullTokens[0]}${fullTokens[1]}${randomWord}${randomPunct1}`; // Standard: tokens + word + punct
            const password2 = `${randomWord}${fullTokens[0]}${fullTokens[1]}${fullTokens[2]}${randomPunct2}`; // Varied: word + tokens + punct
            const password3 = `${fullTokens[0]}${randomWord}123${fullTokens[1]}${randomPunct3}`; // Mixed: token + word + numbers + token + punct
            
            // Calculate specific entropies for each example
            const wordEntropy = EntropyAnalyzer.calculateMemorizedWordEntropy(randomWord.length, 26);
            const numberEntropy = Math.log2(Math.pow(10, 3)); // 3 digits = ~9.97 bits
            
            const entropy1 = calculateTotalEntropy(2) + wordEntropy - memorizedWordEntropy; // Adjust for actual word
            const entropy2 = calculateTotalEntropy(3) + wordEntropy - memorizedWordEntropy; // 3 tokens
            const entropy3 = calculateTotalEntropy(2) + wordEntropy + numberEntropy - memorizedWordEntropy; // 2 tokens + numbers
            
            // Update display elements with corrected entropy calculations
            const seedElement = document.getElementById('seed-entropy-summary');
            const labelElement = document.getElementById('label-entropy-summary');
            const labelHashElement = document.getElementById('label-hash-summary');
            const gridElement = document.getElementById('grid-entropy-summary');
            const memorizedElement = document.getElementById('memorized-entropy-summary');
            const completeElement = document.getElementById('complete-password-total');
            const memorizedOnlyElement = document.getElementById('memorized-only-total');
            const labelCompromisedElement = document.getElementById('label-compromised-total');
            const example1Element = document.getElementById('example-password-1');
            const example2Element = document.getElementById('example-password-2');
            const example3Element = document.getElementById('example-password-3');
            
            if (seedElement) {
                const badge = EntropyAnalyzer.getSecurityBadge(seedEntropy);
                seedElement.innerHTML = `${seedEntropy.toFixed(1)} bits ${badge}`;
            }
            
            if (labelElement) {
                const badge = EntropyAnalyzer.getSecurityBadge(labelEntropy);
                // Show breakdown: Date + CardID + Nonce + Index + Base
                labelElement.innerHTML = `${labelEntropy.toFixed(1)} bits ${badge}`;
                labelElement.title = `Date: ${labelEntropyObj.date.toFixed(1)}b + ID: ${labelEntropyObj.cardId.toFixed(1)}b + Nonce: ${labelEntropyObj.nonce.toFixed(1)}b + Index: ${labelEntropyObj.cardIndex.toFixed(1)}b + Base: ${labelEntropyObj.baseSystem.toFixed(1)}b`;
            }
            
            // Update nonce entropy display if element exists
            const nonceElement = document.getElementById('nonce-entropy-summary');
            if (nonceElement) {
                nonceElement.innerHTML = `${labelEntropyObj.nonce.toFixed(1)} bits (auto-generated)`;
            }
            
            // Update KDF resistance display (only applies to seed brute-force attacks)
            const kdfResistanceElement = document.getElementById('kdf-resistance-display');
            const fullCrackTimeElement = document.getElementById('full-crack-time');
            
            if (kdfResistanceElement) {
                const resistance = this.calculateKDFResistance();
                kdfResistanceElement.innerHTML = `Argon2id (t${resistance.timeCost}m${resistance.memoryMb}p${resistance.parallelism}) — ${resistance.hashesPerSecond.toLocaleString()} hashes/sec with ${resistance.attackerGPUs.toLocaleString()} GPUs`;
            }
            
            if (fullCrackTimeElement) {
                const fullCrackTime = this.formatCrackTime(fullSecurity2Token);
                fullCrackTimeElement.innerHTML = fullCrackTime;
            }
            
            // Update label hash display
            if (labelHashElement) {
                this.calculateLabelHash().then(hash => {
                    if (hash) {
                        // Truncate for display but show it's much longer
                        const displayHash = hash.length > 16 ? `${hash.substring(0, 16)}...` : hash;
                        labelHashElement.textContent = `${displayHash} (SHA-512)`;
                        labelHashElement.title = `Full hash: ${hash}`;
                    } else {
                        labelHashElement.textContent = '-';
                    }
                }).catch(error => {
                    console.error('Error updating label hash:', error);
                    labelHashElement.textContent = 'Error';
                });
            }
            
            if (gridElement) {
                const badge = EntropyAnalyzer.getSecurityBadge(perCoordinateEntropy);
                gridElement.innerHTML = `${perCoordinateEntropy.toFixed(1)} bits per selection ${badge}`;
            }
            
            if (memorizedElement) {
                const totalMemorized = memorizedWordEntropy + pinEntropy + punctuationEntropy + orderEntropy + digitEntropy;
                const badge = EntropyAnalyzer.getSecurityBadge(totalMemorized);
                memorizedElement.innerHTML = `Word (${memorizedWordEntropy.toFixed(1)}) + PIN (${pinEntropy.toFixed(1)}) + Punct (${punctuationEntropy.toFixed(1)}) + Order (${orderEntropy.toFixed(1)}) = ${totalMemorized.toFixed(1)} bits ${badge}`;
            }
            
            if (completeElement) {
                const badge = EntropyAnalyzer.getSecurityBadge(fullSecurity2Token);
                completeElement.innerHTML = `${fullSecurity2Token.toFixed(1)} bits ${badge}`;
            }
            
            if (memorizedOnlyElement) {
                const memorizedOnly = labelEntropy + perCoordinateEntropy + memorizedWordEntropy + pinEntropy + punctuationEntropy + orderEntropy + digitEntropy;
                const badge = EntropyAnalyzer.getSecurityBadge(memorizedOnly);
                memorizedOnlyElement.innerHTML = `${memorizedOnly.toFixed(1)} bits ${badge}`;
            }
            
            if (labelCompromisedElement) {
                // When label is compromised: attacker knows card ID and date
                // Remaining entropy: seed + coordinates + memorized components
                const labelCompromised = seedEntropy + perCoordinateEntropy + memorizedWordEntropy + pinEntropy + punctuationEntropy + orderEntropy + digitEntropy;
                const badge = EntropyAnalyzer.getSecurityBadge(labelCompromised);
                labelCompromisedElement.innerHTML = `${labelCompromised.toFixed(1)} bits ${badge}`;
            }
            
            // Add card compromised scenario
            const cardCompromisedElement = document.getElementById('card-compromised-total');
            if (cardCompromisedElement) {
                // When card is compromised: attacker can see the token grid
                // Remaining entropy: only memorized components (word + PIN + punctuation + order)
                // The 32 bits comes from: memorized word (~23.3) + PIN patterns (~4.0) + punctuation (~3.2) + order (~1.5)
                const cardCompromised = memorizedWordEntropy + pinEntropy + punctuationEntropy + orderEntropy;
                const badge = EntropyAnalyzer.getSecurityBadge(cardCompromised);
                cardCompromisedElement.innerHTML = `${cardCompromised.toFixed(1)} bits ${badge}`;
            }
            
            if (memorizedOnlyElement) {
                const badge = EntropyAnalyzer.getSecurityBadge(seedCompromised2Token);
                memorizedOnlyElement.innerHTML = `${seedCompromised2Token.toFixed(1)} bits (2 tokens) / ${seedCompromised3Token.toFixed(1)} bits (3 tokens) / ${seedCompromisedWithNumbers.toFixed(1)} bits (with numbers) ${badge}`;
            }
            
            if (example1Element) {
                const valueDiv = example1Element.querySelector('.example-value');
                const entropySpan = example1Element.querySelector('.example-entropy');
                const coordDiv = example1Element.querySelector('.example-coordinates');
                const tokensDiv = example1Element.querySelector('.example-tokens');
                
                if (valueDiv) valueDiv.textContent = `${password1} (${password1.length} characters)`;
                if (entropySpan) entropySpan.textContent = `~${entropy1.toFixed(1)} bits`;
                if (coordDiv) coordDiv.textContent = `${coordinates[0]} + ${coordinates[1]} + ${randomWord}!`;
                if (tokensDiv) tokensDiv.textContent = `${fullTokens[0]} + ${fullTokens[1]} + ${randomWord}!`;
            }
            
            if (example2Element) {
                const valueDiv = example2Element.querySelector('.example-value');
                const entropySpan = example2Element.querySelector('.example-entropy');
                const coordDiv = example2Element.querySelector('.example-coordinates');
                const tokensDiv = example2Element.querySelector('.example-tokens');
                
                if (valueDiv) valueDiv.textContent = `${password2} (${password2.length} characters)`;
                if (entropySpan) entropySpan.textContent = `~${entropy2.toFixed(1)} bits`;
                if (coordDiv) coordDiv.textContent = `${coordinates[0]} + ${coordinates[1]} + ${coordinates[2]} + ${randomWord}!`;
                if (tokensDiv) tokensDiv.textContent = `${fullTokens[0]} + ${fullTokens[1]} + ${fullTokens[2]} + ${randomWord}!`;
            }
            
            if (example3Element) {
                const valueDiv = example3Element.querySelector('.example-value');
                const entropySpan = example3Element.querySelector('.example-entropy');
                const coordDiv = example3Element.querySelector('.example-coordinates');
                const tokensDiv = example3Element.querySelector('.example-tokens');
                
                if (valueDiv) valueDiv.textContent = `${password3} (${password3.length} characters)`;
                if (entropySpan) entropySpan.textContent = `~${entropy3.toFixed(1)} bits`;
                if (coordDiv) coordDiv.textContent = `${coordinates[0]} + ${coordinates[1]} + ${randomWord} + 123!`;
                if (tokensDiv) tokensDiv.textContent = `${fullTokens[0]} + ${fullTokens[1]} + ${randomWord} + 123!`;
            }
            
            // Also trigger update of the HTML-based label entropy display
            this.updateLabelEntropyDisplay();
            
        } catch (error) {
            console.error('Error updating password entropy summary:', error);
        }
    }
    
    updateLabelEntropyDisplay() {
        try {
            const cardDateInput = document.getElementById('card-date');
            const cardIdInput = document.getElementById('card-id');
            
            const cardDate = cardDateInput?.value || '';
            const cardId = cardIdInput?.value || '';
            
            // Enhanced entropy calculation using salted SHA-512 approach
            // Label component entropy (32.0 bits) - includes date and label text
            const hasLabel = cardId.length > 0 || cardDate.length > 0;
            const labelComponentEntropy = hasLabel ? 32.0 : 0;
            
            // Card ID component entropy (16.0 bits) - separate ID component  
            const hasCardId = cardId.length > 0;
            const cardIdComponentEntropy = hasCardId ? 16.0 : 0;
            
            const totalLabelEntropy = labelComponentEntropy + cardIdComponentEntropy;
            
            // Update HTML displays
            const dateEntropyEl = document.getElementById('date-entropy');
            const cardIdEntropyEl = document.getElementById('card-id-entropy');
            const totalEntropyEl = document.getElementById('label-total-entropy');
            
            if (dateEntropyEl) {
                dateEntropyEl.textContent = `Label: ${Math.round(labelComponentEntropy * 10) / 10} bits (salted SHA-512)`;
                dateEntropyEl.className = `entropy-stat ${labelComponentEntropy > 0 ? 'valid' : 'empty'}`;
            }
            
            if (cardIdEntropyEl) {
                cardIdEntropyEl.textContent = `Card ID: ${Math.round(cardIdComponentEntropy * 10) / 10} bits`;
                cardIdEntropyEl.className = `entropy-stat ${cardIdComponentEntropy > 0 ? 'valid' : 'empty'}`;
            }
            
            if (totalEntropyEl) {
                totalEntropyEl.textContent = `Total Label: ${Math.round(totalLabelEntropy * 10) / 10} bits`;
                totalEntropyEl.className = `entropy-stat ${totalLabelEntropy > 0 ? 'valid' : 'empty'}`;
            }
        } catch (error) {
            console.error('Error updating label entropy display:', error);
        }
    }
    
    calculateCurrentLabelEntropy() {
        try {
            const cardIdInput = document.getElementById('card-id');
            const cardDateInput = document.getElementById('card-date');
            
            const cardId = cardIdInput?.value || '';
            const cardDate = cardDateInput?.value || '';
            
            // Comprehensive label entropy calculation
            // Label format: v1|SEED_TYPE|KDF|KDF_PARAMS|BASE|DATE|NONCE|CARD_ID|INDEX
            
            // Date entropy: YYYY-MM-DD format
            // ~365 days/year * reasonable range (10 years) = ~3650 possibilities
            const dateEntropy = cardDate.length > 0 ? Math.log2(3650) : 0; // ~11.8 bits
            
            // Card ID entropy: based on actual string complexity
            // Assume alphanumeric + dots/dashes, estimate charset of 40 chars
            const cardIdEntropy = cardId.length > 0 ? Math.log2(Math.pow(40, Math.min(cardId.length, 20))) : 0;
            
            // Nonce entropy: 48 bits when auto-generated (8 chars from base64-like alphabet)
            // Always assume auto-generated for maximum entropy estimation
            const nonceEntropy = 48.0;
            
            // Card index entropy: selecting from 100 cards (A0-J9)
            const cardIndexEntropy = Math.log2(100); // ~6.64 bits
            
            // Base system selection: 3 options (Base90/62/10) - minor contribution
            const baseSystemEntropy = Math.log2(3); // ~1.58 bits
            
            // Total label entropy
            const totalEntropy = dateEntropy + cardIdEntropy + nonceEntropy + cardIndexEntropy + baseSystemEntropy;
            
            return {
                date: dateEntropy,
                cardId: cardIdEntropy,
                nonce: nonceEntropy,
                cardIndex: cardIndexEntropy,
                baseSystem: baseSystemEntropy,
                total: totalEntropy
            };
        } catch (error) {
            console.error('Error calculating label entropy:', error);
            return { date: 0, cardId: 0, nonce: 0, cardIndex: 0, baseSystem: 0, total: 0 };
        }
    }
    
    /**
     * Calculate KDF resistance factor - NOT entropy, but attack cost multiplier
     * Returns human-readable resistance in terms of energy/time
     */
    calculateKDFResistance() {
        const timeCost = parseInt(document.getElementById('argon2-time')?.value || '3');
        const memoryMb = parseInt(document.getElementById('argon2-memory')?.value || '64');
        const parallelism = parseInt(document.getElementById('argon2-parallelism')?.value || '8');
        
        // Argon2id cost estimation
        // Modern GPU can do ~10 billion SHA-256/s but Argon2 is memory-hard
        // Rough estimate: 1 Argon2 hash with 64MB/3iter takes ~100ms on high-end GPU
        // This means ~10 hashes/second per GPU at 64MB/3iter
        
        const baseHashesPerSecondPerGPU = 10; // Conservative for 64MB/3iter
        
        // Scale by memory and time cost
        // Higher memory = fewer parallel hashes (limited by VRAM)
        // Higher iterations = linear slowdown
        const memoryScaling = 64 / memoryMb; // Relative to 64MB baseline
        const timeScaling = 3 / timeCost; // Relative to 3 iterations baseline
        
        const effectiveHashesPerGPU = baseHashesPerSecondPerGPU * memoryScaling * timeScaling;
        
        // Assume attacker has 10,000 high-end GPUs (nation-state level)
        const attackerGPUs = 10000;
        const hashesPerSecond = effectiveHashesPerGPU * attackerGPUs;
        
        // Calculate time to crack various entropy levels
        const secondsPerYear = 365.25 * 24 * 60 * 60;
        
        // Energy cost estimation (rough)
        // High-end GPU uses ~300W, running 24/7
        const wattsPerGPU = 300;
        const totalWatts = attackerGPUs * wattsPerGPU; // 3MW for our attack cluster
        const joulesPerSecond = totalWatts;
        
        // Sun outputs ~3.8 × 10^26 watts
        const sunPowerWatts = 3.8e26;
        
        return {
            hashesPerSecond,
            hashesPerYear: hashesPerSecond * secondsPerYear,
            attackerGPUs,
            memoryMb,
            timeCost,
            parallelism,
            joulesPerSecond,
            sunPowerWatts,
            // Helper function to convert entropy to crack time
            entropyToCrackTime: (entropyBits) => {
                const combinations = Math.pow(2, entropyBits);
                const expectedGuesses = combinations / 2; // Average case
                const secondsToCrack = expectedGuesses / hashesPerSecond;
                const yearsToCrack = secondsToCrack / secondsPerYear;
                const energyJoules = secondsToCrack * joulesPerSecond;
                const sunYearsEquivalent = energyJoules / (sunPowerWatts * secondsPerYear);
                
                return {
                    seconds: secondsToCrack,
                    years: yearsToCrack,
                    millennia: yearsToCrack / 1000,
                    energyJoules,
                    sunYears: sunYearsEquivalent
                };
            }
        };
    }
    
    /**
     * Format crack time in human-readable terms using intuitive comparisons
     */
    formatCrackTime(entropyBits) {
        const resistance = this.calculateKDFResistance();
        const crackTime = resistance.entropyToCrackTime(entropyBits);
        const years = crackTime.years;
        
        // Cosmic/geological reference points for intuitive comparison
        const AGE_OF_UNIVERSE = 13.8e9;      // 13.8 billion years
        const AGE_OF_EARTH = 4.5e9;          // 4.5 billion years
        const AGE_OF_DINOSAURS = 230e6;      // 230 million years (first dinosaurs)
        const AGE_OF_HUMANS = 300e3;         // 300,000 years (modern humans)
        
        if (years >= AGE_OF_UNIVERSE * 1e6) {
            // Incomprehensibly long - just say it's safe forever
            return `${(years / AGE_OF_UNIVERSE).toExponential(1)}× age of universe 🌌`;
        } else if (years >= AGE_OF_UNIVERSE) {
            const multiple = years / AGE_OF_UNIVERSE;
            if (multiple >= 1000) {
                return `${(multiple / 1000).toFixed(0)}k× age of universe 🌌`;
            } else if (multiple >= 100) {
                return `${Math.round(multiple)}× age of universe 🌌`;
            } else {
                return `${multiple.toFixed(1)}× age of universe 🌌`;
            }
        } else if (years >= AGE_OF_EARTH) {
            const multiple = years / AGE_OF_EARTH;
            return `${multiple.toFixed(1)}× Earth's age 🌍`;
        } else if (years >= AGE_OF_DINOSAURS) {
            return `${(years / 1e6).toFixed(0)} million years (dinosaur-era) 🦖`;
        } else if (years >= AGE_OF_HUMANS) {
            return `${(years / 1e6).toFixed(1)} million years 🏛️`;
        } else if (years >= 10000) {
            return `${(years / 1000).toFixed(0)}k years (civilizations rise & fall) 📜`;
        } else if (years >= 1000) {
            return `${Math.round(years).toLocaleString()} years 📅`;
        } else if (years >= 100) {
            return `${Math.round(years)} years 📅`;
        } else if (years >= 1) {
            return `${years.toFixed(1)} years 📅`;
        } else if (crackTime.seconds >= 86400) {
            return `${Math.round(crackTime.seconds / 86400)} days ⏰`;
        } else if (crackTime.seconds >= 3600) {
            return `${Math.round(crackTime.seconds / 3600)} hours ⏰`;
        } else if (crackTime.seconds >= 60) {
            return `${Math.round(crackTime.seconds / 60)} minutes ⚠️`;
        } else {
            return `${crackTime.seconds.toFixed(1)} seconds ⚠️ (WEAK!)`;
        }
    }
    
    async calculateLabelHash() {
        try {
            const cardIdInput = document.getElementById('card-id');
            const cardDateInput = document.getElementById('card-date');
            
            const cardId = cardIdInput?.value || '';
            const cardDate = cardDateInput?.value || '';
            
            // Combine label inputs for hashing
            const labelData = `${cardId}|${cardDate}`;
            
            if (labelData === '|') {
                return null; // No label data to hash
            }
            
            // Use Web Crypto API to create SHA-512 hash
            const encoder = new TextEncoder();
            const data = encoder.encode(labelData);
            const hashBuffer = await crypto.subtle.digest('SHA-512', data);
            const hashArray = new Uint8Array(hashBuffer);
            const hashHex = Array.from(hashArray, byte => byte.toString(16).padStart(2, '0')).join('');
            
            // Return full SHA-512 hash for better label obfuscation
            return hashHex.toUpperCase();
        } catch (error) {
            console.error('Error calculating label hash:', error);
            return null;
        }
    }
    
    async generatePasswordExamples(matrix) {
        
        try {
            // Generate basic patterns for examples
            const basicExamples = PatternGenerator.generateExamples(matrix, PatternGenerator.BASIC_PATTERNS);
            
            // Generate secure patterns for examples
            const secureExamples = PatternGenerator.generateExamples(matrix, PatternGenerator.SECURE_PATTERNS);
            
            // Generate fewer combined pattern examples for security section (2 from each category)
            const combinedExamples = [
                ...basicExamples.slice(0, 2).map(example => ({...example, category: 'Basic'})),
                ...secureExamples.slice(0, 2).map(example => ({...example, category: 'Secure'}))
            ];
            
            this.displayPatternAnalysis('entropy-breakdown', combinedExamples);
            
            // Update pattern entropy explanation
            this.updatePatternEntropyExplanation(combinedExamples);
            
            // Update entropy summary
            this.updatePasswordEntropySummary();
            
        } catch (error) {
            console.error('Failed to generate password examples:', error);
        }
    }
    
    displayPatternExamples(containerId, examples) {
        const container = document.getElementById(containerId);
        if (!container) return;
        
        // Clear container first
        container.innerHTML = '';
        
        // Create individual pattern example elements and append them to the container
        examples.forEach((example, index) => {
            // Parse coordinates from pattern (e.g., "A0 B1 C2 D3" -> ["A0", "B1", "C2", "D3"])
            const coordinates = example.pattern.split(' ').filter(coord => coord.trim());
            
            // Calculate entropy for this pattern
            const entropyAnalysis = EntropyAnalyzer.analyzeCoordinatePattern(coordinates);
            
            // Extract tokens for this pattern
            const tokens = coordinates.map(coord => {
                const col = coord.charCodeAt(0) - 65; // A=0, B=1, etc.
                const row = parseInt(coord.slice(1));
                return this.currentMatrix?.[row]?.[col] || '????';
            });
            
            // Calculate memorized word entropy (simplified)
            const memorizedEntropy = EntropyAnalyzer.calculateMemorizedWordEntropy(2); // Assume 2 memorized words
            
            // Create unique ID for this example
            const exampleId = `password-example-${containerId}-${index}`;
            
            // Prepare data for modal
            const passwordData = {
                label: `Password Example: ${example.description}`,
                pattern: example.pattern,
                coordinates: coordinates,
                tokens: tokens,
                entropy: entropyAnalysis,
                password: example.password,
                memorizedEntropy: memorizedEntropy
            };
            
            // Create pattern example element
            const patternDiv = document.createElement('div');
            patternDiv.className = 'pattern-example';
            patternDiv.innerHTML = `
                <div class="pattern-info">
                    <div class="pattern-header">
                        <span><strong>${example.pattern}</strong> - ${example.description}</span>
                        <button class="entropy-help-btn" data-example-id="${exampleId}" title="Show detailed entropy breakdown">
                            <span class="help-icon">?</span>
                        </button>
                    </div>
                    <div class="entropy-info">
                        <span class="entropy-label">Entropy:</span> 
                        <span class="entropy-value">${entropyAnalysis.effective_entropy} bits</span>
                        ${EntropyAnalyzer.getSecurityBadge(entropyAnalysis.security_level, entropyAnalysis.security_color)}
                    </div>
                </div>
                <div class="pattern-password">
                    <span class="password-value">${example.password}</span>
                    <span class="token-count">(${coordinates.length} tokens)</span>
                </div>
            `;
            
            // Store password data for later access
            patternDiv.dataset.passwordData = JSON.stringify(passwordData);
            patternDiv.dataset.exampleId = exampleId;
            
            // Append to container
            container.appendChild(patternDiv);
        });
        
        // Set up event delegation for help buttons
        this.setupEntropyHelpButtons(container);
    }
    
    displayPatternAnalysis(containerId, examples) {
        const container = document.getElementById(containerId);
        if (!container) return;
        
        // Create individual pattern example elements and append them to the container
        examples.forEach((example, index) => {
            // Parse coordinates from pattern (e.g., "A0 B1 C2 D3" -> ["A0", "B1", "C2", "D3"])
            const coordinates = example.pattern.split(' ').filter(coord => coord.trim());
            
            // Calculate entropy for this pattern
            const entropyAnalysis = EntropyAnalyzer.analyzeCoordinatePattern(coordinates);
            
            // Extract tokens for this pattern
            const tokens = coordinates.map(coord => {
                const col = coord.charCodeAt(0) - 65; // A=0, B=1, etc.
                const row = parseInt(coord.slice(1));
                return this.currentMatrix?.[row]?.[col] || '????';
            });
            
            // Calculate memorized word entropy (simplified)
            const memorizedEntropy = EntropyAnalyzer.calculateMemorizedWordEntropy(2); // Assume 2 memorized words
            
            // Category-based styling
            const categoryClass = example.category.toLowerCase();
            const categoryIcon = example.category === 'Basic' ? '🔸' : '🔹';
            
            // Create unique ID for this example
            const exampleId = `example-${containerId}-${index}`;
            
            // Prepare data for modal
            const passwordData = {
                label: `${example.category} Pattern: ${example.description}`,
                pattern: example.pattern,
                coordinates: coordinates,
                tokens: tokens,
                entropy: entropyAnalysis,
                password: example.password,
                memorizedEntropy: memorizedEntropy
            };
            
            // Create pattern example element
            const patternDiv = document.createElement('div');
            patternDiv.className = `pattern-example ${categoryClass}`;
            patternDiv.innerHTML = `
                <div class="pattern-header">
                    <span class="pattern-category">${categoryIcon} ${example.category}</span>
                    <span class="pattern-entropy">${entropyAnalysis.effective_entropy} bits ${EntropyAnalyzer.getSecurityBadge(entropyAnalysis.security_level, entropyAnalysis.security_color)}</span>
                    <button class="entropy-help-btn" data-example-id="${exampleId}" title="Show detailed entropy breakdown">
                        <span class="help-icon">?</span>
                    </button>
                </div>
                <div class="pattern-coordinates">
                    <strong>${example.pattern}</strong> - ${example.description}
                </div>
                <div class="pattern-password">
                    <span class="password-value">${example.password}</span>
                    <span class="token-count">(${coordinates.length} tokens)</span>
                </div>
            `;
            
            // Store password data for later access
            patternDiv.dataset.passwordData = JSON.stringify(passwordData);
            patternDiv.dataset.exampleId = exampleId;
            
            // Append to container
            container.appendChild(patternDiv);
        });
        
        // Set up event delegation for help buttons
        this.setupEntropyHelpButtons(container);
    }
    
    setupEntropyHelpButtons(container) {
        container.addEventListener('click', (event) => {
            if (event.target.classList.contains('entropy-help-btn') || 
                event.target.closest('.entropy-help-btn')) {
                
                const helpBtn = event.target.classList.contains('entropy-help-btn') ? 
                    event.target : event.target.closest('.entropy-help-btn');
                
                const exampleId = helpBtn.dataset.exampleId;
                const patternDiv = container.querySelector(`[data-example-id="${exampleId}"]`);
                
                if (patternDiv && patternDiv.dataset.passwordData) {
                    try {
                        const passwordData = JSON.parse(patternDiv.dataset.passwordData);
                        showPasswordEntropyModal(passwordData);
                    } catch (error) {
                        console.error('Error parsing password data:', error);
                    }
                }
            }
        });
    }
    
    updatePatternEntropyExplanation(examples) {
        const explanationElement = document.getElementById('pattern-entropy-explanation');
        const modalExplanationElement = document.getElementById('modal-pattern-entropy-explanation');
        
        if (examples && examples.length > 0) {
            // Calculate typical pattern entropy from examples
            const tokenCounts = examples.map(example => 
                example.pattern.split(' ').filter(coord => coord.trim()).length
            );
            const avgTokens = tokenCounts.reduce((sum, count) => sum + count, 0) / tokenCounts.length;
            const minTokens = Math.min(...tokenCounts);
            const maxTokens = Math.max(...tokenCounts);
            
            const tokenEntropy = EntropyAnalyzer.calculateTokenEntropy(); // ~25.9 bits
            
            let explanationText;
            if (minTokens === maxTokens) {
                explanationText = `${minTokens} tokens = ${(tokenEntropy * minTokens).toFixed(1)} bits`;
            } else {
                explanationText = `${minTokens}-${maxTokens} tokens = ${(tokenEntropy * minTokens).toFixed(1)}-${(tokenEntropy * maxTokens).toFixed(1)} bits`;
            }
            
            if (explanationElement) explanationElement.textContent = explanationText;
            if (modalExplanationElement) modalExplanationElement.textContent = explanationText;
        } else {
            const defaultText = 'Varies by coordinate selection';
            if (explanationElement) explanationElement.textContent = defaultText;
            if (modalExplanationElement) modalExplanationElement.textContent = defaultText;
        }
    }
    
    displayMemorizedWords(containerId, words) {
        const container = document.getElementById(containerId);
        if (!container) return;
        
        // Calculate comprehensive entropy for memorized components
        const avgWordLength = words.reduce((sum, word) => sum + word.length, 0) / words.length;
        const wordEntropy = EntropyAnalyzer.calculateMemorizedWordEntropy(avgWordLength, 26); // Lowercase letters
        const punctuationEntropy = EntropyAnalyzer.calculatePunctuationEntropy(1, 32); // One punctuation mark
        const combinedMemorizedEntropy = wordEntropy + punctuationEntropy;
        
        // Calculate sample password properties
        const sampleWord = words[0];
        const samplePassword = `A0B1${sampleWord}!`; // Grid tokens + memorized word + punctuation
        const gridTokens = 2; // A0, B1
        const gridEntropy = EntropyAnalyzer.calculatePasswordEntropy(gridTokens);
        const totalPasswordEntropy = gridEntropy + combinedMemorizedEntropy;
        
        container.innerHTML = `
            <div class="memorized-words">
                <div class="words-list">
                    ${words.map((word, i) => `<span class="word-example">${word}</span>`).join('')}
                </div>
                <div class="words-usage">
                    <strong>Example Password:</strong> ${samplePassword} (${samplePassword.length} characters)
                </div>
                <div class="entropy-breakdown">
                    <div class="entropy-component">
                        <span class="component-label">Grid Tokens (${gridTokens}):</span>
                        <span class="component-value">${Math.round(gridEntropy * 10) / 10} bits</span>
                    </div>
                    <div class="entropy-component">
                        <span class="component-label">Memorized Word:</span>
                        <span class="component-value">${Math.round(wordEntropy * 10) / 10} bits</span>
                    </div>
                    <div class="entropy-component">
                        <span class="component-label">Punctuation:</span>
                        <span class="component-value">${Math.round(punctuationEntropy * 10) / 10} bits</span>
                    </div>
                    <div class="entropy-component total">
                        <span class="component-label">Total Password:</span>
                        <span class="component-value">${Math.round(totalPasswordEntropy * 10) / 10} bits ${EntropyAnalyzer.getSecurityBadge(totalPasswordEntropy)}</span>
                    </div>
                </div>
                <div class="usage-note">
                    Note: Memorized components reduce dependency on grid access while maintaining security
                </div>
            </div>
        `;
    }
    
    async generateDemoMatrix() {
        try {
            const seedBytes = await SeedSources.simpleToSeed('test phrase');
            const base = this.getSelectedBase?.() || 'base90';
            const result = await SeedCardCrypto.generateTokenMatrix(seedBytes, 'A0', base);
            this.displayDemoMatrix(result.matrix);
        } catch (error) {
            console.error('Demo matrix generation failed:', error);
            // Show a fallback message if auto-generation fails
            const demoContainer = document.getElementById('demo-matrix');
            if (demoContainer) {
                demoContainer.innerHTML = `
                    <div class="demo-error">
                        <p>Demo matrix generation failed. Please try the "Generate Sample" button.</p>
                    </div>
                `;
            }
        }
    }
    
    displayDemoMatrix(matrix) {
        const demoContainer = document.getElementById('demo-matrix');
        if (!demoContainer) return;
        
        // Create table element
        const table = document.createElement('table');
        table.className = 'password-matrix demo-matrix';
        
        // Use the same renderMatrixTable method to ensure consistency, but disable index buttons for demo
        this.renderMatrixTable(table, matrix, false);
        
        // Update entropy information for demo matrix
        this.updateMatrixEntropy();
        
        // Create demo info
        const demoInfo = document.createElement('div');
        demoInfo.className = 'demo-info';
        demoInfo.innerHTML = '<p>This 10×10 matrix shows deterministic token generation from "test phrase"</p>';
        
        // Clear container and add elements
        demoContainer.innerHTML = '';
        demoContainer.appendChild(table);
        demoContainer.appendChild(demoInfo);
    }
    
    showResults() {
        const resultsArea = document.getElementById('results');
        const resultsHeader = resultsArea?.querySelector('.section-header-nav');
        
        if (resultsArea) {
            resultsArea.style.display = 'block';
            
            // Ensure header is visible
            if (resultsHeader) {
                resultsHeader.style.display = 'flex';
                resultsHeader.style.visibility = 'visible';
            }
        }
    }
    
    /*
    showBatchDisplay() {
        
        // Hide single card, show batch cards
        const singleCard = document.getElementById('single-card');
        const batchCards = document.getElementById('batch-cards');
        const resultsArea = document.getElementById('results');
        
        if (singleCard) {
            singleCard.style.display = 'none';
        }
        if (batchCards) {
            batchCards.style.display = 'block';
        }
        if (resultsArea) {
            // Clear any loading states
            const loadingIndicator = resultsArea.querySelector('.loading-indicator');
            if (loadingIndicator) {
                loadingIndicator.remove();
            }
            
            // Show the header and password examples
            const header = resultsArea.querySelector('.section-header-nav');
            const passwordExamples = resultsArea.querySelector('.password-examples');
            
            if (header) {
                header.style.display = 'flex';
            }
            if (passwordExamples) {
                passwordExamples.style.display = 'block';
            }
            
            resultsArea.style.display = 'block';
            // Removed auto-scroll to prevent page jumping
        }
    }
    */
    
    showLoadingState() {
        // Show loading indicator in results area without destroying existing content
        const resultsArea = document.getElementById('results');
        if (resultsArea) {
            // Check if loading indicator already exists
            let loadingIndicator = resultsArea.querySelector('.loading-indicator');
            if (!loadingIndicator) {
                // Create and insert loading indicator without destroying existing content
                loadingIndicator = document.createElement('div');
                loadingIndicator.className = 'loading-indicator';
                loadingIndicator.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Loading...';
                resultsArea.insertAdjacentElement('afterbegin', loadingIndicator);
            } else {
                // Update existing loading indicator
                loadingIndicator.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Loading...';
            }
            
            // Hide other content during loading
            const header = resultsArea.querySelector('.section-header-nav');
            const singleCard = resultsArea.querySelector('#single-card');
            const batchCards = resultsArea.querySelector('#batch-cards');
            const passwordExamples = resultsArea.querySelector('.password-examples');
            
            if (header) header.style.display = 'none';
            if (singleCard) singleCard.style.display = 'none';
            if (batchCards) batchCards.style.display = 'none';
            if (passwordExamples) passwordExamples.style.display = 'none';
            
            resultsArea.style.display = 'block';
        }
    }
    
    hideLoadingState() {
        // Loading state is cleared when results are displayed
        // No button to update anymore
    }
    
    updateProgress(current, total) {
        // Update progress in results area without destroying existing content
        const resultsArea = document.getElementById('results');
        if (resultsArea) {
            const percent = Math.round((current / total) * 100);
            let loadingIndicator = resultsArea.querySelector('.loading-indicator');
            if (loadingIndicator) {
                loadingIndicator.innerHTML = `<i class="fas fa-spinner fa-spin"></i> Generating... ${percent}%`;
            }
        }
    }
    
    showError(message) {
        // Create or update error display
        let errorDiv = document.querySelector('.error-message');
        if (!errorDiv) {
            errorDiv = document.createElement('div');
            errorDiv.className = 'error-message';
            errorDiv.style.cssText = `
                background: #fee2e2;
                border: 1px solid #fecaca;
                color: #dc2626;
                padding: 1rem;
                border-radius: 8px;
                margin: 1rem 0;
            `;
            
            const formContainer = document.querySelector('.generator-form');
            if (formContainer) {
                formContainer.appendChild(errorDiv);
            } else {
                document.body.appendChild(errorDiv);
            }
        }
        
        errorDiv.innerHTML = `<i class="fas fa-exclamation-triangle"></i> ${SecurityUtils.sanitizeHTML(message)}`;
        
        // Auto-hide after 5 seconds
        setTimeout(() => {
            if (errorDiv.parentNode) {
                errorDiv.parentNode.removeChild(errorDiv);
            }
        }, 5000);
    }
    
    handleCopyMatrix() {
        if (!this.currentMatrix) return;
        this.copyEntireMatrix(this.currentMatrix);
    }
    
    handlePrint() {
        window.print();
    }
    
    handleDownload() {
        if (!this.currentMatrix || !this.currentCardId) return;
        
        // Create downloadable content
        const content = this.generateDownloadContent();
        const blob = new Blob([content], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        
        const a = document.createElement('a');
        a.href = url;
        a.download = `seed-card-${this.currentCardId}.txt`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }
    
    generateDownloadContent() {
        const matrixText = this.currentMatrix.map((row, rowIndex) => {
            const rowLetter = String.fromCharCode('A'.charCodeAt(0) + rowIndex);
            return `${rowLetter}  ${row.join('  ')}`;
        }).join('\n');
        
        return `Seed Card Password Matrix
Generated: ${new Date().toISOString()}
Card ID: ${this.currentCardId}

Matrix:
   ${Array.from({length: 10}, (_, i) => i).join('   ')}
${matrixText}

Usage Instructions:
1. Select coordinates like A0, B1, C2 for password patterns
2. Use diagonal, row, or scattered patterns for different security levels
3. Add separators (-) and memorized words for stronger passwords

Example Patterns:
- Basic: A0 B1 C2 D3 (diagonal)
- Secure: B3 F7 D1 H5 (scattered)
- Memorable: A0 A1 A2 (row)

Security Notice:
This tool is designed for online services with rate limiting.
Always use 2FA for critical accounts.
`;
    }
    
    handleAddSlip39Share() {
        const sharesContainer = document.querySelector('.slip39-shares');
        if (!sharesContainer) return;
        
        const shareCount = sharesContainer.children.length;
        if (shareCount >= 5) return; // Max 5 shares
        
        const newShare = document.createElement('textarea');
        newShare.className = 'slip39-share';
        newShare.placeholder = `Share ${shareCount + 1}: Enter SLIP-39 share...`;
        newShare.rows = 2;
        
        sharesContainer.appendChild(newShare);
    }
    
}

// Initialize app when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    // Pre-initialize Argon2 Web Worker for faster first derivation
    if (typeof Argon2Worker !== 'undefined' && Argon2Worker.isSupported()) {
        Argon2Worker.getWorker(); // Start loading worker in background
    }
    
    window.app = new SeedCardApp();
});

// Add print styles
const printStyles = `
    @media print {
        .navbar, .footer, .security-notice, .form-section, .results-actions {
            display: none !important;
        }
        
        .card-front {
            page-break-inside: avoid;
            border: 2px solid #000 !important;
        }
        
        .password-matrix {
            font-size: 12px;
        }
        
        .password-matrix th,
        .password-matrix td {
            border: 1px solid #000 !important;
            padding: 4px !important;
        }
    }
`;

const styleSheet = document.createElement('style');
styleSheet.textContent = printStyles;
document.head.appendChild(styleSheet);

// Global navigation function for section scrolling
function scrollToSection(sectionId) {
    if (!sectionId) return; // Handle disabled buttons
    
    const element = document.getElementById(sectionId);
    if (element) {
        // Get actual navbar height dynamically
        const navbar = document.querySelector('.navbar');
        let navbarHeight = 80; // Default fallback
        
        if (navbar) {
            navbarHeight = navbar.getBoundingClientRect().height;
        }
        
        // Calculate position accounting for navbar with extra padding
        const elementPosition = element.getBoundingClientRect().top + window.pageYOffset;
        const offsetPosition = elementPosition - navbarHeight - 20; // Extra 20px padding
        
        window.scrollTo({
            top: offsetPosition,
            behavior: 'smooth'
        });
    }
}

// Make it globally accessible
window.scrollToSection = scrollToSection;

// Generate cards and navigate to results
function generateAndNext() {
    
    // First generate the cards using the app instance
    if (window.app && window.app.handleGenerate) {
        window.app.handleGenerate(false); // false = not auto-generation
    }
    
    // Then scroll to results after a brief delay to ensure generation completes
    setTimeout(() => {
        scrollToSection('results');
    }, 100);
}

// Make it globally accessible
window.generateAndNext = generateAndNext;

// Global modal functions (simpler fallback version)
window.showTokenEntropyModal = function() {
    // Try app instance first
    if (window.app && window.app.showTokenEntropyModal) {
        window.app.showTokenEntropyModal();
        return;
    }
    
    // Fallback: show modal directly
    const modal = document.getElementById('token-entropy-modal');
    if (modal) {
        modal.style.display = 'block';
        modal.classList.add('show');
        document.body.style.overflow = 'hidden';
        
        // Set up close functionality if not already done
        const closeBtn = modal.querySelector('.close-btn');
        if (closeBtn && !closeBtn.hasAttribute('data-listener-added')) {
            closeBtn.setAttribute('data-listener-added', 'true');
            closeBtn.addEventListener('click', () => {
                modal.classList.remove('show');
                modal.style.display = 'none';
                document.body.style.overflow = 'auto';
            });
        }
        
        // Close on outside click
        if (!modal.hasAttribute('data-outside-listener-added')) {
            modal.setAttribute('data-outside-listener-added', 'true');
            modal.addEventListener('click', (event) => {
                if (event.target === modal) {
                    modal.classList.remove('show');
                    modal.style.display = 'none';
                    document.body.style.overflow = 'auto';
                }
            });
        }
    } else {
        console.error('Modal not found in DOM');
    }
};

window.hideTokenEntropyModal = function() {
    if (window.app && window.app.hideTokenEntropyModal) {
        window.app.hideTokenEntropyModal();
    } else {
        console.error('App instance not available for hideTokenEntropyModal');
    }
};

/**
 * Copy text to clipboard with visual feedback
 */
function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
        // Show temporary success message
        const toast = document.createElement('div');
        toast.textContent = 'Copied to clipboard!';
        toast.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            background: #28a745;
            color: white;
            padding: 8px 16px;
            border-radius: 4px;
            z-index: 10000;
            font-size: 14px;
            font-weight: 500;
        `;
        document.body.appendChild(toast);
        
        setTimeout(() => {
            if (toast.parentNode) {
                toast.parentNode.removeChild(toast);
            }
        }, 2000);
    }).catch(err => {
        console.error('Failed to copy text: ', err);
    });
}

/**
 * Add click-to-copy functionality to modal elements
 */
function addCopyFunctionality(modalContent) {
    // Add copy functionality to formulas
    const formulas = modalContent.querySelectorAll('.calc-formula');
    formulas.forEach(formula => {
        formula.style.cursor = 'pointer';
        formula.title = 'Click to copy formula';
        formula.addEventListener('click', () => {
            copyToClipboard(formula.textContent);
        });
    });
    
    // Add copy functionality to sub-formulas
    const subFormulas = modalContent.querySelectorAll('.calc-sub-formula');
    subFormulas.forEach(subFormula => {
        subFormula.style.cursor = 'pointer';
        subFormula.title = 'Click to copy sub-formula';
        subFormula.addEventListener('click', () => {
            copyToClipboard(subFormula.textContent);
        });
    });
    
    // Add copy functionality to values
    const values = modalContent.querySelectorAll('.calc-value');
    values.forEach(value => {
        value.style.cursor = 'pointer';
        value.title = 'Click to copy value';
        value.addEventListener('click', () => {
            copyToClipboard(value.textContent);
        });
    });
    
    // Add copy functionality to sub-values
    const subValues = modalContent.querySelectorAll('.calc-sub-value');
    subValues.forEach(subValue => {
        subValue.style.cursor = 'pointer';
        subValue.title = 'Click to copy sub-value';
        subValue.addEventListener('click', () => {
            copyToClipboard(subValue.textContent);
        });
    });
    
    // Add copy functionality to passwords
    const passwords = modalContent.querySelectorAll('.password-display');
    passwords.forEach(password => {
        password.style.cursor = 'pointer';
        password.title = 'Click to copy password';
        password.addEventListener('click', () => {
            copyToClipboard(password.textContent);
        });
    });
}

window.showPasswordEntropyModal = function(passwordData) {
    const modal = document.getElementById('password-entropy-modal');
    if (modal) {
        // Update modal content with specific password data
        const titleElement = modal.querySelector('.modal-title');
        const contentElement = modal.querySelector('.modal-entropy-breakdown');
        
        if (titleElement) {
            titleElement.textContent = `🔐 ${passwordData.label} - Entropy Breakdown`;
        }
        
        if (contentElement) {
            contentElement.innerHTML = generatePasswordEntropyHTML(passwordData);
            // Add click-to-copy functionality to the new content
            addCopyFunctionality(contentElement);
        }
        
        modal.style.display = 'block';
        modal.classList.add('show');
        document.body.style.overflow = 'hidden';
    } else {
    }
};

/**
 * Interactive Threat Analysis Functions
 */
const threatAnalysisData = {
    components: {
        seed: { name: 'Seed Source', entropy: 128.0, compromised: false },
        card: { name: 'Physical Card', entropy: 63.0, compromised: false },
        label: { name: 'Card Label', entropy: 32.0, compromised: false }, // Increased with salted hash
        cardid: { name: 'Card ID', entropy: 16.0, compromised: false }, // Increased with salt/expansion
        tokens: { name: 'Selected Tokens', entropy: calculateTokenEntropy(4), compromised: false },
        sequence: { name: 'Token Sequence', entropy: calculateSequenceEntropy(4), compromised: false },
        memorized: { name: 'Memorized', entropy: calculateMemorizedEntropy(), compromised: false },
        patterns: { name: 'Usage Patterns', entropy: 7.6, compromised: false }
    },
    tokenCount: 4 // Default number of tokens used
};

/**
 * Calculate sequence entropy based on the complexity of the sequence pattern
 * This represents the entropy of the actual sequence order/pattern, not just position selection
 * Considers factors like: randomness vs patterns, repetitions, ordering complexity
 * @param {number} tokenCount - Number of tokens in sequence (1-10)
 * @returns {number} - Sequence complexity entropy in bits
 */
function calculateSequenceEntropy(tokenCount = 4) {
    if (tokenCount <= 0) return 0;
    if (tokenCount === 1) return 0; // Single token has no sequence complexity
    
    // Base entropy from token ordering permutations
    // For n tokens, there are n! possible orderings
    let permutationEntropy = 0;
    for (let i = 2; i <= tokenCount; i++) {
        permutationEntropy += Math.log2(i);
    }
    
    // Reduce entropy for human pattern bias
    // Humans tend to use simpler patterns (sequential, diagonal, etc.)
    // Apply reduction factor based on psychological research
    const humanPatternReduction = 0.7; // 30% reduction for human predictability
    
    // Additional entropy from spatial relationships on 10x10 grid
    // Patterns like diagonal, L-shapes, corners, etc. add complexity
    const spatialComplexityBonus = Math.log2(tokenCount + 1); // Small bonus for spatial variety
    
    const totalEntropy = (permutationEntropy * humanPatternReduction) + spatialComplexityBonus;
    
    return Math.max(0, totalEntropy);
}

/**
 * Calculate token entropy based on number of tokens selected
 * Each token is 4 characters from 90-character alphabet: log2(90^4) ≈ 26.0 bits per token
 * @param {number} tokenCount - Number of tokens selected (1-10)
 * @returns {number} - Token entropy in bits
 */
function calculateTokenEntropy(tokenCount = 4) {
    // Each token is 4 characters from Base90 alphabet: log2(90^4) ≈ 26.0 bits per token
    const entropyPerToken = Math.log2(90) * 4; // 4 characters per token
    return tokenCount * entropyPerToken;
}

/**
 * Update token entropy display based on current token count
 */
function updateTokenEntropyDisplay() {
    const tokenCountInput = document.getElementById('token-count');
    const tokenEntropyValue = document.getElementById('token-entropy-value');
    const tokenEntropyDisplay = document.querySelector('.token-entropy-display');
    
    if (tokenCountInput && tokenEntropyValue) {
        const tokenCount = parseInt(tokenCountInput.value) || 4;
        const tokenEntropy = calculateTokenEntropy(tokenCount);
        const sequenceEntropy = calculateSequenceEntropy(tokenCount);
        const entropyPerToken = Math.log2(90) * 4; // 4 characters per token
        
        // Update data
        threatAnalysisData.tokenCount = tokenCount;
        threatAnalysisData.components.sequence.entropy = sequenceEntropy;
        
        // Update display
        tokenEntropyValue.textContent = tokenEntropy.toFixed(1) + ' bits';
        tokenEntropyDisplay.innerHTML = `
            Token values: <span id="token-entropy-value">${tokenEntropy.toFixed(1)} bits</span>
            (${tokenCount} token${tokenCount !== 1 ? 's' : ''} × ${entropyPerToken.toFixed(1)} bits each)
        `;
        
        // Update sequence entropy display in checkboxes  
        const sequenceEntropyDisplay = document.getElementById('sequence-entropy-display');
        if (sequenceEntropyDisplay) {
            sequenceEntropyDisplay.textContent = sequenceEntropy.toFixed(1) + ' bits';
        }
        updateThreatAnalysis();
    }
}

/**
 * Get current seed entropy based on selected seed type
 */
function getCurrentSeedEntropy() {
    const seedType = document.querySelector('input[name="seedType"]:checked');
    if (!seedType) return 128.0; // Default BIP-39
    
    switch (seedType.value) {
        case 'bip39':
            // Standard BIP-39 with 128-bit entropy (12 words * ~10.67 bits per word)
            return 128.0;
        case 'simple':
            // Simple phrases: estimate entropy based on phrase characteristics
            return estimateSimplePhraseEntropy();
        case 'slip39':
            // SLIP-39 provides reconstructed entropy (typically 128-256 bits)
            return 256.0;
        default:
            return 128.0;
    }
}

/**
 * Estimate entropy of simple phrases based on common patterns
 */
function estimateSimplePhraseEntropy() {
    const simpleInput = document.getElementById('simple-seed');
    if (!simpleInput || !simpleInput.value) {
        // Default estimate for typical simple phrases
        return 35.0; // ~5-7 words with moderate complexity
    }
    
    const phrase = simpleInput.value.trim();
    const words = phrase.split(/\s+/).filter(word => word.length > 0);
    const totalChars = phrase.replace(/\s/g, '').length;
    
    // Estimate based on word count and character complexity
    if (words.length === 0) return 0;
    
    // Base entropy per word (assuming common English words)
    const wordsEntropy = words.length * Math.log2(10000); // ~13.3 bits per word
    
    // Character complexity bonus
    const hasNumbers = /\d/.test(phrase);
    const hasSpecialChars = /[^a-zA-Z0-9\s]/.test(phrase);
    const hasMixedCase = /[a-z]/.test(phrase) && /[A-Z]/.test(phrase);
    
    let complexityBonus = 0;
    if (hasNumbers) complexityBonus += 3.0;
    if (hasSpecialChars) complexityBonus += 5.0;
    
    // Enhanced mixed capitalization analysis
    if (hasMixedCase) {
        // Count capitalization patterns across words
        const capitalPatterns = words.map(word => {
            if (word === word.toLowerCase()) return 'lower';
            if (word === word.toUpperCase()) return 'upper';
            if (word[0] === word[0].toUpperCase() && word.slice(1) === word.slice(1).toLowerCase()) return 'title';
            return 'mixed';
        });
        
        const uniquePatterns = new Set(capitalPatterns).size;
        // More entropy for varied capitalization patterns
        complexityBonus += Math.min(uniquePatterns * 2.0, 8.0); // Up to 8 bits for complex patterns
    }
    
    // Length bonus for longer phrases
    const lengthBonus = Math.min(totalChars * 0.5, 15.0);
    
    const estimatedEntropy = wordsEntropy + complexityBonus + lengthBonus;
    
    // Cap at reasonable maximum for human-generated phrases
    return Math.min(estimatedEntropy, 80.0);
}

/**
 * Calculate memorized component entropy based on actual usage patterns
 * Considers capitalization, numbers, and word selection
 */
function calculateMemorizedEntropy() {
    // Base entropy from word selection (example: "Banking" from BIP-39 subset)
    // Assuming selection from ~200 common service words
    const wordSelectionEntropy = Math.log2(200); // ~7.6 bits
    
    // Mixed capitalization entropy (multiple patterns possible)
    // Examples: "banking", "Banking", "BANKING", "bANKING", "BaNkInG"
    // For a typical 7-letter word, consider reasonable capitalization patterns
    const capitalizationEntropy = 3.0; // ~8 common patterns (all-lower, title-case, all-upper, etc.)
    
    // Numeric component entropy (example: "1234" PIN)
    // Assuming 4-digit PIN with reasonable human patterns
    const numericEntropy = Math.log2(10000 * 0.3); // ~11.9 bits (reduced for human patterns)
    
    // Position/combination entropy (how word and number are combined)
    const combinationEntropy = Math.log2(4); // ~2 bits (word+num, num+word, word-num, num-word)
    
    return wordSelectionEntropy + capitalizationEntropy + numericEntropy + combinationEntropy;
}

function updateThreatAnalysis() {
    
    // Update seed entropy based on current selection
    try {
        threatAnalysisData.components.seed.entropy = getCurrentSeedEntropy();
    } catch (error) {
        console.error('Error updating seed entropy:', error);
        return;
    }
    
    // Update token-dependent entropies based on current token count
    const tokenCountInput = document.getElementById('token-count');
    const tokenCount = tokenCountInput ? parseInt(tokenCountInput.value) || 4 : 4;
    threatAnalysisData.tokenCount = tokenCount;
    
    // Update selected tokens entropy
    threatAnalysisData.components.tokens.entropy = calculateTokenEntropy(tokenCount);
    
    // Update sequence entropy
    threatAnalysisData.components.sequence.entropy = calculateSequenceEntropy(tokenCount);
    
    // Calculate total entropy based on compromise scenarios
    const isCardCompromised = threatAnalysisData.components.card.compromised;
    const isSeedCompromised = threatAnalysisData.components.seed.compromised;
    const isLabelCompromised = threatAnalysisData.components.label.compromised;
    const isCardidCompromised = threatAnalysisData.components.cardid.compromised;
    
    let totalEntropy = 0;
    
    if (isCardCompromised) {
        // Card compromised: seed, label, and cardid become irrelevant (all are on the card)
        // BUT: attacker still needs to know which tokens are selected and in what sequence
        // Token VALUES are visible (0 entropy), but token SELECTION still provides entropy
        if (!threatAnalysisData.components.tokens.compromised) {
            // Only coordinate selection entropy: log2(100) per coordinate selected
            const coordinateSelectionEntropy = tokenCount * Math.log2(100);
            totalEntropy += coordinateSelectionEntropy;
        }
        if (!threatAnalysisData.components.sequence.compromised) {
            // Sequence entropy still applies - order of selected coordinates
            totalEntropy += threatAnalysisData.components.sequence.entropy;
        }
        if (!threatAnalysisData.components.memorized.compromised) {
            totalEntropy += threatAnalysisData.components.memorized.entropy;
        }
        if (!threatAnalysisData.components.patterns.compromised) {
            totalEntropy += threatAnalysisData.components.patterns.entropy;
        }
    } else {
        // Card not compromised: seed+label+cardid generates tokens deterministically
        if (!isSeedCompromised) {
            totalEntropy += threatAnalysisData.components.seed.entropy;
        }
        if (!isLabelCompromised) {
            totalEntropy += threatAnalysisData.components.label.entropy;
        }
        if (!isCardidCompromised) {
            totalEntropy += threatAnalysisData.components.cardid.entropy;
        }
        
        // CRITICAL: Token entropy depends on what's compromised
        if (isSeedCompromised && (isLabelCompromised || isCardidCompromised)) {
            // If seed + (label OR cardid) known: attacker can generate token grid
            // Tokens provide NO additional entropy - only selection matters
            if (!threatAnalysisData.components.tokens.compromised) {
                // Only coordinate selection entropy: log2(100) per token
                const coordinateSelectionEntropy = tokenCount * Math.log2(100);
                totalEntropy += coordinateSelectionEntropy;
            }
        } else if (isLabelCompromised && isCardidCompromised && !isSeedCompromised) {
            // If label+cardid known but seed unknown: tokens still provide reduced entropy
            // Attacker can generate grids for candidate seeds, making brute force easier
            if (!threatAnalysisData.components.tokens.compromised) {
                // Reduced token entropy due to known metadata
                const reducedTokenEntropy = threatAnalysisData.components.tokens.entropy * 0.3; // 70% reduction
                totalEntropy += reducedTokenEntropy;
            }
        } else if (!isSeedCompromised && !isLabelCompromised && !isCardidCompromised) {
            // All generation parameters secure: tokens derived, only memorized components matter
            // Tokens/sequence are deterministic outputs of secure inputs
            // Don't add token entropy - they're already accounted for in the generation entropy
        } else {
            // Partial compromise scenarios: some token entropy remains
            if (!threatAnalysisData.components.tokens.compromised) {
                totalEntropy += threatAnalysisData.components.tokens.entropy;
            }
        }
        
        // Sequence entropy: only relevant when tokens have independent value
        if (!isSeedCompromised || (!isLabelCompromised && !isCardidCompromised)) {
            if (!threatAnalysisData.components.sequence.compromised) {
                totalEntropy += threatAnalysisData.components.sequence.entropy;
            }
        }
        
        // Memorized and patterns always contribute if not compromised
        if (!threatAnalysisData.components.memorized.compromised) {
            totalEntropy += threatAnalysisData.components.memorized.entropy;
        }
        if (!threatAnalysisData.components.patterns.compromised) {
            totalEntropy += threatAnalysisData.components.patterns.entropy;
        }
    }
    
    
    // Update dynamic token display based on compromise scenario
    const tokensDisplay = document.getElementById('tokens-entropy-display');
    if (tokensDisplay) {
        let tokenDisplayText;
        let tokenEffectiveEntropy;
        
        if (isCardCompromised) {
            // Card visible: only coordinate selection matters, not token values
            const coordinateEntropy = tokenCount * Math.log2(100);
            tokenDisplayText = `${coordinateEntropy.toFixed(1)} bits (selection only)`;
            tokenEffectiveEntropy = coordinateEntropy;
        } else if (isSeedCompromised && (isLabelCompromised || isCardidCompromised)) {
            // Tokens can be generated: only coordinate selection matters
            const coordinateEntropy = tokenCount * Math.log2(100);
            tokenDisplayText = `${coordinateEntropy.toFixed(1)} bits (position only)`;
            tokenEffectiveEntropy = coordinateEntropy;
        } else if (isLabelCompromised && isCardidCompromised && !isSeedCompromised) {
            // Reduced entropy due to known metadata
            const reducedEntropy = threatAnalysisData.components.tokens.entropy * 0.3;
            tokenDisplayText = `${reducedEntropy.toFixed(1)} bits (reduced)`;
            tokenEffectiveEntropy = reducedEntropy;
        } else {
            // Full token entropy
            tokenDisplayText = `${threatAnalysisData.components.tokens.entropy.toFixed(1)} bits`;
            tokenEffectiveEntropy = threatAnalysisData.components.tokens.entropy;
        }
        
        tokensDisplay.textContent = tokenDisplayText;
        tokensDisplay.className = tokenEffectiveEntropy < (tokenCount * Math.log2(90)) ? 'entropy-value compromised' : 'entropy-value';
    }
    
    // Update sequence display similarly
    const sequenceDisplay = document.getElementById('sequence-entropy-display');
    if (sequenceDisplay) {
        let sequenceDisplayText;
        let sequenceEffectiveEntropy;
        
        if (isSeedCompromised && (isLabelCompromised || isCardidCompromised)) {
            // When grid can be generated, sequence provides less entropy
            const reducedSequenceEntropy = threatAnalysisData.components.sequence.entropy * 0.5;
            sequenceDisplayText = `${reducedSequenceEntropy.toFixed(1)} bits (reduced)`;
            sequenceEffectiveEntropy = reducedSequenceEntropy;
        } else {
            sequenceDisplayText = `${threatAnalysisData.components.sequence.entropy.toFixed(1)} bits`;
            sequenceEffectiveEntropy = threatAnalysisData.components.sequence.entropy;
        }
        
        sequenceDisplay.textContent = sequenceDisplayText;
        sequenceDisplay.className = sequenceEffectiveEntropy < 2 ? 'entropy-value compromised' : 'entropy-value';
    }
    
    // Update display
    const entropyElement = document.getElementById('remaining-entropy');
    const securityLevelElement = document.getElementById('remaining-security-level');
    const entropyDisplayElement = document.querySelector('.entropy-display');
    const complexityElement = document.getElementById('attack-complexity');
    const actionElement = document.getElementById('recommended-action');
    const timeElement = document.getElementById('time-to-break');
    
    if (entropyElement) entropyElement.textContent = totalEntropy.toFixed(1);
    
    // Determine security level
    let securityLevel, complexity, action, timeToBreak;
    
    // Calculate total entropy (remove debug log)
    
    if (totalEntropy >= 128) {
        securityLevel = 'EXCELLENT';
        complexity = `Computationally infeasible (2^${totalEntropy.toFixed(0)}+ operations)`;
        action = 'No action required - excellent security';
        timeToBreak = 'Universe lifetime + beyond current technology';
    } else if (totalEntropy >= 90) {
        securityLevel = 'STRONG';
        complexity = `Very high (2^${totalEntropy.toFixed(0)} operations)`;
        action = 'Continue normal operations - strong security';
        timeToBreak = 'Centuries with current technology';
    } else if (totalEntropy >= 65) {
        securityLevel = 'GOOD';
        complexity = `High (2^${totalEntropy.toFixed(0)} operations)`;
        action = 'Monitor for additional compromises';
        timeToBreak = 'Years to decades with dedicated resources';
    } else if (totalEntropy >= 40) {
        securityLevel = 'BASIC';
        complexity = `Medium (2^${totalEntropy.toFixed(0)} operations)`;
        action = 'Consider password rotation';
        timeToBreak = 'Months to years with specialized hardware';
    } else {
        securityLevel = 'INSUFFICIENT';
        complexity = `Low (2^${totalEntropy.toFixed(0)} operations)`;
        action = 'IMMEDIATE password change required';
        timeToBreak = 'Days to weeks with standard computing';
    }
    
    
    if (securityLevelElement) {
        securityLevelElement.textContent = securityLevel;
        securityLevelElement.classList.remove('excellent', 'strong', 'good', 'basic', 'insufficient');
        securityLevelElement.classList.add(securityLevel.toLowerCase());
    }
    
    // Update entropy-display border color
    if (entropyDisplayElement) {
        entropyDisplayElement.classList.remove('excellent', 'strong', 'good', 'basic', 'insufficient');
        entropyDisplayElement.classList.add(securityLevel.toLowerCase());
    }
    
    // Update entropy-number text color
    if (entropyElement) {
        entropyElement.classList.remove('excellent', 'strong', 'good', 'basic', 'insufficient');
        entropyElement.classList.add(securityLevel.toLowerCase());
    }
    
    if (complexityElement) complexityElement.textContent = complexity;
    if (actionElement) actionElement.textContent = action;
    if (timeElement) timeElement.textContent = timeToBreak;
}

function resetThreatAnalysis() {
    // Reset all checkboxes
    Object.keys(threatAnalysisData.components).forEach(componentId => {
        const checkbox = document.getElementById(`compromise-${componentId}`);
        if (checkbox) {
            checkbox.checked = false;
            threatAnalysisData.components[componentId].compromised = false;
        }
    });
    updateThreatAnalysis();
}

function setPreset(presetName) {
    resetThreatAnalysis(); // Start fresh
    
    switch (presetName) {
        case 'seed-only':
            document.getElementById('compromise-seed').checked = true;
            threatAnalysisData.components.seed.compromised = true;
            break;
        case 'card-stolen':
            // When card is stolen, the attacker can see:
            // 1. The entire token grid (card compromise)
            // 2. The card ID/date (label compromise)
            // 3. Coordinate selection becomes visible
            // Note: Seed is still secret unless separately compromised
            document.getElementById('compromise-card').checked = true;
            document.getElementById('compromise-label').checked = true;
            threatAnalysisData.components.card.compromised = true;
            threatAnalysisData.components.label.compromised = true;
            break;
        case 'memorized-only':
            document.getElementById('compromise-memorized').checked = true;
            threatAnalysisData.components.memorized.compromised = true;
            break;
        case 'worst-case':
            // Worst case: everything except the seed is compromised
            // (If seed was also compromised, there would be no security left)
            document.getElementById('compromise-card').checked = true;
            document.getElementById('compromise-label').checked = true;
            document.getElementById('compromise-memorized').checked = true;
            document.getElementById('compromise-patterns').checked = true;
            threatAnalysisData.components.card.compromised = true;
            threatAnalysisData.components.label.compromised = true;
            threatAnalysisData.components.memorized.compromised = true;
            threatAnalysisData.components.patterns.compromised = true;
            break;
    }
    updateThreatAnalysis();
}

// Initialize threat analysis when page loads
document.addEventListener('DOMContentLoaded', function() {
    
    // Initialize token entropy display
    updateTokenEntropyDisplay();
    
    // Add event listener for token count changes
    const tokenCountInput = document.getElementById('token-count');
    if (tokenCountInput) {
        tokenCountInput.addEventListener('input', function() {
            updateTokenEntropyDisplay();
            updateThreatAnalysis();
        });
        tokenCountInput.addEventListener('change', function() {
            updateTokenEntropyDisplay();
            updateThreatAnalysis();
        });
    }
    
    // Update entropy displays with calculated values
    const memorizedEntropy = calculateMemorizedEntropy();
    threatAnalysisData.components.memorized.entropy = memorizedEntropy;
    
    // Update seed entropy based on current selection
    threatAnalysisData.components.seed.entropy = getCurrentSeedEntropy();
    
    // Update display elements
    const memorizedDisplay = document.getElementById('memorized-entropy-display');
    if (memorizedDisplay) {
        memorizedDisplay.textContent = `${memorizedEntropy.toFixed(1)} bits`;
    }
    
    const seedDisplay = document.getElementById('seed-entropy-display');
    if (seedDisplay) {
        seedDisplay.textContent = `${getCurrentSeedEntropy().toFixed(1)} bits`;
    }
    
    const cardidDisplay = document.getElementById('cardid-entropy-display');
    if (cardidDisplay) {
        cardidDisplay.textContent = `${threatAnalysisData.components.cardid.entropy.toFixed(1)} bits`;
    }
    
    // Add event listeners to checkboxes
    Object.keys(threatAnalysisData.components).forEach(componentId => {
        const checkbox = document.getElementById(`compromise-${componentId}`);
        if (checkbox) {
            checkbox.addEventListener('change', function() {
                threatAnalysisData.components[componentId].compromised = this.checked;
                
                // Handle special logic for compromise dependencies
                if (componentId === 'card') {
                    const seedCheckbox = document.getElementById('compromise-seed');
                    const labelCheckbox = document.getElementById('compromise-label');
                    const cardidCheckbox = document.getElementById('compromise-cardid');
                    const tokensCheckbox = document.getElementById('compromise-tokens');
                    const sequenceCheckbox = document.getElementById('compromise-sequence');
                    
                    if (this.checked) {
                        // Card compromised: seed, label, and cardid become irrelevant (auto-select and disable)
                        if (seedCheckbox) {
                            seedCheckbox.checked = true;
                            seedCheckbox.disabled = true;
                            threatAnalysisData.components.seed.compromised = true;
                        }
                        if (labelCheckbox) {
                            labelCheckbox.checked = true;
                            labelCheckbox.disabled = true;
                            threatAnalysisData.components.label.compromised = true;
                        }
                        if (cardidCheckbox) {
                            cardidCheckbox.checked = true;
                            cardidCheckbox.disabled = true;
                            threatAnalysisData.components.cardid.compromised = true;
                        }
                    } else {
                        // Card not compromised: re-enable seed, label, and cardid selection
                        if (seedCheckbox) {
                            seedCheckbox.disabled = false;
                        }
                        if (labelCheckbox) {
                            labelCheckbox.disabled = false;
                        }
                        if (cardidCheckbox) {
                            cardidCheckbox.disabled = false;
                        }
                    }
                }
                
                // Handle seed+label+cardid dependency on tokens/sequence
                if (componentId === 'seed' || componentId === 'label' || componentId === 'cardid') {
                    const cardCheckbox = document.getElementById('compromise-card');
                    const seedCheckbox = document.getElementById('compromise-seed');
                    const labelCheckbox = document.getElementById('compromise-label');
                    const cardidCheckbox = document.getElementById('compromise-cardid');
                    const tokensCheckbox = document.getElementById('compromise-tokens');
                    const sequenceCheckbox = document.getElementById('compromise-sequence');
                    
                    // Only apply logic if card is not compromised
                    if (cardCheckbox && !cardCheckbox.checked) {
                        const isSeedCompromised = seedCheckbox && seedCheckbox.checked;
                        const isLabelCompromised = labelCheckbox && labelCheckbox.checked;
                        const isCardidCompromised = cardidCheckbox && cardidCheckbox.checked;
                        
                        if (isSeedCompromised || isLabelCompromised || isCardidCompromised) {
                            // One of seed/label/cardid compromised: tokens and sequence become relevant
                            if (tokensCheckbox) tokensCheckbox.disabled = false;
                            if (sequenceCheckbox) sequenceCheckbox.disabled = false;
                        } else {
                            // All seed, label, and cardid secure: tokens/sequence are derived (disable and uncheck)
                            if (tokensCheckbox) {
                                tokensCheckbox.checked = false;
                                tokensCheckbox.disabled = true;
                                threatAnalysisData.components.tokens.compromised = false;
                            }
                            if (sequenceCheckbox) {
                                sequenceCheckbox.checked = false;
                                sequenceCheckbox.disabled = true;
                                threatAnalysisData.components.sequence.compromised = false;
                            }
                        }
                    }
                }
                
                updateThreatAnalysis();
            });
        }
    });
    
    // Add event listeners to seed type changes
    const seedTypeRadios = document.querySelectorAll('input[name="seedType"]');
    seedTypeRadios.forEach(radio => {
        radio.addEventListener('change', function() {
            // Update seed entropy when seed type changes
            threatAnalysisData.components.seed.entropy = getCurrentSeedEntropy();
            const seedDisplay = document.getElementById('seed-entropy-display');
            if (seedDisplay) {
                seedDisplay.textContent = `${getCurrentSeedEntropy().toFixed(1)} bits`;
            }
            updateThreatAnalysis();
        });
    });
    
    // Add event listener to simple seed input for real-time entropy updates
    const simpleInput = document.getElementById('simple-seed');
    if (simpleInput) {
        simpleInput.addEventListener('input', function() {
            if (document.querySelector('input[name="seedType"]:checked')?.value === 'simple') {
                threatAnalysisData.components.seed.entropy = getCurrentSeedEntropy();
                const seedDisplay = document.getElementById('seed-entropy-display');
                if (seedDisplay) {
                    seedDisplay.textContent = `${getCurrentSeedEntropy().toFixed(1)} bits`;
                }
                updateThreatAnalysis();
            }
        });
    }
    
    // Initialize checkbox dependencies
    function initializeCheckboxDependencies() {
        const cardCheckbox = document.getElementById('compromise-card');
        const seedCheckbox = document.getElementById('compromise-seed');
        const labelCheckbox = document.getElementById('compromise-label');
        const cardidCheckbox = document.getElementById('compromise-cardid');
        const tokensCheckbox = document.getElementById('compromise-tokens');
        const sequenceCheckbox = document.getElementById('compromise-sequence');
        
        // Set initial state based on current checkbox values
        if (cardCheckbox && cardCheckbox.checked) {
            // Card compromised means seed, label, and cardid are automatically compromised
            if (seedCheckbox) {
                seedCheckbox.checked = true;
                seedCheckbox.disabled = true;
            }
            if (labelCheckbox) {
                labelCheckbox.checked = true;
                labelCheckbox.disabled = true;
            }
            if (cardidCheckbox) {
                cardidCheckbox.checked = true;
                cardidCheckbox.disabled = true;
            }
        } else {
            // Ensure seed, label, and cardid are enabled when card is not compromised
            if (seedCheckbox) seedCheckbox.disabled = false;
            if (labelCheckbox) labelCheckbox.disabled = false;
            if (cardidCheckbox) cardidCheckbox.disabled = false;
        }
        
        // If seed, label, or cardid compromised, ensure tokens and sequence are relevant
        const seedOrLabelOrCardidCompromised = (seedCheckbox && seedCheckbox.checked) || 
                                              (labelCheckbox && labelCheckbox.checked) ||
                                              (cardidCheckbox && cardidCheckbox.checked);
        
        if (tokensCheckbox) {
            tokensCheckbox.style.opacity = seedOrLabelOrCardidCompromised ? '1' : '0.6';
        }
        if (sequenceCheckbox) {
            sequenceCheckbox.style.opacity = seedOrLabelOrCardidCompromised ? '1' : '0.6';
        }
    }
    
    // Initialize dependencies and update display
    initializeCheckboxDependencies();
    updateThreatAnalysis();
});

// Card Compromise Modal Function
window.showCardCompromiseModal = function() {
    const modal = document.createElement('div');
    modal.className = 'modal show';
    modal.innerHTML = `
        <div class="modal-content card-compromise-modal">
            <div class="modal-header">
                <h3>🃏 Card Compromise Entropy Analysis</h3>
                <button class="modal-close">×</button>
            </div>
            <div class="modal-body">
                <p><strong>Physical card compromise</strong> reveals the complete 10×10 token grid but preserves the secrecy of memorized components and coordinate selection patterns.</p>
                
                <div class="entropy-calculation">
                    <h4>Detailed Entropy Breakdown:</h4>
                    
                    <div class="calc-step">
                        <div class="calc-label">🧠 Memorized Word Selection</div>
                        <div class="calc-formula">log₂(200) = 7.6 bits</div>
                        <div class="calc-explanation">Choice from ~200 common service words</div>
                    </div>
                    
                    <div class="calc-step">
                        <div class="calc-label">🔤 Mixed Capitalization Patterns</div>
                        <div class="calc-formula">log₂(8) = 3.0 bits</div>
                        <div class="calc-explanation">Multiple patterns: lowercase, Title, UPPER, miXeD, etc.</div>
                    </div>
                    
                    <div class="calc-step">
                        <div class="calc-label">🔢 PIN/Number Selection</div>
                        <div class="calc-formula">log₂(10000 × 0.3) = 11.9 bits</div>
                        <div class="calc-explanation">4-digit PIN reduced for human patterns</div>
                    </div>
                    
                    <div class="calc-step">
                        <div class="calc-label">🎯 Combination Pattern</div>
                        <div class="calc-formula">log₂(4) = 2.0 bits</div>
                        <div class="calc-explanation">How word and numbers are combined</div>
                    </div>
                    
                    <div class="calc-step">
                        <div class="calc-label">💡 Punctuation Choice</div>
                        <div class="calc-formula">log₂(8) = 3.0 bits</div>
                        <div class="calc-explanation">Selection from common punctuation marks</div>
                    </div>
                    
                    <div class="calc-step">
                        <div class="calc-label">📐 Coordinate Selection</div>
                        <div class="calc-formula">log₂(100) = 6.6 bits</div>
                        <div class="calc-explanation">Which grid positions to use (per coordinate)</div>
                    </div>
                    
                    <div class="calc-total">
                        <div class="calc-label"><strong>Total Remaining Security</strong></div>
                        <div class="calc-formula"><strong>7.6 + 3.0 + 11.9 + 2.0 + 3.0 + 6.6 = 34.1 bits</strong></div>
                        <div class="calc-explanation">Approximately 17.2 billion possible combinations</div>
                    </div>
                </div>
                
                <div class="attack-scenarios">
                    <h4>Attack Scenarios:</h4>
                    <ul>
                        <li><strong>Brute Force:</strong> ~17.2 billion attempts needed on average</li>
                        <li><strong>Social Engineering:</strong> Guessing memorized components reduces entropy significantly</li>
                        <li><strong>Pattern Analysis:</strong> Observing usage patterns over time</li>
                    </ul>
                </div>
                
                <div class="mitigation-strategies">
                    <h4>Mitigation Strategies:</h4>
                    <ul>
                        <li>Use longer coordinate patterns (3+ coordinates)</li>
                        <li>Choose less predictable memorized words</li>
                        <li>Add complexity with mixed capitalization and numbers</li>
                        <li>Store cards securely to prevent physical access</li>
                        <li>Consider multiple cards for different security levels</li>
                    </ul>
                </div>
            </div>
        </div>
    `;
    
    // Add click outside to close
    modal.addEventListener('click', (e) => {
        if (e.target === modal) {
            modal.remove();
            document.body.style.overflow = 'auto';
        }
    });
    
    // Close on Escape
    const closeOnEscape = (e) => {
        if (e.key === 'Escape') {
            modal.remove();
            document.body.style.overflow = 'auto';
            document.removeEventListener('keydown', closeOnEscape);
        }
    };
    document.addEventListener('keydown', closeOnEscape);
    
    document.body.appendChild(modal);
    
    // Ensure modal is visible
    modal.style.display = 'block';
    document.body.style.overflow = 'hidden';
    
    // Add close button click handler
    const closeButton = modal.querySelector('.modal-close');
    if (closeButton) {
        closeButton.addEventListener('click', () => {
            modal.remove();
            document.body.style.overflow = 'auto';
        });
    }
    
    // Add copy functionality to formulas
    addCopyFunctionality(modal);
};

window.hidePasswordEntropyModal = function() {
    if (window.app && window.app.hidePasswordEntropyModal) {
        window.app.hidePasswordEntropyModal();
    } else {
        console.error('App instance not available for hidePasswordEntropyModal');
    }
};

window.showPasswordEntropyForExample = function(exampleId) {
    const example = document.getElementById(exampleId);
    if (example && example.dataset.passwordData) {
        try {
            const passwordData = JSON.parse(example.dataset.passwordData);
            showPasswordEntropyModal(passwordData);
        } catch (error) {
            console.error('Error parsing password data for example:', exampleId, error);
        }
    } else {
    }
};

function generatePasswordEntropyHTML(passwordData) {
    const { pattern, coordinates, tokens, entropy, password, label } = passwordData;
    
    let html = '<div class="entropy-calculation-steps">';
    
    // Following the correct formula: H_seed + H_label + H_card + coordinates * (H_coordinate + H_token) + H_memorized + H_punctuation + H_order
    
    // 1. H_seed: Get actual seed entropy from current input
    const app = window.app;
    const seedBits = app ? app.calculateActualSeedEntropy() : 128; // Fallback to 128 if app not available
    const seedType = document.querySelector('input[name="seedType"]:checked')?.value || 'unknown';
    
    html += `
        <div class="calc-step">
            <div class="calc-label">🌱 Seed Entropy (H_seed):</div>
            <div class="calc-value">Current seed type: ${seedType.toUpperCase()}</div>
            <div class="calc-formula">H_seed = ${seedBits.toFixed(1)} bits</div>
        </div>
    `;
    
    // 2. H_label: Label components (card ID + date)
    const labelBits = app ? app.calculateCurrentLabelEntropy() : 20; // Use actual calculation
    html += `
        <div class="calc-step">
            <div class="calc-label">🏷️ Label Entropy (H_label):</div>
            <div class="calc-value">Card ID and date combination from current inputs</div>
            <div class="calc-formula">H_label = ${labelBits.toFixed(1)} bits</div>
        </div>
    `;
    
    // 3. H_card: Card selection entropy
    const cardBits = 6.64;
    html += `
        <div class="calc-step">
            <div class="calc-label">🗂️ Card Selection (H_card):</div>
            <div class="calc-value">Matrix ID determines which of 100 possible cards (A0-J9)</div>
            <div class="calc-formula">H_card = log₂(100) = ${cardBits.toFixed(2)} bits</div>
        </div>
    `;
    
    // 4. Per-coordinate breakdown first
    const coordinateBits = 6.64; // log₂(100) for position selection
    const tokenBits = 25.9; // log₂(90⁴) for token value
    const effectiveTokenBits = Math.min(tokenBits, seedBits / 4); // Token entropy limited by seed quality
    
    html += `
        <div class="calc-step">
            <div class="calc-label">📍 Per-Coordinate Selection:</div>
            <div class="calc-value">Choosing position from 10×10 grid</div>
            <div class="calc-formula">H_coordinate = log₂(100) = ${coordinateBits.toFixed(2)} bits each</div>
        </div>
    `;
    
    html += `
        <div class="calc-step">
            <div class="calc-label">🎯 Per-Token Value:</div>
            <div class="calc-value">4-character Base90 token (limited by seed quality)</div>
            <div class="calc-formula">H_token = min(log₂(90⁴), seed_quality) = ${effectiveTokenBits.toFixed(1)} bits each</div>
        </div>
    `;
    
    // 5. Combined coordinate calculation
    const coordCount = coordinates.length;
    const perCoordBits = coordinateBits + effectiveTokenBits;
    const totalCoordBits = coordCount * perCoordBits;
    
    html += `
        <div class="calc-step">
            <div class="calc-label">📊 Combined Coordinate Entropy:</div>
            <div class="calc-value">${coordCount} coordinates: ${coordinates.join(', ')}</div>
            <div class="calc-formula">coordinates × (H_coordinate + H_token) = ${coordCount} × ${perCoordBits.toFixed(1)} = ${totalCoordBits.toFixed(1)} bits</div>
        </div>
    `;
    
    // 6. Memorized components - analyze user-added components (not token content)
    // Look for patterns that suggest user-added numbers/PIN separate from tokens
    const tokenPatterns = coordinates.map(coord => {
        // Extract token patterns like tJt3, r7q[, etc.
        const tokenPattern = /[a-zA-Z0-9!@#$%^&*()_+\-=\[\]{};':"\\|,.<>?\/`~]{4}/g;
        return tokenPattern;
    });
    
    // Remove all known token-like patterns to identify user-added content
    let userContent = password;
    // Remove the actual tokens that we know are from the grid
    tokens.forEach(token => {
        userContent = userContent.replace(token, '');
    });
    
    // Now check for user-added numbers in remaining content
    const hasUserNumbers = /\d/.test(userContent);
    const userNumberMatches = userContent.match(/\d/g);
    const userNumberCount = userNumberMatches ? userNumberMatches.length : 0;
    const digitEntropy = 3.32; // log₂(10)
    
    // Extract memorized word (non-token, non-number content)
    const memorizedWord = userContent.replace(/\d+/g, '').replace(/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>?\/`~]/g, '').trim();
    const wordLength = memorizedWord.length;
    const wordEntropy = wordLength > 0 ? Math.log2(Math.pow(26, Math.min(wordLength, 8))) : 0; // Cap word entropy at 8 chars
    
    const userNumberBits = userNumberCount * digitEntropy;
    const totalMemorizedBits = wordEntropy + userNumberBits;
    
    html += `
        <div class="calc-step">
            <div class="calc-label">🧠 Memorized Component (H_memorized):</div>
            <div class="calc-breakdown">
                ${memorizedWord.length > 0 ? `
                <div class="calc-sub-step">
                    <div class="calc-sub-label">• Memorized Word/Phrase:</div>
                    <div class="calc-sub-formula">log₂(26^${Math.min(wordLength, 8)}) ≈ ${wordEntropy.toFixed(1)} bits</div>
                    <div class="calc-sub-desc">"${memorizedWord}" - ${wordLength} characters from alphabet</div>
                </div>
                ` : ''}
                ${hasUserNumbers ? `
                <div class="calc-sub-step">
                    <div class="calc-sub-label">• User-Added Numbers/PIN:</div>
                    <div class="calc-sub-formula">${userNumberCount} × log₂(10) = ${userNumberCount} × ${digitEntropy.toFixed(1)} = ${userNumberBits.toFixed(1)} bits</div>
                    <div class="calc-sub-desc">${userNumberCount} user-chosen digits (not from tokens)</div>
                </div>
                ` : ''}
            </div>
            <div class="calc-value">Total memorized component: ${wordEntropy > 0 && hasUserNumbers ? `${wordEntropy.toFixed(1)} + ${userNumberBits.toFixed(1)}` : wordEntropy > 0 ? wordEntropy.toFixed(1) : hasUserNumbers ? userNumberBits.toFixed(1) : '0'} = ${totalMemorizedBits.toFixed(1)} bits</div>
        </div>
        <div class="calc-formula">H_memorized = ${totalMemorizedBits.toFixed(1)} bits</div>
    `;
    
    // 7. H_punctuation: Punctuation entropy
    const punctBits = 5.0;
    html += `
        <div class="calc-step">
            <div class="calc-label">💥 Punctuation (H_punctuation):</div>
            <div class="calc-value">Punctuation marks and special characters</div>
            <div class="calc-formula">H_punctuation ≈ ${punctBits.toFixed(1)} bits</div>
        </div>
    `;
    
    // 8. H_order: Ordering entropy
    const orderBits = 2.6;
    html += `
        <div class="calc-step">
            <div class="calc-label">🔄 Component Ordering (H_order):</div>
            <div class="calc-value">Arrangement pattern of tokens, words, punctuation</div>
            <div class="calc-formula">H_order ≈ ${orderBits.toFixed(1)} bits</div>
        </div>
    `;
    
    // Total entropy using your formula
    const totalBits = seedBits + labelBits + cardBits + totalCoordBits + totalMemorizedBits + punctBits + orderBits;
    html += `
        <div class="calc-step calc-total">
            <div class="calc-label">🎯 Total Security:</div>
            <div class="calc-value">H_seed + H_label + H_card + coordinates×(H_coordinate + H_token) + H_memorized + H_punctuation + H_order</div>
            <div class="calc-formula">H_total = ${totalBits.toFixed(1)} bits</div>
        </div>
    `;
    
    // Seed compromised scenario
    const seedCompromisedBits = labelBits + cardBits + (coordCount * coordinateBits) + totalMemorizedBits + punctBits + orderBits;
    html += `
        <div class="calc-step calc-warning">
            <div class="calc-label">⚠️ If Seed Compromised:</div>
            <div class="calc-value">Only coordinate selection, memorized, punctuation, and order remain secret</div>
            <div class="calc-formula">H_remaining = ${seedCompromisedBits.toFixed(1)} bits</div>
        </div>
    `;
    
    // Label compromised scenario  
    const labelCompromisedBits = seedBits + cardBits + (coordCount * coordinateBits) + totalMemorizedBits + punctBits + orderBits;
    html += `
        <div class="calc-step calc-warning">
            <div class="calc-label">🔓 If Label Compromised:</div>
            <div class="calc-value">Attacker knows card ID and date, but seed and user choices remain secret</div>
            <div class="calc-breakdown">
                <div class="calc-sub-step">
                    <div class="calc-sub-desc">• Seed entropy: ${seedBits.toFixed(1)} bits (still secret)</div>
                    <div class="calc-sub-desc">• Coordinate selection: ${(coordCount * coordinateBits).toFixed(1)} bits (user choice)</div>
                    <div class="calc-sub-desc">• Memorized components: ${totalMemorizedBits.toFixed(1)} bits (user secret)</div>
                    <div class="calc-sub-desc">• Punctuation & order: ${(punctBits + orderBits).toFixed(1)} bits (user choice)</div>
                </div>
            </div>
            <div class="calc-formula">H_remaining = ${labelCompromisedBits.toFixed(1)} bits</div>
        </div>
    `;
    
    // Security classification
    const securityLevel = totalBits >= 80 ? 'EXCELLENT' : totalBits >= 60 ? 'STRONG' : totalBits >= 40 ? 'GOOD' : 'BASIC';
    const securityClass = securityLevel.toLowerCase();
    html += `
        <div class="calc-step calc-security">
            <div class="calc-label">🛡️ Security Classification:</div>
            <div class="calc-value security-${securityClass}">${securityLevel}</div>
            <div class="calc-formula">Based on total entropy and threat model</div>
        </div>
    `;
    
    html += '</div>';
    return html;
}
