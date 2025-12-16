/**
 * SPA Initialization Module
 * 
 * Handles KDF selection, nonce generation, label preview updates,
 * and demo functionality for the Seed Card web application.
 */

// SPA-specific initialization after all scripts load
document.addEventListener('DOMContentLoaded', function() {
    // Handle KDF selection toggle for Argon2 options visibility
    function updateKdfOptions() {
        const kdfRadios = document.querySelectorAll('input[name="kdfType"]');
        const argon2Options = document.getElementById('argon2-options');
        
        if (argon2Options) {
            const selectedKdf = document.querySelector('input[name="kdfType"]:checked')?.value || 'argon2';
            if (selectedKdf === 'argon2') {
                argon2Options.style.display = 'block';
            } else {
                argon2Options.style.display = 'none';
            }
        }
        
        // Update label when KDF changes
        updateDomainNextButton();
    }
    
    // Generate random nonce button handler
    function generateNonce() {
        const nonceInput = document.getElementById('card-nonce');
        if (nonceInput && window.LabelUtils) {
            nonceInput.value = window.LabelUtils.generateNonce();
            updateDomainNextButton();
            // Dispatch input event to trigger auto-regeneration
            nonceInput.dispatchEvent(new Event('input', { bubbles: true }));
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
            updateDomainNextButton();
            // Dispatch input event to trigger auto-regeneration
            nonceInput.dispatchEvent(new Event('input', { bubbles: true }));
        }
    }
    
    // Set up KDF radio button listeners
    const kdfRadios = document.querySelectorAll('input[name="kdfType"]');
    kdfRadios.forEach(radio => {
        radio.addEventListener('change', updateKdfOptions);
    });
    
    // Set up generate nonce button
    const generateNonceBtn = document.getElementById('generate-nonce-btn');
    if (generateNonceBtn) {
        generateNonceBtn.addEventListener('click', generateNonce);
    }
    
    // Set up argon2 selector listeners
    const argon2MemorySelect = document.getElementById('argon2-memory');
    if (argon2MemorySelect) {
        argon2MemorySelect.addEventListener('change', updateDomainNextButton);
    }
    
    const argon2TimeSelect = document.getElementById('argon2-time');
    if (argon2TimeSelect) {
        argon2TimeSelect.addEventListener('change', updateDomainNextButton);
    }
    
    const argon2ParallelismSelect = document.getElementById('argon2-parallelism');
    if (argon2ParallelismSelect) {
        argon2ParallelismSelect.addEventListener('change', updateDomainNextButton);
    }
    
    // Set up nonce input listener
    const nonceInput = document.getElementById('card-nonce');
    if (nonceInput) {
        nonceInput.addEventListener('input', updateDomainNextButton);
    }
    
    // Handle card ID validation for next button and update label display
    function updateDomainNextButton() {
        const cardIdInput = document.getElementById('card-id');
        const cardDateInput = document.getElementById('card-date');
        const nextBtn = document.getElementById('domain-next-btn');
        const labelOutput = document.getElementById('label-output');
        
        if (cardIdInput && nextBtn) {
            const value = cardIdInput.value.trim();
            // More lenient validation: just require non-empty and reasonable length
            const isValid = value.length >= 1 && value.length <= 50 && /^[a-zA-Z0-9][a-zA-Z0-9.\-_]*$/.test(value);
            
            if (isValid) {
                nextBtn.disabled = false;
                nextBtn.classList.remove('domain-next-btn-disabled');
                nextBtn.classList.add('domain-next-btn-enabled');
            } else {
                nextBtn.disabled = true;
                nextBtn.classList.add('domain-next-btn-disabled');
                nextBtn.classList.remove('domain-next-btn-enabled');
            }
        }
        
        // Update label output with full v1 format
        if (labelOutput && cardIdInput) {
            const cardId = cardIdInput.value.trim() || 'CARD';
            const cardDate = cardDateInput?.value.trim() || new Date().toISOString().split('T')[0];
            
            // Determine seed type from selected radio button
            const selectedSeedType = document.querySelector('input[name="seedType"]:checked')?.value || 'simple';
            const seedTypeMap = {
                'simple': 'SIMPLE',
                'bip39': 'BIP-39',
                'slip39': 'SLIP-39'
            };
            const seedType = seedTypeMap[selectedSeedType] || 'SIMPLE';
            
            // Determine KDF type - always Argon2id
            const kdfType = 'ARGON2ID';
            
            // Get Argon2 parameters
            const timeCost = document.getElementById('argon2-time')?.value || '3';
            const memoryMb = document.getElementById('argon2-memory')?.value || '64';
            const parallelism = document.getElementById('argon2-parallelism')?.value || '8';
            const kdfParams = `t${timeCost}m${memoryMb}p${parallelism}`;
            
            // Get base format from selection (default to BASE90)
            const selectedBase = document.querySelector('input[name="baseSystem"]:checked')?.value || 'base90';
            const baseFormat = selectedBase.toUpperCase();
            
            // Get nonce (will be auto-generated if empty)
            let nonce = document.getElementById('card-nonce')?.value.trim() || '';
            if (!nonce) {
                nonce = 'xxxxxxxx';  // Placeholder to show nonce will be generated
            }
            
            // Build v1 Bastion label: v1:TOKEN:ALGO:PARAMS:IDENT:DATE|CHECK
            // Use LabelUtils.buildLabel if available, otherwise show placeholder
            let label;
            if (typeof LabelUtils !== 'undefined' && LabelUtils.buildLabel) {
                label = LabelUtils.buildLabel(seedType, kdfType, kdfParams, baseFormat, cardDate, nonce, cardId, 'A0');
            } else {
                // Fallback placeholder format
                const algo = `${seedType}-${kdfType}`;
                const params = `t${timeCost}-m${memoryMb}-p${parallelism}-N.${nonce}-${baseFormat}`;
                const ident = `${cardId.toLowerCase()}.A0`;
                label = `v1:TOKEN:${algo}:${params}:${ident}:${cardDate}|?`;
            }
            
            labelOutput.innerHTML = `<code>${SecurityUtils ? SecurityUtils.sanitizeHTML(label) : label}</code>`;
        }
    }
    
    // Set up card ID and date input listeners
    const cardIdInput = document.getElementById('card-id');
    const cardDateInput = document.getElementById('card-date');
    if (cardIdInput) {
        cardIdInput.addEventListener('input', updateDomainNextButton);
        // Run initial check
        setTimeout(updateDomainNextButton, 100); // Small delay to ensure DOM is ready
    }
    if (cardDateInput) {
        cardDateInput.addEventListener('input', updateDomainNextButton);
        // Set default date to today if empty
        if (!cardDateInput.value.trim()) {
            cardDateInput.value = new Date().toISOString().split('T')[0];
        }
    }
    
    // Set up seed type radio button listeners
    const seedTypeRadios = document.querySelectorAll('input[name="seedType"]');
    seedTypeRadios.forEach(radio => {
        radio.addEventListener('change', updateDomainNextButton);
    });
    
    // Set up base system radio button listeners
    const baseSystemRadios = document.querySelectorAll('input[name="baseSystem"]');
    baseSystemRadios.forEach(radio => {
        radio.addEventListener('change', updateDomainNextButton);
    });
    
    // Initialize KDF options visibility
    setTimeout(updateKdfOptions, 100);
    
    // Auto-generate nonce on page load if empty
    // Wait for crypto.js to be loaded (LabelUtils should be available)
    function tryGenerateNonce() {
        const nonceInput = document.getElementById('card-nonce');
        if (nonceInput && !nonceInput.value.trim()) {
            generateNonce();
            // Verify it worked
            if (nonceInput.value.trim()) {
                console.log('Nonce auto-generated:', nonceInput.value);
                return true;
            }
        }
        return false;
    }
    
    // Try immediately, then retry with increasing delays if needed
    if (!tryGenerateNonce()) {
        setTimeout(() => {
            if (!tryGenerateNonce()) {
                setTimeout(() => {
                    if (!tryGenerateNonce()) {
                        console.warn('Failed to auto-generate nonce after retries');
                    }
                }, 500);
            }
        }, 200);
    }
    
    // Demo functionality
    const demoGenerateBtn = document.getElementById('demo-generate');
    const demoSeedInput = document.getElementById('demo-seed');
    const demoMatrixOutput = document.getElementById('demo-matrix');
    
    if (demoGenerateBtn && demoSeedInput && demoMatrixOutput) {
        demoGenerateBtn.addEventListener('click', function() {
            const seedValue = demoSeedInput.value.trim();
            if (seedValue && window.SeedCard && window.SeedCard.generateGrid) {
                try {
                    const grid = window.SeedCard.generateGrid(seedValue);
                    const escapedSeed = SecurityUtils ? SecurityUtils.sanitizeHTML(seedValue) : seedValue;
                    demoMatrixOutput.innerHTML = '<div class="demo-matrix-preview">' +
                        '<div class="demo-note">Sample 5x5 preview from "' + escapedSeed + '":</div>' +
                        '<div class="matrix-sample">' +
                        '<div class="matrix-header">' +
                        '<span>A</span><span>B</span><span>C</span><span>D</span><span>E</span>' +
                        '</div>' +
                        grid.slice(0, 5).map((row, i) => 
                            '<div class="matrix-row">' +
                            '<span class="coord">' + i + '</span>' +
                            row.slice(0, 5).map(token => '<span class="token">' + (SecurityUtils ? SecurityUtils.sanitizeHTML(token) : token) + '</span>').join('') +
                            '</div>'
                        ).join('') +
                        '</div></div>';
                } catch (error) {
                    demoMatrixOutput.innerHTML = '<div class="demo-error">Demo not available - core libraries loading</div>';
                }
            } else {
                demoMatrixOutput.innerHTML = '<div class="demo-placeholder">Enter a seed phrase above and click Generate Sample</div>';
            }
        });
    }
});
