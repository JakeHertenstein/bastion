/**
 * Generator Page Specific JavaScript
 * Extends the main app functionality for the generator page
 */

// Generator page initialization
document.addEventListener('DOMContentLoaded', () => {
    
    // Wait for the main app to be initialized first
    const waitForApp = () => {
        if (window.app) {
            // Add generator-specific functionality
            initializeGeneratorFeatures();
        } else {
            setTimeout(waitForApp, 50);
        }
    };
    
    waitForApp();
});

function initializeGeneratorFeatures() {
    
    // Auto-focus on first input
    const firstInput = document.getElementById('card-id');
    if (firstInput) {
        firstInput.focus();
    }
    
    // Add input validation
    addInputValidation();
    
    // Initialize tooltips
    initializeTooltips();
    
    // Add sample data buttons
    addSampleDataButtons();
    
    // Output mode descriptions
    const genModeInputs = document.querySelectorAll('input[name="genMode"]');
    genModeInputs.forEach(input => {
        input.addEventListener('change', updateOutputDescription);
    });
    
    function updateOutputDescription() {
        const selectedModeElement = document.querySelector('input[name="genMode"]:checked');
        if (!selectedModeElement) {
            // No mode selected yet, this can happen during initialization
            return;
        }
        
        const selectedMode = selectedModeElement.value;
        
        // Hide all descriptions
        document.querySelectorAll('.desc-content').forEach(desc => {
            desc.style.display = 'none';
        });
        
        // Show selected description
        const selectedDesc = document.getElementById(`desc-${selectedMode}`);
        if (selectedDesc) {
            selectedDesc.style.display = 'block';
        }
    }
    
    // Initialize output description
    updateOutputDescription();
    
    // Seed type switching
    const seedTypeInputs = document.querySelectorAll('input[name="seedType"]');
    seedTypeInputs.forEach(input => {
        input.addEventListener('change', switchSeedInput);
    });
    
    function switchSeedInput() {
        const selectedType = document.querySelector('input[name="seedType"]:checked').value;
        
        // Hide all seed inputs
        document.querySelectorAll('.seed-input').forEach(input => {
            input.classList.remove('active');
        });
        
        // Show selected seed input
        const selectedInput = document.getElementById(`${selectedType}-input`);
        if (selectedInput) {
            selectedInput.classList.add('active');
        }
        
        // Focus on the new input
        setTimeout(() => {
            let focusElement;
            if (selectedType === 'simple') {
                focusElement = document.getElementById('simple-phrase');
            } else if (selectedType === 'bip39') {
                focusElement = document.getElementById('bip39-mnemonic');
            } else if (selectedType === 'slip39') {
                focusElement = document.querySelector('.slip39-share');
            }
            
            if (focusElement) {
                focusElement.focus();
            }
        }, 100);
    }
    
    // Enhanced keyboard shortcuts
    document.addEventListener('keydown', (event) => {
        // Ctrl/Cmd + Enter to generate (now triggers through the app instance)
        if ((event.ctrlKey || event.metaKey) && event.key === 'Enter') {
            event.preventDefault();
            if (window.app && typeof window.app.handleGenerate === 'function') {
                window.app.handleGenerate(false); // Manual generation
            }
        }
        
        // Escape to clear error messages
        if (event.key === 'Escape') {
            const errorMessage = document.querySelector('.error-message');
            if (errorMessage && errorMessage.parentNode) {
                errorMessage.parentNode.removeChild(errorMessage);
            }
        }
    });
    
    // Real-time validation feedback
    function enableRealTimeValidation() {
        // Card ID validation
        const cardIdInput = document.getElementById('card-id');
        if (cardIdInput) {
            cardIdInput.addEventListener('input', (e) => {
                const value = e.target.value.trim();
                e.target.classList.remove('valid', 'invalid');
                
                if (value.length > 0) {
                    e.target.classList.add('valid');
                    showValidationMessage(e.target, '✓ Valid card ID', 'success');
                } else {
                    clearValidationMessage(e.target);
                }
            });
        }
        
        // Simple phrase validation
        const simplePhraseInput = document.getElementById('simple-phrase');
        if (simplePhraseInput) {
            simplePhraseInput.addEventListener('input', (e) => {
                const value = e.target.value.trim();
                e.target.classList.remove('valid', 'invalid');
                
                if (value.length > 0) {
                    e.target.classList.add('valid');
                    showValidationMessage(e.target, '✓ Valid seed phrase', 'success');
                } else {
                    clearValidationMessage(e.target);
                }
            });
        }
        
        // BIP-39 validation
        const bip39Input = document.getElementById('bip39-mnemonic');
        if (bip39Input) {
            bip39Input.addEventListener('input', validateBip39Mnemonic);
        }
        
        // SLIP-39 validation
        const slip39Inputs = document.querySelectorAll('.slip39-share');
        slip39Inputs.forEach(input => {
            input.addEventListener('input', validateSlip39Shares);
        });
    }
    
    function validateSlip39Shares() {
        const shares = Array.from(document.querySelectorAll('.slip39-share'))
            .map(textarea => textarea.value.trim())
            .filter(share => share.length > 0);
        
        const firstInput = document.querySelector('.slip39-share');
        if (firstInput) {
            firstInput.classList.remove('valid', 'invalid');
            
            if (shares.length >= 2) {
                firstInput.classList.add('valid');
                showValidationMessage(firstInput, `✓ ${shares.length} shares entered`, 'success');
            } else if (shares.length === 1) {
                showValidationMessage(firstInput, `⚠ Need at least 2 shares (have ${shares.length})`, 'warning');
            } else {
                clearValidationMessage(firstInput);
            }
        }
    }
    
    function clearValidationMessage(element) {
        const existingMessage = element.parentNode.querySelector('.validation-message');
        if (existingMessage) {
            existingMessage.remove();
        }
    }
    
    // Enable real-time validation
    enableRealTimeValidation();
    
    // Form submission validation
    function validateEntireForm() {
        let isValid = true;
        const errors = [];
        
        // Validate card ID
        const cardId = document.getElementById('card-id').value.trim();
        if (!cardId) {
            errors.push('Please enter a card ID');
            isValid = false;
        }
        
        // Validate seed based on type
        const seedType = document.querySelector('input[name="seedType"]:checked').value;
        
        if (seedType === 'simple') {
            const phrase = document.getElementById('simple-phrase').value.trim();
            if (!phrase) {
                errors.push('Please enter a seed phrase');
                isValid = false;
            }
        } else if (seedType === 'bip39') {
            const mnemonic = document.getElementById('bip39-mnemonic').value.trim();
            if (!mnemonic) {
                errors.push('Please enter a BIP-39 mnemonic');
                isValid = false;
            }
        } else if (seedType === 'slip39') {
            const shares = Array.from(document.querySelectorAll('.slip39-share'))
                .map(textarea => textarea.value.trim())
                .filter(share => share.length > 0);
            
            if (shares.length < 2) {
                errors.push('Please enter at least 2 SLIP-39 shares');
                isValid = false;
            }
        }
        
        // Display errors if any
        if (!isValid) {
            const errorMessage = errors.join('\n');
            alert(errorMessage); // Simple alert for now, could be improved with better UI
        }
        
        return isValid;
    }
}



function addInputValidation() {
    // BIP-39 mnemonic validation
    const bip39Input = document.getElementById('bip39-mnemonic');
    if (bip39Input) {
        bip39Input.addEventListener('input', validateBip39Mnemonic);
    }
    
    // Card ID validation
    const cardIdInput = document.getElementById('card-id');
    if (cardIdInput) {
        cardIdInput.addEventListener('input', validateCardId);
    }
    
    // PBKDF2 iterations validation
    const iterationsInput = document.getElementById('bip39-iterations');
    if (iterationsInput) {
        iterationsInput.addEventListener('input', validateIterations);
    }
}

function validateBip39Mnemonic(event) {
    const input = event.target;
    const value = input.value.trim();
    const words = value.split(/\s+/).filter(word => word.length > 0);
    
    // Clear previous validation
    input.classList.remove('valid', 'invalid');
    
    if (value.length === 0) {
        return; // Empty is okay
    }
    
    // Check word count
    const validCounts = [12, 15, 18, 21, 24];
    if (validCounts.includes(words.length)) {
        input.classList.add('valid');
        showValidationMessage(input, `✓ ${words.length} words detected`, 'success');
    } else {
        input.classList.add('invalid');
        showValidationMessage(input, `⚠ Expected 12, 15, 18, 21, or 24 words, found ${words.length}`, 'warning');
    }
}

function validateCardId(event) {
    const input = event.target;
    const value = input.value.trim();
    
    // Remove validation classes
    input.classList.remove('valid', 'invalid');
    
    if (value.length === 0) {
        return; // Empty is okay
    }
    
    // Accept any non-empty string as valid card ID
    if (value.length > 0) {
        input.classList.add('valid');
        showValidationMessage(input, '✓ Valid card ID', 'success');
    }
}

function validateIterations(event) {
    const input = event.target;
    const value = parseInt(input.value);
    
    input.classList.remove('valid', 'invalid');
    
    if (isNaN(value) || value < 1000) {
        input.classList.add('invalid');
        showValidationMessage(input, '⚠ Minimum 1000 iterations recommended', 'warning');
    } else if (value > 100000) {
        input.classList.add('invalid');
        showValidationMessage(input, '⚠ Very high iteration count may be slow', 'warning');
    } else {
        input.classList.add('valid');
        showValidationMessage(input, '✓ Good iteration count', 'success');
    }
}

function showValidationMessage(input, message, type) {
    // Remove existing validation message
    const existingMsg = input.parentNode.querySelector('.validation-message');
    if (existingMsg) {
        existingMsg.remove();
    }
    
    // Create new validation message
    const msgDiv = document.createElement('div');
    msgDiv.className = `validation-message ${type}`;
    msgDiv.style.cssText = `
        font-size: 0.875rem;
        margin-top: 0.25rem;
        padding: 0.25rem 0.5rem;
        border-radius: 4px;
        ${type === 'success' ? 'color: #059669; background: #d1fae5;' : 'color: #d97706; background: #fef3cd;'}
    `;
    msgDiv.textContent = message;
    
    input.parentNode.appendChild(msgDiv);
    
    // Auto-remove after 5 seconds
    setTimeout(() => {
        if (msgDiv.parentNode) {
            msgDiv.parentNode.removeChild(msgDiv);
        }
    }, 5000);
}

function initializeTooltips() {
    // Add tooltips to help icons
    const helpIcons = document.querySelectorAll('.input-help i');
    helpIcons.forEach(icon => {
        icon.title = icon.parentNode.textContent.trim();
    });
}

function addSampleDataButtons() {
    // Add sample data button for BIP-39
    const bip39Input = document.getElementById('bip39-mnemonic');
    if (bip39Input) {
        const sampleBtn = createSampleButton('Load Sample', () => {
            bip39Input.value = 'word1 word2 word3 word4 word5 word6 word7 word8 word9 word10 word11 word12';
            bip39Input.dispatchEvent(new Event('input'));
        });
        bip39Input.parentNode.appendChild(sampleBtn);
    }
    
    // Add sample data button for Card ID
    const cardIdInput = document.getElementById('card-id');
    if (cardIdInput) {
        const sampleBtn = createSampleButton('Example', () => {
            const examples = ['SYS.01.02', 'WEB.03.15', 'FIN.01.07', 'SOC.02.11'];
            const randomExample = examples[Math.floor(Math.random() * examples.length)];
            cardIdInput.value = randomExample;
            cardIdInput.dispatchEvent(new Event('input'));
        });
        cardIdInput.parentNode.appendChild(sampleBtn);
    }
    
    // Add sample SLIP-39 shares
    const slip39Container = document.querySelector('.slip39-shares');
    if (slip39Container) {
        const sampleBtn = createSampleButton('Load Sample Shares', () => {
            const sampleShares = [
                'academic acid academic academic academic academic academic academic academic academic academic academic academic abandon tactics',
                'academic acid academic academic academic academic academic academic academic academic academic academic academic dwarf oven',
                'academic acid academic academic academic academic academic academic academic academic academic academic academic maiden briefing'
            ];
            
            const shareInputs = slip39Container.querySelectorAll('.slip39-share');
            shareInputs.forEach((input, index) => {
                if (index < sampleShares.length) {
                    input.value = sampleShares[index];
                }
            });
        });
        slip39Container.parentNode.appendChild(sampleBtn);
    }
}

function createSampleButton(text, onClick) {
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'btn btn-secondary btn-sm';
    btn.style.cssText = 'margin-top: 0.5rem; font-size: 0.75rem;';
    btn.innerHTML = `<i class="fas fa-flask"></i> ${text}`;
    btn.onclick = onClick;
    return btn;
}

// Add advanced features
function addAdvancedFeatures() {
    // Add entropy visualization
    addEntropyVisualization();
    
    // Add pattern strength analyzer
    // addPatternAnalyzer(); // Temporarily disabled - function not implemented yet
    
    // Add bulk generation tools
    // addBulkGenerationTools(); // Temporarily disabled - function not implemented yet
}

function addEntropyVisualization() {
    // Create entropy meter for different seed types
    const seedInputs = document.querySelectorAll('.seed-input input, .seed-input textarea');
    
    seedInputs.forEach(input => {
        input.addEventListener('input', (event) => {
            const entropy = calculateInputEntropy(event.target.value);
            updateEntropyMeter(event.target, entropy);
        });
    });
}

function calculateInputEntropy(input) {
    if (!input || input.length === 0) return 0;
    
    // Simple entropy calculation
    const chars = new Set(input);
    const uniqueChars = chars.size;
    const length = input.length;
    
    // Shannon entropy approximation
    return Math.log2(uniqueChars) * length;
}

function updateEntropyMeter(input, entropy) {
    let meter = input.parentNode.querySelector('.entropy-meter');
    
    if (!meter) {
        meter = document.createElement('div');
        meter.className = 'entropy-meter';
        meter.style.cssText = `
            margin-top: 0.25rem;
            height: 4px;
            background: #e5e7eb;
            border-radius: 2px;
            overflow: hidden;
        `;
        
        const fill = document.createElement('div');
        fill.className = 'entropy-fill';
        fill.style.cssText = `
            height: 100%;
            transition: all 0.3s;
            border-radius: 2px;
        `;
        
        meter.appendChild(fill);
        input.parentNode.appendChild(meter);
    }
    
    const fill = meter.querySelector('.entropy-fill');
    const maxEntropy = 200; // Reasonable maximum for visualization
    const percentage = Math.min((entropy / maxEntropy) * 100, 100);
    
    fill.style.width = `${percentage}%`;
    
    if (percentage < 30) {
        fill.style.background = '#ef4444'; // Red
    } else if (percentage < 70) {
        fill.style.background = '#f59e0b'; // Yellow
    } else {
        fill.style.background = '#10b981'; // Green
    }
}

// Initialize advanced features when page loads
document.addEventListener('DOMContentLoaded', () => {
    setTimeout(addAdvancedFeatures, 1000); // Delay to allow main app to initialize
});

// Add CSS for input validation
const validationStyles = `
    .seed-input input.valid,
    .seed-input textarea.valid {
        border-color: #10b981;
        box-shadow: 0 0 0 3px rgba(16, 185, 129, 0.1);
    }
    
    .seed-input input.invalid,
    .seed-input textarea.invalid {
        border-color: #ef4444;
        box-shadow: 0 0 0 3px rgba(239, 68, 68, 0.1);
    }
    
    .validation-message {
        display: flex;
        align-items: center;
        gap: 0.25rem;
        font-weight: 500;
    }
    
    .entropy-meter {
        position: relative;
    }
    
    .entropy-meter::after {
        content: attr(data-entropy);
        position: absolute;
        right: 0;
        top: -20px;
        font-size: 0.75rem;
        color: #6b7280;
    }
`;

const validationStyleSheet = document.createElement('style');
validationStyleSheet.textContent = validationStyles;
document.head.appendChild(validationStyleSheet);
