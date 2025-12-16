/**
 * Seed Validation Module
 * 
 * BIP-39 and SLIP-39 mnemonic validation with checksum verification.
 * Loaded as ES module to access BIP39_WORDLIST.
 */

import { BIP39_WORDLIST } from './assets/bip39-wordlist.js';

/**
 * Normalize mnemonic words (lowercase, handle smart quotes, split)
 */
function normalizeWords(s) {
    return s.trim().toLowerCase().replace(/[\u2019\u2018]/g, "'").split(/\s+/).filter(Boolean);
}

/**
 * Validate BIP-39 checksum using SHA-256
 */
async function validateBIP39Checksum(words) {
    const wordCount = words.length;
    const checksumBits = wordCount / 3;
    const entropyBits = wordCount * 11 - checksumBits;
    
    const indices = words.map(word => {
        const index = BIP39_WORDLIST.indexOf(word);
        if (index === -1) return null;
        return index;
    });
    
    if (indices.includes(null)) return false;
    
    let binaryString = '';
    for (const index of indices) {
        binaryString += index.toString(2).padStart(11, '0');
    }
    
    const entropyBinary = binaryString.slice(0, entropyBits);
    const checksumBinary = binaryString.slice(entropyBits);
    
    const entropyBytes = new Uint8Array(entropyBits / 8);
    for (let i = 0; i < entropyBytes.length; i++) {
        const byte = entropyBinary.slice(i * 8, (i + 1) * 8);
        entropyBytes[i] = parseInt(byte, 2);
    }
    
    const hashBuffer = await crypto.subtle.digest('SHA-256', entropyBytes);
    const hashArray = new Uint8Array(hashBuffer);
    const hashBinary = Array.from(hashArray)
        .map(b => b.toString(2).padStart(8, '0'))
        .join('');
    
    const computedChecksum = hashBinary.slice(0, checksumBits);
    return computedChecksum === checksumBinary;
}

function isValidBIP39Mnemonic(m) {
    const words = normalizeWords(m);
    if (![12, 15, 18, 21, 24].includes(words.length)) return false;
    for (const w of words) {
        if (!BIP39_WORDLIST.includes(w)) return false;
    }
    return true;
}

function isValidSLIP39Share(shareText) {
    const words = normalizeWords(shareText);
    return words.length === 20 || words.length === 33;
}

function validateSLIP39Shares() {
    const shares = document.querySelectorAll('.slip39-share');
    let validCount = 0;
    let hasContent = false;
    
    shares.forEach(shareEl => {
        const text = shareEl.value.trim();
        if (text) {
            hasContent = true;
            const valid = isValidSLIP39Share(text);
            shareEl.classList.toggle('invalid', !valid);
            shareEl.classList.toggle('valid', valid);
            if (valid) validCount++;
        } else {
            shareEl.classList.remove('invalid', 'valid');
        }
    });
    
    return hasContent ? validCount >= 2 : true;
}

function calculateStringEntropy(str, charsetSize = null) {
    if (!str || str.length === 0) return 0;
    
    if (!charsetSize) {
        const hasLower = /[a-z]/.test(str);
        const hasUpper = /[A-Z]/.test(str);
        const hasDigits = /[0-9]/.test(str);
        const hasSpecial = /[^a-zA-Z0-9]/.test(str);
        
        charsetSize = 0;
        if (hasLower) charsetSize += 26;
        if (hasUpper) charsetSize += 26;
        if (hasDigits) charsetSize += 10;
        if (hasSpecial) charsetSize += 32;
        
        charsetSize = Math.max(charsetSize, 10);
    }
    
    return Math.log2(Math.pow(charsetSize, str.length));
}

function updateLabelEntropy(date, cardId) {
    const dateEntropy = calculateStringEntropy(date, 11);
    const cardIdEntropy = calculateStringEntropy(cardId, 63);
    const totalLabelEntropy = dateEntropy + cardIdEntropy;
    
    const dateEntropyEl = document.getElementById('date-entropy');
    const cardIdEntropyEl = document.getElementById('card-id-entropy');
    const totalEntropyEl = document.getElementById('label-total-entropy');
    
    if (dateEntropyEl) {
        dateEntropyEl.textContent = `Date: ${Math.round(dateEntropy * 10) / 10} bits`;
        dateEntropyEl.className = `entropy-stat ${dateEntropy > 0 ? 'valid' : 'empty'}`;
    }
    
    if (cardIdEntropyEl) {
        cardIdEntropyEl.textContent = `Card ID: ${Math.round(cardIdEntropy * 10) / 10} bits`;
        cardIdEntropyEl.className = `entropy-stat ${cardIdEntropy > 0 ? 'valid' : 'empty'}`;
    }
    
    if (totalEntropyEl) {
        totalEntropyEl.textContent = `Total Label: ${Math.round(totalLabelEntropy * 10) / 10} bits`;
        totalEntropyEl.className = `entropy-stat ${totalLabelEntropy > 0 ? 'valid' : 'empty'}`;
    }
}

function updateLabelPreview() {
    const idEl = document.getElementById('card-id');
    const dateEl = document.getElementById('card-date');
    const output = document.getElementById('label-output');

    const id = idEl ? idEl.value.trim() : '';
    const date = dateEl ? dateEl.value : '';

    const seedTypeRadio = document.querySelector('input[name="seedType"]:checked');
    const seedType = seedTypeRadio ? seedTypeRadio.value.toUpperCase() : 'SIMPLE';
    const label = `v1|${seedType}|${date || ''}|${id}`;
    if (output) output.textContent = label;

    updateLabelEntropy(date, id);

    const bipArea = document.getElementById('bip39-mnemonic');
    if (bipArea && bipArea.value.trim()) {
        const words = normalizeWords(bipArea.value);
        const basicValid = isValidBIP39Mnemonic(bipArea.value);
        
        if (basicValid && [12, 15, 18, 21, 24].includes(words.length)) {
            validateBIP39Checksum(words).then(checksumValid => {
                bipArea.classList.toggle('invalid', !checksumValid);
                if (checksumValid) {
                    bipArea.classList.add('valid');
                } else {
                    bipArea.classList.remove('valid');
                }
            }).catch(() => {
                bipArea.classList.add('invalid');
                bipArea.classList.remove('valid');
            });
        } else {
            bipArea.classList.toggle('invalid', !basicValid);
            bipArea.classList.remove('valid');
        }
    }
    
    const slip39Visible = document.querySelector('#slip39-input');
    if (slip39Visible && slip39Visible.style.display !== 'none') {
        validateSLIP39Shares();
    }
}

document.addEventListener('DOMContentLoaded', () => {
    const cardId = document.getElementById('card-id');
    const cardDate = document.getElementById('card-date');
    if (cardId) cardId.addEventListener('input', updateLabelPreview);
    if (cardDate) cardDate.addEventListener('input', updateLabelPreview);
    document.querySelectorAll('input[name="seedType"]').forEach(r => r.addEventListener('change', updateLabelPreview));
    
    document.querySelectorAll('.slip39-share').forEach(shareEl => {
        shareEl.addEventListener('input', updateLabelPreview);
    });
    
    updateLabelPreview();
});

export {
    calculateStringEntropy, isValidBIP39Mnemonic,
    isValidSLIP39Share, normalizeWords, updateLabelPreview, validateBIP39Checksum, validateSLIP39Shares
};
