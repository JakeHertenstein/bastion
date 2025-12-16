/**
 * HKDF-Expand (RFC 5869) Test Vectors
 * 
 * These test vectors verify cross-platform consistency between
 * Python and JavaScript implementations.
 * 
 * Uses Bastion label format for HMAC info labels:
 * - v1:TOKEN:HMAC:{card}.{token}|CHECK
 * 
 * Run with: node test_hkdf_vectors.js
 * Or in browser console after loading crypto.js
 */

// Test vectors generated from Python implementation
const TEST_VECTORS = [
    {
        name: "Vector 1: Zeros PRK",
        prk: "0".repeat(128), // 64 bytes of zeros in hex
        info: "v1:TOKEN:HMAC:A0.A0|X",  // Bastion format with Luhn check
        length: 32,
        expected: "60b720df40d95ad27edc288c086392dfb0e4eaf19c1010787e29d2e133526baf"
    },
    {
        name: "Vector 2: Sequential PRK",
        prk: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
        info: "v1:TOKEN:HMAC:A0.B5|Q",  // Bastion format with Luhn check
        length: 64,
        expected: "c8f73382db183e307d3a5c406c45ffcd52082cab66652783d5b7aaf879a6f4dc3d58804790a35a76cae9973f52564476f1133145087f1c10d24e4d1863379d38"
    },
    {
        name: "Vector 3: Realistic PRK (SHA512 of 'test-seed-for-vectors')",
        prk: "b71ccf0744aa86b613f6fd8e91d68ea29da80e72d78d8e209e1ceb6390cf17f195434eb0dee0adfc322a87b90f06111508e3b6867912d816146da5361e1efe83",
        info: "v1:TOKEN:HMAC:B2.J9|0",  // Bastion format with Luhn check
        length: 128,
        expected: "71a06841f4013cdc8008000dd1497e4933e606438802e8660efd72aa5bd4feed17e4b4af1dfb41f5dd749aa8a8e1b0c889d6ebcfda15c2dc4c2b84de641d71af14cb90d0ac3e814f46434c8c192c2a0c731a398ddfc03ed4f3ec7be29f49f5f6737ebed4a04dfee99c8c00978b8190f8532f37d371267cf70e9ee7cdda43a22b"
    },
    {
        name: "Vector 4: Multi-block (0xAA PRK)",
        prk: "aa".repeat(64), // 64 bytes of 0xAA in hex
        info: "CR80-EXPANSION-TEST",  // Generic info (no label format)
        length: 192,
        expected: "d5ad42979b5727095c925b1391a3127f331b77214a14e5e2a456e6a9ebe0ba2bde5103a0f6c22d2a66917c241de9716358f74ddbd37589868264f3beceb7f82e5fac5bf164bd04618b3dc573598ec933a56ed43ca451291efa8f002d5493cb482bbd347c22216d1224b708ec58d340e43cccd09b5566421a2b8601f86b9594eee71b79086e095078ff2843376095a976e2d7dbf4d385a44fd3cd11652b2811c8c22461713e450951c05488c54422507eac6610a41593d6bbb4ad1650ef3f2053"
    }
];

// Helper functions
function hexToBytes(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
    }
    return bytes;
}

function bytesToHex(bytes) {
    return Array.from(bytes)
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}

/**
 * Run all HKDF test vectors
 * @returns {Promise<{passed: number, failed: number, results: Array}>}
 */
async function runHKDFTests() {
    const results = [];
    let passed = 0;
    let failed = 0;
    
    console.log("=== HKDF-Expand (RFC 5869) Test Vectors ===\n");
    
    for (const vector of TEST_VECTORS) {
        try {
            const prk = hexToBytes(vector.prk);
            const info = new TextEncoder().encode(vector.info);
            
            const output = await SeedCardCrypto.hkdfExpand(prk, info, vector.length);
            const outputHex = bytesToHex(output);
            
            const success = outputHex === vector.expected;
            
            if (success) {
                console.log(`✅ ${vector.name}: PASSED`);
                passed++;
            } else {
                console.log(`❌ ${vector.name}: FAILED`);
                console.log(`   Expected: ${vector.expected}`);
                console.log(`   Got:      ${outputHex}`);
                failed++;
            }
            
            results.push({
                name: vector.name,
                success,
                expected: vector.expected,
                actual: outputHex
            });
        } catch (error) {
            console.log(`❌ ${vector.name}: ERROR - ${error.message}`);
            failed++;
            results.push({
                name: vector.name,
                success: false,
                error: error.message
            });
        }
    }
    
    console.log(`\n=== Results: ${passed}/${TEST_VECTORS.length} passed ===`);
    
    return { passed, failed, results };
}

/**
 * Test HKDF chaining is working correctly
 * This verifies the implementation chains blocks properly (T(i-1) || info || i)
 */
async function testHKDFChaining() {
    console.log("\n=== HKDF Chaining Verification ===\n");
    
    const prk = hexToBytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f");
    const info = new TextEncoder().encode("test");
    
    // Get 128 bytes (2 full SHA-512 blocks)
    const fullOutput = await SeedCardCrypto.hkdfExpand(prk, info, 128);
    
    // Manually compute what chaining should produce
    const key = await crypto.subtle.importKey(
        'raw', prk,
        { name: 'HMAC', hash: 'SHA-512' },
        false, ['sign']
    );
    
    // T(1) = HMAC(PRK, "" || info || 0x01)
    const msg1 = new Uint8Array([...info, 1]);
    const t1 = new Uint8Array(await crypto.subtle.sign('HMAC', key, msg1));
    
    // T(2) = HMAC(PRK, T(1) || info || 0x02)
    const msg2 = new Uint8Array([...t1, ...info, 2]);
    const t2 = new Uint8Array(await crypto.subtle.sign('HMAC', key, msg2));
    
    const expected = new Uint8Array([...t1, ...t2]);
    
    const fullOutputHex = bytesToHex(fullOutput);
    const expectedHex = bytesToHex(expected);
    
    if (fullOutputHex === expectedHex) {
        console.log("✅ HKDF chaining verification: PASSED");
        console.log("   Block chaining is working correctly (T(i) = HMAC(PRK, T(i-1) || info || i))");
        return true;
    } else {
        console.log("❌ HKDF chaining verification: FAILED");
        console.log(`   Expected: ${expectedHex}`);
        console.log(`   Got:      ${fullOutputHex}`);
        return false;
    }
}

/**
 * Test that HKDF differs from old counter-mode
 */
async function testDiffersFromCounterMode() {
    console.log("\n=== Counter Mode Differentiation Test ===\n");
    
    const prk = hexToBytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f");
    const info = new TextEncoder().encode("test");
    
    // New HKDF-Expand (chained)
    const hkdfOutput = await SeedCardCrypto.hkdfExpand(prk, info, 128);
    
    // Old counter-mode (independent blocks) - simulate what it would have done
    const key = await crypto.subtle.importKey(
        'raw', prk,
        { name: 'HMAC', hash: 'SHA-512' },
        false, ['sign']
    );
    
    const counterOutput = [];
    for (let i = 0; i < 2; i++) {
        // Old format: info || counter_2bytes (big-endian)
        const counter = new Uint8Array([(i >> 8) & 0xFF, i & 0xFF]);
        const msg = new Uint8Array([...info, ...counter]);
        const block = new Uint8Array(await crypto.subtle.sign('HMAC', key, msg));
        counterOutput.push(...block);
    }
    
    const hkdfHex = bytesToHex(hkdfOutput);
    const counterHex = bytesToHex(new Uint8Array(counterOutput.slice(0, 128)));
    
    if (hkdfHex !== counterHex) {
        console.log("✅ Counter mode differentiation: PASSED");
        console.log("   HKDF-Expand output differs from old counter-mode (as expected)");
        console.log(`   HKDF first 32 bytes:    ${hkdfHex.slice(0, 64)}`);
        console.log(`   Counter first 32 bytes: ${counterHex.slice(0, 64)}`);
        return true;
    } else {
        console.log("❌ Counter mode differentiation: FAILED");
        console.log("   Outputs should be different!");
        return false;
    }
}

// Export for module usage
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { runHKDFTests, testHKDFChaining, testDiffersFromCounterMode, TEST_VECTORS };
}

// Auto-run if in browser with SeedCardCrypto available
if (typeof window !== 'undefined' && typeof SeedCardCrypto !== 'undefined') {
    console.log("HKDF test vectors loaded. Run tests with:");
    console.log("  runHKDFTests()");
    console.log("  testHKDFChaining()");
    console.log("  testDiffersFromCounterMode()");
}
