#!/usr/bin/env node
/**
 * Node.js HKDF Test Vectors
 * 
 * Verifies JavaScript HKDF implementation matches Python test vectors.
 * Run with: node test_hkdf_node.js
 */

const crypto = require('crypto');

/**
 * HKDF-Expand (RFC 5869) - identical to browser implementation
 */
async function hkdfExpand(prk, info, length) {
    const hashLen = 64; // SHA-512
    const maxLength = 255 * hashLen;
    
    if (length > maxLength) {
        throw new Error(`HKDF-Expand length ${length} exceeds maximum ${maxLength}`);
    }
    
    const n = Math.ceil(length / hashLen);
    const okm = [];
    let t = Buffer.alloc(0); // T(0) = empty
    
    for (let i = 1; i <= n; i++) {
        // T(i) = HMAC(PRK, T(i-1) || info || i)
        const message = Buffer.concat([t, Buffer.from(info), Buffer.from([i])]);
        const hmac = crypto.createHmac('sha512', prk);
        hmac.update(message);
        t = hmac.digest();
        okm.push(...t);
    }
    
    return Buffer.from(okm.slice(0, length));
}

// Test vectors from Python implementation
const TEST_VECTORS = [
    {
        name: "Vector 1: Zeros PRK",
        prk: Buffer.alloc(64, 0),
        info: "v1|A0|TOKEN|A0",
        length: 32,
        expected: "dfd9a1a5ee14473ab654abe440efd92d2198bb021b62c7bb5235d0c7c0664904"
    },
    {
        name: "Vector 2: Sequential PRK",
        prk: Buffer.from(Array.from({length: 64}, (_, i) => i)),
        info: "v1|A0|TOKEN|B5",
        length: 64,
        expected: "38b4ab576511be4a23e2362e36cd1ca4ac7a14c2aa1d0c9bfccee25f8c0731725b4e623a177ac87f46a19b81b51e2525165047992abf0d703033b1f74894acf9"
    },
    {
        name: "Vector 3: Realistic PRK (SHA512 of 'test-seed-for-vectors')",
        prk: Buffer.from("b71ccf0744aa86b613f6fd8e91d68ea29da80e72d78d8e209e1ceb6390cf17f195434eb0dee0adfc322a87b90f06111508e3b6867912d816146da5361e1efe83", "hex"),
        info: "v1|B2|TOKEN|J9",
        length: 128,
        expected: "f55751941f8d82ea7a404f303937668f961837cb0042dc0f0bdcfbafbbf2720f07fa62b73156b1ae82efcf4381665c3dcc6dd3ce2bd6b8cd6e38b18042879f8972d24c67318efd9c9e8ed03aadd89d43e0c86db84b25e4aa6fface8830fc3f7c8ca670ea995f5aec51d440c913ae5ed1f6cd13fee4dab1b7cee1e839928195df"
    },
    {
        name: "Vector 4: Multi-block (0xAA PRK)",
        prk: Buffer.alloc(64, 0xAA),
        info: "CR80-EXPANSION-TEST",
        length: 192,
        expected: "d5ad42979b5727095c925b1391a3127f331b77214a14e5e2a456e6a9ebe0ba2bde5103a0f6c22d2a66917c241de9716358f74ddbd37589868264f3beceb7f82e5fac5bf164bd04618b3dc573598ec933a56ed43ca451291efa8f002d5493cb482bbd347c22216d1224b708ec58d340e43cccd09b5566421a2b8601f86b9594eee71b79086e095078ff2843376095a976e2d7dbf4d385a44fd3cd11652b2811c8c22461713e450951c05488c54422507eac6610a41593d6bbb4ad1650ef3f2053"
    }
];

async function runTests() {
    console.log("=== HKDF-Expand (RFC 5869) Test Vectors ===\n");
    
    let passed = 0;
    let failed = 0;
    
    for (const vector of TEST_VECTORS) {
        try {
            const output = await hkdfExpand(vector.prk, vector.info, vector.length);
            const outputHex = output.toString('hex');
            
            if (outputHex === vector.expected) {
                console.log(`✅ ${vector.name}: PASSED`);
                passed++;
            } else {
                console.log(`❌ ${vector.name}: FAILED`);
                console.log(`   Expected: ${vector.expected}`);
                console.log(`   Got:      ${outputHex}`);
                failed++;
            }
        } catch (error) {
            console.log(`❌ ${vector.name}: ERROR - ${error.message}`);
            failed++;
        }
    }
    
    console.log(`\n=== Results: ${passed}/${TEST_VECTORS.length} passed ===`);
    
    // Test chaining verification
    console.log("\n=== HKDF Chaining Verification ===\n");
    
    const prk = Buffer.from(Array.from({length: 64}, (_, i) => i));
    const info = "test";
    
    const fullOutput = await hkdfExpand(prk, info, 128);
    
    // Manually compute chained blocks
    const hmac1 = crypto.createHmac('sha512', prk);
    hmac1.update(Buffer.concat([Buffer.from(info), Buffer.from([1])]));
    const t1 = hmac1.digest();
    
    const hmac2 = crypto.createHmac('sha512', prk);
    hmac2.update(Buffer.concat([t1, Buffer.from(info), Buffer.from([2])]));
    const t2 = hmac2.digest();
    
    const expected = Buffer.concat([t1, t2]);
    
    if (fullOutput.equals(expected)) {
        console.log("✅ Chaining verification: PASSED");
        console.log("   Block chaining is working correctly (T(i) = HMAC(PRK, T(i-1) || info || i))");
    } else {
        console.log("❌ Chaining verification: FAILED");
    }
    
    // Exit with appropriate code
    process.exit(failed > 0 ? 1 : 0);
}

runTests();
