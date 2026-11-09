
"use strict";

// Import the Keychain class and password encryption/decryption functions.
const {
    Keychain,
    encryptPassword,
    decryptPassword
} = require("./password-manager");

// Import Web Crypto API for HMAC testing.
const { subtle } = require("crypto").webcrypto;

// Import helper functions for converting strings and encoding results.
const {
    stringToBuffer,
    encodeBuffer
} = require("./lib");

async function test() {

    // 1. KEY GENERATION TEST
    // Initialize a new Keychain using the master password.
    // The init() method generates a random salt and derives the AES and HMAC keys.

    const keychain = await Keychain.init("MyPassword123");

    console.log("\n--- KEY GENERATION TEST ---");

    // Display the generated salt and the algorithms used by both keys.
    console.log("Salt:", keychain.data.salt);
    console.log("AES Algorithm:", keychain.secrets.aesKey.algorithm.name);
    console.log("AES Key Length:", keychain.secrets.aesKey.algorithm.length);
    console.log("HMAC Algorithm:", keychain.secrets.hmacKey.algorithm.name);
    console.log("HMAC Key Length:", keychain.secrets.hmacKey.algorithm.length);


    // 2. ENCRYPTION TEST
    // Encrypt a sample password using the AES key and its associated domain.
    // The domain is included as Additional Authenticated Data (AAD).

    console.log("\n--- ENCRYPTION TEST ---");

    const domain = "google.com";
    const password = "GooglePassword123";

    const encrypted = await encryptPassword(
        keychain.secrets.aesKey,
        domain,
        password
    );

    // Display the encrypted record containing the IV and ciphertext.
    console.log("Encrypted record:", encrypted);


    // 3. DECRYPTION TEST
    // Decrypt the encrypted record using the same AES key and domain.
    // Check whether the recovered password matches the original password.

    console.log("\n--- DECRYPTION TEST ---");

    const decrypted = await decryptPassword(
        keychain.secrets.aesKey,
        domain,
        encrypted
    );

    console.log("Original password:", password);
    console.log("Decrypted password:", decrypted);
    console.log("Password matches:", password === decrypted);


    // 4. SWAP ATTACK TEST
    // Attempt to decrypt the Google password using a different domain.
    // AES-GCM should reject the operation because the AAD does not match.

    console.log("\n--- SWAP ATTACK TEST ---");

    try {
        await decryptPassword(
            keychain.secrets.aesKey,
            "facebook.com",
            encrypted
        );

        console.log("ERROR: Wrong domain was accepted!");

    } catch (error) {
        console.log("SUCCESS: Wrong domain rejected!");
    }


    // 5. HMAC GENERATION TEST
    // Generate an HMAC identifier for the Google domain twice.
    // The same key and domain should always produce the same HMAC.

    console.log("\n--- HMAC TEST ---");

    const hmac1 = await subtle.sign(
        "HMAC",
        keychain.secrets.hmacKey,
        stringToBuffer(domain)
    );

    const hmac2 = await subtle.sign(
        "HMAC",
        keychain.secrets.hmacKey,
        stringToBuffer(domain)
    );

    // Convert the generated HMAC values into Base64 strings for display.
    const hash1 = encodeBuffer(new Uint8Array(hmac1));
    const hash2 = encodeBuffer(new Uint8Array(hmac2));

    console.log("First HMAC:", hash1);
    console.log("Second HMAC:", hash2);
    console.log("Same domain produces same HMAC:", hash1 === hash2);


    // 6. DIFFERENT DOMAIN TEST
    // Generate an HMAC for a different domain using the same HMAC key.
    // Different domains should produce different HMAC identifiers.

    console.log("\n--- DIFFERENT DOMAIN TEST ---");

    const differentDomain = "facebook.com";

    const hmac3 = await subtle.sign(
        "HMAC",
        keychain.secrets.hmacKey,
        stringToBuffer(differentDomain)
    );

    const hash3 = encodeBuffer(new Uint8Array(hmac3));

    console.log("Google HMAC:", hash1);
    console.log("Facebook HMAC:", hash3);

    console.log(
        "Different domains produce different HMACs:",
        hash1 !== hash3
    );


    // 7. RANDOM SALT TEST
    // Initialize another Keychain using the same master password.
    // A new random salt should be generated instead of reusing the first salt.

    console.log("\n--- RANDOM SALT TEST ---");

    const secondKeychain = await Keychain.init("MyPassword123");

    console.log("First salt:", keychain.data.salt);
    console.log("Second salt:", secondKeychain.data.salt);

    console.log(
        "Salts are different:",
        keychain.data.salt !== secondKeychain.data.salt
    );
}

// Run all tests and display an error if any test fails unexpectedly.
test().catch(error => {
    console.error("Test failed:", error);
});
