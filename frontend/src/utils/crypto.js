import forge from 'node-forge';

export const generateKeyPair = () => {
    // Generate async to avoid blocking UI, but for MVP sync is okay if fast enough
    // 1024 bits is faster for demo; 2048 is standard.
    // Sync generation might freeze for a second.
    const keypair = forge.pki.rsa.generateKeyPair({ bits: 2048, e: 0x10001 });
    const publicKeyPem = forge.pki.publicKeyToPem(keypair.publicKey);
    const privateKeyPem = forge.pki.privateKeyToPem(keypair.privateKey);
    return { publicKeyPem, privateKeyPem };
};

export const signData = (dataString, privateKeyPem) => {
    const md = forge.md.sha256.create();
    md.update(dataString, 'utf8');
    const privateKey = forge.pki.privateKeyFromPem(privateKeyPem);
    const signature = privateKey.sign(md);
    return forge.util.bytesToHex(signature);
};

export const verifySignature = (dataString, signatureHex, publicKeyPem) => {
    try {
        const md = forge.md.sha256.create();
        md.update(dataString, 'utf8');
        const publicKey = forge.pki.publicKeyFromPem(publicKeyPem);
        const signature = forge.util.hexToBytes(signatureHex);
        return publicKey.verify(md.digest().bytes(), signature);
    } catch (e) {
        console.error("Verification failed", e);
        return false;
    }
};

// Helper to ensure deterministic stringify (simple version)
// Should match backend's JSON.stringify behavior on the simple object
export const deterministicStringify = (obj) => {
    return JSON.stringify(obj);
};
