const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const KEYS_DIR = path.join(__dirname, 'keys');
const PRIVATE_KEY_PATH = path.join(KEYS_DIR, 'private.pem');
const PUBLIC_KEY_PATH = path.join(KEYS_DIR, 'public.pem');

// Ensure keys directory exists
if (!fs.existsSync(KEYS_DIR)) {
    fs.mkdirSync(KEYS_DIR);
}

// Generate keys if they don't exist
function ensureKeys() {
    if (!fs.existsSync(PRIVATE_KEY_PATH) || !fs.existsSync(PUBLIC_KEY_PATH)) {
        console.log('Generating new key pair...');
        const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
            modulusLength: 2048,
            publicKeyEncoding: {
                type: 'spki',
                format: 'pem'
            },
            privateKeyEncoding: {
                type: 'pkcs8',
                format: 'pem'
            }
        });

        fs.writeFileSync(PRIVATE_KEY_PATH, privateKey);
        fs.writeFileSync(PUBLIC_KEY_PATH, publicKey);
    }
}

function getPrivateKey() {
    ensureKeys();
    return fs.readFileSync(PRIVATE_KEY_PATH, 'utf8');
}

function getPublicKey() {
    ensureKeys();
    return fs.readFileSync(PUBLIC_KEY_PATH, 'utf8');
}

function signData(data) {
    const sign = crypto.createSign('SHA256');
    sign.update(JSON.stringify(data));
    sign.end();
    const privateKey = getPrivateKey();
    return sign.sign(privateKey, 'hex');
}

function verifySignature(data, signature) {
    const verify = crypto.createVerify('SHA256');
    verify.update(JSON.stringify(data));
    verify.end();
    const publicKey = getPublicKey();
    return verify.verify(publicKey, signature, 'hex');
}

function hashData(data) {
    const hash = crypto.createHash('sha256');
    hash.update(data);
    return hash.digest('hex');
}

module.exports = {
    ensureKeys,
    getPrivateKey,
    getPublicKey,
    signData,
    verifySignature,
    hashData
};
