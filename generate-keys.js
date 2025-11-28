// generate-keys.js
// Ejecutar: node generate-keys.js

const crypto = require('crypto');
const fs = require('fs');

console.log('🔐 Generando par de claves RSA 2048...');

// Generar par de claves
const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
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

// Guardar claves en archivos
fs.writeFileSync('private_key.pem', privateKey);
fs.writeFileSync('public_key.pem', publicKey);

console.log('✅ Claves generadas exitosamente:');
console.log('   📄 private_key.pem (mantén en secreto)');
console.log('   📄 public_key.pem (úsala en tu app iOS)');
console.log('');
console.log('📋 Clave pública para tu LicenseValidator.swift:');
console.log('');
console.log(publicKey);

// Generar clave HMAC
const hmacSecret = crypto.randomBytes(32).toString('hex');
console.log('');
console.log('🔑 Clave HMAC para tu app (guárdala en tu código Swift):');
console.log(`   ${hmacSecret}`);
console.log('');
console.log('⚠️ Agrega esto a tu .env del servidor:');
console.log(`HMAC_SECRET=${hmacSecret}`);
console.log(`ADMIN_API_KEY=${crypto.randomBytes(32).toString('hex')}`);
