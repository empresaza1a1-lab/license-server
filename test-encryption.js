// test-encryption.js
const crypto = require('crypto');

const HMAC_SECRET = '1e50454dbd76bf5602668874ef6f8d2712a87f3375cf81e834b9e09ed1901f28'; // Tu HMAC_SECRET real

// Datos de prueba
const testData = {
    codigoEmpresa: "TEST-001",
    razonSocial: "Test Company",
    nit: "123456-7"
};

const empresaJSON = JSON.stringify(testData);
console.log('📋 Datos originales:');
console.log(empresaJSON);
console.log('');

// Preparar clave de 32 bytes - DEBE ser idéntico a Swift
const key = Buffer.from(HMAC_SECRET.padEnd(32, '0').slice(0, 32));
console.log('🔑 Clave (32 bytes):');
console.log('   Hex:', key.toString('hex'));
console.log('   Primeros 16:', key.slice(0, 16).toString('hex'));
console.log('');

// Nonce de 12 bytes
const nonce = Buffer.alloc(12, 0);
console.log('🎲 Nonce (12 bytes):');
console.log('   Hex:', nonce.toString('hex'));
console.log('');

// Encriptar
const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce);
let encrypted = cipher.update(empresaJSON, 'utf8');
encrypted = Buffer.concat([encrypted, cipher.final()]);

// Obtener tag
const authTag = cipher.getAuthTag();

console.log('🔒 Resultado encriptación:');
console.log('   Ciphertext length:', encrypted.length, 'bytes');
console.log('   Ciphertext (hex):', encrypted.toString('hex'));
console.log('   Auth Tag length:', authTag.length, 'bytes');
console.log('   Auth Tag (hex):', authTag.toString('hex'));
console.log('');

// Combinar
const combined = Buffer.concat([encrypted, authTag]);
const combinedBase64 = combined.toString('base64');

console.log('📦 Combined:');
console.log('   Total length:', combined.length, 'bytes');
console.log('   Base64:', combinedBase64);
console.log('');

// VERIFICAR: Desencriptar para confirmar
console.log('✅ Verificando desencriptación...');
const decipher = crypto.createDecipheriv('aes-256-gcm', key, nonce);
decipher.setAuthTag(authTag);

let decrypted = decipher.update(encrypted, null, 'utf8');
decrypted += decipher.final('utf8');

console.log('   Desencriptado:', decrypted);
console.log('   ¿Coincide?', decrypted === empresaJSON ? '✅ SÍ' : '❌ NO');