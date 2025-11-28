// verify-secret.js
const crypto = require('crypto');

const HMAC_SECRET = process.env.HMAC_SECRET || '1e50454dbd76bf5602668874ef6f8d2712a87f3375cf81e834b9e09ed1901f28';

console.log('🔑 HMAC_SECRET configurado:');
console.log('   Valor: "' + HMAC_SECRET + '"');
console.log('   Longitud: ' + HMAC_SECRET.length + ' caracteres');
console.log('');

// Generar clave de 32 bytes como lo hace el servidor
const key32 = HMAC_SECRET.padEnd(32, '0').slice(0, 32);
const keyBuffer = Buffer.from(key32, 'utf8');

console.log('🔑 Clave de 32 bytes generada:');
console.log('   String: "' + key32 + '"');
console.log('   Hex: ' + keyBuffer.toString('hex'));
console.log('');

console.log('📋 Copia este valor EXACTAMENTE en tu LicenseManager.swift:');
console.log('');
console.log('private let hmacSecret = "' + HMAC_SECRET + '"');
console.log('');