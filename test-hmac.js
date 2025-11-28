const crypto = require('crypto');

// IMPORTANTE: Reemplaza este valor con tu HMAC_SECRET real
const hmacSecret = 'daadffb5898a8fce2ee110198ce1581e345ad12e5432c3d83c3a343932e53090';

const deviceID = '12345-67890';
const timestamp = Math.floor(Date.now() / 1000);

const message = `${deviceID}:${timestamp}`;
const signature = crypto
  .createHmac('sha256', hmacSecret)
  .update(message)
  .digest('hex');

console.log('📋 Datos para el request de validación:');
console.log('');
console.log(JSON.stringify({
  device_id: deviceID,
  timestamp: timestamp,
  signature: signature,
  app_version: "1.0"
}, null, 2));

console.log('');
console.log('📝 Comando curl completo:');
console.log('');
console.log(`curl -X POST https://responsible-liberation-production.up.railway.app/api/validate \\
  -H "Content-Type: application/json" \\
  -d '{
    "device_id": "${deviceID}",
    "timestamp": ${timestamp},
    "signature": "${signature}",
    "app_version": "1.0"
  }'`);
