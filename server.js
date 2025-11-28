// server.js - Sistema completo de licencias con Express
const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const app = express();

app.use(express.json());

// ============================================
// CONFIGURACIÓN DE CLAVES RSA
// ============================================
const PRIVATE_KEY = process.env.PRIVATE_KEY || fs.readFileSync('private_key.pem', 'utf8');
const PUBLIC_KEY = process.env.PUBLIC_KEY || fs.readFileSync('public_key.pem', 'utf8');

// Clave secreta para HMAC
const HMAC_SECRET = process.env.HMAC_SECRET || '1e50454dbd76bf5602668874ef6f8d2712a87f3375cf81e834b9e09ed1901f28';

// ============================================
// BASE DE DATOS DE LICENCIAS
// ============================================
const LICENCIAS_DB = {
    "38E48E43-6299-434E-BB5F-07E1619E2220": {
        hardwareID: "38E48E43-6299-434E-BB5F-07E1619E2220",
        empresa: {
            codigoEmpresa: "CDE-123",
            razonSocial: "MiEmpresa, S.A.",
            nit: "123456-7",
            nombreComercial: "MiComercio",
            direccionFiscal: "Calle A, Zona 10",
            direccionComercial: "Centro Comercial",
            nombreRepresentante: "Juan Pérez"
        },
        expirationDate: "2026-12-31T23:59:59Z",
        features: ["export", "import", "reports"],
        activa: true,
        createdAt: "2025-01-15T10:00:00Z"
    }
};

// ============================================
// FUNCIONES AUXILIARES
// ============================================

function generarFirmaHMAC(deviceID, timestamp) {
    const message = `${deviceID}:${timestamp}`;
    return crypto
        .createHmac('sha256', HMAC_SECRET)
        .update(message)
        .digest('hex');
}

function generarLicenciaFirmada(licenciaData) {
    const hardwareID = licenciaData.hardwareID;
    const expiration = licenciaData.expirationDate || '';
    const features = licenciaData.features.join(',');
    
    const dataToSign = `${hardwareID}|${expiration}|${features}`;
    
    const sign = crypto.createSign('RSA-SHA256');
    sign.update(dataToSign);
    const signature = sign.sign(PRIVATE_KEY, 'base64');
    
    return `${dataToSign}|${signature}`;
}

function validarTimestamp(timestamp) {
    const now = Date.now() / 1000;
    const diff = Math.abs(now - timestamp);
    return diff < 300;
}

// ============================================
// ENDPOINTS
// ============================================

app.get('/health', (req, res) => {
    res.json({ 
        status: 'ok', 
        timestamp: new Date().toISOString(),
        version: '1.0.1'
    });
});

app.get('/public-key', (req, res) => {
    res.type('text/plain');
    res.send(PUBLIC_KEY);
});

app.post('/api/validate', (req, res) => {
    const { device_id, app_version, timestamp, signature } = req.body;
    
    console.log(`📥 Request de validación para: ${device_id}`);
    
    // 1. Validar campos requeridos
    if (!device_id || !timestamp || !signature) {
        return res.status(400).json({
            valid: false,
            error: 'Faltan campos requeridos'
        });
    }
    
    // 2. Validar timestamp
    if (!validarTimestamp(timestamp)) {
        return res.status(401).json({
            valid: false,
            error: 'Timestamp inválido o expirado'
        });
    }
    
    // 3. Validar firma HMAC
    const expectedSignature = generarFirmaHMAC(device_id, timestamp);
    if (signature !== expectedSignature) {
        console.log(`⚠️ Firma inválida para device: ${device_id}`);
        console.log(`   Recibida: ${signature}`);
        console.log(`   Esperada: ${expectedSignature}`);
        return res.status(401).json({
            valid: false,
            error: 'Firma de autenticación inválida'
        });
    }
    
    // 4. Buscar licencia
    const licencia = LICENCIAS_DB[device_id];
    if (!licencia) {
        console.log(`❌ Licencia no encontrada para device: ${device_id}`);
        return res.status(403).json({
            valid: false,
            error: 'Licencia no encontrada'
        });
    }
    
    // 5. Verificar que esté activa
    if (!licencia.activa) {
        console.log(`❌ Licencia desactivada para device: ${device_id}`);
        return res.status(403).json({
            valid: false,
            error: 'Licencia desactivada'
        });
    }
    
    // 6. Verificar expiración
    if (licencia.expirationDate) {
        const expDate = new Date(licencia.expirationDate);
        if (expDate < new Date()) {
            console.log(`❌ Licencia expirada para device: ${device_id}`);
            return res.status(403).json({
                valid: false,
                error: 'Licencia expirada',
                expired: true
            });
        }
    }
    
    // 7. Generar licencia firmada
    const licenseString = generarLicenciaFirmada(licencia);
    
    // 8. Encriptar datos
    const empresaJSON = JSON.stringify(licencia.empresa);
    console.log(`🔐 Encriptando datos para: ${licencia.empresa.razonSocial}`);
    console.log(`   JSON length: ${empresaJSON.length}`);
    
    const key = Buffer.from(HMAC_SECRET.padEnd(32, '0').slice(0, 32));
    const nonce = Buffer.alloc(12, 0);
    
    console.log(`   Key (hex): ${key.toString('hex')}`);
    console.log(`   Nonce (hex): ${nonce.toString('hex')}`);
    
    const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce);
    
    let encrypted = cipher.update(empresaJSON, 'utf8');
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    
    const authTag = cipher.getAuthTag();
    
    console.log(`   Encrypted length: ${encrypted.length}`);
    console.log(`   Auth tag length: ${authTag.length}`);
    console.log(`   Auth tag (hex): ${authTag.toString('hex')}`);
    
    const combined = Buffer.concat([encrypted, authTag]);
    
    console.log(`   Combined length: ${combined.length}`);
    console.log(`✅ Licencia validada para device: ${device_id}`);
    
    res.json({
        valid: true,
        licenseString: licenseString,
        encryptedData: combined.toString('base64'),
        expiresAt: licencia.expirationDate,
        features: licencia.features
    });
});

app.post('/api/register', (req, res) => {
    const { api_key, device_id, empresa, expirationDate, features } = req.body;
    
    if (api_key !== process.env.ADMIN_API_KEY) {
        return res.status(401).json({ error: 'API key inválida' });
    }
    
    LICENCIAS_DB[device_id] = {
        hardwareID: device_id,
        empresa: empresa,
        expirationDate: expirationDate,
        features: features || ["export", "import", "reports"],
        activa: true,
        createdAt: new Date().toISOString()
    };
    
    console.log(`✅ Nueva licencia registrada: ${device_id}`);
    
    res.json({
        success: true,
        message: 'Licencia registrada exitosamente',
        device_id: device_id
    });
});

app.post('/api/revoke', (req, res) => {
    const { api_key, device_id } = req.body;
    
    if (api_key !== process.env.ADMIN_API_KEY) {
        return res.status(401).json({ error: 'API key inválida' });
    }
    
    if (LICENCIAS_DB[device_id]) {
        LICENCIAS_DB[device_id].activa = false;
        console.log(`⚠️ Licencia revocada: ${device_id}`);
        res.json({ success: true, message: 'Licencia revocada' });
    } else {
        res.status(404).json({ error: 'Licencia no encontrada' });
    }
});

app.get('/api/licenses', (req, res) => {
    const { api_key } = req.query;
    
    if (api_key !== process.env.ADMIN_API_KEY) {
        return res.status(401).json({ error: 'API key inválida' });
    }
    
    const licenses = Object.values(LICENCIAS_DB).map(lic => ({
        hardwareID: lic.hardwareID,
        empresa: lic.empresa.razonSocial,
        activa: lic.activa,
        expirationDate: lic.expirationDate,
        createdAt: lic.createdAt
    }));
    
    res.json({ licenses });
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log(`🚀 Servidor de licencias iniciado en puerto ${PORT}`);
    console.log(`📋 HMAC_SECRET length: ${HMAC_SECRET.length}`);
    console.log(`📋 Licencias registradas: ${Object.keys(LICENCIAS_DB).length}`);
    console.log(`   Endpoints disponibles:`);
    console.log(`   GET  /health`);
    console.log(`   GET  /public-key`);
    console.log(`   POST /api/validate`);
    console.log(`   POST /api/register`);
    console.log(`   POST /api/revoke`);
    console.log(`   GET  /api/licenses`);
});