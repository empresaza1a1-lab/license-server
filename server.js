// server.js - Sistema de licencias con PostgreSQL
const express = require('express');
const crypto = require('crypto');
const { Pool } = require('pg');
const fs = require('fs');
const app = express();

app.use(express.json());

// ============================================
// CONFIGURACIÓN DE CLAVES RSA
// ============================================
const PRIVATE_KEY = process.env.PRIVATE_KEY || fs.readFileSync('private_key.pem', 'utf8');
const PUBLIC_KEY = process.env.PUBLIC_KEY || fs.readFileSync('public_key.pem', 'utf8');
const HMAC_SECRET = process.env.HMAC_SECRET || '1e50454dbd76bf5602668874ef6f8d2712a87f3375cf81e834b9e09ed1901f28';

// ============================================
// CONFIGURACIÓN DE POSTGRESQL
// ============================================
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

// Inicializar base de datos
async function initDatabase() {
    const client = await pool.connect();
    try {
        await client.query(`
            CREATE TABLE IF NOT EXISTS licencias (
                id SERIAL PRIMARY KEY,
                hardware_id VARCHAR(255) UNIQUE NOT NULL,
                empresa_data JSONB NOT NULL,
                expiration_date TIMESTAMP,
                features TEXT[] DEFAULT ARRAY['export', 'import', 'reports'],
                activa BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            CREATE INDEX IF NOT EXISTS idx_hardware_id ON licencias(hardware_id);
            CREATE INDEX IF NOT EXISTS idx_activa ON licencias(activa);
        `);
        
        console.log('✅ Base de datos inicializada correctamente');
    } catch (error) {
        console.error('❌ Error inicializando base de datos:', error);
    } finally {
        client.release();
    }
}

// Inicializar DB al arrancar
initDatabase();

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
    const hardwareID = licenciaData.hardware_id;
    const expiration = licenciaData.expiration_date 
        ? new Date(licenciaData.expiration_date).toISOString() 
        : '';
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
        version: '1.0.2',
        database: 'PostgreSQL'
    });
});

app.get('/public-key', (req, res) => {
    res.type('text/plain');
    res.send(PUBLIC_KEY);
});

app.post('/api/validate', async (req, res) => {
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
        return res.status(401).json({
            valid: false,
            error: 'Firma de autenticación inválida'
        });
    }
    
    try {
        // 4. Buscar licencia en PostgreSQL
        const result = await pool.query(
            'SELECT * FROM licencias WHERE hardware_id = $1',
            [device_id]
        );
        
        if (result.rows.length === 0) {
            console.log(`❌ Licencia no encontrada para device: ${device_id}`);
            return res.status(403).json({
                valid: false,
                error: 'Licencia no encontrada'
            });
        }
        
        const licencia = result.rows[0];
        
        // 5. Verificar que esté activa
        if (!licencia.activa) {
            console.log(`❌ Licencia desactivada para device: ${device_id}`);
            return res.status(403).json({
                valid: false,
                error: 'Licencia desactivada'
            });
        }
        
        // 6. Verificar expiración
        if (licencia.expiration_date) {
            const expDate = new Date(licencia.expiration_date);
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
        const empresaJSON = JSON.stringify(licencia.empresa_data);
        
        const key = Buffer.from(HMAC_SECRET.padEnd(32, '0').slice(0, 32));
        const nonce = Buffer.alloc(12, 0);
        
        const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce);
        
        let encrypted = cipher.update(empresaJSON, 'utf8');
        encrypted = Buffer.concat([encrypted, cipher.final()]);
        
        const authTag = cipher.getAuthTag();
        const combined = Buffer.concat([encrypted, authTag]);
        
        console.log(`✅ Licencia validada para device: ${device_id} - ${licencia.empresa_data.razonSocial}`);
        
        res.json({
            valid: true,
            licenseString: licenseString,
            encryptedData: combined.toString('base64'),
            expiresAt: licencia.expiration_date,
            features: licencia.features
        });
        
    } catch (error) {
        console.error('❌ Error en validación:', error);
        res.status(500).json({
            valid: false,
            error: 'Error interno del servidor'
        });
    }
});

app.post('/api/register', async (req, res) => {
    const { api_key, device_id, empresa, expirationDate, features } = req.body;
    
    if (api_key !== process.env.ADMIN_API_KEY) {
        return res.status(401).json({ error: 'API key inválida' });
    }
    
    try {
        await pool.query(
            `INSERT INTO licencias (hardware_id, empresa_data, expiration_date, features, activa)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (hardware_id) 
             DO UPDATE SET 
                empresa_data = $2,
                expiration_date = $3,
                features = $4,
                activa = $5,
                updated_at = CURRENT_TIMESTAMP`,
            [
                device_id,
                JSON.stringify(empresa),
                expirationDate || null,
                features || ['export', 'import', 'reports'],
                true
            ]
        );
        
        console.log(`✅ Licencia registrada/actualizada: ${device_id}`);
        
        res.json({
            success: true,
            message: 'Licencia registrada exitosamente',
            device_id: device_id
        });
        
    } catch (error) {
        console.error('❌ Error registrando licencia:', error);
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

app.post('/api/revoke', async (req, res) => {
    const { api_key, device_id } = req.body;
    
    if (api_key !== process.env.ADMIN_API_KEY) {
        return res.status(401).json({ error: 'API key inválida' });
    }
    
    try {
        const result = await pool.query(
            'UPDATE licencias SET activa = false, updated_at = CURRENT_TIMESTAMP WHERE hardware_id = $1',
            [device_id]
        );
        
        if (result.rowCount === 0) {
            return res.status(404).json({ error: 'Licencia no encontrada' });
        }
        
        console.log(`⚠️ Licencia revocada: ${device_id}`);
        res.json({ success: true, message: 'Licencia revocada' });
        
    } catch (error) {
        console.error('❌ Error revocando licencia:', error);
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

app.get('/api/licenses', async (req, res) => {
    const { api_key } = req.query;
    
    if (api_key !== process.env.ADMIN_API_KEY) {
        return res.status(401).json({ error: 'API key inválida' });
    }
    
    try {
        const result = await pool.query(
`SELECT 
    hardware_id AS "hardwareID",
    empresa_data->>'razonSocial' as empresa, 
    activa,
    expiration_date AS "expirationDate",
    features,
    created_at AS "createdAt"
 FROM licencias
 ORDER BY created_at DESC`
);
        
        res.json({ 
            licenses: result.rows,
            total: result.rowCount
        });
        
    } catch (error) {
        console.error('❌ Error listando licencias:', error);
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

// Endpoint para estadísticas (opcional)
app.get('/api/stats', async (req, res) => {
    const { api_key } = req.query;
    
    if (api_key !== process.env.ADMIN_API_KEY) {
        return res.status(401).json({ error: 'API key inválida' });
    }
    
    try {
        const stats = await pool.query(`
            SELECT 
                COUNT(*) as total,
                COUNT(*) FILTER (WHERE activa = true) as activas,
                COUNT(*) FILTER (WHERE activa = false) as revocadas,
                COUNT(*) FILTER (WHERE expiration_date IS NOT NULL AND expiration_date < NOW()) as expiradas
            FROM licencias
        `);
        
        res.json(stats.rows[0]);
        
    } catch (error) {
        console.error('❌ Error obteniendo estadísticas:', error);
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log(`🚀 Servidor de licencias iniciado en puerto ${PORT}`);
    console.log(`📊 Base de datos: PostgreSQL`);
    console.log(`📋 Endpoints disponibles:`);
    console.log(`   GET  /health`);
    console.log(`   GET  /public-key`);
    console.log(`   POST /api/validate`);
    console.log(`   POST /api/register`);
    console.log(`   POST /api/revoke`);
    console.log(`   GET  /api/licenses`);
    console.log(`   GET  /api/stats`);
});

// Manejo de cierre graceful
process.on('SIGTERM', async () => {
    console.log('SIGTERM recibido, cerrando...');
    await pool.end();
    process.exit(0);
});