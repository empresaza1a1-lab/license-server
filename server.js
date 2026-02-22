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
const AES_SECRET = process.env.AES_SECRET || 'clave_aes_segura_32bytes_railway!'; // Variable de entorno en Railway

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

initDatabase();

// ============================================
// FUNCIONES AUXILIARES
// ============================================

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

function firmarRespuesta(licenseString, encryptedData, expiresAt, features) {
    // String canónico: campos fijos en orden definido, separados por |
    const expiresStr = expiresAt ? new Date(expiresAt).toISOString() : '';
    const featuresStr = features ? features.join(',') : '';
    const canonical = `${licenseString}|${encryptedData}|${expiresStr}|${featuresStr}`;
    
    const sign = crypto.createSign('RSA-SHA256');
    sign.update(canonical);
    return sign.sign(PRIVATE_KEY, 'base64');
}

function encriptarDatos(empresaJSON) {
    const key = Buffer.from(AES_SECRET.padEnd(32, '0').slice(0, 32));
    const nonce = Buffer.alloc(12, 0);

    const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce);

    let encrypted = cipher.update(empresaJSON, 'utf8');
    encrypted = Buffer.concat([encrypted, cipher.final()]);

    const authTag = cipher.getAuthTag();
    const combined = Buffer.concat([encrypted, authTag]);

    return combined.toString('base64');
}

// ============================================
// ENDPOINTS
// ============================================

app.get('/health', (req, res) => {
    res.json({
        status: 'ok',
        timestamp: new Date().toISOString(),
        version: '2.0.0',
        database: 'PostgreSQL'
    });
});

app.get('/public-key', (req, res) => {
    res.type('text/plain');
    res.send(PUBLIC_KEY);
});

app.post('/api/validate', async (req, res) => {
    const { device_id, app_version } = req.body;

    console.log(`📥 Request de validación para: ${device_id}`);

    // 1. Validar campos requeridos
    if (!device_id) {
        return res.status(400).json({
            valid: false,
            error: 'Falta device_id'
        });
    }

    try {
        // 2. Buscar licencia en PostgreSQL
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

        // 3. Verificar que esté activa
        if (!licencia.activa) {
            console.log(`❌ Licencia desactivada para device: ${device_id}`);
            return res.status(403).json({
                valid: false,
                error: 'Licencia desactivada'
            });
        }

        // 4. Verificar expiración
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

        // 5. Generar licencia firmada con RSA
        const licenseString = generarLicenciaFirmada(licencia);

        // 6. Encriptar datos de empresa con AES
        const empresaJSON = JSON.stringify(licencia.empresa_data);
        const encryptedData = encriptarDatos(empresaJSON);

        // 7. Construir payload y firmarlo con RSA
        const payload = {
            valid: true,
            licenseString: licenseString,
            encryptedData: encryptedData,
            expiresAt: licencia.expiration_date,
            features: licencia.features
        };

        const responseSignature = firmarRespuesta(
            licenseString,
            encryptedData,
            licencia.expiration_date,
            licencia.features
        );

        console.log(`✅ Licencia validada para device: ${device_id} - ${licencia.empresa_data.razonSocial}`);

        res.json({
            ...payload,
            responseSignature: responseSignature
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
                hardware_id,
                empresa_data->>'razonSocial' as empresa,
                activa,
                expiration_date,
                features,
                created_at
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
    console.log(`🔐 Autenticación: RSA (sin HMAC)`);
    console.log(`📋 Endpoints disponibles:`);
    console.log(`   GET  /health`);
    console.log(`   GET  /public-key`);
    console.log(`   POST /api/validate`);
    console.log(`   POST /api/register`);
    console.log(`   POST /api/revoke`);
    console.log(`   GET  /api/licenses`);
    console.log(`   GET  /api/stats`);
});

process.on('SIGTERM', async () => {
    console.log('SIGTERM recibido, cerrando...');
    await pool.end();
    process.exit(0);
});
