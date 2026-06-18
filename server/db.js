'use strict';

// Capa PostGIS del índice geo, con replicación (CRDT last-writer-wins por
// issued_at + tombstones). `applyPin`/`applyTombstone` se usan tanto para
// escrituras locales (cliente) como para las replicadas (peers): el LWW garantiza
// convergencia sin importar el orden de llegada.

const fs = require('node:fs');
const path = require('node:path');
const { Pool } = require('pg');

let pool = null;

// Reloj monótono local para `updated_at` (watermark de anti-entropía). Estricto
// crecimiento → /since con `> watermark` nunca pierde una fila.
let _lastSeq = 0;
function nowSeq() { const t = Date.now(); _lastSeq = t > _lastSeq ? t : _lastSeq + 1; return _lastSeq; }

async function init(connectionString) {
    pool = new Pool(connectionString ? { connectionString } : undefined);
    await pool.query(fs.readFileSync(path.join(__dirname, 'schema.sql'), 'utf8'));
    return pool;
}

/**
 * Aplica un pin (local o replicado) con semántica LWW. `expiresAt` ya viene
 * capado por el llamador. Devuelve { changed } — true si modificó el estado
 * (entonces hay que propagarlo a los peers).
 */
async function applyPin({ pubkeyId, publickey, dataJson, signature, lat, lng, geohash, payload, tags, issuedAt, expiresAt }) {
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        const tomb = await client.query('SELECT issued_at FROM tombstones WHERE pubkey_id = $1', [pubkeyId]);
        if (tomb.rows[0] && Number(tomb.rows[0].issued_at) >= issuedAt) {
            await client.query('ROLLBACK'); return { changed: false };
        }
        const ex = await client.query('SELECT issued_at FROM pins WHERE pubkey_id = $1', [pubkeyId]);
        if (ex.rows[0] && Number(ex.rows[0].issued_at) >= issuedAt) {
            await client.query('ROLLBACK'); return { changed: false };
        }
        // El pin es más nuevo que cualquier tombstone → limpiamos el tombstone.
        await client.query('DELETE FROM tombstones WHERE pubkey_id = $1 AND issued_at < $2', [pubkeyId, issuedAt]);
        await client.query(
            `INSERT INTO pins (pubkey_id, publickey, data_json, signature, geog, geohash, payload, tags, issued_at, expires_at, updated_at)
             VALUES ($1,$2,$3,$4, ST_SetSRID(ST_MakePoint($5,$6),4326)::geography, $7, $8::jsonb, $9, $10, $11, $12)
             ON CONFLICT (pubkey_id) DO UPDATE SET
                publickey=EXCLUDED.publickey, data_json=EXCLUDED.data_json, signature=EXCLUDED.signature,
                geog=EXCLUDED.geog, geohash=EXCLUDED.geohash, payload=EXCLUDED.payload, tags=EXCLUDED.tags,
                issued_at=EXCLUDED.issued_at, expires_at=EXCLUDED.expires_at, updated_at=EXCLUDED.updated_at`,
            [pubkeyId, publickey, dataJson, signature, lng, lat, geohash, JSON.stringify(payload || {}), Array.isArray(tags) ? tags : [], issuedAt, expiresAt, nowSeq()]
        );
        await client.query('COMMIT');
        return { changed: true };
    } catch (e) {
        await client.query('ROLLBACK'); throw e;
    } finally { client.release(); }
}

/**
 * Aplica un tombstone (borrado firmado) con LWW. `expiresAt` = hasta cuándo
 * conservarlo (para tapar la ventana de sync). Devuelve { changed }.
 */
async function applyTombstone({ pubkeyId, dataJson, signature, issuedAt, expiresAt }) {
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        const tomb = await client.query('SELECT issued_at FROM tombstones WHERE pubkey_id = $1', [pubkeyId]);
        if (tomb.rows[0] && Number(tomb.rows[0].issued_at) >= issuedAt) {
            await client.query('ROLLBACK'); return { changed: false };
        }
        // Borra el pin si el tombstone es igual o más nuevo.
        await client.query('DELETE FROM pins WHERE pubkey_id = $1 AND issued_at <= $2', [pubkeyId, issuedAt]);
        await client.query(
            `INSERT INTO tombstones (pubkey_id, data_json, signature, issued_at, expires_at, updated_at)
             VALUES ($1,$2,$3,$4,$5,$6)
             ON CONFLICT (pubkey_id) DO UPDATE SET
                data_json=EXCLUDED.data_json, signature=EXCLUDED.signature,
                issued_at=EXCLUDED.issued_at, expires_at=EXCLUDED.expires_at, updated_at=EXCLUDED.updated_at`,
            [pubkeyId, dataJson, signature, issuedAt, expiresAt, nowSeq()]
        );
        await client.query('COMMIT');
        return { changed: true };
    } catch (e) {
        await client.query('ROLLBACK'); throw e;
    } finally { client.release(); }
}

async function queryRadius({ lat, lng, radiusMeters, limit, filter, tags, now }) {
    const params = [lng, lat, radiusMeters, now];
    let filterSql = '';
    if (filter && typeof filter === 'object' && Object.keys(filter).length) {
        params.push(JSON.stringify(filter));
        filterSql += ` AND payload @> $${params.length}::jsonb`;
    }
    if (Array.isArray(tags) && tags.length) {
        params.push(tags);
        filterSql += ` AND tags && $${params.length}::text[]`;  // overlap: tiene ALGUNA
    }
    params.push(limit);
    const { rows } = await pool.query(`
        SELECT publickey, ST_Y(geog::geometry) AS lat, ST_X(geog::geometry) AS lng, geohash, payload, tags, expires_at,
               ST_Distance(geog, ST_SetSRID(ST_MakePoint($1,$2),4326)::geography) AS distance_m
        FROM pins
        WHERE expires_at > $4
          AND ST_DWithin(geog, ST_SetSRID(ST_MakePoint($1,$2),4326)::geography, $3)
          ${filterSql}
        ORDER BY distance_m ASC LIMIT $${params.length}`, params);
    return rows.map(r => ({
        publickey: r.publickey, lat: r.lat, lng: r.lng, geohash: r.geohash,
        payload: r.payload, tags: r.tags || [], distanceMeters: Math.round(r.distance_m), expiresAt: Number(r.expires_at)
    }));
}

/**
 * Anti-entropía: cambios locales con updated_at > since. Devuelve sobres
 * {data, signature} para que el peer los re-aplique, + el maxUpdatedAt visto.
 */
async function changesSince(since, limit) {
    const pins = await pool.query(
        `SELECT data_json, signature, updated_at FROM pins WHERE updated_at > $1 ORDER BY updated_at ASC LIMIT $2`,
        [since, limit]);
    const tombs = await pool.query(
        `SELECT data_json, signature, updated_at FROM tombstones WHERE updated_at > $1 ORDER BY updated_at ASC LIMIT $2`,
        [since, limit]);
    const items = [];
    for (const r of pins.rows) items.push({ kind: 'pin', updatedAt: Number(r.updated_at), data: JSON.parse(r.data_json), signature: r.signature });
    for (const r of tombs.rows) items.push({ kind: 'tombstone', updatedAt: Number(r.updated_at), data: JSON.parse(r.data_json), signature: r.signature });
    items.sort((a, b) => a.updatedAt - b.updatedAt);
    const capped = items.slice(0, limit);
    const maxUpdatedAt = capped.length ? capped[capped.length - 1].updatedAt : since;
    return { items: capped, maxUpdatedAt };
}

async function purgeExpired(now) {
    const a = await pool.query('DELETE FROM pins WHERE expires_at <= $1', [now]);
    const b = await pool.query('DELETE FROM tombstones WHERE expires_at <= $1', [now]);
    return (a.rowCount || 0) + (b.rowCount || 0);
}

async function close() { if (pool) await pool.end(); pool = null; }

module.exports = { init, applyPin, applyTombstone, queryRadius, changesSince, purgeExpired, close };
