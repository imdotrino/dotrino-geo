'use strict';

// geo.dotrino.com — índice de descubrimiento georreferenciado del ecosistema
// Dotrino. HTTP/JSON sobre Node nativo + PostGIS. Es SOLO descubrimiento:
// el contacto en vivo va por el proxy. Ver README.md.
//
// Endpoints:
//   PUT    /pins        publica/reemplaza el pin de una identidad (sobre firmado)
//   DELETE /pins        retira el pin (tombstone firmado)
//   GET    /pins?lat&lng&r&limit&filter   consulta pública por radio
//   GET    /health      liveness

const http = require('node:http');
const db = require('./db.js');
const { verifyEnvelope, pubkeyId } = require('./signature.js');
const rl = require('./rateLimiter.js');
const here = require('./here.js');   // bridge CERRADO de círculos privados (POST /here)

const PORT = Number(process.env.PORT || 8090);
const DATABASE_URL = process.env.DATABASE_URL || '';
// Techo de vida de un pin = 24 h, alineado con la ventana de mensajes offline
// del proxy. El pin es un ANUNCIO efímero (no almacenamiento): lleva el pubkey
// de la identidad para contactarla por el proxy (sendByPubkey), donde ocurre la
// transacción real. Sin "hidratación" (republicar), no debe sobrevivir más que
// un mensaje offline. Para vivir más, la identidad republica.
const MAX_TTL_MS = Number(process.env.GEO_MAX_TTL_MS || 24 * 60 * 60 * 1000);   // 24h cap
const CLOCK_SKEW_MS = Number(process.env.GEO_CLOCK_SKEW_MS || 5 * 60 * 1000); // anti-replay
const MAX_BODY = 16 * 1024; // 16 KB: un pin es chico; payloads grandes se rechazan
const PURGE_INTERVAL_MS = 60 * 1000;

// --- Federación: nodos peer con los que replicamos (allowlist). ---
// GEO_PEERS = lista separada por comas de URLs base (https://geo-b...,https://geo-c...).
const PEERS = (process.env.GEO_PEERS || '').split(',').map(s => s.trim().replace(/\/+$/, '')).filter(Boolean);
// Token compartido opcional para autenticar el tráfico nodo-a-nodo (/replicate, /since).
const REPL_TOKEN = process.env.GEO_REPLICATION_TOKEN || '';
const ANTI_ENTROPY_MS = Number(process.env.GEO_ANTI_ENTROPY_MS || 30 * 1000);
const SINCE_LIMIT = 500;

function send(res, status, obj, extraHeaders) {
    const body = JSON.stringify(obj);
    res.writeHead(status, {
        'content-type': 'application/json',
        'access-control-allow-origin': '*',
        'access-control-allow-methods': 'GET,PUT,DELETE,OPTIONS',
        'access-control-allow-headers': 'content-type',
        'cache-control': 'no-store',
        ...(extraHeaders || {})
    });
    res.end(body);
}

function readBody(req) {
    return new Promise((resolve, reject) => {
        let size = 0;
        const chunks = [];
        req.on('data', c => {
            size += c.length;
            if (size > MAX_BODY) { reject(new Error('body too large')); req.destroy(); return; }
            chunks.push(c);
        });
        req.on('end', () => {
            try { resolve(chunks.length ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : {}); }
            catch (_) { reject(new Error('invalid json')); }
        });
        req.on('error', reject);
    });
}

// Valida frescura del sobre para evitar replays de pins viejos.
function freshEnough(issuedAt, now) {
    return typeof issuedAt === 'number' && Math.abs(now - issuedAt) <= CLOCK_SKEW_MS;
}

// Normaliza etiquetas: lowercase, trim, slug unicode, ≤32 chars, dedup, máx 10.
function normalizeTags(tags) {
    if (!Array.isArray(tags)) return [];
    const out = [];
    for (const t of tags) {
        if (typeof t !== 'string') continue;
        const s = t.trim().toLowerCase();
        if (!/^[\p{L}\p{N}_-]{1,32}$/u.test(s)) continue;
        if (!out.includes(s)) out.push(s);
        if (out.length >= 10) break;
    }
    return out;
}

// Valida + aplica un PIN firmado (usado por el cliente y por la replicación).
// `fresh` (anti-replay por reloj) solo se exige a escrituras del cliente, no a
// las replicadas (que pueden ser de hace rato y aún válidas dentro del TTL).
async function applyPinEnvelope(data, signature, now, { fresh } = {}) {
    if (!data || typeof data !== 'object') return { status: 400, error: 'falta data' };
    if (!verifyEnvelope(data, signature)) return { status: 401, error: 'firma inválida' };
    if (typeof data.issuedAt !== 'number') return { status: 400, error: 'issuedAt requerido' };
    if (fresh && !freshEnough(data.issuedAt, now)) return { status: 401, error: 'sobre vencido o reloj fuera de rango' };
    const { lat, lng, geohash, payload, expiresAt } = data;
    if (typeof lat !== 'number' || lat < -90 || lat > 90) return { status: 400, error: 'lat inválida' };
    if (typeof lng !== 'number' || lng < -180 || lng > 180) return { status: 400, error: 'lng inválida' };
    if (typeof geohash !== 'string' || !geohash) return { status: 400, error: 'geohash requerido' };
    // Cada nodo capa el TTL con SU reloj (la firma es sobre el expiresAt original).
    const cappedExpires = Math.min(typeof expiresAt === 'number' ? expiresAt : now, now + MAX_TTL_MS);
    if (cappedExpires <= now) return { status: 400, error: 'expiresAt en el pasado' };
    const { changed } = await db.applyPin({
        pubkeyId: pubkeyId(data.publickey), publickey: data.publickey,
        dataJson: JSON.stringify(data), signature,
        lat, lng, geohash, payload: payload && typeof payload === 'object' ? payload : {},
        tags: normalizeTags(data.tags),
        issuedAt: data.issuedAt, expiresAt: cappedExpires
    });
    return { status: 200, changed, cappedExpires, geohash };
}

// Valida + aplica un TOMBSTONE firmado. Se conserva hasta now+MAX_TTL para tapar
// la ventana de sincronización (que no resucite el pin desde otro nodo).
async function applyTombstoneEnvelope(data, signature, now, { fresh } = {}) {
    if (!data || typeof data !== 'object') return { status: 400, error: 'falta data' };
    if (data.action !== 'remove') return { status: 400, error: 'action debe ser "remove"' };
    if (!verifyEnvelope(data, signature)) return { status: 401, error: 'firma inválida' };
    if (typeof data.issuedAt !== 'number') return { status: 400, error: 'issuedAt requerido' };
    if (fresh && !freshEnough(data.issuedAt, now)) return { status: 401, error: 'sobre vencido' };
    const { changed } = await db.applyTombstone({
        pubkeyId: pubkeyId(data.publickey), dataJson: JSON.stringify(data), signature,
        issuedAt: data.issuedAt, expiresAt: now + MAX_TTL_MS
    });
    return { status: 200, changed };
}

async function handlePut(req, res, now) {
    const { data, signature } = (await readBody(req)) || {};
    const r = await applyPinEnvelope(data, signature, now, { fresh: true });
    if (r.status !== 200) return send(res, r.status, { error: r.error });
    if (r.changed) pushToPeers('pin', data, signature);  // propagar a la federación
    return send(res, 200, { ok: true, expiresAt: r.cappedExpires, geohash: r.geohash });
}

async function handleDelete(req, res, now) {
    const { data, signature } = (await readBody(req)) || {};
    const r = await applyTombstoneEnvelope(data, signature, now, { fresh: true });
    if (r.status !== 200) return send(res, r.status, { error: r.error });
    if (r.changed) pushToPeers('tombstone', data, signature);
    return send(res, 200, { ok: true });
}

// --- Replicación entre nodos ---

// Recibe un sobre empujado por un peer y lo aplica (sin re-empujar → sin loops).
async function handleReplicate(req, res, now) {
    if (REPL_TOKEN && req.headers['x-geo-token'] !== REPL_TOKEN) return send(res, 401, { error: 'token inválido' });
    const body = (await readBody(req)) || {};
    const { kind, data, signature } = body;
    const r = kind === 'tombstone'
        ? await applyTombstoneEnvelope(data, signature, now, { fresh: false })
        : await applyPinEnvelope(data, signature, now, { fresh: false });
    if (r.status !== 200) return send(res, r.status, { error: r.error });
    return send(res, 200, { ok: true, changed: r.changed });
}

// Anti-entropía: devuelve los cambios locales con updated_at > since.
async function handleSince(req, res, url) {
    if (REPL_TOKEN && req.headers['x-geo-token'] !== REPL_TOKEN) return send(res, 401, { error: 'token inválido' });
    const since = Number(url.searchParams.get('since') || 0) || 0;
    const { items, maxUpdatedAt } = await db.changesSince(since, SINCE_LIMIT);
    return send(res, 200, { items, maxUpdatedAt });
}

// Empuja un sobre a todos los peers (fire-and-forget, con timeout).
function pushToPeers(kind, data, signature) {
    if (!PEERS.length) return;
    const payload = JSON.stringify({ kind, data, signature });
    for (const peer of PEERS) {
        const ctrl = new AbortController();
        const t = setTimeout(() => ctrl.abort(), 5000);
        fetch(`${peer}/replicate`, {
            method: 'POST',
            headers: { 'content-type': 'application/json', ...(REPL_TOKEN ? { 'x-geo-token': REPL_TOKEN } : {}) },
            body: payload, signal: ctrl.signal
        }).catch(e => console.warn(`[geo] push a ${peer} falló:`, e.message)).finally(() => clearTimeout(t));
    }
}

async function handleGet(req, res, url, now) {
    const q = url.searchParams;
    // Number(null) === 0, así que un parámetro AUSENTE no puede pasar como 0.
    if (!q.has('lat') || !q.has('lng') || !q.has('r')) {
        return send(res, 400, { error: 'lat, lng y r son requeridos' });
    }
    const lat = Number(q.get('lat'));
    const lng = Number(q.get('lng'));
    const radiusMeters = Number(q.get('r'));
    let limit = Number(q.get('limit') || 50);
    if (!Number.isFinite(lat) || lat < -90 || lat > 90) return send(res, 400, { error: 'lat inválida' });
    if (!Number.isFinite(lng) || lng < -180 || lng > 180) return send(res, 400, { error: 'lng inválida' });
    if (!Number.isFinite(radiusMeters) || radiusMeters <= 0) return send(res, 400, { error: 'r inválido' });
    limit = Math.max(1, Math.min(200, limit || 50));

    let filter = null;
    const rawFilter = q.get('filter');
    if (rawFilter) {
        try { filter = JSON.parse(rawFilter); }
        catch (_) { return send(res, 400, { error: 'filter no es JSON válido' }); }
    }
    // Búsqueda por tags (overlap): ?tags=comida,bici → pins con alguna de ellas.
    const tags = normalizeTags((q.get('tags') || '').split(',').map(s => s.trim()).filter(Boolean));
    const pins = await db.queryRadius({ lat, lng, radiusMeters, limit, filter, tags, now });
    return send(res, 200, { pins });
}

const server = http.createServer(async (req, res) => {
    const now = Date.now();
    try {
        const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);

        if (req.method === 'OPTIONS') return send(res, 204, {});
        if (url.pathname === '/health') return send(res, 200, { ok: true });

        // Bridge CERRADO de "here" (OwnTracks HTTP-mode). Canal PRIVADO por círculo,
        // separado del pin-store ABIERTO de /pins. Aditivo: no toca las rutas de abajo.
        if (url.pathname === '/here' && req.method === 'POST') {
            return await here.handleHere(req, res, now, readBody, send);
        }
        // Revocación end-to-end: el DUEÑO postea un sobre firmado para cortar un
        // cap en el feed de revocación del bridge (no solo en su vault).
        if (url.pathname === '/here/revoke' && req.method === 'POST') {
            return await here.handleRevoke(req, res, now, readBody, send);
        }

        // Endpoints de federación (nodo-a-nodo).
        if (url.pathname === '/replicate' && req.method === 'POST') return await handleReplicate(req, res, now);
        if (url.pathname === '/since' && req.method === 'GET') return await handleSince(req, res, url);

        if (url.pathname === '/pins') {
            // Rate limit por IP: lecturas y escrituras en cubetas separadas.
            const cls = req.method === 'GET' ? 'read' : 'write';
            const { allowed, retryAfter } = rl.take(cls, rl.clientIp(req), now);
            if (!allowed) {
                return send(res, 429, { error: 'demasiadas solicitudes, reintentá más tarde' },
                    { 'retry-after': String(retryAfter) });
            }
            if (req.method === 'PUT') return await handlePut(req, res, now);
            if (req.method === 'DELETE') return await handleDelete(req, res, now);
            if (req.method === 'GET') return await handleGet(req, res, url, now);
            return send(res, 405, { error: 'método no permitido' });
        }
        return send(res, 404, { error: 'not found' });
    } catch (err) {
        const msg = err && err.message ? err.message : 'error';
        const status = (msg === 'body too large' || msg === 'invalid json') ? 400 : 500;
        return send(res, status, { error: msg });
    }
});

async function main() {
    await db.init(DATABASE_URL);
    setInterval(async () => {
        try {
            const n = await db.purgeExpired(Date.now());
            if (n) console.log(`[geo] purgados ${n} pins expirados`);
        } catch (e) { console.error('[geo] purge error', e.message); }
        rl.prune(Date.now());
        here.purge(Date.now());   // bridge "here": purga blobs de presencia expirados
    }, PURGE_INTERVAL_MS).unref();

    // Anti-entropía: cada N s, traemos de cada peer sus cambios desde nuestro
    // watermark y los aplicamos (cubre pushes perdidos / nodos que estuvieron
    // caídos). No re-empujamos lo aplicado → sin loops.
    const watermarks = new Map(); // peerUrl -> último updated_at visto de ese peer
    if (PEERS.length) {
        console.log(`[geo] federación con ${PEERS.length} peer(s): ${PEERS.join(', ')}`);
        setInterval(async () => {
            for (const peer of PEERS) {
                try {
                    const since = watermarks.get(peer) || 0;
                    const ctrl = new AbortController();
                    const t = setTimeout(() => ctrl.abort(), 8000);
                    const resp = await fetch(`${peer}/since?since=${since}`, {
                        headers: REPL_TOKEN ? { 'x-geo-token': REPL_TOKEN } : {}, signal: ctrl.signal
                    }).finally(() => clearTimeout(t));
                    if (!resp.ok) continue;
                    const { items, maxUpdatedAt } = await resp.json();
                    const nowTs = Date.now();
                    for (const it of (items || [])) {
                        if (it.kind === 'tombstone') await applyTombstoneEnvelope(it.data, it.signature, nowTs, { fresh: false });
                        else await applyPinEnvelope(it.data, it.signature, nowTs, { fresh: false });
                    }
                    if (typeof maxUpdatedAt === 'number' && maxUpdatedAt > since) watermarks.set(peer, maxUpdatedAt);
                } catch (e) { console.warn(`[geo] anti-entropía con ${peer} falló:`, e.message); }
            }
        }, ANTI_ENTROPY_MS).unref();
    }

    server.listen(PORT, () => console.log(`[geo] geo.dotrino.com escuchando en :${PORT}`));
}

main().catch(err => { console.error('[geo] fatal', err); process.exit(1); });
