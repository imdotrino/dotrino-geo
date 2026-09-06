'use strict';

// "here" — BRIDGE CERRADO de ubicación para círculos privados (OwnTracks HTTP-mode).
//
// Es un canal SEPARADO del pin-store ABIERTO de discovery (Trueque/Eco). Aquí NO
// hay descubrimiento, ni proximidad, ni broadcast, ni acceso anónimo: es el canal
// PRIVADO de un círculo, cerrado y cifrado de punta a punta por OwnTracks. El bridge
// solo ve ciphertext opaco + el agrupamiento por circleId (un metadato), nunca la
// ubicación.
//
// Modelo:
//   - circleId = pubkeyId(ownerMasterPubkey) + ':' + slug   (liga el círculo a su DUEÑO)
//   - El dueño emite a cada DISPOSITIVO un cert de delegación (capabilities.js) con
//     scope que incluye 'geo:publish' y 'geo:read:<circleId>'.
//   - OwnTracks (HTTP mode) hace POST /here con:
//       · Auth: HTTP Basic → username = circleId, password = base64url(JSON.stringify(cert))
//       · Body: un mensaje OwnTracks JSON. Para publicar va CIFRADO:
//         { _type:'encrypted', data:'<b64 secretbox>' }  (opaco; el bridge NO lo descifra).
//         También puede traer _type:'card' (tarjeta de contacto, igualmente opaca para el bridge).
//   - El bridge: parsea el cert del password; verifyDelegation con 'geo:publish' y exige
//     que el scope incluya 'geo:read:<circleId>'; exige pubkeyId(cert.iss) === circleId.split(':')[0];
//     chequea exp + revocación. Sin cap válido → 401, NO escribe ni lee.
//   - Guarda el ÚLTIMO blob por miembro (memberId = pubkeyId(cert.sub) ó tid del body),
//     EFÍMERO (TTL + OVERWRITE, sin historial). Responde 200 con un ARRAY de los blobs
//     más recientes de los OTROS miembros del MISMO círculo → OwnTracks los pinta como amigos.

// El cert/respuesta del bridge debe ser chico; un blob OwnTracks cifrado es pequeño.
const MAX_HERE_BODY = 16 * 1024;       // 16 KB por POST
// Vida de un blob de presencia: efímero. Más corto que el pin abierto: una posición
// vieja no debe sobrevivir. Si el dispositivo sigue vivo, OwnTracks reenvía y reescribe.
const HERE_TTL_MS = Number(process.env.GEO_HERE_TTL_MS || 30 * 60 * 1000);  // 30 min
const MAX_MEMBERS_RETURNED = 64;       // tope de amigos devueltos por respuesta
// Tolerancia de reloj entre el vault (emisor del cert) y este bridge (verificador).

// --- carga perezosa (una sola vez) de la primitiva de delegación (ESM desde CJS) ---
let _capsPromise = null;
function loadCaps() {
    if (!_capsPromise) {
        // El server es CommonJS y capabilities.js es ESM → dynamic import una vez al boot.
        // Preferimos el subpath del paquete; si el monorepo aún no lo enlazó, caemos a la
        // ruta relativa dentro del ecosistema (…/dotrino-identity/vault/capabilities.js).
        _capsPromise = import('@dotrino/identity/capabilities')
            .catch(() => import('../../dotrino-identity/vault/capabilities.js'));
    }
    return _capsPromise;
}

// --- y el acta, que es quien dice qué puede cada llave (mismo origen que las caps) ---
let _actaPromise = null;
function loadActa() {
    if (!_actaPromise) {
        _actaPromise = import('@dotrino/identity/acta')
            .catch(() => import('../../dotrino-identity/vault/acta.js'));
    }
    return _actaPromise;
}

// --- store EFÍMERO en memoria: circleId -> Map(memberId -> { blob, expiresAt }) ---
// Sin historial: cada miembro tiene a lo sumo UN blob (overwrite). TTL por entrada.
const circles = new Map();

// --- feed de revocación en memoria (nonces revocados). El bridge consulta este set;
// es alimentable por fuera (p.ej. un feed firmado del dueño). EFÍMERO por diseño. ---
const revokedNonces = new Set();
function revoke(nonce) { if (nonce) revokedNonces.add(String(nonce)); }
function isRevoked(nonce) { return revokedNonces.has(String(nonce)); }

/** Purga entradas (y círculos vacíos) expirados. Devuelve cuántas entradas eliminó. */
function purge(now = Date.now()) {
    let removed = 0;
    for (const [circleId, members] of circles) {
        for (const [memberId, entry] of members) {
            if (entry.expiresAt <= now) { members.delete(memberId); removed++; }
        }
        if (members.size === 0) circles.delete(circleId);
    }
    return removed;
}

// --- parse de HTTP Basic: "Basic base64(user:pass)" → { user, pass } o null ---
function parseBasicAuth(headerValue) {
    if (typeof headerValue !== 'string') return null;
    const m = /^Basic\s+(.+)$/i.exec(headerValue.trim());
    if (!m) return null;
    let decoded;
    try { decoded = Buffer.from(m[1], 'base64').toString('utf8'); }
    catch (_) { return null; }
    // OJO: el username (circleId = "pubkeyId:slug") CONTIENE un ':'. HTTP Basic usa el
    // ':' como separador user/pass, así que NO podemos partir por el PRIMER ':'.
    // El password es base64url(cert) y el alfabeto base64url (A-Za-z0-9-_) NO tiene ':',
    // así que el ÚLTIMO ':' separa inequívocamente circleId (con su ':') del password.
    const i = decoded.lastIndexOf(':');
    if (i < 0) return null;
    return { user: decoded.slice(0, i), pass: decoded.slice(i + 1) };
}

// --- decodifica el cert del password (base64url(JSON.stringify(cert))) ---
/**
 * El password del Basic trae el PAPEL Y EL ACTA: `{ cert, chain }`.
 *
 * Antes traía el certificado suelto, y con eso ya no se puede juzgar nada: desde que un
 * papel no caduca por reloj, lo que puede hacer una llave lo dice el acta del perfil
 * (`seq` + quién sella), y sin ella `verifyDelegation` responde «no-acta» — correctamente.
 * Un papel a secas se acepta al decodificar y se rechaza después, con su motivo: aquí no
 * se rellena lo que falta.
 */
function decodeCap(passwordB64url) {
    if (typeof passwordB64url !== 'string' || !passwordB64url) return null;
    try {
        // Buffer acepta base64url directamente (también tolera base64 estándar).
        const json = Buffer.from(passwordB64url, 'base64url').toString('utf8');
        const paquete = JSON.parse(json);
        if (!paquete || typeof paquete !== 'object') return null;
        if (paquete.cert && typeof paquete.cert === 'object') {
            return { cert: paquete.cert, chain: Array.isArray(paquete.chain) ? paquete.chain : null };
        }
        return { cert: paquete, chain: null };   // formato viejo: sin acta, no se puede juzgar
    } catch (_) { return null; }
}

const scopeIncludes = (scope, want) =>
    Array.isArray(scope) ? scope.includes(want) : scope === want;

// --- verificación de sobres firmados {data, signature} (mismo formato que /pins) ---
// Reusa la primitiva del ecosistema; no reimplementamos cripto.
const { verifyEnvelope, pubkeyId: pubkeyIdSync } = require('./signature.js');

/**
 * Maneja POST /here/revoke. Recibe un sobre FIRMADO por el DUEÑO del círculo:
 *   data = { op:'revoke', circleId, nonce, issuedAt, publickey }   (publickey = JWK del firmante)
 *   signature = base64 ECDSA-P256 sobre el JSON canónico de data.
 *
 * Verifica:
 *   (1) firma válida sobre data (verifyEnvelope);
 *   (2) op === 'revoke', circleId/nonce presentes;
 *   (3) pubkeyId(data.publickey) === circleId.split(':')[0]  (solo el DUEÑO revoca su círculo).
 * Si todo ok → here.revoke(nonce) (el cert deja de poder publicar/leer end-to-end).
 * Firma de otro / sin firma → 401/403, NO revoca.
 *
 * @param req  IncomingMessage
 * @param res  ServerResponse
 * @param now  timestamp
 * @param readBody  async (req) => objeto JSON parseado del body
 * @param send  (res, status, obj, extraHeaders) => void
 */
async function handleRevoke(req, res, now, readBody, send) {
    let body;
    try { body = await readBody(req); }
    catch (e) {
        const msg = e && e.message ? e.message : 'invalid body';
        return send(res, 400, { error: msg });
    }
    const data = body && body.data;
    const signature = body && body.signature;
    if (!data || typeof data !== 'object') return send(res, 400, { error: 'missing data' });
    if (data.op !== 'revoke') return send(res, 400, { error: 'op must be "revoke"' });

    const circleId = data.circleId;
    const nonce = data.nonce;
    if (typeof circleId !== 'string' || !circleId.includes(':')) {
        return send(res, 400, { error: 'invalid circleId' });
    }
    if (typeof nonce !== 'string' || !nonce) {
        return send(res, 400, { error: 'nonce required' });
    }

    // (1) firma válida sobre `data` (data.publickey embebido = firmante).
    if (typeof data.publickey !== 'string' || !verifyEnvelope(data, signature)) {
        return send(res, 401, { error: 'invalid signature' });
    }

    // (3) ligadura dueño↔círculo: el firmante debe ser el DUEÑO del circleId.
    //     403 (autenticado pero NO autorizado para revocar ESTE círculo).
    const ownerId = circleId.split(':')[0];
    let signerId;
    try { signerId = pubkeyIdSync(data.publickey); }
    catch (_) { return send(res, 401, { error: 'invalid publickey' }); }
    if (signerId !== ownerId) {
        return send(res, 403, { error: 'only the circle owner can revoke', reason: 'owner-mismatch' });
    }

    revoke(nonce);
    // TODO(persistencia): el set de revocación vive en memoria; un reinicio lo
    // pierde. Persistir (tabla/archivo) para que la revocación sobreviva reinicios.
    return send(res, 200, { ok: true, circleId, nonce });
}

/**
 * Maneja POST /here. CERRADO: sin cap válido no escribe ni lee.
 * @param req  IncomingMessage
 * @param res  ServerResponse
 * @param now  timestamp
 * @param readBody  async (req) => objeto JSON parseado del body (con tope de tamaño)
 * @param send  (res, status, obj, extraHeaders) => void   (el del server)
 */
async function handleHere(req, res, now, readBody, send) {
    const caps = await loadCaps();
    const { verifyDelegation, pubkeyId } = caps;

    // (1) Basic auth: username = circleId, password = base64url(cert).
    const basic = parseBasicAuth(req.headers['authorization']);
    if (!basic) return send(res, 401, { error: 'auth required' }, { 'www-authenticate': 'Basic realm="here"' });
    const circleId = basic.user;
    if (typeof circleId !== 'string' || !circleId.includes(':')) {
        return send(res, 401, { error: 'invalid circleId' });
    }
    const ownerId = circleId.split(':')[0];

    const cap = decodeCap(basic.pass);
    if (!cap) return send(res, 401, { error: 'invalid cert' });
    const { cert, chain } = cap;

    // (2) EL ACTA DEL PERFIL, que es quien dice qué puede cada llave. El papel ya no
    //     caduca por reloj: lleva el `seq` del acta con el que se emitió, y quien verifica
    //     necesita el acta para juzgarlo. Sin ella no se juzga y se dice por qué.
    if (!chain || !chain.length) return send(res, 401, { error: 'invalid cap', reason: 'sin-acta' });
    const { verifySealerChain } = await loadActa();
    const acta = await verifySealerChain(chain);
    if (!acta.ok) return send(res, 401, { error: 'invalid cap', reason: 'acta:' + acta.reason });

    // (2b) verifyDelegation: una selladora de ESE perfil avaló esta llave, con este scope,
    //      y no está revocada. `expectedScope` 'geo:publish' (publicar).
    const v = await verifyDelegation({ cert, expectedScope: 'geo:publish', revoked: isRevoked, actaSeq: acta.seq, sealers: acta.sealers });
    if (!v.ok) return send(res, 401, { error: 'invalid cap', reason: v.reason });

    // (2b) además el scope DEBE incluir 'geo:read:<circleId>' (leer a los amigos de ESTE círculo).
    if (!scopeIncludes(cert.scope, 'geo:read:' + circleId)) {
        return send(res, 401, { error: 'invalid cap', reason: 'scope-read-circle' });
    }

    // (3) ligadura criptográfica círculo↔dueño: el círculo es del PERFIL, no de una llave
    //     suelta. Se compara contra el `profileId` de la cadena —la llave del génesis, que
    //     no cambia nunca— y no contra quien firmó el papel: así el círculo sigue siendo
    //     tuyo aunque cambie quién sella. Una cap de otro perfil NO sirve para este círculo.
    let issuerId;
    try { issuerId = await pubkeyId(acta.profileId); }
    catch (_) { return send(res, 401, { error: 'invalid iss' }); }
    if (issuerId !== ownerId) {
        return send(res, 401, { error: 'invalid cap', reason: 'issuer-circle-mismatch' });
    }

    // memberId estable: id del dispositivo (sub del cert). El tid del body es solo cosmético.
    let memberId;
    try { memberId = await pubkeyId(cert.sub); }
    catch (_) { return send(res, 401, { error: 'invalid sub' }); }

    // --- body: un mensaje OwnTracks JSON (opaco). ---
    let body;
    try { body = await readBody(req); }
    catch (e) {
        const msg = e && e.message ? e.message : 'invalid body';
        return send(res, 400, { error: msg });
    }
    if (!body || typeof body !== 'object') return send(res, 400, { error: 'invalid body' });

    purge(now);

    let members = circles.get(circleId);
    if (!members) { members = new Map(); circles.set(circleId, members); }

    // El tid es cosmético/identificador de visualización; si viene, lo usamos como memberId
    // de display alternativo SOLO cuando no hay sub (no debería pasar, pero el contrato lo permite).
    const writeKey = memberId || (typeof body.tid === 'string' && body.tid ? 'tid:' + body.tid : null);

    // (Acción de publicación) Guardamos el ÚLTIMO blob del miembro, EFÍMERO + OVERWRITE.
    // Aceptamos _type:'encrypted' (posición cifrada) y _type:'card' (tarjeta). El bridge
    // jamás descifra: el blob viaja tal cual (opaco) a los demás miembros.
    // Canal CIFRADO: SOLO _type:'encrypted' (posición cifrada) o _type:'card' (tarjeta, metadato
    // no sensible). Rechazamos ubicación EN CLARO (_type:'location') para no romper el E2E del círculo.
    if (writeKey && (body._type === 'encrypted' || body._type === 'card')) {
        members.set(writeKey, { blob: body, expiresAt: now + HERE_TTL_MS });
    }

    // (Respuesta) ARRAY de los blobs MÁS RECIENTES de los OTROS miembros del MISMO círculo.
    // OwnTracks los descifra localmente (con la clave del círculo) y los pinta como amigos.
    const friends = [];
    for (const [otherId, entry] of members) {
        if (otherId === writeKey) continue;        // nunca me devuelvo a mí mismo
        if (entry.expiresAt <= now) continue;      // defensivo: ya purgado arriba
        friends.push(entry.blob);
        if (friends.length >= MAX_MEMBERS_RETURNED) break;
    }

    // OwnTracks HTTP-mode espera un ARRAY JSON de mensajes en la respuesta.
    return send(res, 200, friends);
}

module.exports = {
    handleHere,
    handleRevoke,
    purge,
    revoke,
    isRevoked,
    // Exportados para tests / herramientas:
    parseBasicAuth,
    decodeCap,
    HERE_TTL_MS,
    MAX_HERE_BODY,
    _circles: circles,
    _revokedNonces: revokedNonces
};
