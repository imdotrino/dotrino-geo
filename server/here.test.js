'use strict';

// Tests del bridge CERRADO de "here" (server/here.js).
//
// Cubre el contrato:
//   (a) publica ok con cap válida; otro miembro del MISMO círculo recibe el blob;
//   (b) SIN cap (sin Authorization / Basic malformado) → 401;
//   (c) cap de OTRO círculo / OTRO issuer → 401 (no escribe ni lee);
//   (d) cert expirado → 401; cert revocado → 401;
//   (e) el blob es OPACO: el bridge nunca lo descifra (lo devuelve tal cual).
//
// Identidad: import RELATIVO al paquete del ecosistema (no requiere npm link).

const test = require('node:test');
const assert = require('node:assert/strict');

// --- carga ESM (identity Node adapter + capabilities) desde este test CJS ---
const ID_BASE = '../../dotrino-identity';
let Identity, makeDeviceKey, signWithDevice, pubkeyId;

async function loadIdentity() {
    if (Identity) return;
    const node = await import(ID_BASE + '/src/node.js');
    const caps = await import(ID_BASE + '/vault/capabilities.js');
    Identity = node.Identity;
    makeDeviceKey = caps.makeDeviceKey;
    signWithDevice = caps.signWithDevice;
    pubkeyId = caps.pubkeyId;
}

const here = require('./here.js');

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

// --- helpers de simulación HTTP (no levantamos el server; llamamos handleHere directo) ---

function basicHeader(circleId, cert) {
    const pass = Buffer.from(JSON.stringify(cert), 'utf8').toString('base64url');
    const raw = Buffer.from(`${circleId}:${pass}`, 'utf8').toString('base64');
    return 'Basic ' + raw;
}

// req simulado: solo necesitamos headers (handleHere lee req.headers['authorization']).
function fakeReq(authHeader) {
    return { headers: authHeader ? { authorization: authHeader } : {}, method: 'POST' };
}

// readBody inyectado: devuelve un body fijo (el server real lo parsea del stream;
// el contrato de handleHere recibe readBody como parámetro, así que lo simulamos).
function readBodyOf(body) {
    return async () => body;
}

// send inyectado: captura status + payload.
function captureSend() {
    const out = { status: null, body: null, headers: null };
    out.send = (res, status, obj, extraHeaders) => {
        out.status = status; out.body = obj; out.headers = extraHeaders || null;
    };
    return out;
}

// Owner identity en un directorio temporal único (cada test su propio "usuario").
async function makeOwner() {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'here-owner-'));
    const id = await Identity.connect({ dir });
    // El master pubkey (JWK string) sale firmando algo: signData devuelve { publickey }.
    const { publickey } = await id.signData({ probe: 1 });
    const ownerId = await pubkeyId(publickey);
    return { id, dir, masterPubkey: publickey, ownerId };
}

// Emite un cert a un dispositivo para un círculo, con scopes geo:publish + geo:read:<circleId>.
async function issueCert(owner, circleId, { ttlMs, exp } = {}) {
    const device = await makeDeviceKey({ label: 'owntracks' });
    const scope = ['geo:publish', 'geo:read:' + circleId];
    const opts = {};
    if (typeof ttlMs === 'number') opts.ttlMs = ttlMs;
    if (typeof exp === 'number') opts.exp = exp;
    const { cert } = await owner.id.signDelegation(device.publickey, scope, opts);
    return { device, cert };
}

// limpia el store en memoria entre tests (es un módulo singleton).
function resetStore() {
    here._circles.clear();
    here._revokedNonces.clear();
}

test.before(loadIdentity);
test.beforeEach(resetStore);

test('publica ok y otro miembro del círculo recibe el blob OPACO', async () => {
    const owner = await makeOwner();
    const circleId = owner.ownerId + ':familia';

    // miembro A publica su posición cifrada
    const a = await issueCert(owner, circleId);
    const blobA = { _type: 'encrypted', data: 'AAAA-ciphertext-de-A' };
    {
        const cap = captureSend();
        await here.handleHere(fakeReq(basicHeader(circleId, a.cert)), {}, Date.now(),
            readBodyOf(blobA), cap.send);
        assert.equal(cap.status, 200, 'A publica ok');
        assert.ok(Array.isArray(cap.body), 'respuesta es array');
        assert.equal(cap.body.length, 0, 'A no se ve a sí mismo y no hay otros aún');
    }

    // miembro B del MISMO círculo publica → debe recibir el blob de A (tal cual, opaco)
    const b = await issueCert(owner, circleId);
    const blobB = { _type: 'encrypted', data: 'BBBB-ciphertext-de-B' };
    {
        const cap = captureSend();
        await here.handleHere(fakeReq(basicHeader(circleId, b.cert)), {}, Date.now(),
            readBodyOf(blobB), cap.send);
        assert.equal(cap.status, 200, 'B publica ok');
        assert.ok(Array.isArray(cap.body));
        assert.equal(cap.body.length, 1, 'B ve a A');
        const seen = cap.body[0];
        // OPACO: el bridge devuelve el blob idéntico, sin descifrar ni mutar.
        assert.deepEqual(seen, blobA, 'el blob de A llega intacto (opaco)');
        assert.equal(seen.data, 'AAAA-ciphertext-de-A');
        assert.ok(!('lat' in seen) && !('lon' in seen), 'el bridge no expone coordenadas');
    }

    // y A, al re-publicar, ahora ve a B (overwrite + lectura cruzada)
    {
        const cap = captureSend();
        await here.handleHere(fakeReq(basicHeader(circleId, a.cert)), {}, Date.now(),
            readBodyOf(blobA), cap.send);
        assert.equal(cap.status, 200);
        assert.equal(cap.body.length, 1, 'A ahora ve a B');
        assert.deepEqual(cap.body[0], blobB);
    }
});

test('SIN cap (sin Authorization) → 401, no escribe ni lee', async () => {
    const owner = await makeOwner();
    const circleId = owner.ownerId + ':familia';
    const cap = captureSend();
    await here.handleHere(fakeReq(null), {}, Date.now(),
        readBodyOf({ _type: 'encrypted', data: 'x' }), cap.send);
    assert.equal(cap.status, 401, 'sin auth → 401');
    assert.equal(here._circles.size, 0, 'no creó ningún círculo');
});

test('Basic malformado / cert ilegible → 401', async () => {
    const cap = captureSend();
    await here.handleHere(fakeReq('Basic not-base64-:::'), {}, Date.now(),
        readBodyOf({ _type: 'encrypted', data: 'x' }), cap.send);
    assert.equal(cap.status, 401);
});

test('cap de OTRO círculo (mismo dueño, otro slug) → 401', async () => {
    const owner = await makeOwner();
    const circleId = owner.ownerId + ':familia';
    const otherCircle = owner.ownerId + ':trabajo';
    // cert emitido para "trabajo" (scope geo:read:<trabajo>), pero lo presentamos al círculo "familia"
    const c = await issueCert(owner, otherCircle);
    const cap = captureSend();
    await here.handleHere(fakeReq(basicHeader(circleId, c.cert)), {}, Date.now(),
        readBodyOf({ _type: 'encrypted', data: 'x' }), cap.send);
    assert.equal(cap.status, 401, 'scope geo:read:<otroCírculo> no autoriza este círculo');
    assert.equal(here._circles.size, 0, 'no escribió');
});

test('cap de OTRO issuer (otro dueño) para un circleId ajeno → 401', async () => {
    const ownerA = await makeOwner();
    const ownerB = await makeOwner();
    // circleId pertenece a A (prefijo = pubkeyId(A.master))
    const circleId = ownerA.ownerId + ':familia';
    // pero B emite un cert con scope geo:read:<circleId-de-A> (intento de suplantar)
    const c = await issueCert(ownerB, circleId);
    const cap = captureSend();
    await here.handleHere(fakeReq(basicHeader(circleId, c.cert)), {}, Date.now(),
        readBodyOf({ _type: 'encrypted', data: 'x' }), cap.send);
    assert.equal(cap.status, 401, 'pubkeyId(cert.iss) !== prefijo del circleId → 401');
    assert.equal(here._circles.size, 0, 'no escribió');
});

test('cert EXPIRADO → 401', async () => {
    const owner = await makeOwner();
    const circleId = owner.ownerId + ':familia';
    // exp en el pasado, MÁS ALLÁ del skew tolerado por el bridge (si no, 5 min de gracia lo admitiría)
    const past = Date.now() - here.HERE_SKEW_MS - 60 * 1000;
    const c = await issueCert(owner, circleId, { exp: past });
    const cap = captureSend();
    await here.handleHere(fakeReq(basicHeader(circleId, c.cert)), {}, Date.now(),
        readBodyOf({ _type: 'encrypted', data: 'x' }), cap.send);
    assert.equal(cap.status, 401, 'cert vencido → 401');
    assert.equal(here._circles.size, 0, 'no escribió');
});

test('cert REVOCADO → 401', async () => {
    const owner = await makeOwner();
    const circleId = owner.ownerId + ':familia';
    const c = await issueCert(owner, circleId);
    // el bridge consulta su feed de revocación en memoria
    here.revoke(c.cert.nonce);
    const cap = captureSend();
    await here.handleHere(fakeReq(basicHeader(circleId, c.cert)), {}, Date.now(),
        readBodyOf({ _type: 'encrypted', data: 'x' }), cap.send);
    assert.equal(cap.status, 401, 'cert revocado → 401');
    assert.equal(here._circles.size, 0, 'no escribió');
});

test('cross-círculo: dos círculos del mismo dueño NO se ven entre sí', async () => {
    const owner = await makeOwner();
    const circle1 = owner.ownerId + ':familia';
    const circle2 = owner.ownerId + ':amigos';

    const a = await issueCert(owner, circle1);
    const cap1 = captureSend();
    await here.handleHere(fakeReq(basicHeader(circle1, a.cert)), {}, Date.now(),
        readBodyOf({ _type: 'encrypted', data: 'fam' }), cap1.send);
    assert.equal(cap1.status, 200);

    const b = await issueCert(owner, circle2);
    const cap2 = captureSend();
    await here.handleHere(fakeReq(basicHeader(circle2, b.cert)), {}, Date.now(),
        readBodyOf({ _type: 'encrypted', data: 'amg' }), cap2.send);
    assert.equal(cap2.status, 200);
    assert.equal(cap2.body.length, 0, 'el círculo "amigos" no ve presencias de "familia"');
});

// --- /here/revoke: sobre {data, signature} firmado por el DUEÑO ---------------
// data lleva publickey EMBEBIDO (lo exige verifyEnvelope del server). signData
// firma el JSON canónico de data y devuelve { signature, publickey }.
async function signedRevokeEnvelope(signerId, circleId, nonce, { issuedAt } = {}) {
    const { publickey } = await signerId.signData({ probe: 1 });
    const data = { op: 'revoke', circleId, nonce, issuedAt: issuedAt ?? Date.now(), publickey };
    const { signature } = await signerId.signData(data);
    return { data, signature };
}

test('/here/revoke: firma del DUEÑO revoca el nonce (200 + isRevoked)', async () => {
    const owner = await makeOwner();
    const circleId = owner.ownerId + ':familia';
    const c = await issueCert(owner, circleId);
    const nonce = c.cert.nonce;

    assert.equal(here.isRevoked(nonce), false, 'arranca no revocado');

    const env = await signedRevokeEnvelope(owner.id, circleId, nonce);
    const cap = captureSend();
    await here.handleRevoke({ headers: {}, method: 'POST' }, {}, Date.now(),
        readBodyOf(env), cap.send);
    assert.equal(cap.status, 200, 'firma válida del dueño → 200');
    assert.equal(cap.body && cap.body.ok, true);
    assert.equal(here.isRevoked(nonce), true, 'el nonce queda en el feed de revocación');
});

test('/here/revoke: tras revocar, el cert ya NO puede publicar en /here (401)', async () => {
    const owner = await makeOwner();
    const circleId = owner.ownerId + ':familia';
    const c = await issueCert(owner, circleId);

    // publica ok ANTES de revocar
    {
        const cap = captureSend();
        await here.handleHere(fakeReq(basicHeader(circleId, c.cert)), {}, Date.now(),
            readBodyOf({ _type: 'encrypted', data: 'x' }), cap.send);
        assert.equal(cap.status, 200, 'antes de revocar publica ok');
    }

    // el dueño revoca por el endpoint firmado
    {
        const env = await signedRevokeEnvelope(owner.id, circleId, c.cert.nonce);
        const cap = captureSend();
        await here.handleRevoke({ headers: {}, method: 'POST' }, {}, Date.now(),
            readBodyOf(env), cap.send);
        assert.equal(cap.status, 200);
    }

    // ahora /here lo rechaza (cap revocado → 401)
    {
        const cap = captureSend();
        await here.handleHere(fakeReq(basicHeader(circleId, c.cert)), {}, Date.now(),
            readBodyOf({ _type: 'encrypted', data: 'y' }), cap.send);
        assert.equal(cap.status, 401, 'cert revocado → 401 end-to-end');
    }
});

test('/here/revoke: firma de OTRO (no el dueño) → 403, no revoca', async () => {
    const owner = await makeOwner();
    const attacker = await makeOwner();
    const circleId = owner.ownerId + ':familia';
    const c = await issueCert(owner, circleId);
    const nonce = c.cert.nonce;

    // attacker firma un sobre que dice revocar el círculo del owner
    const env = await signedRevokeEnvelope(attacker.id, circleId, nonce);
    const cap = captureSend();
    await here.handleRevoke({ headers: {}, method: 'POST' }, {}, Date.now(),
        readBodyOf(env), cap.send);
    assert.equal(cap.status, 403, 'pubkeyId(firmante) !== dueño del circleId → 403');
    assert.equal(here.isRevoked(nonce), false, 'NO revocó');
});

test('/here/revoke: firma manipulada / inválida → 401, no revoca', async () => {
    const owner = await makeOwner();
    const circleId = owner.ownerId + ':familia';
    const c = await issueCert(owner, circleId);
    const nonce = c.cert.nonce;

    const env = await signedRevokeEnvelope(owner.id, circleId, nonce);
    // manoseamos el data DESPUÉS de firmar → la firma deja de validar
    env.data.nonce = 'otro-nonce-cualquiera';
    const cap = captureSend();
    await here.handleRevoke({ headers: {}, method: 'POST' }, {}, Date.now(),
        readBodyOf(env), cap.send);
    assert.equal(cap.status, 401, 'firma no corresponde a data → 401');
    assert.equal(here.isRevoked(nonce), false, 'NO revocó el original');
    assert.equal(here.isRevoked('otro-nonce-cualquiera'), false, 'NO revocó el manipulado');
});

test('/here/revoke: body sin op:"revoke" o circleId malformado → 400', async () => {
    const owner = await makeOwner();
    const circleId = owner.ownerId + ':familia';
    // op incorrecta
    {
        const env = await signedRevokeEnvelope(owner.id, circleId, 'n1');
        env.data.op = 'nope';
        const cap = captureSend();
        await here.handleRevoke({ headers: {}, method: 'POST' }, {}, Date.now(),
            readBodyOf(env), cap.send);
        assert.equal(cap.status, 400, 'op != revoke → 400');
    }
    // circleId sin ':'
    {
        const cap = captureSend();
        await here.handleRevoke({ headers: {}, method: 'POST' }, {}, Date.now(),
            readBodyOf({ data: { op: 'revoke', circleId: 'sindospuntos', nonce: 'n', publickey: 'x' }, signature: 'AAAAAAAAAA' }),
            cap.send);
        assert.equal(cap.status, 400, 'circleId malformado → 400');
    }
});

test('TTL: un blob expirado no se devuelve a otro miembro', async () => {
    const owner = await makeOwner();
    const circleId = owner.ownerId + ':familia';

    const a = await issueCert(owner, circleId);
    const t0 = a.cert.iat;   // base = cuándo el cert pasó a ser válido (evita now < iat)
    const capA = captureSend();
    await here.handleHere(fakeReq(basicHeader(circleId, a.cert)), {}, t0,
        readBodyOf({ _type: 'encrypted', data: 'vieja' }), capA.send);
    assert.equal(capA.status, 200);

    // B publica MUCHO después → el blob de A ya expiró (TTL) y no debe verse
    const b = await issueCert(owner, circleId);
    const capB = captureSend();
    const later = t0 + here.HERE_TTL_MS + 1000;
    await here.handleHere(fakeReq(basicHeader(circleId, b.cert)), {}, later,
        readBodyOf({ _type: 'encrypted', data: 'nueva' }), capB.send);
    assert.equal(capB.status, 200);
    assert.equal(capB.body.length, 0, 'el blob de A expiró por TTL');
});
