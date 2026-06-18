'use strict';

// Verificación de sobres firmados {data, signature} del ecosistema Dotrino.
// La identidad es una clave ECDSA P-256 (del vault id.dotrino.com) en formato
// JWK string, embebida en `data.publickey`. La firma es ECDSA-SHA256 sobre la
// serialización canónica de `data`, en base64.
//
// A diferencia del proxy (que en error de verificación devolvía `true` como
// atajo de dev), acá la verificación es estricta: si algo falla, es inválido.

const crypto = require('node:crypto');

function canonicalStringify(value) {
    if (value === null || typeof value !== 'object') {
        return JSON.stringify(value);
    }
    if (Array.isArray(value)) {
        return '[' + value.map(canonicalStringify).join(',') + ']';
    }
    const keys = Object.keys(value).sort();
    return '{' + keys.map(k => JSON.stringify(k) + ':' + canonicalStringify(value[k])).join(',') + '}';
}

/**
 * @param {object} data        objeto firmado; debe incluir data.publickey (JWK string)
 * @param {string} signatureB64 firma base64
 * @returns {boolean}
 */
function verifyEnvelope(data, signatureB64) {
    try {
        if (!data || typeof data !== 'object') return false;
        if (typeof data.publickey !== 'string') return false;
        if (typeof signatureB64 !== 'string' || signatureB64.length < 10) return false;

        const jwk = JSON.parse(data.publickey);
        if (jwk.kty !== 'EC' || jwk.crv !== 'P-256' || !jwk.x || !jwk.y) return false;

        const keyObject = crypto.createPublicKey({
            key: { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y },
            format: 'jwk'
        });

        const dataStr = canonicalStringify(data);
        // WebCrypto firma ECDSA produce firmas "raw" (r||s, 64 bytes), no DER.
        const sig = Buffer.from(signatureB64, 'base64');

        return crypto.verify(
            'sha256',
            Buffer.from(dataStr, 'utf8'),
            { key: keyObject, dsaEncoding: 'ieee-p1363' },
            sig
        );
    } catch (_) {
        return false;
    }
}

/**
 * Identificador estable y corto de una identidad (para PK de fila): SHA-256 del
 * JWK pubkey canónico, en hex. Evita usar el JWK entero (largo) como clave.
 */
function pubkeyId(publickeyJwkString) {
    try {
        const jwk = JSON.parse(publickeyJwkString);
        const canon = canonicalStringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y });
        return crypto.createHash('sha256').update(canon).digest('hex');
    } catch (_) {
        return crypto.createHash('sha256').update(String(publickeyJwkString)).digest('hex');
    }
}

module.exports = { verifyEnvelope, canonicalStringify, pubkeyId };
