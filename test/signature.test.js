// Verifica la interoperabilidad criptográfica entre el vault (WebCrypto, firma
// ECDSA "raw" r||s) y la verificación del servidor (Node crypto, ieee-p1363).
// Si este test pasa, los pins firmados en el navegador validan en geo.dotrino.com.

import { test } from 'node:test'
import assert from 'node:assert'
import { webcrypto } from 'node:crypto'
import { createRequire } from 'node:module'
import { encodeGeohash } from '../src/geohash.js'

const require = createRequire(import.meta.url)
const { verifyEnvelope, canonicalStringify, pubkeyId } = require('../server/signature.js')

const subtle = webcrypto.subtle

function b64 (bytes) {
  return Buffer.from(bytes).toString('base64')
}

async function makeIdentity () {
  const pair = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])
  const publicJwk = await subtle.exportKey('jwk', pair.publicKey)
  const publickey = JSON.stringify(publicJwk)
  async function signData (data) {
    const bytes = new TextEncoder().encode(canonicalStringify(data))
    const sig = await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, pair.privateKey, bytes)
    return b64(new Uint8Array(sig))
  }
  return { publickey, signData }
}

test('firma WebCrypto válida verifica en el servidor', async () => {
  const id = await makeIdentity()
  const data = {
    publickey: id.publickey,
    lat: -2.1709, lng: -79.9224,
    geohash: encodeGeohash(-2.1709, -79.9224, 7),
    payload: { role: 'driver' },
    issuedAt: 1700000000000,
    expiresAt: 1700000600000
  }
  const signature = await id.signData(data)
  assert.strictEqual(verifyEnvelope(data, signature), true)
})

test('data alterada NO verifica', async () => {
  const id = await makeIdentity()
  const data = { publickey: id.publickey, lat: 0, lng: 0, geohash: 's000', issuedAt: 1 }
  const signature = await id.signData(data)
  const tampered = { ...data, lat: 10 }
  assert.strictEqual(verifyEnvelope(tampered, signature), false)
})

test('otra identidad NO puede firmar por la primera', async () => {
  const a = await makeIdentity()
  const b = await makeIdentity()
  const data = { publickey: a.publickey, action: 'remove', issuedAt: 1 }
  const sigByB = await b.signData(data) // b firma datos que dicen ser de a
  assert.strictEqual(verifyEnvelope(data, sigByB), false)
})

test('pubkeyId es estable y distinto por identidad', async () => {
  const a = await makeIdentity()
  const b = await makeIdentity()
  assert.strictEqual(pubkeyId(a.publickey), pubkeyId(a.publickey))
  assert.notStrictEqual(pubkeyId(a.publickey), pubkeyId(b.publickey))
})

test('geohash de precisión creciente comparte prefijo', () => {
  const g7 = encodeGeohash(-2.1709, -79.9224, 7)
  const g5 = encodeGeohash(-2.1709, -79.9224, 5)
  assert.ok(g7.startsWith(g5))
  assert.strictEqual(g5.length, 5)
})
