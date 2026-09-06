// PARA QUIÉN es un pin. Sin destinatario, la misma firma servía en este índice y en
// cualquier otro servicio del ecosistema que verificara igual: `verifyEnvelope` solo
// pregunta si la firma cuadra, no si el sobre venía a esta puerta.
//
// El cliente pone `aud` con el origen del `baseUrl` (autohospedar cambia el destinatario,
// y debe), y el servidor lo comprueba antes que la firma.

import { test } from 'node:test'
import assert from 'node:assert'
import { createGeoClient } from '../src/index.js'

const GEO = 'https://geo.dotrino.com'

/** Un cliente que no llega a la red: guarda lo que habría enviado. */
function clienteDePrueba (baseUrl = GEO) {
  const enviado = []
  const client = createGeoClient({
    baseUrl,
    getPublicKeyJwk: async () => '{"kty":"EC","crv":"P-256","x":"x","y":"y"}',
    signData: async () => ({ signature: 'firma', publickey: '{"kty":"EC"}', chain: [{ seq: 1 }] }),
    fetch: async (url, opts) => {
      enviado.push({ url, body: JSON.parse(opts.body), method: opts.method })
      return { ok: true, status: 200, json: async () => ({ ok: true }) }
    }
  })
  return { client, enviado }
}

test('el pin dice para quién es, y sale del baseUrl', async () => {
  const { client, enviado } = clienteDePrueba()
  await client.publishPin({ lat: -2.17, lng: -79.92 })
  assert.strictEqual(enviado[0].body.data.aud, GEO)
})

test('autohospedar cambia el destinatario', async () => {
  const { client, enviado } = clienteDePrueba('https://geo.miempresa.com/')
  await client.publishPin({ lat: 0, lng: 0 })
  assert.strictEqual(enviado[0].body.data.aud, 'https://geo.miempresa.com',
    'un pin firmado para el índice de la empresa no puede valer ante el nuestro')
})

test('retirar el pin manda la FIRMA, no el paquete entero', async () => {
  const { client, enviado } = clienteDePrueba()
  await client.removePin()
  const { data, signature, signer, chain } = enviado[0].body
  assert.strictEqual(enviado[0].method, 'DELETE')
  assert.strictEqual(data.aud, GEO)
  // Antes iba el objeto `{signature, publickey, chain}` donde el servidor espera la firma
  // en base64, así que retirar un pin respondía 401 siempre.
  assert.strictEqual(typeof signature, 'string')
  assert.strictEqual(signature, 'firma')
  assert.strictEqual(signer, '{"kty":"EC"}', 'y con quién firmó')
  assert.deepStrictEqual(chain, [{ seq: 1 }], 'y su cadena: se puede retirar desde otro aparato de la cuenta')
})

test('un baseUrl que no es una URL revienta al crear el cliente, no al publicar', () => {
  assert.throws(() => clienteDePrueba('esto-no-es-una-url'))
})
