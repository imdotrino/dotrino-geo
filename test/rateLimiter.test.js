// Token bucket por IP: ráfaga hasta capacity, luego 429 con retry-after, y
// recarga con el tiempo. `now` se inyecta para que sea determinista.

import { test } from 'node:test'
import assert from 'node:assert'
import { createRequire } from 'node:module'

const require = createRequire(import.meta.url)
// Config de prueba acotada vía env ANTES de requerir el módulo.
process.env.GEO_RL_READ_PER_MIN = '60' // 1/s sostenido, ráfaga 60
process.env.GEO_RL_WRITE_PER_MIN = '6'
const rl = require('../server/rateLimiter.js')

test('clientIp prioriza el primer hop de X-Forwarded-For', () => {
  const req = { headers: { 'x-forwarded-for': '203.0.113.7, 10.0.0.1' }, socket: { remoteAddress: '127.0.0.1' } }
  assert.strictEqual(rl.clientIp(req), '203.0.113.7')
})

test('clientIp cae al socket si no hay XFF', () => {
  const req = { headers: {}, socket: { remoteAddress: '198.51.100.9' } }
  assert.strictEqual(rl.clientIp(req), '198.51.100.9')
})

test('permite la ráfaga hasta capacity y luego 429', () => {
  const ip = '203.0.113.10'
  const t0 = 1_000_000
  let allowed = 0
  for (let i = 0; i < 60; i++) {
    if (rl.take('read', ip, t0).allowed) allowed++
  }
  assert.strictEqual(allowed, 60) // toda la ráfaga pasa
  const next = rl.take('read', ip, t0)
  assert.strictEqual(next.allowed, false) // el 61 se deniega
  assert.ok(next.retryAfter >= 1) // y dice cuándo reintentar
})

test('recarga con el tiempo (1 token/s a 60/min)', () => {
  const ip = '203.0.113.11'
  const t0 = 2_000_000
  for (let i = 0; i < 60; i++) rl.take('read', ip, t0) // agota
  assert.strictEqual(rl.take('read', ip, t0).allowed, false)
  // 2 s después hay ~2 tokens
  assert.strictEqual(rl.take('read', ip, t0 + 2000).allowed, true)
  assert.strictEqual(rl.take('read', ip, t0 + 2000).allowed, true)
  assert.strictEqual(rl.take('read', ip, t0 + 2000).allowed, false)
})

test('read y write son cubetas independientes', () => {
  const ip = '203.0.113.12'
  const t0 = 3_000_000
  for (let i = 0; i < 6; i++) assert.ok(rl.take('write', ip, t0).allowed)
  assert.strictEqual(rl.take('write', ip, t0).allowed, false) // write agotado
  assert.strictEqual(rl.take('read', ip, t0).allowed, true)   // read intacto
})

test('IPs distintas no se afectan entre sí', () => {
  const t0 = 4_000_000
  for (let i = 0; i < 60; i++) rl.take('read', 'a', t0)
  assert.strictEqual(rl.take('read', 'a', t0).allowed, false)
  assert.strictEqual(rl.take('read', 'b', t0).allowed, true)
})
