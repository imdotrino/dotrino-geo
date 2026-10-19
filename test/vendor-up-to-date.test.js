// El servidor lleva copiadas (server/vendor/shared.js) las funciones que comparte con el
// cliente. Si alguien toca src/ y no corre `node vendor.mjs`, esto falla.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { createRequire } from 'node:module'
import { render, TARGET } from '../vendor.mjs'
import { canonicalStringify, normalizeTags } from '../src/index.js'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')
const require = createRequire(import.meta.url)

test('server/vendor/shared.js is up to date with src/ (run `node vendor.mjs`)', () => {
  assert.equal(readFileSync(join(root, TARGET), 'utf8'), render())
})

test('the server and the client produce the same bytes', () => {
  const shared = require('../server/vendor/shared.js')
  const sample = { b: [1, { z: null, a: 'á' }], a: true, publickey: '{"x":1}' }
  assert.equal(shared.canonicalStringify(sample), canonicalStringify(sample))
  const tags = [' Pizza ', 'pizza', 'no spaces', 'café', 'x'.repeat(33)]
  assert.deepEqual(shared.normalizeTags(tags), normalizeTags(tags))
})
