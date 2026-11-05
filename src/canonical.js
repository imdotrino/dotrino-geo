/**
 * Serialización JSON canónica (claves ordenadas recursivamente).
 * Necesaria para que las firmas coincidan entre cliente y servidor.
 * Idéntica a la del proxy-client / proxy-server del ecosistema.
 *
 * Fuente ÚNICA dentro de este repo: el servidor la recibe copiada en
 * server/vendor/shared.js por `node vendor.mjs` (una prueba falla si se desincronizan).
 */
/**
 * @param {unknown} value
 * @returns {string}
 */
export function canonicalStringify (value) {
  if (value === null || typeof value !== 'object') {
    // `undefined` da undefined, como JSON.stringify: el tipo lo dice (igual que el original).
    return /** @type {string} */ (JSON.stringify(value))
  }
  if (Array.isArray(value)) {
    return '[' + value.map(canonicalStringify).join(',') + ']'
  }
  const keys = Object.keys(value).sort()
  const parts = keys.map(k => JSON.stringify(k) + ':' + canonicalStringify(/** @type {Record<string, unknown>} */ (value)[k]))
  return '{' + parts.join(',') + '}'
}
