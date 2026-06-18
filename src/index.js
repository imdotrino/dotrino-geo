/**
 * @dotrino/geo — cliente del índice geo `geo.dotrino.com`.
 *
 * Cuarto pilar del ecosistema: DESCUBRIMIENTO georreferenciado. Una identidad
 * publica un pin firmado (lat/lng + payload) con TTL corto; cualquiera puede
 * consultar pins dentro de un radio. PostGIS hace la query espacial.
 *
 * REGLAS DEL ECOSISTEMA QUE RESPETA:
 *  - Identidad = el vault (`id.dotrino.com`). Este cliente NO genera ni guarda
 *    claves: recibe `signData` y `getPublicKeyJwk` inyectados desde
 *    `@dotrino/identity` (única fuente de identidad). Mismo
 *    patrón de sobre firmado `{data, signature}` que el proxy-client.
 *  - Transporte = el proxy. Este índice es SOLO descubrimiento. Una vez que
 *    encontrás al peer cercano, el handshake y la ubicación en vivo van por
 *    `@dotrino/proxy-client` (sendByPubkey / canal / WebRTC).
 *    NO hagas streaming de posición a alta frecuencia contra este índice.
 *  - Privacidad: un pin por identidad (upsert: overwrite, sin historial), TTL
 *    corto, y geohash grueso para descubrimiento. Publicar es siempre opt-in.
 */

import { canonicalStringify } from './canonical.js'
import { encodeGeohash } from './geohash.js'

export { encodeGeohash } from './geohash.js'

const DEFAULT_BASE = 'https://geo.dotrino.com'
const DEFAULT_TTL_MS = 10 * 60 * 1000 // 10 min: pins efímeros por diseño

/**
 * Crea un cliente del índice geo.
 *
 * @param {object} opts
 * @param {(data:object)=>Promise<string>} opts.signData   firma canónica → base64 (del vault)
 * @param {()=>Promise<string>} opts.getPublicKeyJwk        pubkey JWK string (del vault)
 * @param {string} [opts.baseUrl]                           default https://geo.dotrino.com
 * @param {typeof fetch} [opts.fetch]                       fetch inyectable (tests/SSR)
 */
export function createGeoClient ({ signData, getPublicKeyJwk, baseUrl = DEFAULT_BASE, fetch: f } = {}) {
  if (typeof signData !== 'function' || typeof getPublicKeyJwk !== 'function') {
    throw new Error('dotrino-geo: signData y getPublicKeyJwk son requeridos (inyectalos desde el vault de identidad)')
  }
  const doFetch = f || (typeof fetch !== 'undefined' ? fetch.bind(globalThis) : null)
  if (!doFetch) throw new Error('dotrino-geo: no hay fetch disponible; inyectalo en opts.fetch')
  const base = baseUrl.replace(/\/+$/, '')

  /**
   * Publica (o reemplaza) el pin de esta identidad.
   * Upsert por pubkey: SIEMPRE pisa el pin anterior — no se guarda historial.
   *
   * @param {object} p
   * @param {number} p.lat
   * @param {number} p.lng
   * @param {object} [p.payload]          datos de app (rol, capacidad, etc). Mantenelo chico.
   * @param {string[]} [p.tags]           etiquetas para búsqueda (máx 10, slug ≤32). Se buscan por overlap.
   * @param {number} [p.ttlMs]            vida del pin (default 10 min)
   * @param {number} [p.geohashPrecision] precisión del geohash público (default 7)
   * @returns {Promise<{ok:true, expiresAt:number, geohash:string}>}
   */
  async function publishPin ({ lat, lng, payload = {}, tags, ttlMs = DEFAULT_TTL_MS, geohashPrecision = 7, now } = {}) {
    assertLatLng(lat, lng)
    const publickey = await getPublicKeyJwk()
    const ts = now ?? Date.now()
    const data = {
      publickey,
      lat: round(lat, 6),
      lng: round(lng, 6),
      geohash: encodeGeohash(lat, lng, geohashPrecision),
      payload,
      issuedAt: ts,
      expiresAt: ts + ttlMs
    }
    const cleanTags = normalizeTags(tags)
    if (cleanTags.length) data.tags = cleanTags
    const signature = await signData(data)
    const res = await doFetch(`${base}/pins`, {
      method: 'PUT',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ data, signature })
    })
    return handle(res)
  }

  /**
   * Consulta pins dentro de un radio. NO requiere firma (lectura pública).
   *
   * @param {object} q
   * @param {number} q.lat
   * @param {number} q.lng
   * @param {number} q.radiusMeters
   * @param {number} [q.limit]   default 50, máx 200
   * @param {string} [q.filter]  JSON string opcional para filtrar por payload (igualdad exacta de claves)
   * @param {string[]} [q.tags]  buscar pins que tengan ALGUNA de estas etiquetas (overlap)
   * @returns {Promise<{pins:Array<{publickey,lat,lng,geohash,payload,tags,distanceMeters,expiresAt}>}>}
   */
  async function queryRadius ({ lat, lng, radiusMeters, limit = 50, filter, tags } = {}) {
    assertLatLng(lat, lng)
    if (!(radiusMeters > 0)) throw new Error('dotrino-geo: radiusMeters debe ser > 0')
    const params = new URLSearchParams({
      lat: String(lat), lng: String(lng), r: String(radiusMeters), limit: String(limit)
    })
    if (filter) params.set('filter', typeof filter === 'string' ? filter : JSON.stringify(filter))
    const cleanTags = normalizeTags(tags)
    if (cleanTags.length) params.set('tags', cleanTags.join(','))
    const res = await doFetch(`${base}/pins?${params.toString()}`)
    return handle(res)
  }

  /**
   * Retira el pin de esta identidad antes de que expire (firma un tombstone).
   * @returns {Promise<{ok:true}>}
   */
  async function removePin ({ now } = {}) {
    const publickey = await getPublicKeyJwk()
    const data = { publickey, action: 'remove', issuedAt: now ?? Date.now() }
    const signature = await signData(data)
    const res = await doFetch(`${base}/pins`, {
      method: 'DELETE',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ data, signature })
    })
    return handle(res)
  }

  return { publishPin, queryRadius, removePin }
}

// ----- helpers -----------------------------------------------------------

function assertLatLng (lat, lng) {
  if (typeof lat !== 'number' || lat < -90 || lat > 90) throw new Error('dotrino-geo: lat inválida')
  if (typeof lng !== 'number' || lng < -180 || lng > 180) throw new Error('dotrino-geo: lng inválida')
}

function round (n, decimals) {
  const f = Math.pow(10, decimals)
  return Math.round(n * f) / f
}

// Normaliza etiquetas: lowercase, trim, slug unicode (letras/números/_/-), ≤32
// chars, dedup, máx 10. Descarta las inválidas en silencio.
export function normalizeTags (tags) {
  if (!Array.isArray(tags)) return []
  const out = []
  for (const t of tags) {
    if (typeof t !== 'string') continue
    const s = t.trim().toLowerCase()
    if (!/^[\p{L}\p{N}_-]{1,32}$/u.test(s)) continue
    if (!out.includes(s)) out.push(s)
    if (out.length >= 10) break
  }
  return out
}

async function handle (res) {
  let body = null
  try { body = await res.json() } catch (_) {}
  if (!res.ok) {
    const msg = (body && body.error) || `HTTP ${res.status}`
    throw new Error(`dotrino-geo: ${msg}`)
  }
  return body
}

export { canonicalStringify }
