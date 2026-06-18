/**
 * Geohash encode (base32, Gustavo Niemeyer). Se usa para descubrimiento por
 * "bucket" grueso sin exponer coordenadas exactas: publicás un geohash de
 * precisión baja (p.ej. 6 chars ≈ 1.2 km) y las coords finas se intercambian
 * P2P por el proxy recién tras consentimiento mutuo.
 *
 * Precisión aproximada por longitud:
 *   5 → ±2.4 km   6 → ±0.61 km   7 → ±0.076 km   8 → ±0.019 km
 */
const BASE32 = '0123456789bcdefghjkmnpqrstuvwxyz'

export function encodeGeohash (lat, lng, precision = 7) {
  let idx = 0
  let bit = 0
  let evenBit = true
  let geohash = ''
  let latMin = -90, latMax = 90
  let lngMin = -180, lngMax = 180

  while (geohash.length < precision) {
    if (evenBit) {
      const mid = (lngMin + lngMax) / 2
      if (lng >= mid) { idx = (idx << 1) + 1; lngMin = mid } else { idx = idx << 1; lngMax = mid }
    } else {
      const mid = (latMin + latMax) / 2
      if (lat >= mid) { idx = (idx << 1) + 1; latMin = mid } else { idx = idx << 1; latMax = mid }
    }
    evenBit = !evenBit
    if (++bit === 5) {
      geohash += BASE32[idx]
      bit = 0
      idx = 0
    }
  }
  return geohash
}
