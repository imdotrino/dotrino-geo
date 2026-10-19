/**
 * Normaliza etiquetas: lowercase, trim, slug unicode (letras/números/_/-), ≤32
 * chars, dedup, máx 10. Descarta las inválidas en silencio.
 *
 * Fuente ÚNICA: el servidor (CommonJS, imagen Docker con contexto ./server) la recibe
 * copiada en server/vendor/shared.js por `node vendor.mjs`, y una prueba falla si se
 * desincronizan.
 */
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
