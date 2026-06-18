# Apps sobre el servicio GEO — roadmap

Apps que consumen `@dotrino/geo` (`geo.dotrino.com`). Todas
comparten el **mismo esqueleto**: mapa/proximidad + publicar pin firmado +
listar por radio + tap → contacto por el **messenger/proxy**. El pin es un
**anuncio efímero** (≤24h, overwrite, sin historial); el trato real ocurre en el
transporte, no en el índice. Identidad y firma salen del vault (`id.dotrino.com`).

## Estado

| # | App | Estado |
|---|-----|--------|
| 2 | **Cerca / Trueque** | **En desarrollo** (primera, estrena el pilar) |
| 1 | Pickup (deporte ahora) | Documentada — pendiente |
| 3 | Mano (ayuda cerca) | Documentada — pendiente |
| 4 | Uber clásico (viajes) | Documentada — pendiente |

---

## 2. Cerca / Trueque — clasificados efímeros geolocalizados  ⭐ primera

**Qué es:** publicás un anuncio georreferenciado — *"vendo bici, a 300 m"*,
*"regalo cajas de mudanza"*, *"busco torno por unas horas"* — que vive ≤24h.
La gente cerca lo ve y el trato se cierra por el messenger.

- **payload del pin:** `{ kind: 'vendo'|'regalo'|'busco', title, price?, emoji? }`
  (texto corto; nada de datos personales).
- **descubrir:** `queryRadius` con el radio que elija el usuario; filtro por `kind`.
- **contactar:** tap en un anuncio → `sendByPubkey([pin.publickey], …)` abre hilo
  en el messenger (o deep-link a `messenger.dotrino.com`).
- **publicar:** un pin por identidad activo (overwrite). Para varios anuncios a la
  vez, ver "Extensión futura" abajo.
- **mapa:** vista **radar/proximidad sin tiles de terceros** (privacidad): dibuja
  los pines como puntos alrededor del usuario por distancia+rumbo, en canvas.
  (Un mapa real Leaflet+OSM queda como toggle opcional con aviso: el tile-server
  vería el viewport.)

## 1. Pickup — deporte de barrio, ahora

**Qué es:** *"Faltan 2 para vóley en la cancha del parque, en 30 min"*. Gente
cerca lo ve, se suma por messenger, y al arrancar abren el **Contador
Ecuavóley/Pádel** que ya existe en el ecosistema.

- **payload:** `{ sport, needed, when, place }`.
- **Sinergia máxima:** handoff a los contadores existentes; reputación
  (web-of-trust de identity) para filtrar a quien siempre falla.
- Lo efímero calza perfecto: el partido es "ahora".

## 3. Mano — pedir/ofrecer ayuda cerca

**Qué es:** ayuda puntual cercana — arrancar un auto, prestar una herramienta,
mascota perdida, *"soy enfermero y hay una urgencia acá"*.

- **payload:** `{ kind: 'pido'|'ofrezco', need, urgent? }`.
- **Confianza:** apoyarse fuerte en ratings de identity (web-of-trust).
- Posible modo "urgente" con radio más amplio.

## 4. Uber clásico — viajes / mandados

**Qué es:** el caso original. Pasajero publica origen; conductores cerca ven y
ofertan; se coordina por proxy y la ubicación en vivo va por WebRTC/proxy
(NO por el índice geo).

- El más pesado: matching en vivo, estados (buscando/aceptado/en curso),
  tarifa/acuerdo. Conviene hacerlo **después** de validar el esqueleto con las
  apps simples.
- Reglas: streaming de posición en vivo = transporte (proxy), no geo. El pin geo
  solo anuncia "disponible/buscando".

---

## Extensión futura del servicio (si una app lo pide)

- **Varios pines por identidad** (hoy: upsert 1 por pubkey). Para apps tipo
  marketplace con varios anuncios simultáneos, habría que extender geo a
  `pins(pubkey, slot)` o por id de anuncio firmado. Implementarlo **en el paquete**
  (no en la app), versionando. Ver `CLAUDE.md` "Si falta una característica".
- **Geohash buckets** para listados muy densos (ya hay `encodeGeohash`).
