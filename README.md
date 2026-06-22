# @dotrino/geo

> **Parte del ecosistema [Dotrino](https://dotrino.com).** Misión: aplicaciones que resuelven problemas comunes, respetando tu privacidad — sin anuncios, sin cookies, sin rastreo de datos, sin vender tu identidad a nadie.

Índice de **descubrimiento georreferenciado** del ecosistema Dotrino:
`geo.dotrino.com`. Una identidad publica un **pin firmado** (lat/lng + payload)
con TTL corto; cualquiera consulta los pins dentro de un **radio** (PostGIS hace
la query espacial). Pensado para casos tipo "Uber", delivery, "cerca de mí",
marketplace local, eventos.

Es el **cuarto pilar** del ecosistema, complementario a los tres existentes:

| Pilar | Paquete | Rol |
|-------|---------|-----|
| Identidad | `dotrino-identity` | clave del vault, firma |
| Transporte | `dotrino-proxy-client` | mensajería, canales, WebRTC |
| Almacenamiento | `dotrino-store` | datos del usuario en el navegador |
| **Descubrimiento geo** | **`dotrino-geo`** | **encontrar identidades cercanas** |

## El pin es un anuncio efímero, no almacenamiento

Una publicación geo **no es persistente**: es un **anuncio** que apunta a otro
servicio (el messenger) donde ocurre la transacción real. El pin lleva el
**pubkey** de la identidad, que es el handle con el que se la contacta por el
proxy. El dato durable de la transacción vive en el messenger, no acá.

Por eso el **techo de vida de un pin es 24 h**, alineado con la ventana de
**mensajes offline del proxy**: sin que la identidad lo *hidrate* (republicar),
un anuncio no debe sobrevivir más que un mensaje offline. Apps que necesiten
presencia "ahora mismo" usan TTL cortos (default 10 min); anuncios tipo
clasificado pueden llegar al cap de 24 h. El server purga los expirados.

## Principio de diseño: descubrir acá, hablar por el proxy

Este índice es **SOLO descubrimiento**. El flujo correcto es:

1. **Publicás** un pin firmado con `publishPin()` (opt-in, TTL corto).
2. Otra identidad te **encuentra** con `queryRadius()`.
3. A partir de ahí, **todo el contacto en vivo va por el proxy**
   (`@dotrino/proxy-client`): el "pedido de viaje", el handshake
   y el **streaming de ubicación en tiempo real** se hacen con `sendByPubkey` /
   canal / WebRTC. **No** hagas streaming de posición a alta frecuencia contra
   este índice — eso es transporte y ya está resuelto.

Cada pin (y cada query) trae el **pubkey JWK** de la identidad: ese es el handle
con el que el proxy enruta (`sendByPubkey`). Identidad de descubrimiento e
identidad de transporte coinciden, como manda el ecosistema.

## Identidad: el vault es la única fuente

El cliente **no genera ni guarda claves**. Le inyectás `signData` y
`getPublicKeyJwk` desde `@dotrino/identity` (el vault
`id.dotrino.com`). Mismo sobre firmado `{data, signature}` y misma
serialización canónica que el proxy-client.

## Instalación

```bash
npm i @dotrino/geo
```

## Uso (cliente)

```js
import { createGeoClient } from '@dotrino/geo'
import identity from '@dotrino/identity' // el vault

const geo = createGeoClient({
  signData: identity.signData,
  getPublicKeyJwk: identity.getPublicKeyJwk,
  // baseUrl: 'https://geo.dotrino.com'  // default
})

// 1) Publicar mi pin (opt-in). Se reemplaza el anterior; no hay historial.
await geo.publishPin({
  lat: -2.1709, lng: -79.9224,
  payload: { role: 'driver', seats: 4 },
  tags: ['comida', 'vegano'],  // etiquetas de búsqueda (se normalizan)
  ttlMs: 10 * 60 * 1000        // 10 min (el server lo capa a 1h)
})

// 2) Buscar cerca, por radio + tags (overlap: alguna de las etiquetas) y/o filter
const { pins } = await geo.queryRadius({
  lat: -2.1700, lng: -79.9200,
  radiusMeters: 3000,
  tags: ['comida', 'bici'],    // pins con ALGUNA de estas etiquetas
  filter: { role: 'driver' }   // containment JSONB sobre payload (opcional)
})
// pins: [{ publickey, lat, lng, geohash, payload, tags, distanceMeters, expiresAt }, ...]

// 3) Contactar al más cercano POR EL PROXY (no por este índice)
//    proxyClient.sendByPubkey([pins[0].publickey], { type: 'ride-request', ... })

// 4) Retirar mi pin antes de tiempo
await geo.removePin()
```

### Privacidad (no rompe la filosofía Dotrino)

Un índice de ubicación consultable es lo más sensible del ecosistema. Por eso:

- **Un pin por identidad, con overwrite** — no se guarda historial de ubicaciones.
- **TTL corto** por diseño (default 10 min, cap del server 1 h). Un job purga
  expirados cada minuto.
- **Opt-in** siempre: publicar es una acción explícita; `removePin()` lo retira.
- **Geohash grueso** para descubrimiento (default 7 chars ≈ 76 m; bajalo con
  `geohashPrecision` para exponer menos). La recomendación es descubrir por
  bucket y **negociar las coords exactas P2P por el proxy** tras consentimiento.
- **Sólo metadata de app en `payload`** — nunca datos personales del usuario.

## API del servicio (HTTP/JSON)

| Método | Ruta | Auth | Descripción |
|--------|------|------|-------------|
| `PUT` | `/pins` | sobre firmado | publica/reemplaza el pin de la identidad |
| `DELETE` | `/pins` | sobre firmado | retira el pin (tombstone) |
| `GET` | `/pins?lat&lng&r&limit&filter` | pública | pins dentro del radio, por distancia |
| `GET` | `/health` | — | liveness |

El servidor verifica la firma ECDSA P-256 (JWK del vault) sobre el `data`
canónico, chequea frescura (`issuedAt` dentro de ±5 min, anti-replay) y capa el
TTL. Ver [`server/`](./server) y [`DEPLOY.md`](./DEPLOY.md).

## Estructura

```
src/            cliente npm (@dotrino/geo)
  index.js      createGeoClient: publishPin / queryRadius / removePin
  geohash.js    encode base32 (compartido)
  canonical.js  serialización canónica (igual que el resto del ecosistema)
server/         servicio geo.dotrino.com
  server.js     HTTP/JSON nativo
  db.js         capa PostGIS (pg)
  schema.sql    tabla pins (geography + GiST)
  signature.js  verificación de sobres firmados
```

## Licencia

MIT
