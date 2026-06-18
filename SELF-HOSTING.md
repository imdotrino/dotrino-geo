# Correr tu propio nodo geo

`geo.dotrino.com` no tiene por qué ser el único nodo. Cualquiera puede levantar
uno: el servicio es autohospedable y los clientes apuntan a **cualquier endpoint**.
Como los pines van **firmados** por el vault de cada identidad, el nodo no puede
falsificar nada — es infraestructura *trust-minimized*, fungible y replicable.

## 1. Requisitos

- Docker + Docker Compose.
- Un dominio para el nodo (ej. `geo.tudominio.com`) apuntando **A/AAAA a este
  host**, con los puertos **80 y 443 abiertos** (Caddy los usa para sacar el
  cert TLS de Let's Encrypt). DNS directo, **sin proxy de Cloudflare** (un nodo
  geo no debe pasar por un tercero que vea las consultas de ubicación).

## 2. Levantarlo (turnkey)

```bash
git clone https://github.com/imdotrino/dotrino-geo
cd dotrino-geo
cp .env.docker.example .env
# editá .env: GEO_DOMAIN y GEO_DB_PASSWORD (generá: openssl rand -hex 24)
docker compose up -d
```

Eso levanta tres contenedores: **PostGIS** (la base), el **servidor geo**, y
**Caddy** (TLS automático + reverse proxy). En un minuto tenés
`https://geo.tudominio.com/health` → `{"ok":true}`.

### Probar sin dominio/TLS

Para una prueba local, en `docker-compose.yml` comentá el servicio `caddy` y
descomentá el `ports: ["8090:8090"]` del servicio `geo`. Después:

```bash
docker compose up -d db geo
curl http://localhost:8090/health
```

## 3. Usar tu nodo desde una app

El cliente del paquete acepta el endpoint — no hay nada hardcodeado:

```js
import { createGeoClient } from '@dotrino/geo'
const geo = createGeoClient({
  signData, getPublicKeyJwk,
  baseUrl: 'https://geo.tudominio.com'   // <- tu nodo
})
```

## 4. Federación (replicar con otros nodos)

Para que **no importe a qué nodo consulta el cliente**, los nodos **replican los
pines firmados entre sí**. Configurás los peers y listo:

```bash
# en .env
GEO_PEERS=https://geo.otrodominio.com,https://geo.tercero.org
GEO_REPLICATION_TOKEN=un-secreto-compartido-entre-los-nodos
```

Cómo funciona:
- **Push**: cuando tu nodo acepta un pin o borrado nuevo, lo **empuja** a sus peers
  (`POST /replicate`). Ellos **verifican la firma** (no confían en tu nodo) y lo
  aplican con *last-writer-wins* por `issuedAt`.
- **Anti-entropía**: cada ~30 s tu nodo le pide a cada peer sus cambios desde el
  último visto (`GET /since`) y se pone al día — cubre pushes perdidos o nodos que
  estuvieron caídos.
- **Borrados** propagan como *tombstones* firmados (no resucitan al sincronizar).
- **Convergencia**: como cada pin es un registro LWW por pubkey y todo va firmado,
  los nodos convergen sin un coordinador central y sin confiar entre sí.

Hacé la federación **mutua** (cada nodo lista al otro en `GEO_PEERS`) y usá el
mismo `GEO_REPLICATION_TOKEN` en todos. Empezá con una malla chica de nodos que
elegís (allowlist) — eso acota el abuso además de la firma.

## 5. Entrar a la red (descubrimiento)

Para que otros **encuentren** tu nodo (no solo quien conozca su URL), el plan es
un **directorio de nodos firmado** + reputación de nodos (en diseño). Mientras
tanto, compartís la URL y cada quien agrega tu nodo a su `GEO_PEERS` o a la lista
de endpoints de su cliente.

## 6. Operación

- **Datos efímeros**: los pines tienen TTL ≤ 24h y se purgan solos; backups
  opcionales (perder la base solo obliga a republicar).
- **Persistencia**: la base vive en el volumen `geo-db` (sobrevive a `up`/`down`;
  se borra con `down -v`).
- **Actualizar**: `git pull && docker compose up -d --build`.
- **Logs**: `docker compose logs -f geo`.

## Notas

- El rate-limit por IP funciona detrás de Caddy (que setea `X-Forwarded-For`).
- No requiere Cloudflare ni ningún tercero: TLS propio del origen.
- Mismo patrón aplicará a reputation y (con federación) al proxy.
