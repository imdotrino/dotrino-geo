# Deploy — geo.dotrino.com

Servicio Node + PostGIS. Igual que el proxy, corre como servicio autohosteado en
el server del ecosistema, detrás del reverse proxy que termina TLS y mapea el
subdominio `geo.dotrino.com`.

## 1. PostGIS

```bash
# Con Docker (rápido):
docker run -d --name geo-pg \
  -e POSTGRES_USER=geo -e POSTGRES_PASSWORD=geo -e POSTGRES_DB=geo \
  -p 5432:5432 postgis/postgis:16-3.4
```

O en un Postgres existente: `CREATE EXTENSION postgis;` (lo hace también
`schema.sql` al arrancar, si el rol tiene permiso).

## 2. Servicio

```bash
cd server
cp .env.example .env      # configurar DATABASE_URL, PORT, caps
npm install
npm start                 # node server.js  → escucha en :8090
```

El esquema (`schema.sql`) se aplica solo en el primer arranque (idempotente).

## 3. Reverse proxy (TLS + subdominio)

Apuntar `geo.dotrino.com` → `127.0.0.1:8090`. Ejemplo nginx:

```nginx
server {
    server_name geo.dotrino.com;
    location / {
        proxy_pass http://127.0.0.1:8090;
        proxy_set_header Host $host;
    }
}
```

(El servicio ya emite CORS `*` para que las apps del navegador consulten directo.)

## 4. Operación

- **Purga**: el server borra pins expirados cada 60 s. No requiere cron externo.
- **Backups**: opcionales — los pins son efímeros (TTL ≤ 1 h) por diseño; perder
  la tabla solo obliga a republicar. No hay datos durables del usuario acá.
- **Escala**: la query caliente es `ST_DWithin` sobre el índice GiST
  (`idx_pins_geog`). Para volumen alto, subir `work_mem` y considerar
  particionar por región/geohash.

## Variables

| Var | Default | Descripción |
|-----|---------|-------------|
| `PORT` | `8090` | puerto HTTP |
| `DATABASE_URL` | (PG\* del entorno) | conexión PostGIS |
| `GEO_MAX_TTL_MS` | `86400000` | cap del TTL de un pin (24 h, = ventana offline del proxy) |
| `GEO_CLOCK_SKEW_MS` | `300000` | tolerancia anti-replay del sobre (5 min) |
