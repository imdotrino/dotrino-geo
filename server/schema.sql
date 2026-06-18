-- Esquema del índice geo `geo.dotrino.com`, con soporte de REPLICACIÓN entre
-- nodos (federación). Requiere PostGIS.
--
-- Modelo CRDT: un pin por identidad = registro last-writer-wins por `issued_at`
-- (el ts firmado por el autor). Los borrados son tombstones firmados que
-- impiden la "resurrección" de un pin al sincronizar con otro nodo. Guardamos
-- el SOBRE firmado (`data_json` + `signature`) para poder re-verificarlo y
-- re-replicarlo: cualquier nodo valida la firma sin confiar en el nodo emisor.

CREATE EXTENSION IF NOT EXISTS postgis;

CREATE TABLE IF NOT EXISTS pins (
    pubkey_id   TEXT PRIMARY KEY,                 -- sha256(JWK pubkey)
    publickey   TEXT NOT NULL,                    -- JWK string del autor
    data_json   TEXT NOT NULL,                    -- JSON del `data` firmado (para re-verificar/replicar)
    signature   TEXT NOT NULL,                    -- firma del autor sobre canonical(data)
    geog        geography(Point, 4326) NOT NULL,  -- derivado, para query espacial
    geohash     TEXT NOT NULL,
    payload     JSONB NOT NULL DEFAULT '{}'::jsonb, -- derivado (filtro)
    tags        TEXT[] NOT NULL DEFAULT '{}',      -- etiquetas para búsqueda (overlap)
    issued_at   BIGINT NOT NULL,                  -- = data.issuedAt (LWW)
    expires_at  BIGINT NOT NULL,                  -- capado por el nodo (purga/consulta)
    updated_at  BIGINT NOT NULL                   -- cuándo cambió localmente (anti-entropía)
);
-- Migración aditiva para nodos existentes (idempotente).
ALTER TABLE pins ADD COLUMN IF NOT EXISTS tags TEXT[] NOT NULL DEFAULT '{}';
CREATE INDEX IF NOT EXISTS idx_pins_geog ON pins USING GIST (geog);
CREATE INDEX IF NOT EXISTS idx_pins_expires ON pins (expires_at);
CREATE INDEX IF NOT EXISTS idx_pins_payload ON pins USING GIN (payload);
CREATE INDEX IF NOT EXISTS idx_pins_tags ON pins USING GIN (tags);  -- búsqueda por tag
CREATE INDEX IF NOT EXISTS idx_pins_updated ON pins (updated_at);

-- Tombstones: borrados firmados. Un pin con issued_at <= tombstone.issued_at
-- queda suprimido. Se conservan hasta `expires_at` (para tapar la ventana de
-- sincronización) y luego se purgan.
CREATE TABLE IF NOT EXISTS tombstones (
    pubkey_id   TEXT PRIMARY KEY,
    data_json   TEXT NOT NULL,
    signature   TEXT NOT NULL,
    issued_at   BIGINT NOT NULL,
    expires_at  BIGINT NOT NULL,
    updated_at  BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tombstones_updated ON tombstones (updated_at);
CREATE INDEX IF NOT EXISTS idx_tombstones_expires ON tombstones (expires_at);
