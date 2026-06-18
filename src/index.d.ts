export interface GeoClientOptions {
  /** Firma canónica → base64. Inyectada desde el vault (`id.signData`). */
  signData: (data: object) => Promise<string>
  /** Pubkey JWK string. Inyectada desde el vault. */
  getPublicKeyJwk: () => Promise<string>
  /** Default https://geo.dotrino.com */
  baseUrl?: string
  /** fetch inyectable para tests/SSR */
  fetch?: typeof fetch
}

export interface PublishPinInput {
  lat: number
  lng: number
  payload?: Record<string, unknown>
  /** Etiquetas para búsqueda (máx 10, slug ≤32, se normalizan). */
  tags?: string[]
  ttlMs?: number
  geohashPrecision?: number
  now?: number
}

export interface PublishPinResult {
  ok: true
  expiresAt: number
  geohash: string
}

export interface QueryRadiusInput {
  lat: number
  lng: number
  radiusMeters: number
  limit?: number
  filter?: string | Record<string, unknown>
  /** Buscar pins que tengan ALGUNA de estas etiquetas (overlap). */
  tags?: string[]
}

export interface Pin {
  publickey: string
  lat: number
  lng: number
  geohash: string
  payload: Record<string, unknown>
  tags: string[]
  distanceMeters: number
  expiresAt: number
}

export interface QueryRadiusResult {
  pins: Pin[]
}

export interface GeoClient {
  publishPin (input: PublishPinInput): Promise<PublishPinResult>
  queryRadius (input: QueryRadiusInput): Promise<QueryRadiusResult>
  removePin (input?: { now?: number }): Promise<{ ok: true }>
}

export function createGeoClient (opts: GeoClientOptions): GeoClient
export function encodeGeohash (lat: number, lng: number, precision?: number): string
export function normalizeTags (tags: string[]): string[]
export function canonicalStringify (value: unknown): string
