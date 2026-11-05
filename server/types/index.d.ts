// Formas de datos del servidor de geo. Lo que llega por HTTP es JSON sin validar: los
// campos van como `unknown` y el código los comprueba con `typeof` antes de usarlos.

/** `data` de un sobre firmado (pin, tombstone o revocación de /here). */
export interface SignedData {
  publickey?: unknown
  aud?: unknown
  issuedAt?: unknown
  expiresAt?: unknown
  lat?: unknown
  lng?: unknown
  geohash?: unknown
  payload?: unknown
  tags?: unknown
  action?: unknown
  op?: unknown
  circleId?: unknown
  nonce?: unknown
  [key: string]: unknown
}

/** Cuerpo JSON de PUT/DELETE /pins, /replicate y /here/revoke. */
export interface EnvelopeBody {
  kind?: unknown
  data?: SignedData
  signature?: unknown
  /** Llave del aparato que firmó (cuando no es la de la identidad). */
  signer?: unknown
  /** Cadena de selladores que ata `signer` a la identidad. */
  chain?: unknown
  [key: string]: unknown
}

/** Lee y parsea el cuerpo JSON de la petición (con tope de tamaño). */
export type ReadBody = (req: import('node:http').IncomingMessage) => Promise<EnvelopeBody>

/** Responde JSON con las cabeceras CORS del servicio. */
export type Send = (res: import('node:http').ServerResponse, status: number, obj: unknown, extraHeaders?: Record<string, string>) => void

/** Opciones de aplicar un sobre: frescura por reloj y prueba de quién firmó. */
export interface ApplyOptions {
  fresh?: boolean
  signer?: unknown
  chain?: unknown
}

/** Resultado de validar y aplicar un sobre. */
export interface ApplyResult {
  status: number
  error?: string
  changed?: boolean
  cappedExpires?: number
  geohash?: string
}

/** Fila de un pin para `db.applyPin` (ya verificada). */
export interface PinRow {
  pubkeyId: string
  publickey: unknown
  dataJson: string
  signature: unknown
  lat: number
  lng: number
  geohash: string
  payload: object
  tags: string[]
  issuedAt: number
  expiresAt: number
}

/** Fila de un tombstone para `db.applyTombstone` (ya verificada). */
export interface TombstoneRow {
  pubkeyId: string
  dataJson: string
  signature: unknown
  issuedAt: number
  expiresAt: number
}

/** Consulta por radio. */
export interface RadiusQuery {
  lat: number
  lng: number
  radiusMeters: number
  limit: number
  filter: unknown
  tags: string[]
  now: number
}

/** Pin devuelto por la consulta por radio. */
export interface PinHit {
  publickey: string
  lat: number
  lng: number
  geohash: string
  payload: unknown
  tags: string[]
  distanceMeters: number
  expiresAt: number
}

/** Cambio para la anti-entropía entre nodos. */
export interface ChangeItem {
  kind: 'pin' | 'tombstone'
  updatedAt: number
  data: SignedData
  signature: string
  signer?: unknown
  chain?: unknown
}
