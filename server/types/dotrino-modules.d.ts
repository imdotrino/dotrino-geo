// Los subpaths de los pilares que usa el servidor no traen declaraciones de tipos
// (@dotrino/identity 0.121.7 y @dotrino/update 0.9.2 publican solo .js). Aquí se declara
// SOLO lo que este servidor usa, con la forma que tiene en el código del pilar.

declare module '@dotrino/identity/assertion' {
  export function verifySignedFor(args: {
    data: unknown
    signature: unknown
    publickey: unknown
    chain: unknown
    audience: string
    expectedProfileId?: unknown
  }): Promise<{ ok: boolean, reason?: string }>
}

declare module '@dotrino/identity/capabilities' {
  export function pubkeyId(publickey: unknown): Promise<string>
  export function verifyDelegation(args: {
    cert: unknown
    expectedScope?: string
    expectedSub?: string
    actaSeq?: number | null
    sealers?: unknown
    revoked?: (nonce: unknown) => boolean
  }): Promise<{ ok: boolean, reason?: string, iss?: string, sub?: string, scope?: unknown, seq?: number, nonce?: string }>
}

declare module '@dotrino/identity/acta' {
  export function verifySealerChain(chain: unknown[], opts?: { expectedProfileId?: string | null }): Promise<
    | { ok: true, profileId: string, seq: number, sealers: unknown }
    | { ok: false, reason: string }
  >
}

declare module '@dotrino/update/deps' {
  export function watchDependencies(opts: {
    dir: string
    name?: string
    match?: RegExp
    log?: (...args: unknown[]) => void
    onNewer?: (...args: unknown[]) => void
  }): unknown
}
