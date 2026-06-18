# OwnTracks contra geo (`/here`) — guía + formato de config

Esta guía describe cómo conectar la app **OwnTracks** (iOS/Android, background)
al **bridge cerrado y cifrado** de `geo.dotrino.com` para que un **círculo**
privado de personas se vea entre sí en el mapa — sin que el servidor vea
ubicaciones ni pueda descubrir a nadie.

El reparto del trabajo es:

- **OwnTracks** corre solo (background), cifra/descifra localmente y pinta el mapa.
- El **bridge `/here`** de geo corre solo: agrupa por círculo, guarda efímero el
  último blob de cada miembro y devuelve los de los demás. Nunca descifra.
- **"here"** (la app configuradora) **solo se usa para dar de alta/baja**: arma el
  círculo, emite los caps (certs delegados), reparte la clave del círculo y
  **genera la config de OwnTracks como QR / archivo `.otrc`**. Una vez aplicada,
  "here" **no necesita estar abierta**.

Pilares criptográficos (ya existen, **no se tocan**):

- **Caps** = certificados de delegación de
  `@dotrino/identity/capabilities`
  (`/mnt/sda1/Dotrino/dotrino-identity/vault/capabilities.js`).
  Cert = `{ v:1, iss, sub, scope, iat, exp, nonce, sig }`.
- **`circleId`** = `pubkeyId(ownerMasterPubkey) + ':' + slug` — liga el círculo a
  su dueño. El bridge exige `pubkeyId(cert.iss) === circleId.split(':')[0]`.
- **Cifrado** = libsodium **secretbox** de OwnTracks (`_type:encrypted`), con la
  **clave del círculo** compartida fuera de banda. El bridge ve solo ciphertext.

> **Importante sobre nombres de campos.** Todos los nombres usados aquí
> (`mode`, `url`, `auth`, `username`, `password`, `encryptionKey`, `tid`,
> `deviceId`, `_type:configuration`, `_type:encrypted` + `data`, `_type:card`,
> `_type:cmd` + `action`) son los **reales** de OwnTracks (ver
> <https://owntracks.org/booklet/tech/json/> y
> <https://owntracks.org/booklet/features/encrypt/>). No inventes alias.

---

## 1) Cómo configurar OwnTracks en HTTP mode contra `/here`

En la app OwnTracks: **Settings → Connection** (iOS) / **Preferences →
Connection** (Android). Equivalencias con los campos `_type:configuration` que
"here" genera entre paréntesis.

| Campo en la UI de OwnTracks | Valor | Clave en `.otrc` |
| --- | --- | --- |
| **Mode** | `HTTP` (= entero `3`) | `mode: 3` |
| **URL** | `https://geo.dotrino.com/here` | `url` |
| **Authentication** | activado | `auth: true` |
| **UserID / Username** | el **`circleId`** completo (`<ownerId>:<slug>`) | `username` |
| **Password** | `base64url(JSON.stringify(cert))` (el cap del dispositivo) | `password` |
| **DeviceID** | id estable del dispositivo (ver abajo) | `deviceId` |
| **TrackerID (tid)** | 2 caracteres visibles en el mapa (iniciales) | `tid` |
| **Encryption key** | la **clave del círculo** (≤32 chars, secretbox) | `encryptionKey` |

Notas de cada campo:

- **Mode = HTTP.** En OwnTracks el ajuste `mode` es un entero: `0` = MQTT,
  `3` = **HTTP**. La config importable lleva `"mode": 3`. En la UI se elige
  "HTTP" del selector.
- **URL.** Endpoint nuevo del bridge: `POST https://geo.dotrino.com/here`.
  OwnTracks hace POST del mensaje de ubicación y **espera un array JSON de
  respuesta** con las posiciones de los amigos — que es justo lo que `/here`
  devuelve (los blobs `_type:encrypted` / `_type:card` de los **otros** miembros
  del mismo círculo). OwnTracks los pinta como amigos.
- **Auth + Username + Password (HTTP Basic).** OwnTracks manda
  `Authorization: Basic base64(username + ':' + password)`. Aquí:
  - `username` = **`circleId`** (`pubkeyId(ownerMaster):slug`).
  - `password` = **`base64url(JSON.stringify(cert))`** — el cert delegado de
    **este** dispositivo. El bridge: (1) parsea el cert del password,
    (2) `verifyDelegation` con `expectedScope:'geo:publish'` **y** exige que el
    `scope` incluya `'geo:read:'+circleId`, (3) exige
    `pubkeyId(cert.iss) === circleId.split(':')[0]`, (4) chequea `exp` +
    revocación. Sin cap válido → **401**, no escribe ni lee.

    > `base64url` (RFC 4648 §5: `-`/`_`, sin `=`) evita problemas con `+`, `/` y
    > el `:` que HTTP Basic usa como separador. El cert puede ser grande; cabe
    > sin problema en el header Basic.
- **DeviceID.** Identificador del dispositivo (forma parte del par
  `username-deviceid` con que OwnTracks/Recorder namespacean). Usá un valor
  estable por dispositivo; "here" sugiere `pubkeyId(cert.sub).slice(0,12)`.
- **TrackerID (`tid`).** 2 caracteres que OwnTracks muestra en el chincheta del
  mapa (p. ej. iniciales). Es **cosmético** y viaja **dentro** del blob cifrado;
  el bridge puede usar `tid` como `memberId` de respaldo, pero el `memberId`
  canónico es `pubkeyId(cert.sub)`.
- **Encryption key (`encryptionKey`).** La **clave del círculo**. OwnTracks la
  usa con **libsodium secretbox** (passphrase de hasta 32 chars, padded con
  ceros) para **cifrar lo que publica** y **descifrar lo que recibe** de los
  amigos — **localmente**, en el teléfono. Todos los miembros del círculo
  comparten **la misma** `encryptionKey`; el bridge **no la tiene**. Con esto el
  cuerpo que sube OwnTracks es `{ "_type":"encrypted", "data":"<b64 secretbox>" }`
  y el bridge lo trata como **opaco**.

Resultado: OwnTracks publica su posición **cifrada** a `/here` autenticando con
el cap del dispositivo, y recibe **cifradas** las de los demás del círculo, que
descifra y dibuja. El servidor solo ve ciphertext + el agrupamiento por
`circleId` (metadato), nunca la ubicación.

---

## 2) El JSON exacto que "here" genera (`.otrc` / `_type:configuration`) y el QR

### 2.1 Archivo `.otrc` importable

"here" produce **este** documento (un `_type:configuration` de OwnTracks). Es lo
que se vuelca a QR o se entrega como archivo `.otrc`:

```json
{
  "_type": "configuration",
  "mode": 3,
  "url": "https://geo.dotrino.com/here",
  "auth": true,
  "username": "9f2c…ab:familia-perez",
  "password": "eyJ2IjoxLCJpc3MiOiJ7XCJrdHlcIjpcIkVDXCIs…",
  "deviceId": "1a2b3c4d5e6f",
  "tid": "JP",
  "encryptionKey": "clave-del-circulo-familia-2026",
  "locatorInterval": 300,
  "locatorDisplacement": 50,
  "monitoring": 1,
  "pubRetain": false,
  "cmd": false,
  "allowRemoteLocation": false
}
```

Significado de cada campo (todos son ajustes **reales** de OwnTracks):

- `_type:"configuration"` — **obligatorio**; marca el documento como config
  importable.
- `mode: 3` — **HTTP mode**.
- `url` — el endpoint del bridge.
- `auth: true` + `username` + `password` — HTTP Basic; `username`=`circleId`,
  `password`=`base64url(cert)`.
- `deviceId`, `tid` — identidad de dispositivo y etiqueta visible.
- `encryptionKey` — la clave del círculo (secretbox). **Es el único secreto
  compartido**; trátenlo como tal.
- `locatorInterval` (seg), `locatorDisplacement` (m), `monitoring` (1=significant
  / modo normal) — cadencia de reporte; valores sugeridos, ajustables.
- `cmd: false`, `allowRemoteLocation: false` — **desactivan** comandos remotos y
  geofencing remoto (endurecimiento: nadie puede pedir reportes ni reconfigurar
  el teléfono desde el server). `pubRetain: false` porque no hay broker MQTT.

> Los miembros del **mismo** círculo comparten `mode`, `url`, `username`
> (=`circleId`) y `encryptionKey`. Lo que **cambia por dispositivo** es
> `password` (su propio cert), `deviceId` y `tid`.

### 2.2 Volcado a QR para escanear en OwnTracks

OwnTracks importa config por **URL `owntracks:///config`** con el `.otrc`
**base64** en el parámetro `inline`. "here" arma:

```
owntracks:///config?inline=<BASE64( JSON.stringify(otrc) )>
```

> `inline` espera **base64 estándar** (no base64url). Ejemplo real del booklet:
> `owntracks:///config?inline=ewogICJfdHlwZSI6ICJjb25maWd1cmF0aW9uIiwK…`

Pasos que ejecuta "here":

1. `const otrc = { _type:'configuration', mode:3, url:'https://geo.dotrino.com/here', auth:true, username:circleId, password:base64url(JSON.stringify(cert)), deviceId, tid, encryptionKey }`.
2. `const payload = btoa(unescape(encodeURIComponent(JSON.stringify(otrc))))` (UTF-8 → base64).
3. `const deepLink = 'owntracks:///config?inline=' + payload`.
4. Renderiza `deepLink` como **QR** (autohosteado, sin servicios de terceros —
   misma política que `<dotrino-share>`).

El usuario, en OwnTracks: **escanea el QR** (o toca el deep-link). OwnTracks
abre **"import configuration?"** y aplica todos los ajustes de una sola vez. No
hay que tipear nada.

> Alternativa de entrega: el **archivo `.otrc`** crudo (sección 2.1). En OwnTracks
> iOS: compartir el `.otrc` a la app / **Settings → Configuration → import**;
> Android: **Preferences → Configuration management → Import**. El QR es el
> camino recomendado por ser sin-tipeo.

### 2.3 (Opcional) tarjeta de presentación `_type:card`

Para que el amigo aparezca con **nombre y foto** (no solo `tid`), cada miembro
puede publicar una vez su **card**, que también viaja **cifrada** y el bridge
reenvía a los demás:

```json
{ "_type": "card", "tid": "JP", "name": "Juana Pérez", "face": "<base64 PNG>" }
```

(En transporte va envuelta: `{ "_type":"encrypted", "data":"<b64 secretbox de la card>" }`.)

---

## 3) Flujos de alta y baja de un miembro

El bridge es **cerrado**: la pertenencia se controla **emitiendo y revocando
caps** y **rotando la clave del círculo**. "here" orquesta ambos.

### 3.1 Alta de un miembro (emitir cert + repartir clave + entregar QR)

1. **(En el dispositivo del miembro)** generar la sub-clave de dispositivo:
   `const dev = await makeDeviceKey({ label })` → `dev.publickey` (JWK string),
   `dev.deviceId = pubkeyId(dev.publickey)`. La privada **nunca** sale del
   dispositivo.
2. **(En el dueño, "here")** firmar el cap con el vault del dueño:
   `const { cert } = await signDelegation(dev.publickey, ['geo:publish', 'geo:read:'+circleId], { ttlMs, label })`.
   El `cert.iss` es la maestra del dueño → `pubkeyId(cert.iss) === circleId.split(':')[0]`.
3. **Repartir la clave del círculo** (`encryptionKey`) por un **canal fuera de
   banda** (mensajería del proxy `sendByPubkey`, en persona, etc.). Es el secreto
   compartido por **todos**: no viaja por el bridge.
4. **Generar la config** y el **QR** (sección 2):
   `username=circleId`, `password=base64url(JSON.stringify(cert))`,
   `deviceId=dev.deviceId.slice(0,12)`, `tid=<iniciales>`,
   `encryptionKey=<clave del círculo>`.
5. **Entregar el QR** al miembro. Escanea → OwnTracks queda conectado al círculo
   y empieza a publicar/recibir. **"here" ya no hace falta.**

> El cert lleva su propio `nonce` (mango de revocación) y `exp` (≤ 30 días por el
> tope `MAX_DELEGATION_MS`). Para renovar, se re-emite y se entrega un QR nuevo
> (el viejo expira solo).

### 3.2 Baja de un miembro (rotar clave + revocar cap)

La baja es **doble** porque hay dos secretos: el cap (por dispositivo) y la
clave del círculo (compartida).

1. **Revocar el cap del que sale:** `await revokeDelegation(cert.nonce)`. "here"
   publica el `nonce` revocado al **feed/set de revocación** que el bridge
   consulta → desde ya, `/here` responde **401** a ese password aunque no haya
   expirado. (`listDelegations()` para ver/elegir cuál.)
2. **Rotar la `encryptionKey` del círculo:** elegir una clave **nueva**. Esto es
   lo que de verdad lo **expulsa del mapa**: aunque conservara un cap viejo, sin
   la clave nueva no puede **descifrar** a los demás ni producir ciphertext que
   ellos descifren. (El bridge nunca tuvo la clave, así que esto es puramente
   cliente.)
3. **Re-emitir config a los que se quedan:** para cada miembro restante, generar
   un **QR nuevo** con la `encryptionKey` rotada (el `password`/cap de cada uno
   sigue válido; solo cambia la clave). Repartir como en el alta.
4. El miembro dado de baja queda fuera por **ambos** lados: cap revocado (401 en
   escritura/lectura) **y** clave vieja inservible para descifrar.

> Regla práctica: **revocar** corta el acceso al bridge **ya**; **rotar la clave**
> garantiza confidencialidad hacia adelante (forward secrecy del círculo). Hacé
> siempre las dos en una baja real.

---

## Resumen del contrato (lo que "here" debe respetar)

- `username` = `circleId` = `pubkeyId(ownerMaster):slug`.
- `password` = `base64url(JSON.stringify(cert))`, con `cert.scope ⊇
  ['geo:publish','geo:read:'+circleId]` y `pubkeyId(cert.iss) === circleId.split(':')[0]`.
- Cuerpo que sube OwnTracks: `{ "_type":"encrypted", "data":"<b64 secretbox>" }`
  (opaco para el bridge); también `_type:card` (cifrada).
- Respuesta de `/here`: **array JSON** con los últimos blobs de los **otros**
  miembros del **mismo** círculo (efímero, TTL + overwrite, sin historial).
- `encryptionKey` = clave del círculo, compartida fuera de banda, igual para
  todos; el bridge **no la tiene**.
