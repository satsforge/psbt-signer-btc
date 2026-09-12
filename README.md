# PSBT Signer BTC

Firmador de transacciones Bitcoin (PSBT) **100% offline**. Completa el trío
de herramientas de SatsForge: [paper-wallet-btc](../paper-wallet-btc) genera
una wallet air-gapped, **PSBT Signer BTC** firma transacciones sin que la
clave privada toque nunca un equipo conectado a internet, y
[My Wallet BTC](../my_btc_wallet) (u otra wallet/nodo cualquiera) transmite
la transacción ya firmada.

A diferencia de My Wallet BTC, esta herramienta **nunca hace ninguna llamada
de red** — ni para consultar saldo ni para transmitir. Solo lee un PSBT que
le pasás (pegado o desde un archivo), lo firma con la clave que desbloqueás,
y te devuelve el resultado para que lo saques vos mismo (texto, QR, o
archivo `.txt`).

> ⚠️ **Aviso importante — proyecto sin auditoría externa todavía.**
> Firma transacciones reales de Bitcoin. Es software "tal cual", sin
> garantía. **Probá primero en testnet** con transacciones sin valor. Antes
> de confiarle fondos reales en mainnet: leé el código fuente vos mismo. Para
> máxima seguridad, usalo en un equipo desconectado de internet.

## Cómo usarlo

```bash
npm install
npm run build     # genera dist/index.html e index.html
```

Abrí `index.html` — funciona igual como `file://`, servido, u offline.

1. Elegí la red y desbloqueá tu clave: frase semilla (BIP39, en texto plano
   o cifrada con AES-256 al estilo paper-wallet-btc) o clave privada
   (WIF, o BIP38 cifrada) — mismos métodos que My Wallet BTC, incluida la
   carga desde archivo sin portapapeles en modo Avanzado.
2. Pegá o cargá el PSBT que generó otra wallet (base64 o hex).
3. La herramienta identifica qué inputs puede firmar con tu clave, **antes**
   de firmar nada, y te muestra un resumen: total de entradas/salidas,
   comisión, y cada dirección de destino (marcando cuáles son cambio,
   tuyas). Nada se firma sin que confirmes explícitamente ese resumen.
4. Al firmar, si la transacción queda completa te da el hex listo para
   transmitir (más el TXID). Si todavía necesita más firmas (por ejemplo,
   un multisig), te da el PSBT actualizado para pasarle al próximo firmante.
   En ambos casos: texto seleccionable, código QR, y botón de descarga.

## Cómo encuentra qué inputs puede firmar (sin red)

No hay forma de "escanear direcciones usadas" sin conexión, así que usa dos
estrategias en paralelo, sin ninguna llamada de red:

- **`bip32Derivation` del propio PSBT** (preferida): si el input trae esa
  metadata — el fingerprint de la master key y el path exacto — y coincide
  con la clave que desbloqueaste, deriva exactamente esa ruta. Funciona para
  cualquier índice o profundidad, es como lo hacen los hardware wallets.
- **Fuerza bruta offline**: deriva por adelantado tu cuenta BIP84 (ambas
  cadenas, hasta 200 índices) más las 4 direcciones fijas estilo
  paper-wallet-btc, y compara el script de cada candidata contra los inputs
  del PSBT. Sin `bip32Derivation`, esta es la única red de contención.

## Estructura del proyecto

```
src/
  lib/
    mnemonic.js     validación BIP39, derivación de seed (WebCrypto)
    seedcipher.js   descifrado AES-256-GCM de la semilla (formato paper-wallet-btc)
    bip38.js        descifrado BIP38 de un WIF (no-EC-multiply)
    hdwallet.js     derivación BIP32/BIP84, raíz para bip32Derivation, nodo de clave importada
    addresstypes.js direcciones/scripts Legacy/P2SH/Bech32/Taproot para cualquier pubkey o seed
    psbt.js         decodificar, identificar firmantes, firmar, finalizar/exportar, resumen
    i18n.js         diccionario ES/EN + walker data-i18n
  app.js            controlador de la UI (sin frameworks)
  styles.css        tema oscuro/claro al estilo SatsForge
index.src.html      plantilla HTML fuente (placeholders __CSS__/__SCRIPT__/__CSP__)
build.mjs           empaqueta todo en un único index.html autocontenido
test/               tests (node:test) de la lógica de firma
```

## Tests

```bash
npm test
```

Cubre: firma de una cuenta BIP84 propia por fuerza bruta offline, firma de
una dirección fija estilo paper-wallet-btc, firma vía `bip32Derivation` para
un índice fuera del rango de fuerza bruta, firma con una clave importada
(WIF) revisando los 4 formatos de dirección, el caso donde no hay firma
suficiente (PSBT parcial exportado para otro firmante), y el
decode/encode de PSBT en base64 y hex.

## Modelo de seguridad

- **Cero red, de verdad**: CSP con `connect-src 'none'` — a diferencia de
  My Wallet BTC, esta herramienta no tiene ninguna excepción a la política
  "cero red" de paper-wallet-btc. Podés verificarlo en las herramientas de
  desarrollador del navegador.
- **Revisión obligatoria antes de firmar**: el PSBT se decodifica y se
  identifica qué se puede firmar, pero la firma real (`tx.sign(...)`) no
  ocurre hasta que confirmás explícitamente el resumen en pantalla.
- **Alerta de montos no verificables**: sin conexión no hay forma de
  comprobar que el monto que un input SegWit declara (`witnessUtxo`) sea
  real — un coordinador malicioso podría mentir para inflar la comisión
  real sin que se note. La pantalla de revisión distingue dos casos y exige
  una segunda confirmación aparte de la habitual para cualquiera de los
  dos: inputs que sólo traen `witnessUtxo` (monto reclamado, no verificado)
  e inputs que no traen ningún dato de origen (ni `witnessUtxo` ni
  `nonWitnessUtxo` — se cuentan como 0 en el total mostrado, así que ese
  total y la comisión quedan subestimados). También se marca cualquier
  comisión inusualmente alta en relación al total de entradas.
- **Chequeo de red por path**: si el PSBT trae un `bip32Derivation` que
  nombra tu misma master key pero con un path de la otra red (mainnet vs.
  testnet), la herramienta no lo deriva ni lo firma — evita que un PSBT mal
  etiquetado (o malicioso) te haga firmar una transacción de mainnet real
  mientras creés estar operando en testnet.
- **El `bip32Derivation` declarado tiene que corresponder al script real**:
  que un input traiga metadata de derivación consistente con tu semilla
  (fingerprint + path + pubkey que efectivamente derivan) no alcanza — la
  herramienta además comprueba que esa clave derivada pueda gastar el
  script real del input antes de ofrecerlo como "tuyo para firmar" en la
  revisión, para que esa pantalla nunca prometa una firma que después la
  firma real vaya a rechazar.
- **La firma se verifica input por input**: no se asume que todo lo que la
  revisión prometió terminó firmado — cada input se firma y se confirma por
  separado, y si alguno no se pudo firmar (a pesar de haber sido
  identificado como propio), el resultado final lo indica explícitamente en
  vez de reportar como firmado algo que en realidad no lo está.
- **Higiene de memoria**: la seed y la master key (`root`) se sobrescriben
  con ceros apenas se usan para derivar. Una clave derivada por
  `bip32Derivation` (efímera, se recalcula si hace falta de nuevo) se borra
  apenas termina de firmar. Las ~400 claves candidatas de la búsqueda por
  fuerza bruta y la cuenta BIP84 se mantienen mientras la sesión sigue
  desbloqueada — así podés firmar más de un PSBT sin volver a ingresar la
  semilla (por ejemplo, un reemplazo RBF del mismo input) — y se
  sobrescriben con ceros recién al bloquear la sesión.
- **Cero persistencia**: no se usa `localStorage`, `sessionStorage`, cookies
  ni IndexedDB.
- **Sin descarga automática de portapapeles**: igual que My Wallet BTC, la
  frase semilla, el bloque cifrado, la clave privada y el PSBT se pueden
  cargar desde un archivo en vez de copiar/pegar.
- **Auto-bloqueo por inactividad**: si desbloqueaste la herramienta y te
  alejaste, se bloquea sola a los 10 minutos sin actividad — no depende de
  que te acuerdes de apretar "Bloquear".
- **Dirección completa en la revisión**: la pantalla que mostrás confirmar
  nunca trunca una dirección de destino — un ataque de dirección parecida
  (mismo principio/final, medio distinto) depende exactamente de que la
  víctima vea una versión acortada.
- **CSP sin `unsafe-inline` en ningún lado**: tanto el script como la hoja
  de estilos se permiten por hash (`sha256-...`), no por la excepción
  genérica `unsafe-inline` — se puede verificar en las herramientas de
  desarrollador del navegador.

## Limitaciones conocidas

- El rango de fuerza bruta offline es fijo (200 índices por cadena). Si tu
  wallet usa un índice más alto y el PSBT no trae `bip32Derivation`, no se
  va a encontrar la clave automáticamente.
- No arma transacciones desde cero — solo firma un PSBT que ya te dio otra
  herramienta. Para eso están paper-wallet-btc (generar) y My Wallet BTC
  (construir y transmitir).
- No implementa firma de scripts Taproot por script-path (solo key-path),
  ni PSBTs con `tapLeafScript`/`tapMerkleRoot`.

## Licencia

ISC — software "tal cual", sin garantía. Antes de confiarle fondos reales:
leé el código fuente, probá primero en testnet, y considerá auditar la
lógica de `src/lib/` vos mismo.
