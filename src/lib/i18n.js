/**
 * Single source of truth for every user-facing string. Same dictionary/
 * walker pattern as paper-wallet-btc and my-wallet-btc, scoped to this
 * tool's own screens.
 */
export const LANGS = ['es', 'en'];
export const DEFAULT_LANG = 'es';

const dict = {
  // Product name - kept as one fixed English name across languages, like
  // the sibling tools' own names aren't translated either.
  'meta.title': { es: 'PSBT Signer BTC', en: 'PSBT Signer BTC' },
  'topbar.brand': { es: 'PSBT Signer BTC', en: 'PSBT Signer BTC' },
  'topbar.mode.tip': {
    es: 'Básico: solo frase semilla + passphrase, lo esencial para firmar. Avanzado: agrega semilla cifrada (AES), clave privada (WIF/BIP38) y carga desde archivo.',
    en: 'Basic: just seed phrase + passphrase, the essentials to sign. Advanced: adds encrypted seed (AES), private key (WIF/BIP38), and loading from a file.',
  },
  'topbar.mode.prefix': { es: 'Modo:', en: 'Mode:' },
  'topbar.mode.basic': { es: 'Básico', en: 'Basic' },
  'topbar.mode.advanced': { es: 'Avanzado', en: 'Advanced' },
  'topbar.theme.toLight': { es: '☀ Modo claro', en: '☀ Light mode' },
  'topbar.theme.toDark': { es: '🌙 Modo oscuro', en: '🌙 Dark mode' },
  'topbar.lang.toEnglish': { es: '🌐 English', en: '🌐 English' },
  'topbar.lang.toSpanish': { es: '🌐 Español', en: '🌐 Español' },

  'notice.warning': {
    es: '<strong>Aviso:</strong> esta herramienta firma transacciones reales de Bitcoin, pero <strong>nunca transmite nada</strong> — no hace ninguna llamada de red. Para máxima seguridad, usala en un equipo desconectado de internet. Nadie ajeno a este proyecto auditó el código todavía: leelo antes de confiarle fondos.',
    en: '<strong>Warning:</strong> this tool signs real Bitcoin transactions, but it <strong>never broadcasts anything</strong> — it makes no network calls at all. For maximum security, use it on a device disconnected from the internet. Nobody outside this project has audited the code yet: read it yourself before trusting it with funds.',
  },
  'notice.autoLocked': {
    es: '🔒 La sesión se bloqueó sola por inactividad. Volvé a desbloquear para seguir.',
    en: '🔒 The session locked itself due to inactivity. Unlock again to continue.',
  },

  'network.legend': { es: 'Red', en: 'Network' },
  'network.testnet.label': { es: 'Testnet (recomendado para probar)', en: 'Testnet (recommended for testing)' },
  'network.mainnet.label': { es: 'Mainnet (Bitcoin real)', en: 'Mainnet (real Bitcoin)' },
  'network.mainnet.confirm': {
    es: 'Entiendo que voy a operar con Bitcoin real y puedo perder mis fondos si me equivoco.',
    en: 'I understand I am operating with real Bitcoin and can lose my funds if I make a mistake.',
  },
  'network.badge.testnet': { es: 'TESTNET', en: 'TESTNET' },
  'network.badge.mainnet': { es: 'MAINNET', en: 'MAINNET' },

  'unlockMode.legend': { es: 'Como desbloqueás la clave', en: 'How you unlock the key' },
  'unlockMode.seed.label': { es: 'Frase semilla (BIP39)', en: 'Seed phrase (BIP39)' },
  'unlockMode.key.label': { es: 'Clave privada (WIF)', en: 'Private key (WIF)' },

  'fileLoad.hint': {
    es: '"Cargar desde archivo" lee un .txt directo desde un pendrive con el diálogo nativo del sistema operativo — el contenido nunca pasa por el portapapeles (evita el historial de clipboard de apps de terceros y extensiones).',
    en: '"Load from file" reads a .txt straight from a USB stick via the native OS dialog — the content never touches the clipboard (avoids clipboard history from third-party apps and extensions).',
  },
  'fileLoad.button': { es: '📁 Cargar desde archivo (USB)', en: '📁 Load from file (USB)' },

  'seedEncrypted.checkbox': {
    es: 'La frase está cifrada (bloque AES-256-GCM de paper-wallet-btc)',
    en: 'The phrase is encrypted (paper-wallet-btc AES-256-GCM block)',
  },
  'mnemonic.label': { es: 'Frase semilla (12 o 24 palabras, BIP39)', en: 'Seed phrase (12 or 24 words, BIP39)' },
  'encryptedSeed.label': { es: 'Bloque cifrado (del PDF de paper-wallet-btc)', en: 'Encrypted block (from the paper-wallet-btc PDF)' },
  'decryptPassword.label': { es: 'Contraseña de descifrado', en: 'Decryption password' },
  'passphrase.label': { es: 'Passphrase BIP39 (opcional, "palabra 25")', en: 'BIP39 passphrase (optional, "25th word")' },

  'wif.label': { es: 'Clave privada (WIF, o clave BIP38 cifrada que empieza con "6P...")', en: 'Private key (WIF, or an encrypted BIP38 key starting with "6P...")' },
  'wifPassphrase.label': { es: 'Passphrase BIP38 (solo si la clave empieza con "6P...")', en: 'BIP38 passphrase (only if the key starts with "6P...")' },
  'wif.hint': {
    es: 'Se revisan los 4 formatos de dirección posibles para esta clave (Legacy, P2SH-SegWit, Native SegWit y Taproot).',
    en: 'All 4 possible address formats for this key are checked (Legacy, P2SH-SegWit, Native SegWit, and Taproot).',
  },

  'unlock.button': { es: 'Desbloquear clave', en: 'Unlock key' },

  'error.badMnemonic': {
    es: 'La frase semilla no es valida (revisa la cantidad de palabras y el checksum BIP39).',
    en: 'The seed phrase is not valid (check the word count and the BIP39 checksum).',
  },
  'error.badWif': { es: 'Clave WIF invalida.', en: 'Invalid WIF key.' },
  'error.unlockFailed': { es: 'Error al desbloquear: {msg}', en: 'Failed to unlock: {msg}' },
  'error.fileReadFailed': { es: 'No se pudo leer el archivo: {msg}', en: 'Could not read the file: {msg}' },

  'load.title': { es: 'Cargar transacción (PSBT)', en: 'Load transaction (PSBT)' },
  'load.hint': {
    es: 'Pegá o cargá el PSBT sin firmar (o parcialmente firmado) que generó otra wallet — en formato base64 o hex.',
    en: 'Paste or load the unsigned (or partially signed) PSBT that another wallet generated — in base64 or hex format.',
  },
  'load.label': { es: 'PSBT (base64 o hex)', en: 'PSBT (base64 or hex)' },
  'load.analyze': { es: 'Analizar', en: 'Analyze' },
  'load.lock': { es: 'Bloquear', en: 'Lock' },
  'error.decodeFailed': { es: 'No se pudo leer el PSBT: {msg}', en: 'Could not read the PSBT: {msg}' },
  'error.noKeysMatched': {
    es: 'Ninguna clave derivada de lo que desbloqueaste coincide con los inputs de este PSBT — no hay nada para firmar.',
    en: 'None of the keys derived from what you unlocked match this PSBT\'s inputs — nothing to sign.',
  },
  'error.networkMismatch': {
    es: 'Este PSBT deriva claves con tu misma semilla pero para la otra red (Testnet/Mainnet). Cambiá la red seleccionada arriba y volvé a intentar.',
    en: 'This PSBT derives keys with your same seed but for the other network (Testnet/Mainnet). Change the network selected above and try again.',
  },

  'review.title': { es: 'Revisar antes de firmar', en: 'Review before signing' },
  'review.willSign': { es: '{n} de {total} inputs se van a firmar con esta clave', en: '{n} of {total} inputs will be signed with this key' },
  'review.inputsTotal': { es: 'Total de entradas', en: 'Total inputs' },
  'review.outputsTotal': { es: 'Total de salidas', en: 'Total outputs' },
  'review.fee': { es: 'Comisión', en: 'Fee' },
  'review.outputs': { es: 'Salidas', en: 'Outputs' },
  'review.change': { es: '(cambio, es tuya)', en: '(change, yours)' },
  'review.noAddress': { es: '(script sin dirección estándar)', en: '(non-standard script)' },
  'review.confirm': {
    es: 'Revisé el destino y los montos, y quiero firmar esta transacción con la clave que desbloqueé.',
    en: 'I reviewed the destination and amounts, and I want to sign this transaction with the key I unlocked.',
  },
  'review.missingAmounts': {
    es: '{n} de {total} entradas no declaran ningún monto (ni siquiera un witnessUtxo) — se cuentan como 0 en el total de entradas de arriba, así que ese total y la comisión están subestimados, no reflejan lo que en verdad se está gastando.',
    en: '{n} of {total} inputs declare no amount at all (not even a witnessUtxo) — they count as 0 in the inputs total above, so that total and the fee are understated and don\'t reflect what\'s actually being spent.',
  },
  'review.unverifiedAmounts': {
    es: '{n} de {total} entradas no traen la transacción de origen completa: su monto es lo que dice el PSBT, sin forma de verificarlo sin conexión. Un coordinador malicioso podría mentir sobre esos montos para inflar la comisión real. Los totales de arriba pueden no ser exactos.',
    en: '{n} of {total} inputs don\'t include the full source transaction: their amount is whatever the PSBT claims, with no way to verify it offline. A malicious coordinator could lie about those amounts to inflate the real fee. The totals above may not be accurate.',
  },
  'review.feeTooHigh': {
    es: 'La comisión calculada es inusualmente alta en relación al total de entradas. Revisá los montos con cuidado antes de firmar.',
    en: 'The calculated fee is unusually high relative to the total inputs. Review the amounts carefully before signing.',
  },
  'review.riskAck': {
    es: 'Entiendo el riesgo descripto arriba y quiero firmar igual.',
    en: 'I understand the risk described above and want to sign anyway.',
  },
  'review.sign': { es: 'Firmar', en: 'Sign' },
  'review.cancel': { es: 'Cancelar', en: 'Cancel' },
  'error.signFailed': { es: 'Error al firmar: {msg}', en: 'Signing failed: {msg}' },

  'result.title.finalized': { es: 'Transacción firmada y completa', en: 'Transaction signed and complete' },
  'result.title.partial': { es: 'PSBT firmado parcialmente', en: 'PSBT partially signed' },
  'result.finalized.hint': {
    es: 'Todas las firmas necesarias están presentes. Este es el hex listo para transmitir (con My Wallet BTC, un nodo propio, o cualquier otra herramienta).',
    en: 'All required signatures are present. This is the hex ready to broadcast (with My Wallet BTC, your own node, or any other tool).',
  },
  'result.partial.hint': {
    es: 'Esta transacción necesita más firmas (por ejemplo, un multisig). Pasále este PSBT al próximo firmante.',
    en: 'This transaction needs more signatures (for example, a multisig). Pass this PSBT to the next signer.',
  },
  'result.partialSignWarning': {
    es: 'La revisión anterior indicaba que se iban a firmar {expected} input(s) con esta clave, pero sólo se pudieron firmar {signed}. Revisá el resultado con cuidado antes de usarlo.',
    en: 'The review screen indicated {expected} input(s) would be signed with this key, but only {signed} actually were. Review the result carefully before using it.',
  },
  'result.txid': { es: 'TXID', en: 'TXID' },
  'result.hexLabel': { es: 'Transacción firmada (hex)', en: 'Signed transaction (hex)' },
  'result.psbtLabel': { es: 'PSBT actualizado (base64)', en: 'Updated PSBT (base64)' },
  'result.download': { es: '⬇ Descargar .txt', en: '⬇ Download .txt' },
  'result.copy': { es: 'Copiar', en: 'Copy' },
  'result.copied': { es: 'Copiado!', en: 'Copied!' },
  'result.back': { es: 'Firmar otro PSBT', en: 'Sign another PSBT' },
  'result.lock': { es: 'Bloquear', en: 'Lock' },

  'footer.note': {
    es: 'Firma 100% en tu navegador · sin cookies · sin almacenamiento persistente · sin ninguna llamada de red. Revisa el código fuente antes de confiarle fondos.',
    en: 'Signs 100% in your browser · no cookies · no persistent storage · no network calls at all. Review the source before trusting it with funds.',
  },
};

export function t(key, lang, vars) {
  const entry = dict[key];
  let str = entry ? (entry[lang] ?? entry[DEFAULT_LANG]) : key;
  if (vars) {
    for (const [k, v] of Object.entries(vars)) str = str.replaceAll(`{${k}}`, String(v));
  }
  return str;
}
