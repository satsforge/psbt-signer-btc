import { scryptAsync } from '@noble/hashes/scrypt.js';
import { gcm } from '@noble/ciphers/aes.js';
import { utf8ToBytes } from '@noble/hashes/utils.js';
import { base64 } from '@scure/base';

// Must match paper-wallet-btc's src/lib/seedCipher.js exactly - same KDF
// params and layout (salt || nonce || ciphertext) - so blobs printed by
// that tool's "Cifrado AES-256-GCM de la semilla" feature decrypt here.
const SCRYPT_OPTS = { N: 65536, r: 8, p: 1, dkLen: 32 };
const SALT_LEN = 16;
const NONCE_LEN = 12;

/**
 * Decrypts a mnemonic blob produced by paper-wallet-btc's seedCipher.js.
 * Throws if the password is wrong or the blob is malformed (GCM's auth tag
 * fails loudly instead of returning garbage). Strips whitespace first: the
 * printed PDF wraps the base64 blob across several lines.
 */
export async function decryptMnemonic(blob, password) {
  let payload;
  try {
    payload = base64.decode(blob.replace(/\s+/g, ''));
  } catch {
    throw new Error('El bloque cifrado no es un base64 valido.');
  }
  if (payload.length <= SALT_LEN + NONCE_LEN) {
    throw new Error('El bloque cifrado esta incompleto.');
  }
  const salt = payload.slice(0, SALT_LEN);
  const nonce = payload.slice(SALT_LEN, SALT_LEN + NONCE_LEN);
  const ciphertext = payload.slice(SALT_LEN + NONCE_LEN);
  const key = await scryptAsync(utf8ToBytes(password.normalize('NFC')), salt, SCRYPT_OPTS);
  let plaintext;
  try {
    plaintext = gcm(key, nonce).decrypt(ciphertext);
  } catch {
    throw new Error('Contrasena incorrecta o bloque cifrado invalido.');
  }
  return new TextDecoder().decode(plaintext);
}
