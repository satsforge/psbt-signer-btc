import { sha256 } from '@noble/hashes/sha2.js';
import { scryptAsync } from '@noble/hashes/scrypt.js';
import { utf8ToBytes } from '@noble/hashes/utils.js';
import { ecb } from '@noble/ciphers/aes.js';
import { base58check } from '@scure/base';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import * as btc from '@scure/btc-signer';

const b58c = base58check(sha256);

function xorBytes(a, b) {
  const out = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) out[i] = a[i] ^ b[i];
  return out;
}

export function isBip38(text) {
  return /^6P[1-9A-HJ-NP-Za-km-z]+$/.test(text.trim());
}

// P2PKH (legacy, mainnet) address for a given pubkey - the BIP38 salt is
// always computed against this address per spec, regardless of the actual
// receive-address type or network (paper-wallet-btc, the only realistic
// source of these keys, is mainnet-only and pre-dates SegWit/Taproot).
function legacyAddressForSalt(pubkey) {
  return btc.p2pkh(pubkey).address;
}

/**
 * BIP38 decryption (non-EC-multiply mode only - the mode every paper wallet
 * generator, including paper-wallet-btc, actually produces). Verifies the
 * address-hash checksum after decrypting, so a wrong passphrase throws a
 * clear error instead of silently handing back a garbage private key.
 */
export async function decryptBip38(encrypted, passphrase, onProgress) {
  const payload = b58c.decode(encrypted.trim());
  if (payload.length !== 39 || payload[0] !== 0x01) {
    throw new Error('Formato BIP38 invalido.');
  }
  if (payload[1] === 0x43) {
    throw new Error('Claves BIP38 con EC-multiply no estan soportadas.');
  }
  if (payload[1] !== 0x42) {
    throw new Error('Formato BIP38 invalido.');
  }
  const flagByte = payload[2];
  const compressed = (flagByte & 0x20) !== 0;
  const addressHash = payload.slice(3, 7);
  const encryptedHalf1 = payload.slice(7, 23);
  const encryptedHalf2 = payload.slice(23, 39);

  const derived = await scryptAsync(utf8ToBytes(passphrase.normalize('NFC')), addressHash, {
    N: 16384,
    r: 8,
    p: 8,
    dkLen: 64,
    onProgress,
  });
  const derivedHalf1 = derived.slice(0, 32);
  const derivedHalf2 = derived.slice(32, 64);

  const dec1 = ecb(derivedHalf2, { disablePadding: true }).decrypt(encryptedHalf1);
  const dec2 = ecb(derivedHalf2, { disablePadding: true }).decrypt(encryptedHalf2);
  const privateKey = new Uint8Array([
    ...xorBytes(dec1, derivedHalf1.slice(0, 16)),
    ...xorBytes(dec2, derivedHalf1.slice(16, 32)),
  ]);

  const pubkey = secp256k1.getPublicKey(privateKey, compressed);
  const address = legacyAddressForSalt(pubkey);
  const checkHash = sha256(sha256(utf8ToBytes(address))).slice(0, 4);
  const passphraseOk = checkHash.every((b, i) => b === addressHash[i]);
  if (!passphraseOk) {
    privateKey.fill(0);
    throw new Error('Passphrase incorrecta (no coincide el checksum BIP38).');
  }
  return { privateKey, compressed };
}
