import { validateMnemonic, mnemonicToSeedWebcrypto } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english.js';

const VALID_WORD_COUNTS = [12, 15, 18, 21, 24];

export function normalizeMnemonic(phrase) {
  return phrase.trim().toLowerCase().replace(/\s+/g, ' ');
}

export function isValidMnemonic(phrase) {
  const normalized = normalizeMnemonic(phrase);
  if (!normalized) return false;
  const words = normalized.split(' ');
  if (!VALID_WORD_COUNTS.includes(words.length)) return false;
  return validateMnemonic(normalized, wordlist);
}

// WebCrypto PBKDF2: the standard, fast path in every modern browser (vs. the
// pure-JS fallback in mnemonicToSeedSync), and this app only ever runs there.
export async function seedFromMnemonic(phrase, passphrase = '') {
  const normalized = normalizeMnemonic(phrase);
  return mnemonicToSeedWebcrypto(normalized, passphrase);
}
