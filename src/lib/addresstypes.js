import { HDKey } from '@scure/bip32';
import * as btc from '@scure/btc-signer';

// Same 4 address types paper-wallet-btc can print, at the same fixed
// account-0/chain-0/index-0 path per type (that tool never rotates
// addresses - each generated wallet is exactly one address per type).
// Coin type follows SLIP-44 (0' mainnet, 1' any testnet), same convention
// as hdwallet.js's BIP84 account.
export const ADDRESS_TYPES = ['legacy', 'p2sh', 'bech32', 'taproot'];

const PURPOSE = { legacy: 44, p2sh: 49, bech32: 84, taproot: 86 };

export function fixedPath(type, isTestnet) {
  const coinType = isTestnet ? 1 : 0;
  return `m/${PURPOSE[type]}'/${coinType}'/0'/0/0`;
}

/** Address for a given (compressed, 33-byte) ECDSA public key, by type. */
export function addressForType(publicKey, type, network) {
  if (type === 'legacy') return btc.p2pkh(publicKey, network).address;
  if (type === 'p2sh') return btc.p2sh(btc.p2wpkh(publicKey, network), network).address;
  if (type === 'bech32') return btc.p2wpkh(publicKey, network).address;
  if (type === 'taproot') return btc.p2tr(publicKey.slice(1, 33), undefined, network).address;
  throw new Error(`Tipo de direccion desconocido: ${type}`);
}

/** Output script (scriptPubKey) for a given public key, by type - used to
 * match a PSBT input's prevout script against a candidate derived key. */
export function scriptForType(publicKey, type, network) {
  if (type === 'legacy') return btc.p2pkh(publicKey, network).script;
  if (type === 'p2sh') return btc.p2sh(btc.p2wpkh(publicKey, network), network).script;
  if (type === 'bech32') return btc.p2wpkh(publicKey, network).script;
  if (type === 'taproot') return btc.p2tr(publicKey.slice(1, 33), undefined, network).script;
  throw new Error(`Tipo de direccion desconocido: ${type}`);
}

/**
 * Derives the paper-wallet-btc-compatible fixed address for one type
 * directly from the master seed (independent of the BIP84 HD account).
 */
export function deriveFixedTypeNode(seed, type, isTestnet) {
  const root = HDKey.fromMasterSeed(seed);
  const node = root.derive(fixedPath(type, isTestnet));
  root.wipePrivateData();
  return node;
}

/** All 4 address types derived from the same seed, paper-wallet-btc style. */
export function deriveAllFixedTypeNodes(seed, isTestnet) {
  const root = HDKey.fromMasterSeed(seed);
  const nodes = {};
  for (const type of ADDRESS_TYPES) nodes[type] = root.derive(fixedPath(type, isTestnet));
  root.wipePrivateData();
  return nodes;
}
