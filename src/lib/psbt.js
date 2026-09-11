import * as btc from '@scure/btc-signer';
import { base64, hex } from '@scure/base';
import { deriveNode, deriveByPathArray, RECEIVE_CHAIN, CHANGE_CHAIN, btcNetwork } from './hdwallet.js';
import { ADDRESS_TYPES, scriptForType, deriveFixedTypeNode } from './addresstypes.js';

// Offline, no-network brute-force range: how many receive/change indices to
// derive and check against the PSBT's inputs/outputs per chain. There is no
// "used address" signal available offline, so this is a flat cap instead of
// a gap-limit scan.
export const DEFAULT_SCAN_RANGE = 200;

export function decodePsbt(text) {
  const trimmed = text.replace(/\s+/g, '');
  if (!trimmed) throw new Error('Pegá o cargá un PSBT primero.');

  // Hex and base64 alphabets overlap (any hex string is also valid-looking
  // base64), so decoding successfully isn't proof of the right encoding -
  // only a PSBT that actually parses is. Try the encoding the string looks
  // most like first, but fall back to the other before giving up.
  const looksHex = /^[0-9a-fA-F]+$/.test(trimmed) && trimmed.length % 2 === 0;
  const encodings = looksHex ? ['hex', 'base64'] : ['base64', 'hex'];

  let lastError = null;
  for (const encoding of encodings) {
    try {
      const bytes = encoding === 'hex' ? hex.decode(trimmed) : base64.decode(trimmed);
      // allowUnknownInputs: a PSBT may carry a taproot script-path input
      // whose leaf isn't one of this library's recognized templates (e.g.
      // Inheritance Vault BTC's CSV-timelock leaf) - without this, finalize()
      // would throw even after a correct signature was already produced.
      return btc.Transaction.fromPSBT(bytes, { allowUnknown: true, allowUnknownInputs: true });
    } catch (err) {
      lastError = err;
    }
  }
  throw new Error(`No se pudo decodificar el PSBT (ni base64 ni hex valido): ${lastError?.message ?? ''}`);
}

export function encodePsbt(tx) {
  return base64.encode(tx.toPSBT());
}

function prevoutFor(input) {
  if (input.witnessUtxo) return input.witnessUtxo;
  if (input.nonWitnessUtxo) {
    // getInput() may hand back either raw bytes/hex (as originally set via
    // addInput) or the already-decoded transaction object (once the library
    // has normalized it internally) - accept both.
    const raw = input.nonWitnessUtxo;
    const decoded = raw instanceof Uint8Array
      ? btc.RawTx.decode(raw)
      : typeof raw === 'string'
        ? btc.RawTx.decode(hex.decode(raw))
        : raw;
    return decoded.outputs[input.index];
  }
  return null;
}

function scriptHexOf(scriptOrBytes) {
  return typeof scriptOrBytes === 'string' ? scriptOrBytes : hex.encode(scriptOrBytes);
}

// Builds scriptHex -> {node, type} for every key derivable from an
// unlocked seed: our own BIP84 account (both chains, up to `range`) plus
// the 4 paper-wallet-btc-style fixed addresses. Entirely offline - no
// network call, no "used address" concept, just brute-force script
// matching against whatever the PSBT's inputs/outputs actually contain.
export function buildSeedCandidateMap({ account, seed, isTestnet, range = DEFAULT_SCAN_RANGE }) {
  const network = btcNetwork(isTestnet);
  const map = new Map();
  if (account) {
    for (const chain of [RECEIVE_CHAIN, CHANGE_CHAIN]) {
      for (let i = 0; i < range; i++) {
        const node = deriveNode(account, chain, i);
        const script = scriptForType(node.publicKey, 'bech32', network);
        map.set(hex.encode(script), { node, type: 'bech32' });
      }
    }
  }
  if (seed) {
    for (const type of ADDRESS_TYPES) {
      const node = deriveFixedTypeNode(seed, type, isTestnet);
      const script = scriptForType(node.publicKey, type, network);
      map.set(hex.encode(script), { node, type });
    }
  }
  return map;
}

// Single imported key (WIF/BIP38): check all possible address encodings.
export function buildImportedKeyMap({ node, isTestnet, compressed = true }) {
  const network = btcNetwork(isTestnet);
  const map = new Map();
  const types = compressed ? ADDRESS_TYPES : ['legacy', 'taproot'];
  for (const type of types) {
    const script = scriptForType(node.publicKey, type, network);
    map.set(hex.encode(script), { node, type });
  }
  return map;
}

function annotateForType(tx, index, node, type, network) {
  if (type === 'p2sh') {
    tx.updateInput(index, { redeemScript: btc.p2wpkh(node.publicKey, network).script });
  } else if (type === 'taproot') {
    tx.updateInput(index, { tapInternalKey: node.publicKey.slice(1, 33) });
  }
}

/**
 * Figures out which inputs this key material can sign, WITHOUT signing
 * anything yet - the review screen must show this before any private key
 * touches the transaction. Two independent strategies, tried in order per
 * input:
 *  1. The input's own `bip32Derivation` metadata, if present and `root` was
 *     given (seed-based unlock only) - works for any path/depth a wallet
 *     declared, not just our own convention.
 *  2. Brute-force: match the input's prevout script against `candidateMap`.
 * Returns [{ index, node, type }] - `type` is only set for brute-force
 * matches, since those are the ones that may still need redeemScript/
 * tapInternalKey annotated before they can be signed.
 */
export function identifySigners(tx, { candidateMap, root }) {
  const matches = [];
  for (let i = 0; i < tx.inputsLength; i++) {
    const input = tx.getInput(i);
    const prevout = prevoutFor(input);
    if (!prevout) continue;
    const scriptHex = scriptHexOf(prevout.script);

    let node = null;
    let type = null;

    if (root && input.bip32Derivation) {
      for (const [pubkey, deriv] of input.bip32Derivation) {
        if (!deriv || deriv.fingerprint !== root.fingerprint) continue;
        const candidate = deriveByPathArray(root, deriv.path);
        if (hex.encode(candidate.publicKey) === scriptHexOf(pubkey)) {
          node = candidate;
          break;
        }
      }
    }
    // Taproot's own derivation field (BIP174 tapBip32Derivation) carries
    // x-only (32-byte) pubkeys, separate from the legacy bip32Derivation
    // field above - needed for any taproot input whose output key is tweaked
    // by a script tree (e.g. Inheritance Vault BTC), since those can never
    // be found by brute-force script matching: candidateMap only knows how
    // to compute plain key-path-only p2tr scripts.
    if (!node && root && input.tapBip32Derivation) {
      for (const [xOnlyPubkey, deriv] of input.tapBip32Derivation) {
        if (!deriv || deriv.der.fingerprint !== root.fingerprint) continue;
        const candidate = deriveByPathArray(root, deriv.der.path);
        if (hex.encode(candidate.publicKey.slice(1, 33)) === scriptHexOf(xOnlyPubkey)) {
          node = candidate;
          break;
        }
      }
    }
    if (!node && candidateMap) {
      const hit = candidateMap.get(scriptHex);
      if (hit) { node = hit.node; type = hit.type; }
    }
    if (node) matches.push({ index: i, node, type });
  }
  return matches;
}

/** Actually signs, given the matches `identifySigners` already found and
 * the user already confirmed. Mutates `tx` in place. Returns the signed
 * indices (same as the input matches' indices). */
export function applySignatures(tx, matches, network) {
  const neededKeys = new Map(); // pubkeyHex -> privateKey, deduped
  for (const { index, node, type } of matches) {
    if (type) annotateForType(tx, index, node, type, network);
    neededKeys.set(hex.encode(node.publicKey), node.privateKey);
  }
  for (const privateKey of neededKeys.values()) {
    tx.sign(privateKey);
    privateKey.fill(0);
  }
  return matches.map((m) => m.index);
}

/** Tries to finalize (all inputs signed); falls back to exporting the
 * still-partial PSBT for further cosigning elsewhere. */
export function finalizeOrExport(tx) {
  try {
    tx.finalize();
    return { finalized: true, hex: tx.hex, txid: tx.id };
  } catch (err) {
    return { finalized: false, psbt: encodePsbt(tx), error: err.message };
  }
}

function scriptToAddress(script, network) {
  try {
    return btc.Address(network).encode(btc.OutScript.decode(script));
  } catch {
    return null;
  }
}

/** Human-readable summary for the mandatory review screen: totals, fee,
 * and each output's address/amount, flagging which ones are ours (change). */
export function describePsbt(tx, candidateMap, network) {
  let inputsTotal = 0n;
  for (let i = 0; i < tx.inputsLength; i++) {
    const prevout = prevoutFor(tx.getInput(i));
    if (prevout) inputsTotal += prevout.amount;
  }

  let outputsTotal = 0n;
  const outputs = [];
  for (let i = 0; i < tx.outputsLength; i++) {
    const output = tx.getOutput(i);
    outputsTotal += output.amount;
    const isChange = Boolean(candidateMap && candidateMap.has(hex.encode(output.script)));
    outputs.push({
      amount: output.amount,
      address: scriptToAddress(output.script, network),
      isChange,
    });
  }

  return { inputsTotal, outputsTotal, fee: inputsTotal - outputsTotal, outputs };
}
