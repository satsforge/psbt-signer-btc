import * as btc from '@scure/btc-signer';
import { base64, hex } from '@scure/base';
import { deriveNode, deriveByPathArray, RECEIVE_CHAIN, CHANGE_CHAIN, btcNetwork, wipeNode } from './hdwallet.js';
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

const HARDENED_OFFSET = 0x80000000;

// True if `path`'s coin-type component (BIP44 element 1) matches the
// selected network - 0' mainnet, 1' any testnet/signet, same SLIP-44
// convention as hdwallet.js's COIN_TYPE map. A bip32Derivation/
// tapBip32Derivation entry can name our own root fingerprint yet still
// derive a key for the *other* network (the root itself has no notion of
// network - only the UI's chosen convention does), so this is the only
// thing standing between "PSBT says derive m/84'/0'/..." and this tool
// blindly signing a mainnet input while the user believes they're on
// testnet. Paths too shallow to carry a coin type can't be checked and are
// treated as not matching, rather than trusted.
function pathMatchesNetwork(path, isTestnet) {
  if (!Array.isArray(path) || path.length < 2) return false;
  return path[1] === HARDENED_OFFSET + (isTestnet ? 1 : 0);
}

/**
 * True if the PSBT names our own root fingerprint on some input's
 * bip32Derivation/tapBip32Derivation but with a coin-type that doesn't
 * match the selected network. `identifySigners` silently refuses to derive
 * for these (see `pathMatchesNetwork`), so on its own a real mismatch just
 * looks like "no matching keys" - this lets the caller give a specific,
 * actionable error instead of the generic one.
 */
export function hasNetworkMismatch(tx, root, isTestnet) {
  if (!root) return false;
  for (let i = 0; i < tx.inputsLength; i++) {
    const input = tx.getInput(i);
    for (const [, deriv] of input.bip32Derivation ?? []) {
      if (deriv?.fingerprint === root.fingerprint && !pathMatchesNetwork(deriv.path, isTestnet)) {
        return true;
      }
    }
    for (const [, deriv] of input.tapBip32Derivation ?? []) {
      if (deriv?.der.fingerprint === root.fingerprint && !pathMatchesNetwork(deriv.der.path, isTestnet)) {
        return true;
      }
    }
  }
  return false;
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

// The PSBT's own bip32Derivation metadata being internally self-consistent
// (our root really does derive that pubkey at that path) is not proof that
// this input's real prevout script has anything to do with that key - a
// malformed or malicious PSBT could name our fingerprint on an input that
// actually pays somewhere else entirely, and identifySigners would still
// report it as "ours to sign" without this check (applySignatures would
// then simply fail to sign it later, but only after the review screen
// already promised it would). Mirrors the address types buildSeedCandidateMap/
// buildImportedKeyMap already check for a plain (non-taproot) key - taproot's
// tapBip32Derivation is intentionally not covered here, since a script-path
// signer's key legitimately never equals the tweaked output key's own p2tr
// script (see the Inheritance Vault BTC test case).
function derivedKeyMatchesScript(publicKey, scriptHex, network) {
  for (const type of ADDRESS_TYPES) {
    if (type === 'taproot') continue;
    if (hex.encode(scriptForType(publicKey, type, network)) === scriptHex) return true;
  }
  return false;
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
export function identifySigners(tx, { candidateMap, root, isTestnet }) {
  const network = btcNetwork(isTestnet);
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
        if (!pathMatchesNetwork(deriv.path, isTestnet)) continue;
        const candidate = deriveByPathArray(root, deriv.path);
        if (hex.encode(candidate.publicKey) !== scriptHexOf(pubkey)) continue;
        if (!derivedKeyMatchesScript(candidate.publicKey, scriptHex, network)) continue;
        node = candidate;
        break;
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
        if (!pathMatchesNetwork(deriv.der.path, isTestnet)) continue;
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
 * the user already confirmed. Mutates `tx` in place. Returns the indices
 * that were *actually* signed - not necessarily all of `matches`: signing
 * a specific index can still fail even after identifySigners judged it
 * signable (e.g. a sighash this key isn't allowed to produce), and the
 * caller needs the true outcome, not an echo of what was expected. */
export function applySignatures(tx, matches, network) {
  const signed = [];
  // Each match is annotated and signed together, in its own try/catch:
  // signing by its own known index (tx.signIdx) rather than the coarser
  // tx.sign(key) - which tries a key against every input in the transaction
  // and could quietly sign something identifySigners never reported and
  // the review screen never showed - and catching per-match so that one bad
  // match (a redeemScript/tapInternalKey annotation that fails, a sighash
  // this key isn't allowed to produce, ...) can't abort every other,
  // already-reviewed signature this call was supposed to produce, nor leave
  // `tx` annotated-but-unsigned for a match the caller never finds out
  // failed. This also lets a key that legitimately signs more than one
  // match (address reuse) be verified input-by-input instead of collapsed
  // into one all-or-nothing attempt.
  for (const { index, node, type } of matches) {
    const privateKey = node.privateKey;
    try {
      if (type) annotateForType(tx, index, node, type, network);
      tx.signIdx(privateKey, index);
      signed.push(index);
    } catch {
      // This specific match didn't produce a signature after all - leave it
      // out of `signed` and keep going; finalizeOrExport will correctly
      // report the PSBT as still incomplete rather than this function
      // pretending every match succeeded.
    } finally {
      privateKey.fill(0); // scrubs this signing copy; see wipeNode below for the source
    }
  }
  // `node` here is a defensive copy-on-read object (see wipeNode's doc), so
  // signing above never touched its actual private key material. Nodes
  // without a `type` came straight from the PSBT's own bip32Derivation/
  // tapBip32Derivation (see identifySigners) - a fresh, single-use HDKey
  // re-derived from `root` on every call, never cached anywhere else - so
  // it's always safe to destroy them the moment they've been used. Nodes
  // *with* a `type` came from a shared candidateMap the caller may still
  // need for another PSBT this same unlocked session (e.g. re-signing an
  // RBF replacement of the same input); wiping the map's own copy instead
  // is the caller's responsibility, once it truly won't be needed again.
  for (const { node, type } of matches) {
    if (!type) wipeNode(node);
  }
  return signed;
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

// A PSBT's witnessUtxo claims an input's amount with nothing to check it
// against - a coordinator can lie about it, and the library will happily
// produce a valid signature for it anyway (that's the point of the
// SegWit-sighash fee-theft attack hardware wallets had to patch for). A
// nonWitnessUtxo (the full previous transaction) is the only thing this
// offline tool can verify without a network call: the library hashes it
// and checks it against the input's own txid whenever one is declared, so
// its amount can be trusted.
//
// 'verified'   - nonWitnessUtxo present, amount is trustworthy.
// 'unverified' - only witnessUtxo: a claimed amount with nothing checking it.
// 'missing'    - neither: contributes 0 to inputsTotal below, silently
//                understating it (and the fee) rather than just being
//                unverifiable - the worse of the two.
function prevoutVerification(input) {
  if (input.nonWitnessUtxo) return 'verified';
  if (input.witnessUtxo) return 'unverified';
  return 'missing';
}

// Above this fraction of the inputs' value, a fee looks like a mistake (or
// an attack that didn't bother lying convincingly) rather than a real one -
// even a very congested mempool rarely justifies double-digit percentages.
export const FEE_WARNING_RATIO = 0.10;

/** Human-readable summary for the mandatory review screen: totals, fee,
 * and each output's address/amount, flagging which ones are ours (change).
 * Also flags when the numbers above can't be fully trusted - either because
 * an input's amount is unverified (see `isAmountVerified`) or because the
 * resulting fee looks anomalous - so the caller can demand extra
 * confirmation instead of presenting a possibly-fabricated fee as fact. */
export function describePsbt(tx, candidateMap, network) {
  let inputsTotal = 0n;
  let missingInputs = 0;
  let unverifiedAmountInputs = 0;
  for (let i = 0; i < tx.inputsLength; i++) {
    const input = tx.getInput(i);
    const prevout = prevoutFor(input);
    if (prevout) inputsTotal += prevout.amount;
    const verification = prevoutVerification(input);
    if (verification === 'missing') missingInputs++;
    else if (verification === 'unverified') unverifiedAmountInputs++;
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

  const fee = inputsTotal - outputsTotal;
  // Number() is safe here: sats fit well within Number.MAX_SAFE_INTEGER for
  // any real Bitcoin amount, and this ratio only feeds a UI threshold.
  const feeRatio = inputsTotal > 0n ? Number(fee) / Number(inputsTotal) : 0;
  const feeWarning = missingInputs > 0 || unverifiedAmountInputs > 0 || fee < 0n || feeRatio > FEE_WARNING_RATIO;

  return { inputsTotal, outputsTotal, fee, outputs, missingInputs, unverifiedAmountInputs, feeWarning };
}
