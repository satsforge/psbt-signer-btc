import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mnemonicToSeedSync } from '@scure/bip39';
import * as btc from '@scure/btc-signer';
import { hex } from '@scure/base';
import { randomBytes } from '@noble/hashes/utils.js';
import {
  accountFromSeed, rootFromSeed, deriveNode, keyNodeFromPrivateKey,
  RECEIVE_CHAIN, CHANGE_CHAIN, btcNetwork,
} from '../src/lib/hdwallet.js';
import { deriveFixedTypeNode } from '../src/lib/addresstypes.js';
import {
  buildSeedCandidateMap, buildImportedKeyMap, identifySigners, applySignatures, finalizeOrExport,
  describePsbt, decodePsbt, encodePsbt,
} from '../src/lib/psbt.js';

function signAll(tx, opts, network) {
  const matches = identifySigners(tx, opts);
  return applySignatures(tx, matches, network);
}

const VECTOR_MNEMONIC = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

function buildFundingTx(script, amount) {
  const funding = new btc.Transaction({ version: 1 });
  funding.addInput({ txid: new Uint8Array(32), index: 0xffffffff });
  funding.addOutput({ script, amount });
  return funding;
}

function externalAddress(network) {
  return btc.getAddress('wpkh', randomBytes(32), network);
}

test('signs a PSBT input owned by our own BIP84 account via offline brute-force matching', () => {
  const seed = mnemonicToSeedSync(VECTOR_MNEMONIC, '');
  const network = btcNetwork(true);
  const account = accountFromSeed(seed.slice(), true);
  const sourceNode = deriveNode(account, RECEIVE_CHAIN, 5);
  const changeNode = deriveNode(account, CHANGE_CHAIN, 0);
  const sourceScript = btc.p2wpkh(sourceNode.publicKey, network).script;
  const funding = buildFundingTx(sourceScript, 100_000n);

  const tx = new btc.Transaction();
  tx.addInput({ txid: funding.id, index: 0, nonWitnessUtxo: funding.unsignedTx });
  tx.addOutputAddress(externalAddress(network), 50_000n, network);
  tx.addOutputAddress(btc.p2wpkh(changeNode.publicKey, network).address, 49_000n, network);

  const candidateMap = buildSeedCandidateMap({ account, seed, isTestnet: true, range: 20 });
  const signed = signAll(tx, { candidateMap, root: null }, network);
  assert.deepEqual(signed, [0]);

  const summary = describePsbt(tx, candidateMap, network);
  assert.equal(summary.fee, 1_000n);
  assert.equal(summary.outputs[0].isChange, false);
  assert.equal(summary.outputs[1].isChange, true);

  const result = finalizeOrExport(tx);
  assert.equal(result.finalized, true);
  const decoded = btc.Transaction.fromRaw(hex.decode(result.hex));
  const input = decoded.getInput(0);
  assert.ok(input.finalScriptWitness && input.finalScriptWitness.length > 0);
});

test('signs a paper-wallet-btc-style Legacy fixed address via offline matching', () => {
  const seed = mnemonicToSeedSync(VECTOR_MNEMONIC, '');
  const network = btcNetwork(true);
  const account = accountFromSeed(seed.slice(), true);
  const legacyNode = deriveFixedTypeNode(seed.slice(), 'legacy', true);
  const sourceScript = btc.p2pkh(legacyNode.publicKey, network).script;
  const funding = buildFundingTx(sourceScript, 30_000n);

  const tx = new btc.Transaction();
  tx.addInput({ txid: funding.id, index: 0, nonWitnessUtxo: funding.unsignedTx });
  tx.addOutputAddress(externalAddress(network), 28_000n, network);

  const candidateMap = buildSeedCandidateMap({ account, seed, isTestnet: true, range: 5 });
  const signed = signAll(tx, { candidateMap, root: null }, network);
  assert.deepEqual(signed, [0]);
  const result = finalizeOrExport(tx);
  assert.equal(result.finalized, true);
});

test('signs via bip32Derivation metadata for a path outside the brute-force range', () => {
  const seed = mnemonicToSeedSync(VECTOR_MNEMONIC, '');
  const network = btcNetwork(true);
  const root = rootFromSeed(seed.slice());
  const account = accountFromSeed(seed.slice(), true);
  const farIndex = 500; // well beyond the default brute-force range
  const farNode = deriveNode(account, RECEIVE_CHAIN, farIndex);
  const farScript = btc.p2wpkh(farNode.publicKey, network).script;
  const funding = buildFundingTx(farScript, 60_000n);

  const tx = new btc.Transaction();
  tx.addInput({ txid: funding.id, index: 0, nonWitnessUtxo: funding.unsignedTx });
  tx.updateInput(0, {
    bip32Derivation: [[farNode.publicKey, { fingerprint: root.fingerprint, path: btc.bip32Path(`m/84'/1'/0'/0/${farIndex}`) }]],
  });
  tx.addOutputAddress(externalAddress(network), 55_000n, network);

  const signed = signAll(tx, { candidateMap: new Map(), root }, network);
  assert.deepEqual(signed, [0]);
  const result = finalizeOrExport(tx);
  assert.equal(result.finalized, true);
});

test('signs with a standalone imported key (WIF-style), checking all address encodings', () => {
  const network = btcNetwork(true);
  const privateKey = randomBytes(32);
  const node = keyNodeFromPrivateKey(privateKey, true);
  const sourceScript = btc.p2tr(node.publicKey.slice(1, 33), undefined, network).script;
  const funding = buildFundingTx(sourceScript, 40_000n);

  const tx = new btc.Transaction();
  tx.addInput({ txid: funding.id, index: 0, nonWitnessUtxo: funding.unsignedTx });
  tx.addOutputAddress(externalAddress(network), 38_000n, network);

  const candidateMap = buildImportedKeyMap({ node, isTestnet: true, compressed: true });
  const signed = signAll(tx, { candidateMap, root: null }, network);
  assert.deepEqual(signed, [0]);
  const result = finalizeOrExport(tx);
  assert.equal(result.finalized, true);
});

test('finalizeOrExport falls back to a partial PSBT when a required signature is missing', () => {
  const network = btcNetwork(true);
  const privateKey = randomBytes(32);
  const node = keyNodeFromPrivateKey(privateKey, true);
  const sourceScript = btc.p2wpkh(node.publicKey, network).script;
  const funding = buildFundingTx(sourceScript, 20_000n);

  const tx = new btc.Transaction();
  tx.addInput({ txid: funding.id, index: 0, nonWitnessUtxo: funding.unsignedTx });
  tx.addOutputAddress(externalAddress(network), 19_000n, network);

  // No matching key offered - identifySigners should find nothing to sign.
  const signed = signAll(tx, { candidateMap: new Map(), root: null }, network);
  assert.deepEqual(signed, []);

  const result = finalizeOrExport(tx);
  assert.equal(result.finalized, false);
  assert.ok(result.psbt.length > 0);
  // The exported PSBT must still round-trip through the decoder.
  const reloaded = decodePsbt(result.psbt);
  assert.equal(reloaded.inputsLength, 1);
});

test('decodePsbt/encodePsbt round-trips through both base64 and hex', () => {
  const network = btcNetwork(true);
  const privateKey = randomBytes(32);
  const node = keyNodeFromPrivateKey(privateKey, true);
  const sourceScript = btc.p2wpkh(node.publicKey, network).script;
  const funding = buildFundingTx(sourceScript, 15_000n);

  const tx = new btc.Transaction();
  tx.addInput({ txid: funding.id, index: 0, nonWitnessUtxo: funding.unsignedTx });
  tx.addOutputAddress(externalAddress(network), 14_000n, network);

  const b64 = encodePsbt(tx);
  const fromB64 = decodePsbt(b64);
  assert.equal(fromB64.inputsLength, 1);

  const asHex = hex.encode(tx.toPSBT());
  const fromHex = decodePsbt(asHex);
  assert.equal(fromHex.inputsLength, 1);
});

test('decodePsbt rejects garbage input with a clear error', () => {
  assert.throws(() => decodePsbt('not a real psbt'), /No se pudo decodificar/);
  assert.throws(() => decodePsbt(''), /Peg/);
});
