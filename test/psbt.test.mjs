import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mnemonicToSeedSync } from '@scure/bip39';
import * as btc from '@scure/btc-signer';
import { hex } from '@scure/base';
import { randomBytes } from '@noble/hashes/utils.js';
import {
  accountFromSeed, rootFromSeed, deriveNode, keyNodeFromPrivateKey,
  RECEIVE_CHAIN, CHANGE_CHAIN, btcNetwork, wipeNode,
} from '../src/lib/hdwallet.js';
import { deriveFixedTypeNode } from '../src/lib/addresstypes.js';
import {
  buildSeedCandidateMap, buildImportedKeyMap, identifySigners, applySignatures, finalizeOrExport,
  describePsbt, decodePsbt, encodePsbt, hasNetworkMismatch,
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

  const signed = signAll(tx, { candidateMap: new Map(), root, isTestnet: true }, network);
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

test('signs a taproot script-path input via tapBip32Derivation, for a leaf script this library does not recognize', () => {
  // Mirrors Inheritance Vault BTC's real shape: key-path is some unrelated
  // internal key, script-path is a single non-standard leaf
  // (<N> CHECKSEQUENCEVERIFY DROP <pubkey> CHECKSIG). Neither the brute-force
  // candidateMap (which only computes plain key-path-only p2tr scripts) nor
  // the legacy bip32Derivation field can find this signer - only
  // tapBip32Derivation plus allowUnknownInputs (both added for this) can.
  const seed = mnemonicToSeedSync(VECTOR_MNEMONIC, '');
  const network = btcNetwork(true);
  const root = rootFromSeed(seed.slice());
  const heirNode = root.derive("m/86'/1'/0'/0/0");
  const heirXOnly = heirNode.publicKey.slice(1, 33);
  const csvBlocks = 5;
  const leafScript = btc.Script.encode([csvBlocks, 'CHECKSEQUENCEVERIFY', 'DROP', heirXOnly, 'CHECKSIG']);
  const vault = btc.p2tr(btc.TAPROOT_UNSPENDABLE_KEY, { script: leafScript }, network, true);
  const funding = buildFundingTx(vault.script, 100_000n);

  const tx = new btc.Transaction({ allowUnknownInputs: true });
  tx.addInput({
    txid: funding.id,
    index: 0,
    witnessUtxo: { amount: 100_000n, script: vault.script },
    tapLeafScript: vault.tapLeafScript,
    sequence: csvBlocks,
    tapBip32Derivation: [[
      heirXOnly,
      { hashes: [vault.leaves[0].hash], der: { fingerprint: root.fingerprint, path: btc.bip32Path("m/86'/1'/0'/0/0") } },
    ]],
  });
  tx.addOutputAddress(externalAddress(network), 98_000n, network);

  const signed = signAll(tx, { candidateMap: null, root, isTestnet: true }, network);
  assert.deepEqual(signed, [0]);
  const result = finalizeOrExport(tx);
  assert.equal(result.finalized, true, result.error);
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

test('describePsbt flags an input whose amount is only claimed via witnessUtxo, not verified', () => {
  const seed = mnemonicToSeedSync(VECTOR_MNEMONIC, '');
  const network = btcNetwork(true);
  const account = accountFromSeed(seed.slice(), true);
  const node = deriveNode(account, RECEIVE_CHAIN, 4);
  const script = btc.p2wpkh(node.publicKey, network).script;

  // No nonWitnessUtxo attached - a malicious coordinator can claim any
  // amount here and nothing verifies it, unlike the funding-tx-backed
  // inputs the other tests use.
  const tx = new btc.Transaction();
  tx.addInput({ txid: new Uint8Array(32).fill(9), index: 0, witnessUtxo: { amount: 60_000n, script } });
  tx.addOutputAddress(externalAddress(network), 50_000n, network);

  const candidateMap = buildSeedCandidateMap({ account, seed, isTestnet: true, range: 10 });
  const summary = describePsbt(tx, candidateMap, network);
  assert.equal(summary.unverifiedAmountInputs, 1);
  assert.equal(summary.missingInputs, 0);
  assert.equal(summary.feeWarning, true);
});

test('describePsbt does not flag an input backed by a hash-verified nonWitnessUtxo', () => {
  const seed = mnemonicToSeedSync(VECTOR_MNEMONIC, '');
  const network = btcNetwork(true);
  const account = accountFromSeed(seed.slice(), true);
  const node = deriveNode(account, RECEIVE_CHAIN, 4);
  const script = btc.p2wpkh(node.publicKey, network).script;
  const funding = buildFundingTx(script, 100_000n);

  const tx = new btc.Transaction();
  tx.addInput({ txid: funding.id, index: 0, nonWitnessUtxo: funding.unsignedTx });
  tx.addOutputAddress(externalAddress(network), 99_000n, network);

  const candidateMap = buildSeedCandidateMap({ account, seed, isTestnet: true, range: 10 });
  const summary = describePsbt(tx, candidateMap, network);
  assert.equal(summary.unverifiedAmountInputs, 0);
  assert.equal(summary.missingInputs, 0);
  assert.equal(summary.feeWarning, false);
});

test('describePsbt flags an anomalously high fee even when every amount is verified', () => {
  const seed = mnemonicToSeedSync(VECTOR_MNEMONIC, '');
  const network = btcNetwork(true);
  const account = accountFromSeed(seed.slice(), true);
  const node = deriveNode(account, RECEIVE_CHAIN, 4);
  const script = btc.p2wpkh(node.publicKey, network).script;
  const funding = buildFundingTx(script, 100_000n);

  const tx = new btc.Transaction();
  tx.addInput({ txid: funding.id, index: 0, nonWitnessUtxo: funding.unsignedTx });
  tx.addOutputAddress(externalAddress(network), 50_000n, network); // 50% "fee"

  const candidateMap = buildSeedCandidateMap({ account, seed, isTestnet: true, range: 10 });
  const summary = describePsbt(tx, candidateMap, network);
  assert.equal(summary.unverifiedAmountInputs, 0);
  assert.equal(summary.missingInputs, 0);
  assert.equal(summary.feeWarning, true);
});

test('describePsbt flags an input missing any prevout data at all, distinctly from witnessUtxo-only', () => {
  // Regression for M1: an input with neither witnessUtxo nor
  // nonWitnessUtxo silently contributed 0 to inputsTotal, which could make
  // the shown fee wildly wrong (even negative) with no explanation. It
  // should be counted separately from (and be at least as alarming as) the
  // witnessUtxo-only case.
  const seed = mnemonicToSeedSync(VECTOR_MNEMONIC, '');
  const network = btcNetwork(true);
  const account = accountFromSeed(seed.slice(), true);
  const node = deriveNode(account, RECEIVE_CHAIN, 4);
  const script = btc.p2wpkh(node.publicKey, network).script;
  const funding = buildFundingTx(script, 100_000n);

  const tx = new btc.Transaction({ allowUnknownInputs: true });
  tx.addInput({ txid: funding.id, index: 0, nonWitnessUtxo: funding.unsignedTx });
  tx.addInput({ txid: new Uint8Array(32).fill(5), index: 0 }); // no prevout data at all
  tx.addOutputAddress(externalAddress(network), 500_000n, network);

  const candidateMap = buildSeedCandidateMap({ account, seed, isTestnet: true, range: 10 });
  const summary = describePsbt(tx, candidateMap, network);
  assert.equal(summary.missingInputs, 1);
  assert.equal(summary.unverifiedAmountInputs, 0);
  assert.equal(summary.feeWarning, true);
  // The missing input contributes nothing, so the shown total only reflects
  // the one verified input - understated relative to the real (unknown) total.
  assert.equal(summary.inputsTotal, 100_000n);
});

test('identifySigners refuses a bip32Derivation path whose coin type belongs to the other network', () => {
  // Regression for a network-confusion bug: a PSBT can name our own root
  // fingerprint on a mainnet-convention path (coin type 0') while the app
  // is unlocked in testnet mode. Signing it anyway would let a
  // mislabeled/malicious PSBT get a real mainnet signature out of a user
  // who believes they're only operating on testnet.
  const seed = mnemonicToSeedSync(VECTOR_MNEMONIC, '');
  const network = btcNetwork(true); // app is in testnet mode
  const root = rootFromSeed(seed.slice());
  const mainnetNode = root.derive("m/84'/0'/0'/0/0"); // but PSBT path is mainnet (coin type 0')
  const script = btc.p2wpkh(mainnetNode.publicKey, network).script;
  const funding = buildFundingTx(script, 50_000n);

  const tx = new btc.Transaction();
  tx.addInput({ txid: funding.id, index: 0, nonWitnessUtxo: funding.unsignedTx });
  tx.updateInput(0, {
    bip32Derivation: [[mainnetNode.publicKey, { fingerprint: root.fingerprint, path: btc.bip32Path("m/84'/0'/0'/0/0") }]],
  });
  tx.addOutputAddress(externalAddress(network), 49_000n, network);

  const matches = identifySigners(tx, { candidateMap: null, root, isTestnet: true });
  assert.deepEqual(matches, []);
  assert.equal(hasNetworkMismatch(tx, root, true), true);
});

test('applySignatures wipes a bip32Derivation-matched node right after signing (no type => ephemeral)', () => {
  const seed = mnemonicToSeedSync(VECTOR_MNEMONIC, '');
  const network = btcNetwork(true);
  const root = rootFromSeed(seed.slice());
  const account = accountFromSeed(seed.slice(), true);
  const farNode = deriveNode(account, RECEIVE_CHAIN, 500);
  const farScript = btc.p2wpkh(farNode.publicKey, network).script;
  const funding = buildFundingTx(farScript, 60_000n);

  const tx = new btc.Transaction();
  tx.addInput({ txid: funding.id, index: 0, nonWitnessUtxo: funding.unsignedTx });
  tx.updateInput(0, {
    bip32Derivation: [[farNode.publicKey, { fingerprint: root.fingerprint, path: btc.bip32Path("m/84'/1'/0'/0/500") }]],
  });
  tx.addOutputAddress(externalAddress(network), 55_000n, network);

  const matches = identifySigners(tx, { candidateMap: new Map(), root, isTestnet: true });
  assert.equal(matches.length, 1);
  assert.equal(matches[0].type, null); // bip32Derivation match, not brute-force
  applySignatures(tx, matches, network);
  assert.equal(matches[0].node.privateKey, null, 'ephemeral node should be wiped right after signing');
});

test('wiping every candidateMap node and the account (what lockAll now does) actually zeroes their private keys', () => {
  // Regression for the memory-hygiene gap: HDKey.privateKey and
  // keyNodeFromPrivateKey's getter both hand back a *copy*, so the
  // fill(0) callers used to do on that copy scrubbed nothing real. This
  // reproduces the original finding - sign one input, then wipe the way
  // lockAll() does, and confirm the source key material is actually gone.
  const seed = mnemonicToSeedSync(VECTOR_MNEMONIC, '');
  const network = btcNetwork(true);
  const account = accountFromSeed(seed.slice(), true);
  const usedNode = deriveNode(account, RECEIVE_CHAIN, 3);
  const usedScript = btc.p2wpkh(usedNode.publicKey, network).script;
  const funding = buildFundingTx(usedScript, 100_000n);

  const tx = new btc.Transaction();
  tx.addInput({ txid: funding.id, index: 0, nonWitnessUtxo: funding.unsignedTx });
  tx.addOutputAddress(externalAddress(network), 99_000n, network);

  const candidateMap = buildSeedCandidateMap({ account, seed, isTestnet: true, range: 10 });
  const matches = identifySigners(tx, { candidateMap, root: null, isTestnet: true });
  applySignatures(tx, matches, network);

  const unusedScript = btc.p2wpkh(deriveNode(account, RECEIVE_CHAIN, 8).publicKey, network).script;

  wipeNode(account);
  for (const { node } of candidateMap.values()) wipeNode(node);

  const usedHit = candidateMap.get(hex.encode(usedScript));
  const unusedHit = candidateMap.get(hex.encode(unusedScript));
  assert.equal(usedHit.node.privateKey, null);
  assert.equal(unusedHit.node.privateKey, null);
  assert.equal(account.privateKey, null);
});

test('hasNetworkMismatch is false when every bip32Derivation path matches the selected network', () => {
  const seed = mnemonicToSeedSync(VECTOR_MNEMONIC, '');
  const network = btcNetwork(true);
  const root = rootFromSeed(seed.slice());
  const node = root.derive("m/84'/1'/0'/0/0");
  const script = btc.p2wpkh(node.publicKey, network).script;
  const funding = buildFundingTx(script, 50_000n);

  const tx = new btc.Transaction();
  tx.addInput({ txid: funding.id, index: 0, nonWitnessUtxo: funding.unsignedTx });
  tx.updateInput(0, {
    bip32Derivation: [[node.publicKey, { fingerprint: root.fingerprint, path: btc.bip32Path("m/84'/1'/0'/0/0") }]],
  });
  tx.addOutputAddress(externalAddress(network), 49_000n, network);

  assert.equal(hasNetworkMismatch(tx, root, true), false);
  const matches = identifySigners(tx, { candidateMap: null, root, isTestnet: true });
  assert.deepEqual(matches, [{ index: 0, node, type: null }]);
});

test('identifySigners refuses a bip32Derivation entry whose declared pubkey does not match the real prevout script', () => {
  // Regression for M2: the PSBT can be internally self-consistent (our
  // root really does derive that pubkey at that path) while the input's
  // actual prevout script pays somewhere else entirely. Before this check,
  // identifySigners still reported it as "ours to sign", so the review
  // screen promised a signature that would only fail later.
  const seed = mnemonicToSeedSync(VECTOR_MNEMONIC, '');
  const network = btcNetwork(true);
  const root = rootFromSeed(seed.slice());
  const ourNode = root.derive("m/84'/1'/0'/0/0");
  // The real prevout pays an unrelated key, not ourNode.
  const strangerSeed = mnemonicToSeedSync(
    'zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong', '',
  );
  const strangerNode = rootFromSeed(strangerSeed).derive("m/84'/1'/0'/0/0");
  const foreignScript = btc.p2wpkh(strangerNode.publicKey, network).script;
  const funding = buildFundingTx(foreignScript, 70_000n);

  const tx = new btc.Transaction();
  tx.addInput({ txid: funding.id, index: 0, nonWitnessUtxo: funding.unsignedTx });
  tx.updateInput(0, {
    // Names our own root/path, but for a pubkey that plainly isn't what
    // pays this input.
    bip32Derivation: [[ourNode.publicKey, { fingerprint: root.fingerprint, path: btc.bip32Path("m/84'/1'/0'/0/0") }]],
  });
  tx.addOutputAddress(externalAddress(network), 69_000n, network);

  const matches = identifySigners(tx, { candidateMap: null, root, isTestnet: true });
  assert.deepEqual(matches, []);
});

test('applySignatures returns only the indices actually signed, not an echo of what was expected', () => {
  // Regression for M3: a match that identifySigners judged signable can
  // still fail to sign (wrong key for that input, sighash mismatch, etc.) -
  // the caller needs to know which ones really succeeded, not a blind copy
  // of the matches it was given.
  const network = btcNetwork(true);
  const goodKey = randomBytes(32);
  const goodNode = keyNodeFromPrivateKey(goodKey, true);
  const goodScript = btc.p2wpkh(goodNode.publicKey, network).script;
  const goodFunding = buildFundingTx(goodScript, 40_000n);

  const wrongKey = randomBytes(32);
  const wrongNode = keyNodeFromPrivateKey(wrongKey, true);
  // This input actually pays a *different* key than the one in the bogus match below.
  const realNode = keyNodeFromPrivateKey(randomBytes(32), true);
  const realScript = btc.p2wpkh(realNode.publicKey, network).script;
  const badFunding = buildFundingTx(realScript, 30_000n);

  const tx = new btc.Transaction();
  tx.addInput({ txid: goodFunding.id, index: 0, nonWitnessUtxo: goodFunding.unsignedTx });
  tx.addInput({ txid: badFunding.id, index: 0, nonWitnessUtxo: badFunding.unsignedTx });
  tx.addOutputAddress(externalAddress(network), 68_000n, network);

  // Hand-crafted matches, as if identifySigners had (wrongly) reported both -
  // input 1's node doesn't actually correspond to its prevout script.
  const matches = [
    { index: 0, node: goodNode, type: 'bech32' },
    { index: 1, node: wrongNode, type: 'bech32' },
  ];
  const signed = applySignatures(tx, matches, network);
  assert.deepEqual(signed, [0]); // only the genuinely-signable one
  assert.equal(tx.getInput(1).partialSig, undefined);
});

test('applySignatures does not let one failing match abort signing for the others', () => {
  // Regression for the "throws mid-way" minor finding: a broken match used
  // to abort the whole call, leaving every other already-reviewed match
  // unsigned even though nothing was wrong with it. The broken match is
  // listed *first* here specifically to prove a later, valid match still
  // gets processed.
  const network = btcNetwork(true);
  const goodNode = keyNodeFromPrivateKey(randomBytes(32), true);
  const goodScript = btc.p2wpkh(goodNode.publicKey, network).script;
  const goodFunding = buildFundingTx(goodScript, 40_000n);
  const brokenNode = keyNodeFromPrivateKey(randomBytes(32), true);

  const tx = new btc.Transaction();
  tx.addInput({ txid: goodFunding.id, index: 0, nonWitnessUtxo: goodFunding.unsignedTx });
  tx.addOutputAddress(externalAddress(network), 39_000n, network);

  const matches = [
    { index: 99, node: brokenNode, type: 'p2sh' }, // out-of-range index - annotation must throw
    { index: 0, node: goodNode, type: 'bech32' }, // perfectly valid, listed second on purpose
  ];
  const signed = applySignatures(tx, matches, network);
  assert.deepEqual(signed, [0]);
});
