import * as btc from '@scure/btc-signer';
import QRCode from 'qrcode';
import { isValidMnemonic, seedFromMnemonic } from './lib/mnemonic.js';
import { accountFromSeed, rootFromSeed, btcNetwork, keyNodeFromPrivateKey, wipeNode } from './lib/hdwallet.js';
import { decryptMnemonic } from './lib/seedcipher.js';
import { decryptBip38, isBip38 } from './lib/bip38.js';
import {
  buildSeedCandidateMap, buildImportedKeyMap, decodePsbt,
  identifySigners, applySignatures, finalizeOrExport, describePsbt, hasNetworkMismatch,
} from './lib/psbt.js';
import { t, DEFAULT_LANG } from './lib/i18n.js';

const $ = (id) => document.getElementById(id);
const SCREENS = ['unlock', 'load', 'review', 'result'];

const state = {
  isTestnet: true,
  network: null,
  lang: DEFAULT_LANG,
  mode: null, // 'seed' | 'key'
  seed: null,
  root: null,
  account: null,
  importedNode: null,
  importedCompressed: true,
  candidateMap: null,
  tx: null,
  matches: null, // pending, from identifySigners - not yet applied
};

function tr(key, vars) {
  return t(key, state.lang, vars);
}

function showScreen(name) {
  for (const s of SCREENS) $(`screen-${s}`).hidden = s !== name;
}

function fmtBtc(sats) {
  return btc.Decimal.encode(sats);
}

// This is the one screen where a truncated address is actively dangerous:
// clipboard-hijacking malware and lookalike-address attacks specifically
// rely on matching the first/last few characters while swapping the
// middle, which a "10…8" ellipsis would hide from the one review meant to
// catch exactly that. Always show it in full here.
function fmtAddress(address) {
  return address || tr('review.noAddress');
}

function setError(elId, message) {
  const el = $(elId);
  el.textContent = message ?? '';
  el.hidden = !message;
}

function updateNetworkBadge() {
  const badge = $('network-badge');
  badge.textContent = tr(state.isTestnet ? 'network.badge.testnet' : 'network.badge.mainnet');
  badge.classList.toggle('badge-testnet', state.isTestnet);
  badge.classList.toggle('badge-mainnet', !state.isTestnet);
}

function downloadText(filename, text) {
  const blob = new Blob([text], { type: 'text/plain' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

// ---------- Topbar: language / theme / básico-avanzado ----------

function updateThemeButtonLabel() {
  const isLight = document.documentElement.getAttribute('data-theme') === 'light';
  $('theme-toggle').textContent = tr(isLight ? 'topbar.theme.toDark' : 'topbar.theme.toLight');
}

function updateLangButtonLabel() {
  $('lang-toggle').textContent = tr(state.lang === 'es' ? 'topbar.lang.toEnglish' : 'topbar.lang.toSpanish');
}

function updateModeButtonLabel() {
  const isAdvanced = document.documentElement.getAttribute('data-mode') === 'advanced';
  $('ui-mode-label').textContent = tr(isAdvanced ? 'topbar.mode.advanced' : 'topbar.mode.basic');
}

function applyTranslations() {
  document.documentElement.lang = state.lang;
  document.title = tr('meta.title');
  document.querySelectorAll('[data-i18n]').forEach((el) => { el.innerHTML = tr(el.dataset.i18n); });
  document.querySelectorAll('[data-i18n-tip]').forEach((el) => { el.setAttribute('data-tip', tr(el.dataset.i18nTip)); });
  document.querySelectorAll('[data-i18n-placeholder]').forEach((el) => { el.setAttribute('placeholder', tr(el.dataset.i18nPlaceholder)); });
  document.querySelectorAll('[data-i18n-aria]').forEach((el) => { el.setAttribute('aria-label', tr(el.dataset.i18nAria)); });

  updateThemeButtonLabel();
  updateLangButtonLabel();
  updateModeButtonLabel();
  updateNetworkBadge();
  if (state.tx && state.matches) renderReview();
}

function initTopbar() {
  $('lang-toggle').addEventListener('click', () => {
    state.lang = state.lang === 'es' ? 'en' : 'es';
    applyTranslations();
  });

  $('theme-toggle').addEventListener('click', () => {
    const html = document.documentElement;
    html.setAttribute('data-theme', html.getAttribute('data-theme') === 'light' ? 'dark' : 'light');
    updateThemeButtonLabel();
  });

  $('ui-mode-toggle').addEventListener('click', () => {
    const html = document.documentElement;
    const next = html.getAttribute('data-mode') === 'advanced' ? 'basic' : 'advanced';
    html.setAttribute('data-mode', next);
    if (next === 'basic') {
      $('mode-seed').checked = true;
      $('mode-key').checked = false;
      $('seed-encrypted-checkbox').checked = false;
      $('seed-fields').hidden = false;
      $('key-fields').hidden = true;
      $('mnemonic-field').hidden = false;
      $('encrypted-seed-fields').hidden = true;
    }
    $('ui-mode-toggle').setAttribute('aria-pressed', String(next === 'advanced'));
    updateModeButtonLabel();
  });
}

// ---------- Unlock ----------

function initUnlockScreen() {
  const mainnetRadio = $('network-mainnet');
  const testnetRadio = $('network-testnet');
  const mainnetConfirm = $('mainnet-confirm-wrap');
  const unlockBtn = $('unlock-btn');

  function syncNetworkUI() {
    mainnetConfirm.hidden = !mainnetRadio.checked;
    unlockBtn.disabled = mainnetRadio.checked && !$('mainnet-confirm-checkbox').checked;
    state.isTestnet = testnetRadio.checked;
    updateNetworkBadge();
  }
  mainnetRadio.addEventListener('change', syncNetworkUI);
  testnetRadio.addEventListener('change', syncNetworkUI);
  $('mainnet-confirm-checkbox').addEventListener('change', syncNetworkUI);
  syncNetworkUI();

  const modeSeedRadio = $('mode-seed');
  const modeKeyRadio = $('mode-key');
  function syncModeUI() {
    $('seed-fields').hidden = !modeSeedRadio.checked;
    $('key-fields').hidden = !modeKeyRadio.checked;
  }
  modeSeedRadio.addEventListener('change', syncModeUI);
  modeKeyRadio.addEventListener('change', syncModeUI);
  syncModeUI();

  const seedEncryptedCheckbox = $('seed-encrypted-checkbox');
  function syncSeedEncryptedUI() {
    $('mnemonic-field').hidden = seedEncryptedCheckbox.checked;
    $('encrypted-seed-fields').hidden = !seedEncryptedCheckbox.checked;
  }
  seedEncryptedCheckbox.addEventListener('change', syncSeedEncryptedUI);
  syncSeedEncryptedUI();

  $('toggle-passphrase-visibility').addEventListener('click', () => {
    const input = $('passphrase-input');
    input.type = input.type === 'password' ? 'text' : 'password';
  });
  $('toggle-wif-passphrase-visibility').addEventListener('click', () => {
    const input = $('wif-passphrase-input');
    input.type = input.type === 'password' ? 'text' : 'password';
  });

  function wireFileLoad(buttonId, fileInputId, targetId, errorId) {
    const button = $(buttonId);
    const fileInput = $(fileInputId);
    button.addEventListener('click', () => fileInput.click());
    fileInput.addEventListener('change', async () => {
      const file = fileInput.files[0];
      fileInput.value = '';
      if (!file) return;
      try {
        const text = await file.text();
        $(targetId).value = text.trim();
      } catch (err) {
        setError(errorId, tr('error.fileReadFailed', { msg: err.message }));
      }
    });
  }
  wireFileLoad('mnemonic-file-btn', 'mnemonic-file-input', 'mnemonic-input', 'unlock-error');
  wireFileLoad('encrypted-seed-file-btn', 'encrypted-seed-file-input', 'encrypted-seed-input', 'unlock-error');
  wireFileLoad('wif-file-btn', 'wif-file-input', 'wif-input', 'unlock-error');

  function clearUnlockInputs() {
    $('mnemonic-input').value = '';
    $('encrypted-seed-input').value = '';
    $('decrypt-password-input').value = '';
    $('passphrase-input').value = '';
    $('wif-input').value = '';
    $('wif-passphrase-input').value = '';
  }

  $('unlock-form').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    setError('unlock-error', null);
    $('unlock-autolock-notice').hidden = true;
    state.isTestnet = testnetRadio.checked;
    updateNetworkBadge();
    unlockBtn.disabled = true;
    try {
      state.network = btcNetwork(state.isTestnet);
      if (modeKeyRadio.checked) {
        state.mode = 'key';
        const wifRaw = $('wif-input').value.trim();
        const wifPassphrase = $('wif-passphrase-input').value;
        let privateKey, compressed;
        if (isBip38(wifRaw)) {
          const result = await decryptBip38(wifRaw, wifPassphrase);
          privateKey = result.privateKey;
          compressed = result.compressed;
        } else {
          try {
            privateKey = btc.WIF(state.network).decode(wifRaw);
          } catch {
            throw new Error(tr('error.badWif'));
          }
          compressed = true;
        }
        state.importedNode = keyNodeFromPrivateKey(privateKey, compressed);
        state.importedCompressed = compressed;
        privateKey.fill(0);
        state.candidateMap = buildImportedKeyMap({ node: state.importedNode, isTestnet: state.isTestnet, compressed });
      } else {
        state.mode = 'seed';
        let mnemonic;
        if (seedEncryptedCheckbox.checked) {
          const blob = $('encrypted-seed-input').value;
          const password = $('decrypt-password-input').value;
          mnemonic = await decryptMnemonic(blob, password);
        } else {
          mnemonic = $('mnemonic-input').value;
        }
        if (!isValidMnemonic(mnemonic)) {
          throw new Error(tr('error.badMnemonic'));
        }
        const passphrase = $('passphrase-input').value;
        const seed = await seedFromMnemonic(mnemonic, passphrase);
        state.seed = seed;
        state.account = accountFromSeed(seed, state.isTestnet);
        state.root = rootFromSeed(seed);
        state.candidateMap = buildSeedCandidateMap({ account: state.account, seed, isTestnet: state.isTestnet });
      }
      clearUnlockInputs();
      resetInactivityTimer();
      showScreen('load');
    } catch (err) {
      setError('unlock-error', tr('error.unlockFailed', { msg: err.message }));
      unlockBtn.disabled = false;
    }
  });
}

// ---------- Load PSBT ----------

function initLoadScreen() {
  const fileInput = $('psbt-file-input');
  $('psbt-file-btn').addEventListener('click', () => fileInput.click());
  fileInput.addEventListener('change', async () => {
    const file = fileInput.files[0];
    fileInput.value = '';
    if (!file) return;
    try {
      const text = await file.text();
      $('psbt-input').value = text.trim();
    } catch (err) {
      setError('load-error', tr('error.fileReadFailed', { msg: err.message }));
    }
  });

  $('load-lock-btn').addEventListener('click', lockAll);

  $('load-form').addEventListener('submit', (ev) => {
    ev.preventDefault();
    setError('load-error', null);
    let tx;
    try {
      tx = decodePsbt($('psbt-input').value);
    } catch (err) {
      setError('load-error', tr('error.decodeFailed', { msg: err.message }));
      return;
    }
    const matches = identifySigners(tx, {
      candidateMap: state.candidateMap, root: state.root, isTestnet: state.isTestnet,
    });
    if (matches.length === 0) {
      const msg = hasNetworkMismatch(tx, state.root, state.isTestnet)
        ? tr('error.networkMismatch')
        : tr('error.noKeysMatched');
      setError('load-error', msg);
      return;
    }
    state.tx = tx;
    state.matches = matches;
    $('psbt-input').value = '';
    renderReview();
    showScreen('review');
  });
}

// ---------- Review ----------

// Drops the pending `identifySigners` matches, wiping the ones that would
// otherwise leak: a match with no `type` is a fresh, single-use node
// re-derived straight from `bip32Derivation` (see psbt.js), never cached
// anywhere else, so if it's about to be discarded unsigned (the user
// cancels review) this is the only chance to zero it. Matches with a
// `type` live inside `state.candidateMap` too and may still be needed for
// another PSBT this same unlocked session - those are left alone here and
// wiped only at lockAll().
function discardMatches() {
  if (state.matches) {
    for (const { node, type } of state.matches) {
      if (!type) wipeNode(node);
    }
  }
  state.matches = null;
}

function renderReview() {
  const { tx, matches, candidateMap } = state;
  $('review-will-sign').textContent = tr('review.willSign', { n: matches.length, total: tx.inputsLength });

  const summary = describePsbt(tx, candidateMap, state.network);
  $('review-inputs-total').textContent = `${fmtBtc(summary.inputsTotal)} BTC`;
  $('review-outputs-total').textContent = `${fmtBtc(summary.outputsTotal)} BTC`;
  $('review-fee').textContent = `${fmtBtc(summary.fee)} BTC`;

  const list = $('review-outputs');
  list.innerHTML = '';
  for (const output of summary.outputs) {
    const li = document.createElement('li');
    li.className = 'output-row';
    li.innerHTML = `
      <span class="output-address">${fmtAddress(output.address)}${output.isChange ? `<span class="output-change-tag">${tr('review.change')}</span>` : ''}</span>
      <span class="output-amount">${fmtBtc(output.amount)} BTC</span>
    `;
    list.appendChild(li);
  }

  // Unverified amounts (SegWit inputs with no full previous transaction
  // attached), inputs missing a prevout entirely (worse: they silently
  // count as 0 above, understating both totals), or an anomalous fee mean
  // the numbers above can't be fully trusted - describePsbt already
  // computed the specific condition(s), so just build the matching
  // message(s) and demand a second, explicit acknowledgement before
  // signing is allowed at all.
  const warningEl = $('review-risk-warning');
  const ackWrap = $('review-risk-ack-wrap');
  if (summary.feeWarning) {
    const lines = [];
    if (summary.missingInputs > 0) {
      lines.push(tr('review.missingAmounts', { n: summary.missingInputs, total: tx.inputsLength }));
    }
    if (summary.unverifiedAmountInputs > 0) {
      lines.push(tr('review.unverifiedAmounts', { n: summary.unverifiedAmountInputs, total: tx.inputsLength }));
    }
    if (lines.length === 0) lines.push(tr('review.feeTooHigh'));
    warningEl.textContent = lines.join(' ');
    warningEl.hidden = false;
    ackWrap.hidden = false;
  } else {
    warningEl.hidden = true;
    ackWrap.hidden = true;
  }
  $('review-risk-ack-checkbox').checked = false;

  $('review-confirm-checkbox').checked = false;
  $('confirm-sign-btn').disabled = true;
  setError('review-error', null);
}

function syncSignButton() {
  const needsAck = !$('review-risk-ack-wrap').hidden;
  const baseOk = $('review-confirm-checkbox').checked;
  const ackOk = !needsAck || $('review-risk-ack-checkbox').checked;
  $('confirm-sign-btn').disabled = !(baseOk && ackOk);
}

function initReviewScreen() {
  $('review-confirm-checkbox').addEventListener('change', syncSignButton);
  $('review-risk-ack-checkbox').addEventListener('change', syncSignButton);
  $('cancel-review-btn').addEventListener('click', () => {
    state.tx = null;
    discardMatches();
    showScreen('load');
  });
  $('confirm-sign-btn').addEventListener('click', () => {
    setError('review-error', null);
    $('confirm-sign-btn').disabled = true;
    try {
      const expected = state.matches.length;
      const signed = applySignatures(state.tx, state.matches, state.network);
      const result = finalizeOrExport(state.tx);
      discardMatches();
      renderResult(result, { expected, signed: signed.length });
      showScreen('result');
    } catch (err) {
      setError('review-error', tr('error.signFailed', { msg: err.message }));
      $('confirm-sign-btn').disabled = false;
    }
  });
}

// ---------- Result ----------

async function renderResult(result, signInfo) {
  const titleEl = $('result-title');
  const hintEl = $('result-hint');
  const txidRow = $('result-txid-row');
  const outputField = $('result-output');
  const outputLabel = $('result-output-label');

  // The review screen promised `expected` inputs would be signed with this
  // key; `signed` is what applySignatures actually managed (see psbt.js -
  // it no longer just echoes the expectation back). A shortfall here means
  // something the review screen showed didn't hold up during signing -
  // surface it plainly instead of only ever showing the generic
  // finalized/partial framing.
  const partialWarning = $('result-partial-warning');
  if (signInfo && signInfo.signed < signInfo.expected) {
    partialWarning.textContent = tr('result.partialSignWarning', signInfo);
    partialWarning.hidden = false;
  } else {
    partialWarning.hidden = true;
  }

  if (result.finalized) {
    titleEl.textContent = tr('result.title.finalized');
    hintEl.textContent = tr('result.finalized.hint');
    txidRow.hidden = false;
    $('result-txid').textContent = result.txid;
    outputLabel.textContent = tr('result.hexLabel');
    outputField.value = result.hex;
  } else {
    titleEl.textContent = tr('result.title.partial');
    hintEl.textContent = tr('result.partial.hint');
    txidRow.hidden = true;
    outputLabel.textContent = tr('result.psbtLabel');
    outputField.value = result.psbt;
  }

  const qr = $('result-qr');
  try {
    const dataUrl = await QRCode.toDataURL(outputField.value, { margin: 1, width: 240 });
    qr.src = dataUrl;
    qr.hidden = false;
  } catch {
    qr.hidden = true; // payload too large for a single QR - text + download still work
  }
}

function initResultScreen() {
  $('result-copy-btn').addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText($('result-output').value);
      const btnEl = $('result-copy-btn');
      btnEl.textContent = tr('result.copied');
      setTimeout(() => { btnEl.textContent = tr('result.copy'); }, 1500);
    } catch { /* clipboard may be unavailable; text is selectable regardless */ }
  });

  $('result-download-btn').addEventListener('click', () => {
    downloadText('psbt-signer-btc-output.txt', $('result-output').value);
  });

  $('result-back-btn').addEventListener('click', () => {
    state.tx = null;
    discardMatches();
    $('load-error').hidden = true;
    showScreen('load');
  });

  $('result-lock-btn').addEventListener('click', lockAll);
}

// ---------- Lock ----------

function lockAll(opts) {
  // Wired directly as a click handler in a couple of places, so `opts` may
  // actually be a MouseEvent - only the inactivity timer below ever passes
  // a real options object, and only it sets this specific shape.
  const dueToInactivity = Boolean(opts && opts.reason === 'inactivity');
  clearInactivityTimer();
  if (state.seed) state.seed.fill(0);
  if (state.root) state.root.wipePrivateData();
  if (state.account) wipeNode(state.account);
  // Every derived candidate the seed ever produced (up to ~400 BIP84
  // addresses plus the 4 paper-wallet-btc-style fixed ones) lives here with
  // a private key, whether or not it ever matched a PSBT input this
  // session - wipe all of them, not just the ones that got used.
  if (state.candidateMap) {
    for (const { node } of state.candidateMap.values()) wipeNode(node);
  }
  if (state.importedNode) state.importedNode.wipe();
  discardMatches();
  state.mode = null;
  state.seed = null;
  state.root = null;
  state.account = null;
  state.importedNode = null;
  state.candidateMap = null;
  state.tx = null;
  state.network = null;
  $('unlock-btn').disabled = false;
  $('psbt-input').value = '';
  $('unlock-autolock-notice').hidden = !dueToInactivity;
  showScreen('unlock');
}

// ---------- Auto-lock on inactivity ----------

// A local, offline signer holding decrypted key material has no OS-level
// screen lock of its own - if the user unlocks it and then walks away,
// anyone at the keyboard inherits everything until they come back. 10
// minutes matches the kind of default hardware wallets and password
// managers use: long enough to read through a large multisig PSBT
// carefully, short enough that a forgotten unlocked tab isn't a standing
// risk. Only runs once something is actually unlocked (state.mode set) -
// nothing sensitive is held before that.
const INACTIVITY_LOCK_MS = 10 * 60 * 1000;
let inactivityTimer = null;
let lastActivityAt = 0;

function clearInactivityTimer() {
  if (inactivityTimer) { clearTimeout(inactivityTimer); inactivityTimer = null; }
}

function resetInactivityTimer() {
  clearInactivityTimer();
  if (state.mode) {
    inactivityTimer = setTimeout(() => lockAll({ reason: 'inactivity' }), INACTIVITY_LOCK_MS);
  }
}

function initAutoLock() {
  const events = ['mousedown', 'mousemove', 'keydown', 'touchstart', 'scroll', 'wheel'];
  events.forEach((evt) => {
    window.addEventListener(evt, () => {
      // mousemove/scroll can fire hundreds of times a second; only the
      // timer's own duration matters for security, not this precision, so
      // throttle the churn of clearing/re-arming a timeout on every event.
      const now = Date.now();
      if (now - lastActivityAt < 1000) return;
      lastActivityAt = now;
      resetInactivityTimer();
    }, { passive: true });
  });
}

// ---------- Boot ----------

function init() {
  initTopbar();
  initUnlockScreen();
  initLoadScreen();
  initReviewScreen();
  initResultScreen();
  initAutoLock();
  applyTranslations();
  showScreen('unlock');
}

init();
