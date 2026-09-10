import * as btc from '@scure/btc-signer';
import QRCode from 'qrcode';
import { isValidMnemonic, seedFromMnemonic } from './lib/mnemonic.js';
import { accountFromSeed, rootFromSeed, btcNetwork, keyNodeFromPrivateKey } from './lib/hdwallet.js';
import { decryptMnemonic } from './lib/seedcipher.js';
import { decryptBip38, isBip38 } from './lib/bip38.js';
import {
  buildSeedCandidateMap, buildImportedKeyMap, decodePsbt,
  identifySigners, applySignatures, finalizeOrExport, describePsbt,
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

function fmtAddress(address) {
  if (!address) return tr('review.noAddress');
  return address.length > 20 ? `${address.slice(0, 10)}…${address.slice(-8)}` : address;
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
    const matches = identifySigners(tx, { candidateMap: state.candidateMap, root: state.root });
    if (matches.length === 0) {
      setError('load-error', tr('error.noKeysMatched'));
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

  $('review-confirm-checkbox').checked = false;
  $('confirm-sign-btn').disabled = true;
  setError('review-error', null);
}

function initReviewScreen() {
  $('review-confirm-checkbox').addEventListener('change', (ev) => {
    $('confirm-sign-btn').disabled = !ev.target.checked;
  });
  $('cancel-review-btn').addEventListener('click', () => {
    state.tx = null;
    state.matches = null;
    showScreen('load');
  });
  $('confirm-sign-btn').addEventListener('click', () => {
    setError('review-error', null);
    $('confirm-sign-btn').disabled = true;
    try {
      applySignatures(state.tx, state.matches, state.network);
      const result = finalizeOrExport(state.tx);
      state.matches = null;
      renderResult(result);
      showScreen('result');
    } catch (err) {
      setError('review-error', tr('error.signFailed', { msg: err.message }));
      $('confirm-sign-btn').disabled = false;
    }
  });
}

// ---------- Result ----------

async function renderResult(result) {
  const titleEl = $('result-title');
  const hintEl = $('result-hint');
  const txidRow = $('result-txid-row');
  const outputField = $('result-output');
  const outputLabel = $('result-output-label');

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
    state.matches = null;
    $('load-error').hidden = true;
    showScreen('load');
  });

  $('result-lock-btn').addEventListener('click', lockAll);
}

// ---------- Lock ----------

function lockAll() {
  if (state.seed) state.seed.fill(0);
  if (state.root) state.root.wipePrivateData();
  if (state.importedNode) state.importedNode.wipe();
  state.mode = null;
  state.seed = null;
  state.root = null;
  state.account = null;
  state.importedNode = null;
  state.candidateMap = null;
  state.tx = null;
  state.matches = null;
  state.network = null;
  $('unlock-btn').disabled = false;
  $('psbt-input').value = '';
  showScreen('unlock');
}

// ---------- Boot ----------

function init() {
  initTopbar();
  initUnlockScreen();
  initLoadScreen();
  initReviewScreen();
  initResultScreen();
  applyTranslations();
  showScreen('unlock');
}

init();
