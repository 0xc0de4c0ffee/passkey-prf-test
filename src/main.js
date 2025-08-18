import { sha256 } from '@noble/hashes/sha2';
import { addr } from 'micro-eth-signer';
import * as typed from 'micro-eth-signer/typed-data.js';
import { initSig, ethHex } from 'micro-eth-signer/utils.js';

// ---------- Small utils
const enc = new TextEncoder();
const toHex = (buf) => Array.from(buf, b => b.toString(16).padStart(2, '0')).join('');
const hex0x = (buf) => '0x' + toHex(buf);
const bytes = (x) => (x instanceof Uint8Array) ? x : new Uint8Array(x);

// PRF input: constant salt so login doesn’t depend on name
const PRF_SALT = sha256(enc.encode('eth-prf-v1'));

function toBase64Url(buf) {
  const b = btoa(String.fromCharCode(...bytes(buf)));
  return b.replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/,'');
}
function fromBase64Url(s) {
  s = s.replaceAll('-', '+').replaceAll('_', '/');
  const pad = s.length % 4 ? 4 - (s.length % 4) : 0;
  s = s + '='.repeat(pad);
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// Derive checksummed Ethereum address from private key (Uint8Array)
function addressFromPriv(privBytes) {
  // micro-eth-signer accepts Uint8Array or 0x-string
  return addr.fromPrivateKey(privBytes);
}

// ---------- DOM refs
const $ = (id) => document.getElementById(id);
const els = {
  status: $('status'),
  walletName: $('walletName'),
  btnRegister: $('btnRegister'),
  btnLogin: $('btnLogin'),

  btnRefresh: $('btnRefresh'),
  btnSign: $('btnSign'),
  walletSelect: $('walletSelect'),
  loginName: $('loginName'),
  msg: $('msg'),
  addr: $('addr'),
  pub: $('pub'),
  ok: $('ok'),
  cred: $('cred'),
  prf: $('prf'),
  sig: $('sig'),
};

const state = { pub: null, addr: null, credId: null, prfSupported: 'unknown', walletName: null };

function setStatus(text) { els.status.textContent = text; }
function setDebug() {
  els.addr.textContent = state.addr || '-';
  els.pub.textContent = state.pub ? state.pub : '-';
  els.sig.textContent = '-';
  els.ok.textContent = '-';
  els.cred.textContent = state.credId || '-';
  els.prf.textContent = String(state.prfSupported);
}

function requireSecureContext() {
  if (!window.isSecureContext) throw new Error('Requires HTTPS or localhost');
  if (!window.PublicKeyCredential) throw new Error('WebAuthn not supported');
}
let initChecked = false;

async function userIdFromName(name) {
  // Use noble sha256 to derive deterministic user.id; trim to 16 bytes
  const full = sha256(enc.encode(name));
  return full.slice(0, 16);
}

function loadWalletMap() {
  try { return JSON.parse(localStorage.getItem('wallet_keys') || '{}'); } catch { return {}; }
}
function saveWalletMap(map) { localStorage.setItem('wallet_keys', JSON.stringify(map)); }

function loadWalletInfo() {
  try { return JSON.parse(localStorage.getItem('wallet_info') || '{}'); } catch { return {}; }
}
function saveWalletInfo(info) { localStorage.setItem('wallet_info', JSON.stringify(info)); }

function refreshWalletList() {
  const info = loadWalletInfo();
  const names = Object.keys(info).sort();
  els.walletSelect.innerHTML = '';
  for (const name of names) {
    const opt = document.createElement('option');
    const address = info[name]?.address || '';
    opt.value = name;
    opt.textContent = `${name} — ${address ? address.slice(0, 10) + '…' : '-'}`;
    els.walletSelect.appendChild(opt);
  }
}

function getSelectedName() {
  const login = (els.loginName?.value || '').trim();
  if (login) return login;
  const sel = els.walletSelect?.value;
  if (sel) return sel;
  const name = (els.walletSelect.value || els.loginName?.value || els.walletName.value || '').trim();
  return name || '';
}

function applySelectedWallet(name) {
  if (!name) return;
  const info = loadWalletInfo();
  const map = loadWalletMap();
  const address = info[name]?.address || null;
  state.addr = address;
  state.credId = map[name] || null;
  els.addr.textContent = address || '-';
  els.cred.textContent = state.credId || '-';
  // reset per-selection transient fields
  els.pub.textContent = '-';
  els.sig.textContent = '-';
  els.ok.textContent = '-';
  // allow signing with selected wallet (assertion handles both mapped & discoverable)
  els.btnSign.disabled = false;
}

// ---------- WebAuthn flows
async function registerPasskey() {
  try {
    const name = (els.walletSelect.value || els.loginName?.value || els.walletName.value || '').trim();
    if (!name) throw new Error('Enter a wallet name');
    state.walletName = name;

    const userId = await userIdFromName(name);

    const publicKey = {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      rp: { name: 'PasskeyWallet', id: window.location.hostname },
      user: { id: userId, name, displayName: name },
      pubKeyCredParams: [ { type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 } ],
      authenticatorSelection: { authenticatorAttachment: 'platform', residentKey: 'required', userVerification: 'required' },
      timeout: 60000,
      attestation: 'none',
      extensions: { prf: { eval: { first: PRF_SALT } } },
    };

    setStatus('Creating passkey…');
    const cred = await navigator.credentials.create({ publicKey });
    if (!cred) throw new Error('Creation cancelled');

    const rawIdB64u = toBase64Url(cred.rawId);
    const map = loadWalletMap();
    if (map[name]) throw new Error('Wallet name already exists');
    map[name] = rawIdB64u;
    saveWalletMap(map);
    localStorage.setItem(`passkey_${rawIdB64u}`, name);

    const prfOut = cred.getClientExtensionResults()?.prf;
    const hasPRFResult = !!(prfOut && (prfOut.results?.first));
    // Spec: during registration, "enabled" indicates PRF availability even if no results are returned
    state.prfSupported = (prfOut?.enabled ?? hasPRFResult);
    state.credId = rawIdB64u;

    if (hasPRFResult) {
      // Derive address from PRF; do not persist private key
      const priv = new Uint8Array(prfOut.results.first);
      const address = addressFromPriv(priv);
      // zeroize
      priv.fill(0);
      state.pub = null; state.addr = address;
      // store public info only
      const info = loadWalletInfo();
      info[name] = { address };
      saveWalletInfo(info);
      refreshWalletList();
      els.walletSelect.value = name;
      els.btnSign.disabled = false;
      setStatus('Passkey created. Wallet derived from PRF.');
    } else {
      setStatus('Passkey created. PRF output not returned at registration; click "Login" to derive.');
    }
    setDebug();
  } catch (e) {
    console.error(e);
    setStatus('Error: ' + (e?.message || e));
  }
}

async function loginWallet(nameOverride) {
  try {
    const name = (nameOverride ?? getSelectedName());
    // name is just a label; allow empty for discoverable login
    state.walletName = name;

    const map = loadWalletMap();
    let idB64u = map[name];
    const userId = await userIdFromName(name);
    let publicKey;
    if (!idB64u) {
      // Discoverable login: let user pick a passkey, evaluate PRF via eval
      publicKey = {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      rpId: window.location.hostname,
      userVerification: 'required',
      timeout: 60000,
      allowCredentials: [],
      extensions: { prf: { eval: { first: PRF_SALT } } },
      };
    } else {
      // Known credential: request specific id and evaluate PRF per-credential
      const rawId = fromBase64Url(idB64u);
      publicKey = {
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        rpId: window.location.hostname,
        userVerification: 'required',
        timeout: 60000,
        allowCredentials: [ { type: 'public-key', id: rawId, transports: ['internal'] } ],
        extensions: { prf: { evalByCredential: { [idB64u]: { first: PRF_SALT } } } },
      };
    }

    setStatus('Requesting assertion…');
    const cred = await navigator.credentials.get({ publicKey, mediation: 'optional' });
    // If we didn't know the credential ID, save it now
    if (!idB64u) {
      idB64u = toBase64Url(cred.rawId);
      map[name] = idB64u;
      saveWalletMap(map);
    }
    if (!cred) throw new Error('No passkey selected');

    const prfExt = cred.getClientExtensionResults()?.prf || {};
    let results = prfExt.results;
    if (!results && prfExt.resultsByCredential) results = prfExt.resultsByCredential[idB64u];
    if (!results || !results.first) throw new Error('PRF result not returned; authenticator may not support PRF');

    // Use PRF output directly as private key; derive address and forget
    const priv = new Uint8Array(results.first);
    const address = addressFromPriv(priv);
    priv.fill(0);
    state.pub = null; state.addr = address; state.credId = toBase64Url(cred.rawId); state.prfSupported = true;
    // store public info only
    const info = loadWalletInfo();
    info[name] = { address };
    saveWalletInfo(info);
    refreshWalletList();
    els.walletSelect.value = name;
    els.btnSign.disabled = false;
    setDebug();
    setStatus('Logged in.');
  } catch (e) {
    console.error(e);
    setStatus('Error: ' + (e?.message || e));
  }
}

async function signCurrentMessage() {
  try {
    const name = (els.walletSelect.value || els.loginName?.value || els.walletName.value || '').trim();
    
       // Look up credential
    const map = loadWalletMap();
    let idB64u = name ? map[name] : undefined;
    
    // Request PRF output via assertion
    let publicKey;
       if (!idB64u) {
      publicKey = {
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        rpId: window.location.hostname,
      userVerification: 'required',
      timeout: 60000,
      allowCredentials: [],
      extensions: { prf: { eval: { first: PRF_SALT } } },
    };
    } else {
      const rawId = fromBase64Url(idB64u);
      publicKey = {
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        rpId: window.location.hostname,
        userVerification: 'required',
        timeout: 60000,
        allowCredentials: [ { type: 'public-key', id: rawId, transports: ['internal'] } ],
        extensions: { prf: { evalByCredential: { [idB64u]: { first: PRF_SALT } } } },
      };
    }

    setStatus('Authenticate to sign…');
    const assertion = await navigator.credentials.get({ publicKey, mediation: 'optional' });
    if (!assertion) throw new Error('No passkey selected');

    const prfExt = assertion.getClientExtensionResults()?.prf || {};
    let results = prfExt.results;
    if (!results && prfExt.resultsByCredential && idB64u) results = prfExt.resultsByCredential[idB64u];
    if (!results || !results.first) throw new Error('PRF result not returned; authenticator may not support PRF');

    // Derive ephemeral private key
    const priv = new Uint8Array(results.first);
    const address = addressFromPriv(priv);
    // Save mapping if unknown
    if (!idB64u) {
      idB64u = toBase64Url(assertion.rawId);
      // assign a label if name is empty
      let label = name || `wallet-${address.slice(2, 6)}`;
      let i = 1; const original = label;
      while (map[label] && map[label] !== idB64u) { label = `${original}-${i++}`; }
      map[label] = idB64u; saveWalletMap(map);
      // store public info
      const info = loadWalletInfo(); info[label] = { address }; saveWalletInfo(info);
      refreshWalletList(); els.walletSelect.value = label; els.walletName.value = label;
    }
    state.addr = address;

    const msg = els.msg.value ?? '';
    const signature = typed.personal.sign(msg, priv);
    priv.fill(0);

    // Display signature
    els.sig.textContent = signature;

    // Verify and recover public key
    const ok = typed.personal.verify(signature, msg, state.addr);
    els.ok.textContent = String(ok);

    const hashHex = typed.personal._getHash(msg);
    const sigHex = signature.startsWith('0x') ? signature.slice(2) : signature;
    const end = sigHex.slice(-2);
    const comp = '0x' + sigHex.slice(0, -2);
    const rec = end === '1b' ? 0 : 1;
    const sigObj = initSig(ethHex.decode(comp), rec);
    const pubBytes = sigObj.recoverPublicKey(ethHex.decode(hashHex)).toRawBytes(false);
    const pubHex = ethHex.encode(pubBytes);
    els.pub.textContent = pubHex;

    setStatus('Message signed.');
  } catch (e) {
    console.error(e);
    setStatus('Error: ' + (e?.message || e));
  }
}

// ---------- Wire up UI
els.btnRegister.addEventListener('click', registerPasskey);
els.btnLogin.addEventListener('click', () => loginWallet());

els.btnRefresh.addEventListener('click', refreshWalletList);
els.walletSelect.addEventListener('change', () => {
  const name = els.walletSelect.value;
  if (name) els.loginName.value = name;
  applySelectedWallet(name);
});
els.btnSign.addEventListener('click', signCurrentMessage);

// Init
(function init() {
  try {
    if (!initChecked) { requireSecureContext(); initChecked = true; }
    setStatus('Ready.');
  } catch (e) {
    setStatus('Error: ' + (e?.message || e));
  }
  els.btnSign.disabled = true;
  refreshWalletList();
  setDebug();
})();
