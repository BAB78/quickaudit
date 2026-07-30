import { CHECK_META } from '../checks/index.js';
import { storage } from './browser-api.js';
import { activate, deactivate, getLicense } from './license.js';

const $ = (id) => document.getElementById(id);

let cfg = { activeChecks: false, enabled: null };

init();

async function init() {
  const { qaSettings } = await storage.get('qaSettings');
  cfg = { ...cfg, ...(qaSettings || {}) };

  renderChecks();
  renderActive();
  await renderLicense();

  $('activeChecks').addEventListener('change', onActiveToggle);
  $('consentBox').addEventListener('change', onConsent);
  $('activate').addEventListener('click', onActivate);

  if (location.hash === '#pro') $('pro').scrollIntoView({ behavior: 'smooth' });
}

function save() {
  return storage.set({ qaSettings: cfg });
}

function renderChecks() {
  const list = $('check-list');
  list.innerHTML = '';
  const enabled = cfg.enabled ? new Set(cfg.enabled) : null;

  for (const c of CHECK_META) {
    const label = document.createElement('label');
    const box = document.createElement('input');
    box.type = 'checkbox';
    box.checked = !enabled || enabled.has(c.id);
    box.addEventListener('change', () => {
      const current = new Set(cfg.enabled || CHECK_META.map((m) => m.id));
      box.checked ? current.add(c.id) : current.delete(c.id);
      // All-on is stored as null so new checks in future versions are enabled by default.
      cfg.enabled = current.size === CHECK_META.length ? null : [...current];
      save();
    });

    const meta = document.createElement('div');
    meta.className = 'meta';
    const name = document.createElement('div');
    name.className = 'name';
    name.textContent = `${c.id} · ${c.title}`;
    if (c.active) {
      const tag = document.createElement('span');
      tag.className = 'tag';
      tag.textContent = 'sends requests';
      name.appendChild(tag);
    }
    const sev = document.createElement('div');
    sev.className = 'sev';
    sev.textContent = `${c.severity} severity`;
    meta.append(name, sev);
    label.append(box, meta);
    list.appendChild(label);
  }
}

function renderActive() {
  $('activeChecks').checked = Boolean(cfg.activeChecks);
  $('consent').hidden = Boolean(cfg.activeChecks);
  $('consentBox').checked = false;
}

/**
 * Turning the active check on requires ticking the authorisation box first. Turning it off
 * is always allowed immediately.
 */
function onActiveToggle(e) {
  if (!e.target.checked) {
    cfg.activeChecks = false;
    save();
    renderActive();
    return;
  }
  if (!$('consentBox').checked) {
    e.target.checked = false;
    $('consent').hidden = false;
    $('consentBox').focus();
    return;
  }
  cfg.activeChecks = true;
  save();
  renderActive();
}

function onConsent() {
  if ($('consentBox').checked) $('activeChecks').disabled = false;
}

async function renderLicense() {
  const lic = await getLicense();
  const state = $('license-state');
  state.innerHTML = '';
  if (!lic) return;

  const box = document.createElement('div');
  box.className = 'pro-active';
  box.innerHTML = lic.covered
    ? `<b>Pro active</b> — licensed to ${escapeHtml(lic.email)} (issued ${escapeHtml(lic.issued || '—')}).`
    // A genuine key that predates this major version. Say exactly that, rather than the
    // alarming and wrong "invalid key".
    : `<b class="stale">Licence is for an earlier version</b> — ${escapeHtml(lic.reason)}<br>
       Your key (${escapeHtml(lic.email)}) stays valid for that version. Upgrading to this one is a new purchase.`;
  const off = document.createElement('button');
  off.className = 'ghost';
  off.textContent = 'Deactivate on this device';
  off.style.marginTop = '10px';
  off.addEventListener('click', async () => { await deactivate(); await renderLicense(); });
  box.appendChild(document.createElement('br'));
  box.appendChild(off);
  state.appendChild(box);
}

async function onActivate() {
  const msg = $('key-msg');
  const res = await activate($('key').value);
  if (res.valid) {
    msg.className = 'msg ok';
    msg.textContent = `Activated. Thank you — report export is now unlocked.`;
    $('key').value = '';
    await renderLicense();
  } else {
    msg.className = 'msg bad';
    msg.textContent = res.reason;
  }
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
}
