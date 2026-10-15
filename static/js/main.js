/* Crucible v2.0 — main.js */
'use strict';

/* ── Palette registry ──────────────────────────────────────────────── */
const PALETTES = [
    {id: 'tuxedo',      name: 'Tuxedo',      category: 'Professional', swatch: '#2d2d2d'},
    {id: 'blueprint',   name: 'Blueprint',    category: 'Professional', swatch: '#4a90d9'},
    {id: 'forge',       name: 'Forge',        category: 'Professional', swatch: '#c87941'},
    {id: 'bloom',       name: 'Bloom',        category: 'Casual',       swatch: '#2dd4bf'},
    {id: 'ember',       name: 'Ember',        category: 'Casual',       swatch: '#f97316'},
    {id: 'coruscant',   name: 'Coruscant',    category: 'Nerdy',        swatch: '#fbbf24'},
    {id: 'neuromancer', name: 'Neuromancer',  category: 'Nerdy',        swatch: '#06b6d4'},
    {id: 'synthwave',   name: 'Synthwave',    category: 'Nerdy',        swatch: '#e879f9'},
    {id: 'espresso',    name: 'Espresso',     category: 'Natural',      swatch: '#a68b6b'},
    {id: 'sage',        name: 'Sage',         category: 'Natural',      swatch: '#84cc16'},
];
const PALETTE_MAP = Object.fromEntries(PALETTES.map(p => [p.id, p]));
const CATEGORY_ORDER = ['Professional', 'Casual', 'Nerdy', 'Natural'];

const LS_PALETTE = 'crucible-palette';
const LS_MODE    = 'crucible-mode';
const DEFAULT_PALETTE = 'forge';
const DEFAULT_MODE    = 'light';

/* ── localStorage helpers (safe against private-browsing throws) ──── */
function lsGet(key, fallback) {
    try { return localStorage.getItem(key) || fallback; }
    catch { return fallback; }
}
function lsSet(key, val) {
    try { localStorage.setItem(key, val); } catch { /* noop */ }
}

/* ── Palette + theme application ───────────────────────────────────── */
function applyPalette(id) {
    document.documentElement.setAttribute('data-palette', id);
    lsSet(LS_PALETTE, id);
    updatePickerDisplay(id);
}

function applyMode(mode) {
    document.documentElement.setAttribute('data-mode', mode);
    lsSet(LS_MODE, mode);
    syncThemeToggles(mode);
}

function updatePickerDisplay(id) {
    const p = PALETTE_MAP[id];
    if (!p) return;
    const dot = document.getElementById('paletteSwatch');
    const label = document.getElementById('paletteLabel');
    if (dot)   dot.style.backgroundColor = p.swatch;
    if (label) label.textContent = p.name;
}

function syncThemeToggles(mode) {
    const isDark = mode === 'dark';
    const input = document.getElementById('themeToggleInput');
    if (input) input.checked = isDark;
}

/* ── Palette dropdown builder ──────────────────────────────────────── */
function buildPaletteDropdown() {
    const dropdown = document.getElementById('paletteDropdown');
    if (!dropdown) return;
    const ul = dropdown.querySelector('ul') || document.createElement('ul');
    ul.innerHTML = '';

    const grouped = {};
    PALETTES.forEach(p => {
        (grouped[p.category] = grouped[p.category] || []).push(p);
    });

    CATEGORY_ORDER.forEach(cat => {
        const entries = grouped[cat];
        if (!entries) return;
        const header = document.createElement('li');
        header.className = 'palette-category';
        header.textContent = cat;
        ul.appendChild(header);

        entries.forEach(p => {
            const li = document.createElement('li');
            li.className = 'palette-option';
            li.dataset.palette = p.id;
            li.innerHTML =
                `<span class="swatch-dot" style="display:inline-block;width:10px;height:10px;border-radius:50%;background:${p.swatch}"></span>` +
                `<span class="palette-name">${escapeHtml(p.name)}</span>`;
            li.addEventListener('click', () => {
                applyPalette(p.id);
                dropdown.classList.remove('open');
            });
            ul.appendChild(li);
        });
    });

    if (!ul.parentNode) dropdown.appendChild(ul);
}

/* ── Picker toggle + outside-click ─────────────────────────────────── */
function initPalettePicker() {
    const trigger  = document.getElementById('paletteTrigger');
    const dropdown = document.getElementById('paletteDropdown');
    if (!trigger || !dropdown) return;

    trigger.addEventListener('click', (e) => {
        e.stopPropagation();
        dropdown.classList.toggle('open');
    });

    document.addEventListener('click', (e) => {
        if (!dropdown.contains(e.target) && !trigger.contains(e.target)) {
            dropdown.classList.remove('open');
        }
    });
}

/* ── Theme toggle wiring ───────────────────────────────────────────── */
function initThemeToggle() {
    const input = document.getElementById('themeToggleInput');
    if (!input) return;
    input.addEventListener('change', () => {
        applyMode(input.checked ? 'dark' : 'light');
    });
}

/* ── Session timeout (30 min idle, 5 min warning) ──────────────────── */
const SESSION_TIMEOUT  = 30 * 60 * 1000;
const WARNING_BEFORE   = 5  * 60 * 1000;
const CHECK_INTERVAL   = 30 * 1000;
let lastActivity = Date.now();
let countdownTimer = null;

function resetActivity() { lastActivity = Date.now(); }

function initSessionTimeout() {
    ['mousemove', 'keydown', 'click', 'scroll'].forEach(evt =>
        document.addEventListener(evt, resetActivity, {passive: true})
    );
    setInterval(checkSession, CHECK_INTERVAL);
}

function checkSession() {
    const idle = Date.now() - lastActivity;
    if (idle >= SESSION_TIMEOUT - WARNING_BEFORE) showTimeoutOverlay();
}

function _doLogout() {
    fetch('/logout', {credentials: 'same-origin'}).finally(() => {
        window.location.href = '/login';
    });
}

function showTimeoutOverlay() {
    const overlay = document.getElementById('sessionTimeoutOverlay');
    if (!overlay || overlay.classList.contains('visible')) return;
    overlay.classList.add('visible');

    const deadline = lastActivity + SESSION_TIMEOUT;
    const countdownEl = overlay.querySelector('.countdown');
    const continueBtn = overlay.querySelector('.btn-continue');
    const logoutBtn   = overlay.querySelector('.btn-logout');

    function tick() {
        const remain = Math.max(0, deadline - Date.now());
        if (remain <= 0) { _doLogout(); return; }
        const m = Math.floor(remain / 60000);
        const s = Math.floor((remain % 60000) / 1000);
        if (countdownEl) countdownEl.textContent = `${m}:${String(s).padStart(2, '0')}`;
    }
    tick();
    countdownTimer = setInterval(tick, 1000);

    if (continueBtn) continueBtn.onclick = () => continueSession(overlay);
    if (logoutBtn)   logoutBtn.onclick   = () => { _doLogout(); };
}

function continueSession(overlay) {
    clearInterval(countdownTimer);
    countdownTimer = null;
    overlay.classList.remove('visible');
    resetActivity();
    fetch('/api/session_ping', {method: 'POST', credentials: 'same-origin'})
        .then(r => { if (!r.ok) _doLogout(); })
        .catch(() => { _doLogout(); });
}

/* ── Utility: toast notifications ──────────────────────────────────── */
function showToast(message, type) {
    type = type || 'info';
    const container = document.getElementById('toastContainer') || createToastContainer();
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.textContent = message;
    container.appendChild(toast);
    requestAnimationFrame(() => toast.classList.add('show'));
    setTimeout(() => {
        toast.classList.remove('show');
        toast.addEventListener('transitionend', () => toast.remove(), {once: true});
        setTimeout(() => toast.remove(), 500);
    }, 4000);
}

function createToastContainer() {
    const c = document.createElement('div');
    c.id = 'toastContainer';
    document.body.appendChild(c);
    return c;
}

/* ── Utility: format ISO datetime ──────────────────────────────────── */
function formatDateTime(isoString) {
    if (!isoString) return '';
    const d = new Date(isoString);
    if (isNaN(d.getTime())) return isoString;
    const pad = n => String(n).padStart(2, '0');
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ` +
           `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

/* ── Utility: escape HTML entities ─────────────────────────────────── */
function escapeHtml(str) {
    if (typeof str !== 'string') return '';
    const map = {'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'};
    return str.replace(/[&<>"']/g, ch => map[ch]);
}

/* ── Utility: debounce ─────────────────────────────────────────────── */
function debounce(fn, ms) {
    let id;
    return function (...args) {
        clearTimeout(id);
        id = setTimeout(() => fn.apply(this, args), ms);
    };
}

/* ── Bootstrap ─────────────────────────────────────────────────────── */
document.addEventListener('DOMContentLoaded', () => {
    const palette = lsGet(LS_PALETTE, DEFAULT_PALETTE);
    const mode    = lsGet(LS_MODE, DEFAULT_MODE);

    applyPalette(palette);
    applyMode(mode);

    buildPaletteDropdown();
    initPalettePicker();
    initThemeToggle();
    initSessionTimeout();
});
