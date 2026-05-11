/* ============================================================
   Western Mass Bitcoin — Classifieds
   ============================================================
   - Fetches NIP-99 (kind 30402) listings from whitelisted npubs
   - Renders cards + detail modal
   - Login: NIP-07 / NIP-46 (bunker://) / nsec
   - Composer publishes new listings + uploads images to Blossom
   ============================================================ */

import {
  SimplePool,
  nip19,
  finalizeEvent,
  generateSecretKey,
  getPublicKey,
} from 'https://esm.sh/nostr-tools@2.7.2';
import { BunkerSigner, parseBunkerInput } from 'https://esm.sh/nostr-tools@2.7.2/nip46';

// ============================================================
// Config + state
// ============================================================
let config = null;
let whitelistHex = [];        // hex pubkeys allowed to publish listings shown here
let meetupHex = null;         // hex pubkey of the meetup npub (source of kind 3 whitelist)
let relayTemplateHex = null;  // hex pubkey we copy kind 10002 + 10050 from for new users
let pool = null;
const listings = new Map();   // d-tag-key -> latest event
const profiles = new Map();   // hex pubkey -> kind 0 metadata
let activeSigner = null;      // { pubkey, signEvent, kind, close? }

// ============================================================
// Boot
// ============================================================
(async function init() {
  try {
    const res = await fetch('classifieds.json', { cache: 'no-cache' });
    config = await res.json();
  } catch (err) {
    showError('Could not load classifieds.json — site is misconfigured.');
    return;
  }

  try {
    if (config.meetupNpub) meetupHex = nip19.decode(config.meetupNpub).data;
  } catch {}
  try {
    if (config.relayTemplateNpub) relayTemplateHex = nip19.decode(config.relayTemplateNpub).data;
  } catch {}

  pool = new SimplePool();

  wireUI();
  await loadWhitelist();
  loadListings();
})();

// ============================================================
// Whitelist: derived from meetup npub's kind 3 contact list
// ============================================================
async function loadWhitelist() {
  // Try dynamic (kind 3 from meetup npub)
  if (meetupHex) {
    try {
      const followed = await fetchMeetupContacts();
      if (followed.length) {
        whitelistHex = followed;
        return;
      }
    } catch (err) {
      console.warn('Meetup contact list fetch failed; falling back to static whitelist.', err);
    }
  }

  // Fallback: static list in classifieds.json
  whitelistHex = (config.whitelistedNpubs || [])
    .map(n => { try { return nip19.decode(n).data; } catch { return null; } })
    .filter(Boolean);
}

function fetchMeetupContacts() {
  return new Promise((resolve) => {
    let latest = null;
    const sub = pool.subscribeMany(
      config.relays,
      [{ kinds: [3], authors: [meetupHex], limit: 1 }],
      {
        onevent(event) {
          if (!latest || event.created_at > latest.created_at) latest = event;
        },
        oneose() {
          sub.close();
          const pubkeys = latest
            ? latest.tags.filter(t => t[0] === 'p' && /^[0-9a-f]{64}$/.test(t[1] || '')).map(t => t[1])
            : [];
          resolve(pubkeys);
        }
      }
    );
    setTimeout(() => {
      sub.close();
      const pubkeys = latest
        ? latest.tags.filter(t => t[0] === 'p' && /^[0-9a-f]{64}$/.test(t[1] || '')).map(t => t[1])
        : [];
      resolve(pubkeys);
    }, 5000);
  });
}

// ============================================================
// UI wiring
// ============================================================
function wireUI() {
  document.getElementById('cf-post-btn').addEventListener('click', () => {
    if (activeSigner) {
      openComposer();
    } else {
      openLogin();
    }
  });

  // Login options
  document.querySelectorAll('.login-option').forEach(btn => {
    btn.addEventListener('click', () => handleLoginChoice(btn.dataset.method));
  });
  document.querySelectorAll('[data-cancel]').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.login-panel').forEach(p => p.classList.remove('open'));
    });
  });
  document.getElementById('login-bunker-connect').addEventListener('click', loginWithBunker);
  document.getElementById('login-nsec-submit').addEventListener('click', loginWithNsec);

  // Composer
  document.getElementById('composer-form').addEventListener('submit', publishListing);
  document.getElementById('composer-image-add').addEventListener('click', () => {
    document.getElementById('composer-file-input').click();
  });
  document.getElementById('composer-file-input').addEventListener('change', handleImagePick);

  // Signup wizard
  wireSignupWizard();

  // Help tips (click to toggle on mobile, hover/focus already handled by CSS)
  document.querySelectorAll('.help-tip').forEach(tip => {
    tip.addEventListener('click', (e) => {
      e.stopPropagation();
      tip.classList.toggle('open');
    });
  });
  document.addEventListener('click', () => {
    document.querySelectorAll('.help-tip.open').forEach(t => t.classList.remove('open'));
  });

  // Pre-populate the description field with contact prompt
  const desc = document.getElementById('composer-description');
  desc.addEventListener('focus', () => {
    if (!desc.value) {
      desc.value = 'Preferred contact method (this is public): \n\n';
      // Move cursor to end of first line
      desc.setSelectionRange(desc.value.indexOf('\n'), desc.value.indexOf('\n'));
    }
  }, { once: true });
}

// ============================================================
// Listings: fetch + render
// ============================================================
function loadListings() {
  const grid = document.getElementById('cf-grid');

  if (!whitelistHex.length) {
    grid.innerHTML = '';
    const empty = document.createElement('div');
    empty.className = 'listing-empty';
    empty.textContent = 'No approved sellers yet — an organizer is curating the list. Sign up below and you might be next.';
    grid.appendChild(empty);
    setStatus('Waiting for the meetup to approve sellers…');
    return;
  }

  grid.innerHTML = '<div class="listing-loading">Connecting to relays…</div>';

  let eventCount = 0;
  let eosed = false;

  const sub = pool.subscribeMany(
    config.relays,
    [{ kinds: [30402], authors: whitelistHex }],
    {
      onevent(event) {
        const dTag = event.tags.find(t => t[0] === 'd')?.[1] || '';
        const key = `${event.pubkey}:${dTag}`;
        const existing = listings.get(key);
        if (!existing || event.created_at > existing.created_at) {
          // Skip if status:sold tag is set
          const status = event.tags.find(t => t[0] === 'status')?.[1];
          if (status === 'sold' || status === 'inactive') {
            listings.delete(key);
          } else {
            listings.set(key, event);
          }
          eventCount++;
          if (eosed) renderGrid();
        }
      },
      oneose() {
        eosed = true;
        renderGrid();
        // Lazy-fetch seller profiles after we know who they are
        const authors = [...new Set([...listings.values()].map(e => e.pubkey))];
        if (authors.length) fetchProfiles(authors);
      }
    }
  );

  // Safety timeout: if no EOSE within 8s, render whatever we have
  setTimeout(() => {
    if (!eosed) {
      eosed = true;
      renderGrid();
    }
  }, 8000);
}

function renderGrid() {
  const grid = document.getElementById('cf-grid');
  const sorted = [...listings.values()].sort((a, b) => {
    const aPub = +(a.tags.find(t => t[0] === 'published_at')?.[1] || a.created_at);
    const bPub = +(b.tags.find(t => t[0] === 'published_at')?.[1] || b.created_at);
    return bPub - aPub;
  });

  if (!sorted.length) {
    grid.innerHTML = '';
    const empty = document.createElement('div');
    empty.className = 'listing-empty';
    empty.textContent = 'No listings yet. Check back soon — or be the first member to post one.';
    grid.appendChild(empty);
    setStatus(`0 listings from ${whitelistHex.length} verified seller${whitelistHex.length === 1 ? '' : 's'}.`);
    return;
  }

  grid.innerHTML = '';
  for (const event of sorted) {
    grid.appendChild(renderCard(event));
  }
  setStatus(`<strong>${sorted.length}</strong> listing${sorted.length === 1 ? '' : 's'} from ${whitelistHex.length} verified seller${whitelistHex.length === 1 ? '' : 's'}.`);
}

function renderCard(event) {
  const card = document.createElement('div');
  card.className = 'listing-card';
  card.tabIndex = 0;
  card.setAttribute('role', 'button');

  const title = getTitle(event);
  const price = getPrice(event);
  const imgs = getImages(event);

  const imgWrap = document.createElement('div');
  imgWrap.className = 'listing-card-image';
  if (imgs.length) {
    const img = document.createElement('img');
    img.src = imgs[0];
    img.alt = title;
    img.loading = 'lazy';
    img.onerror = () => { imgWrap.textContent = 'No image'; };
    imgWrap.appendChild(img);
  } else {
    imgWrap.textContent = 'No image';
  }

  const body = document.createElement('div');
  body.className = 'listing-card-body';

  const titleEl = document.createElement('div');
  titleEl.className = 'listing-card-title';
  titleEl.textContent = title;

  const priceEl = document.createElement('div');
  priceEl.className = 'listing-card-price';
  priceEl.textContent = price;

  const seller = document.createElement('div');
  seller.className = 'listing-card-seller';
  seller.dataset.pubkey = event.pubkey;
  const sellerImg = document.createElement('img');
  sellerImg.src = profiles.get(event.pubkey)?.picture || transparentPx();
  sellerImg.alt = '';
  const sellerName = document.createElement('span');
  sellerName.textContent = profiles.get(event.pubkey)?.display_name
    || profiles.get(event.pubkey)?.name
    || shortNpub(event.pubkey);
  seller.appendChild(sellerImg);
  seller.appendChild(sellerName);

  body.appendChild(titleEl);
  body.appendChild(priceEl);
  body.appendChild(seller);

  card.appendChild(imgWrap);
  card.appendChild(body);

  card.addEventListener('click', () => openListing(event));
  card.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      openListing(event);
    }
  });
  return card;
}

// ============================================================
// Profile cache
// ============================================================
function fetchProfiles(pubkeys) {
  const missing = pubkeys.filter(p => !profiles.has(p));
  if (!missing.length) return;

  const sub = pool.subscribeMany(
    config.relays,
    [{ kinds: [0], authors: missing }],
    {
      onevent(event) {
        try {
          const meta = JSON.parse(event.content);
          const existing = profiles.get(event.pubkey);
          if (!existing || event.created_at > (existing._ts || 0)) {
            meta._ts = event.created_at;
            profiles.set(event.pubkey, meta);
            updateProfileInDOM(event.pubkey, meta);
          }
        } catch {}
      },
      oneose() {
        // Mark anyone without a profile so we don't re-fetch
        for (const p of missing) {
          if (!profiles.has(p)) profiles.set(p, { _ts: 0 });
        }
        sub.close();
      }
    }
  );
}

function updateProfileInDOM(pubkey, meta) {
  document.querySelectorAll(`.listing-card-seller[data-pubkey="${pubkey}"]`).forEach(el => {
    const img = el.querySelector('img');
    const name = el.querySelector('span');
    if (img && meta.picture) img.src = meta.picture;
    if (name) name.textContent = meta.display_name || meta.name || shortNpub(pubkey);
  });
}

// ============================================================
// Listing detail modal
// ============================================================
function openListing(event) {
  const container = document.getElementById('listing-modal-content');
  container.innerHTML = '';

  const imgs = getImages(event);

  // Images section
  if (imgs.length) {
    const imagesWrap = document.createElement('div');
    imagesWrap.className = 'listing-modal-images';
    const main = document.createElement('div');
    main.className = 'listing-modal-image-main';
    const mainImg = document.createElement('img');
    mainImg.src = imgs[0];
    mainImg.alt = getTitle(event);
    main.appendChild(mainImg);
    imagesWrap.appendChild(main);

    if (imgs.length > 1) {
      const thumbs = document.createElement('div');
      thumbs.className = 'listing-modal-thumbs';
      imgs.forEach((src, i) => {
        const t = document.createElement('div');
        t.className = 'listing-modal-thumb' + (i === 0 ? ' active' : '');
        const ti = document.createElement('img');
        ti.src = src;
        ti.alt = '';
        t.appendChild(ti);
        t.addEventListener('click', () => {
          mainImg.src = src;
          thumbs.querySelectorAll('.listing-modal-thumb').forEach(x => x.classList.remove('active'));
          t.classList.add('active');
        });
        thumbs.appendChild(t);
      });
      imagesWrap.appendChild(thumbs);
    }
    container.appendChild(imagesWrap);
  }

  // Header
  const header = document.createElement('div');
  header.className = 'modal-header';
  const titleH = document.createElement('h3');
  titleH.id = 'listing-modal-title';
  titleH.className = 'listing-modal-title';
  titleH.textContent = getTitle(event);
  header.appendChild(titleH);

  const summary = event.tags.find(t => t[0] === 'summary')?.[1];
  if (summary) {
    const sumEl = document.createElement('p');
    sumEl.className = 'listing-modal-summary';
    sumEl.textContent = summary;
    header.appendChild(sumEl);
  }
  container.appendChild(header);

  // Body
  const body = document.createElement('div');
  body.className = 'modal-body';

  const meta = document.createElement('div');
  meta.className = 'listing-modal-meta';
  const priceEl = document.createElement('div');
  priceEl.className = 'listing-modal-price';
  priceEl.textContent = getPrice(event);
  meta.appendChild(priceEl);
  const pub = +(event.tags.find(t => t[0] === 'published_at')?.[1] || event.created_at);
  const date = document.createElement('div');
  date.style.color = 'var(--text-dim)';
  date.style.fontSize = '0.85rem';
  date.textContent = `Posted ${timeAgo(pub)}`;
  meta.appendChild(date);
  body.appendChild(meta);

  if (event.content) {
    const desc = document.createElement('div');
    desc.className = 'listing-modal-description';
    desc.textContent = event.content;
    body.appendChild(desc);
  }

  const tags = event.tags.filter(t => t[0] === 't').map(t => t[1]);
  if (tags.length) {
    const tagsEl = document.createElement('div');
    tagsEl.className = 'listing-modal-tags';
    tags.forEach(t => {
      const span = document.createElement('span');
      span.className = 'listing-modal-tag';
      span.textContent = '#' + t;
      tagsEl.appendChild(span);
    });
    body.appendChild(tagsEl);
  }

  // Seller
  const sellerEl = document.createElement('div');
  sellerEl.className = 'listing-modal-seller';
  const sImg = document.createElement('img');
  sImg.src = profiles.get(event.pubkey)?.picture || transparentPx();
  sImg.alt = '';
  const sInfo = document.createElement('div');
  sInfo.className = 'listing-modal-seller-info';
  const sName = document.createElement('div');
  sName.className = 'listing-modal-seller-name';
  sName.textContent = profiles.get(event.pubkey)?.display_name
    || profiles.get(event.pubkey)?.name
    || 'Anonymous Bitcoiner';
  const sLink = document.createElement('div');
  sLink.className = 'listing-modal-seller-link';
  const npub = nip19.npubEncode(event.pubkey);
  const sA = document.createElement('a');
  sA.href = `https://njump.me/${npub}`;
  sA.target = '_blank';
  sA.rel = 'noopener';
  sA.textContent = 'View seller on Nostr →';
  sLink.appendChild(sA);
  sInfo.appendChild(sName);
  sInfo.appendChild(sLink);
  sellerEl.appendChild(sImg);
  sellerEl.appendChild(sInfo);
  body.appendChild(sellerEl);

  container.appendChild(body);
  cfOpenModal('listing-modal');
}

// ============================================================
// Helpers
// ============================================================
function getTitle(event) {
  return event.tags.find(t => t[0] === 'title')?.[1] || '(untitled)';
}
function getImages(event) {
  return event.tags
    .filter(t => t[0] === 'image' && typeof t[1] === 'string')
    .map(t => t[1])
    .filter(u => u.startsWith('https://'));
}
function getPrice(event) {
  const p = event.tags.find(t => t[0] === 'price');
  if (!p) return 'Price on request';
  const [, amount, currency] = p;
  if (!amount) return 'Price on request';
  if (currency === 'trade' || /trade/i.test(currency || '')) return 'Trade / Offer';
  const num = Number(amount);
  const fmt = Number.isFinite(num) ? num.toLocaleString() : amount;
  if (!currency) return fmt;
  if (currency.toUpperCase() === 'USD') return `$${fmt}`;
  if (currency.toUpperCase() === 'SATS') return `${fmt} sats`;
  if (currency.toUpperCase() === 'BTC') return `₿${fmt}`;
  return `${fmt} ${currency}`;
}
function shortNpub(hex) {
  try {
    const npub = nip19.npubEncode(hex);
    return `${npub.slice(0, 9)}…${npub.slice(-4)}`;
  } catch { return hex.slice(0, 10); }
}
function timeAgo(unixSec) {
  const s = Math.floor(Date.now() / 1000) - unixSec;
  if (s < 60) return 'just now';
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  const d = Math.floor(s / 86400);
  if (d < 30) return `${d}d ago`;
  if (d < 365) return `${Math.floor(d / 30)}mo ago`;
  return `${Math.floor(d / 365)}y ago`;
}
function transparentPx() {
  return 'data:image/gif;base64,R0lGODlhAQABAAAAACH5BAEKAAEALAAAAAABAAEAAAICTAEAOw==';
}
function setStatus(html) {
  document.getElementById('cf-status-text').innerHTML = html;
}
function showError(msg) {
  const grid = document.getElementById('cf-grid');
  if (grid) grid.innerHTML = `<div class="listing-error">${escapeHtml(msg)}</div>`;
}
function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

// ============================================================
// Login flow
// ============================================================
function openLogin() {
  cfOpenModal('login-modal');
  // NIP-07 button: disable if no extension
  const nip07Btn = document.getElementById('login-nip07');
  if (!window.nostr) {
    nip07Btn.disabled = true;
    nip07Btn.querySelector('.login-option-sub').textContent = 'No extension detected — install Alby or nos2x';
  }
  // Clear any open panels
  document.querySelectorAll('.login-panel').forEach(p => p.classList.remove('open'));
}

function handleLoginChoice(method) {
  if (method === 'signup') {
    cfCloseModal('login-modal');
    cfOpenModal('signup-modal');
    return;
  }
  if (method === 'nip07') return loginWithNip07();
  if (method === 'nip46') {
    document.getElementById('login-panel-nip46').classList.add('open');
    document.getElementById('login-bunker-input').focus();
    return;
  }
  if (method === 'nsec') {
    document.getElementById('login-panel-nsec').classList.add('open');
    document.getElementById('login-nsec-input').focus();
    return;
  }
}

async function loginWithNip07() {
  if (!window.nostr) {
    alert('No NIP-07 extension found. Try Alby, nos2x, or keys.band.');
    return;
  }
  try {
    const pubkey = await window.nostr.getPublicKey();
    activeSigner = {
      pubkey,
      kind: 'nip07',
      signEvent: async (event) => await window.nostr.signEvent(event),
    };
    onLogin();
  } catch (err) {
    alert('Sign-in failed: ' + (err.message || err));
  }
}

async function loginWithBunker() {
  const input = document.getElementById('login-bunker-input').value.trim();
  const statusEl = document.getElementById('login-bunker-status');
  statusEl.classList.remove('error');
  if (!input.startsWith('bunker://')) {
    statusEl.classList.add('error');
    statusEl.textContent = 'Must be a bunker:// URL.';
    return;
  }
  statusEl.textContent = 'Connecting to signer…';
  try {
    const pointer = await parseBunkerInput(input);
    if (!pointer) throw new Error('Could not parse bunker URL.');
    const clientKey = generateSecretKey();
    const signer = new BunkerSigner(clientKey, pointer, { pool });
    let elapsed = 0;
    const tick = setInterval(() => {
      elapsed++;
      statusEl.textContent = `Connecting to signer… (${elapsed}s — approve the request in your signer app)`;
    }, 1000);
    await signer.connect();
    clearInterval(tick);
    const pubkey = await signer.getPublicKey();
    activeSigner = {
      pubkey,
      kind: 'nip46',
      signEvent: async (event) => await signer.signEvent(event),
      close: () => signer.close?.(),
    };
    onLogin();
  } catch (err) {
    statusEl.classList.add('error');
    statusEl.textContent = 'Connect failed: ' + (err.message || err);
  }
}

async function loginWithNsec() {
  const val = document.getElementById('login-nsec-input').value.trim();
  const statusEl = document.getElementById('login-nsec-status');
  statusEl.classList.remove('error');
  try {
    let secretKey;
    if (val.startsWith('nsec1')) {
      const decoded = nip19.decode(val);
      if (decoded.type !== 'nsec') throw new Error('Not an nsec.');
      secretKey = decoded.data;
    } else {
      throw new Error('Paste an nsec1… (bech32-encoded private key).');
    }
    const pubkey = getPublicKey(secretKey);
    activeSigner = {
      pubkey,
      kind: 'nsec',
      signEvent: async (event) => finalizeEvent(event, secretKey),
    };
    // Best-effort: clear the input
    document.getElementById('login-nsec-input').value = '';
    onLogin();
  } catch (err) {
    statusEl.classList.add('error');
    statusEl.textContent = err.message || String(err);
  }
}

function onLogin() {
  cfCloseModal('login-modal');
  renderUserChip();
  // Fetch the user's own profile so the chip displays nicely
  if (!profiles.has(activeSigner.pubkey)) {
    fetchProfiles([activeSigner.pubkey]);
  }
  openComposer();
}

function renderUserChip() {
  const actions = document.getElementById('cf-toolbar-actions');
  actions.innerHTML = '';

  const chip = document.createElement('span');
  chip.className = 'classifieds-user-chip';
  const img = document.createElement('img');
  img.src = profiles.get(activeSigner.pubkey)?.picture || transparentPx();
  img.alt = '';
  const name = document.createElement('span');
  name.textContent = profiles.get(activeSigner.pubkey)?.display_name
    || profiles.get(activeSigner.pubkey)?.name
    || shortNpub(activeSigner.pubkey);
  const out = document.createElement('button');
  out.textContent = 'sign out';
  out.addEventListener('click', logout);
  chip.appendChild(img);
  chip.appendChild(name);
  chip.appendChild(out);

  const postBtn = document.createElement('button');
  postBtn.className = 'btn btn-orange';
  postBtn.id = 'cf-post-btn';
  postBtn.textContent = 'Post a Listing';
  postBtn.addEventListener('click', openComposer);

  actions.appendChild(chip);
  actions.appendChild(postBtn);

  // If not in whitelist, warn the user
  if (!whitelistHex.includes(activeSigner.pubkey)) {
    const warn = document.createElement('div');
    warn.style.flex = '0 0 100%';
    warn.style.color = 'var(--text-dim)';
    warn.style.fontSize = '0.8rem';
    warn.style.marginTop = '4px';
    warn.textContent = 'Heads up — your npub isn\'t on the meetup whitelist yet, so your listing won\'t appear here until an organizer approves it. Email reedlabarge@gmail.com with your npub to get added.';
    actions.appendChild(warn);
  }
}

function logout() {
  try { activeSigner?.close?.(); } catch {}
  activeSigner = null;
  const actions = document.getElementById('cf-toolbar-actions');
  actions.innerHTML = '';
  const btn = document.createElement('button');
  btn.className = 'btn btn-orange';
  btn.id = 'cf-post-btn';
  btn.textContent = 'Post a Listing';
  btn.addEventListener('click', () => openLogin());
  actions.appendChild(btn);
}

// ============================================================
// Composer
// ============================================================
const composerImages = []; // { url, sha256 }

function openComposer() {
  cfOpenModal('composer-modal');
}

function handleImagePick(e) {
  const files = Array.from(e.target.files || []);
  e.target.value = ''; // allow re-pick of same file
  for (const file of files) {
    if (composerImages.length >= 4) break;
    uploadImage(file);
  }
}

async function uploadImage(file) {
  if (!file.type.startsWith('image/')) return;
  if (file.size > 8 * 1024 * 1024) {
    composerStatus('Image too large (max 8MB).', 'error');
    return;
  }
  if (!activeSigner) {
    composerStatus('You must be signed in to upload images.', 'error');
    return;
  }

  const slot = { url: null, sha256: null, pending: true, file };
  composerImages.push(slot);

  // Render placeholder
  const wrap = document.createElement('div');
  wrap.className = 'composer-image';
  const img = document.createElement('img');
  const fileUrl = URL.createObjectURL(file);
  img.src = fileUrl;
  wrap.appendChild(img);
  const prog = document.createElement('div');
  prog.className = 'composer-image-progress';
  prog.textContent = 'Uploading…';
  wrap.appendChild(prog);
  const rm = document.createElement('button');
  rm.className = 'composer-image-remove';
  rm.type = 'button';
  rm.textContent = '×';
  rm.addEventListener('click', () => {
    const i = composerImages.indexOf(slot);
    if (i >= 0) composerImages.splice(i, 1);
    wrap.remove();
    URL.revokeObjectURL(fileUrl);
  });
  wrap.appendChild(rm);

  const container = document.getElementById('composer-images');
  const addBtn = document.getElementById('composer-image-add');
  container.insertBefore(wrap, addBtn);

  try {
    const { url, sha256 } = await uploadToBlossom(file, activeSigner);
    slot.url = url;
    slot.sha256 = sha256;
    slot.pending = false;
    prog.remove();
  } catch (err) {
    composerStatus('Image upload failed: ' + (err.message || err), 'error');
    const i = composerImages.indexOf(slot);
    if (i >= 0) composerImages.splice(i, 1);
    wrap.remove();
    URL.revokeObjectURL(fileUrl);
  }

  hideAddButtonIfFull();
}

function hideAddButtonIfFull() {
  const addBtn = document.getElementById('composer-image-add');
  addBtn.style.display = composerImages.length >= 4 ? 'none' : '';
}

async function publishListing(e) {
  e.preventDefault();
  if (!activeSigner) {
    composerStatus('You must be signed in.', 'error');
    return;
  }
  if (composerImages.some(s => s.pending)) {
    composerStatus('Wait for images to finish uploading.', 'error');
    return;
  }

  const title = document.getElementById('composer-title').value.trim();
  const summary = document.getElementById('composer-summary').value.trim();
  const description = document.getElementById('composer-description').value.trim();
  const amount = document.getElementById('composer-price-amount').value.trim();
  const currency = document.getElementById('composer-price-currency').value;
  const tagsRaw = document.getElementById('composer-tags').value.trim();

  if (!title) return composerStatus('Title is required.', 'error');
  if (!description) return composerStatus('Description is required.', 'error');

  const submitBtn = document.getElementById('composer-submit');
  submitBtn.disabled = true;
  submitBtn.textContent = 'Publishing…';
  composerStatus('Signing event…', 'success');

  try {
    const now = Math.floor(Date.now() / 1000);
    const dTag = `wmb-${now.toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
    const tags = [
      ['d', dTag],
      ['title', title],
      ['published_at', String(now)],
      ['location', 'Western Massachusetts'],
      ['client', 'westernmassbitcoin'],
    ];
    if (summary) tags.push(['summary', summary]);
    if (amount) tags.push(['price', amount, currency]);
    composerImages.forEach(s => {
      if (s.url) tags.push(['image', s.url]);
    });
    if (tagsRaw) {
      tagsRaw.split(',').map(t => t.trim().replace(/^#/, '')).filter(Boolean).forEach(t => {
        tags.push(['t', t]);
      });
    }

    const event = await activeSigner.signEvent({
      kind: 30402,
      created_at: now,
      content: description,
      tags,
    });

    const quiet = document.getElementById('composer-quiet').checked;
    const targetRelays = quiet && config.quietRelay ? [config.quietRelay] : config.relays;
    composerStatus(quiet ? `Publishing quietly to ${config.quietRelay}…` : 'Publishing to relays…', 'success');

    const results = await Promise.allSettled(pool.publish(targetRelays, event));
    const ok = results.filter(r => r.status === 'fulfilled').length;
    if (ok === 0) throw new Error(quiet ? 'The quiet relay did not accept the listing.' : 'No relays accepted the listing.');

    const quietNote = quiet ? ' (quiet mode — only on relay.mynostr.app)' : '';
    composerStatus(`Published to ${ok}/${results.length} relay${results.length === 1 ? '' : 's'}${quietNote}. ${whitelistHex.includes(activeSigner.pubkey) ? 'Your listing will appear here shortly.' : 'Your listing is live on Nostr — email reedlabarge@gmail.com with your npub so we can add you to the meetup whitelist and it will appear here.'}`, 'success');

    // Reset form
    document.getElementById('composer-form').reset();
    composerImages.length = 0;
    document.querySelectorAll('.composer-image').forEach(el => el.remove());
    hideAddButtonIfFull();

    // Close after a beat so the user can read the success message
    setTimeout(() => {
      cfCloseModal('composer-modal');
      composerStatus('', '');
      // Add the new listing locally so it shows up before relay-roundtrip
      if (whitelistHex.includes(event.pubkey)) {
        listings.set(`${event.pubkey}:${dTag}`, event);
        renderGrid();
      }
    }, 2500);
  } catch (err) {
    composerStatus('Publish failed: ' + (err.message || err), 'error');
  } finally {
    submitBtn.disabled = false;
    submitBtn.textContent = 'Publish to Nostr';
  }
}

function composerStatus(msg, kind) {
  const el = document.getElementById('composer-status');
  el.className = 'composer-status' + (msg ? ' show ' + (kind || '') : '');
  el.textContent = msg;
}

// ============================================================
// Blossom upload helper (used by composer + signup wizard)
// ============================================================
async function uploadToBlossom(file, signer) {
  if (!file.type.startsWith('image/')) throw new Error('Not an image.');
  if (file.size > 8 * 1024 * 1024) throw new Error('Image too large (max 8MB).');
  if (!signer) throw new Error('Not signed in.');

  const buf = await file.arrayBuffer();
  const hashBuf = await crypto.subtle.digest('SHA-256', buf);
  const sha256 = [...new Uint8Array(hashBuf)].map(b => b.toString(16).padStart(2, '0')).join('');

  const authEvent = await signer.signEvent({
    kind: 24242,
    created_at: Math.floor(Date.now() / 1000),
    content: 'Upload from westernmassbitcoin.com classifieds',
    tags: [
      ['t', 'upload'],
      ['x', sha256],
      ['expiration', String(Math.floor(Date.now() / 1000) + 600)],
      ['client', 'westernmassbitcoin'],
    ],
  });

  const authHeader = 'Nostr ' + btoa(JSON.stringify(authEvent));

  const res = await fetch(`${config.blossom.server}/upload`, {
    method: 'PUT',
    headers: {
      'Authorization': authHeader,
      'Content-Type': file.type || 'application/octet-stream',
    },
    body: buf,
  });

  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error(`Blossom ${res.status}: ${text.slice(0, 120)}`);
  }

  const body = await res.json();
  return { url: body.url, sha256: body.sha256 || sha256 };
}

// ============================================================
// Signup wizard
// ============================================================
let signupState = null;

function wireSignupWizard() {
  document.getElementById('wizard-generate-btn').addEventListener('click', wizardGenerate);

  document.querySelectorAll('.wizard-key-copy').forEach(btn => {
    btn.addEventListener('click', () => wizardCopy(btn));
  });

  document.getElementById('wizard-download-btn').addEventListener('click', wizardDownload);

  document.getElementById('wizard-saved-checkbox').addEventListener('change', (e) => {
    document.getElementById('wizard-step1-next').disabled = !e.target.checked;
  });

  document.getElementById('wizard-step1-next').addEventListener('click', () => wizardGoToStep(2));
  document.getElementById('wizard-step2-back').addEventListener('click', () => wizardGoToStep(1));
  document.getElementById('wizard-step2-next').addEventListener('click', wizardStep2Submit);
  document.getElementById('wizard-finish-btn').addEventListener('click', wizardFinish);

  document.getElementById('wizard-pfp-input').addEventListener('change', (e) => wizardUploadProfileImage(e, 'pfp'));
  document.getElementById('wizard-banner-input').addEventListener('change', (e) => wizardUploadProfileImage(e, 'banner'));
}

function wizardGenerate() {
  const secretKey = generateSecretKey();           // Uint8Array
  const pubkey = getPublicKey(secretKey);          // hex
  const nsec = nip19.nsecEncode(secretKey);
  const npub = nip19.npubEncode(pubkey);

  signupState = {
    secretKey,
    pubkey,
    nsec,
    npub,
    pfpUrl: null,
    bannerUrl: null,
    signEvent: async (event) => finalizeEvent(event, secretKey),
  };

  document.getElementById('wizard-npub').textContent = npub;
  document.getElementById('wizard-nsec').textContent = nsec;
  document.getElementById('wizard-keygen-pre').style.display = 'none';
  document.getElementById('wizard-keygen-post').style.display = '';
}

function wizardCopy(btn) {
  if (!signupState) return;
  const what = btn.dataset.copy;
  const val = what === 'nsec' ? signupState.nsec : signupState.npub;
  navigator.clipboard.writeText(val).then(() => {
    const original = btn.textContent;
    btn.textContent = 'Copied!';
    btn.classList.add('copied');
    setTimeout(() => {
      btn.textContent = original;
      btn.classList.remove('copied');
    }, 1500);
  });
}

function wizardDownload() {
  if (!signupState) return;
  const txt = [
    '# Western Mass Bitcoin — Nostr account backup',
    `# Generated: ${new Date().toISOString()}`,
    '',
    '# Your public key (share freely):',
    signupState.npub,
    '',
    '# Your secret key (KEEP PRIVATE — anyone with this controls your account):',
    signupState.nsec,
    '',
    '# How to use this:',
    '# - Import the nsec into a Nostr client (Primal, Damus, Amethyst, etc.) to sign in.',
    '# - Or paste it back into westernmassbitcoin.com/classifieds under "Paste nsec".',
    '# - Treat it like a seed phrase: if you lose it, your account is gone.',
  ].join('\n');

  const blob = new Blob([txt], { type: 'text/plain' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `westernmassbitcoin-nostr-${signupState.npub.slice(0, 12)}.txt`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function wizardGoToStep(n) {
  document.querySelectorAll('.wizard-pane').forEach(p => p.classList.toggle('active', +p.dataset.pane === n));
  document.querySelectorAll('.wizard-step').forEach(s => {
    const sn = +s.dataset.step;
    s.classList.toggle('active', sn === n);
    s.classList.toggle('done', sn < n);
  });
}

async function wizardUploadProfileImage(e, which) {
  const file = e.target.files?.[0];
  e.target.value = '';
  if (!file || !signupState) return;

  const wrap = document.getElementById(which === 'pfp' ? 'wizard-pfp-pick' : 'wizard-banner-pick');
  const placeholder = wrap.querySelector(which === 'pfp' ? '.wizard-pfp-placeholder' : '.wizard-banner-placeholder');

  // Show local preview immediately
  const preview = document.createElement('img');
  const objectUrl = URL.createObjectURL(file);
  preview.src = objectUrl;
  // Remove any previous preview
  wrap.querySelectorAll('img').forEach(el => el.remove());
  wrap.querySelectorAll('.wizard-pfp-uploading, .wizard-banner-uploading').forEach(el => el.remove());
  wrap.appendChild(preview);
  if (placeholder) placeholder.style.display = 'none';
  wrap.classList.add('has-image');

  // Progress overlay
  const overlay = document.createElement('span');
  overlay.className = which === 'pfp' ? 'wizard-pfp-uploading' : 'wizard-banner-uploading';
  overlay.textContent = 'Uploading…';
  wrap.appendChild(overlay);

  try {
    const { url } = await uploadToBlossom(file, signupState);
    if (which === 'pfp') signupState.pfpUrl = url;
    else signupState.bannerUrl = url;
    overlay.remove();
  } catch (err) {
    overlay.textContent = 'Upload failed';
    setTimeout(() => {
      preview.remove();
      overlay.remove();
      if (placeholder) placeholder.style.display = '';
      wrap.classList.remove('has-image');
      URL.revokeObjectURL(objectUrl);
    }, 2000);
  }
}

async function wizardStep2Submit() {
  const name = document.getElementById('wizard-name').value.trim();
  if (!name) {
    document.getElementById('wizard-name').focus();
    document.getElementById('wizard-name').reportValidity?.();
    return;
  }

  signupState.name = name.toLowerCase().replace(/\s+/g, '');
  signupState.displayName = document.getElementById('wizard-display-name').value.trim();
  signupState.about = document.getElementById('wizard-about').value.trim();
  signupState.lud16 = document.getElementById('wizard-lud16').value.trim();
  signupState.website = document.getElementById('wizard-website').value.trim();

  wizardGoToStep(3);
  await wizardPublishAll();
}

function markWizardProgress(task, status) {
  const li = document.querySelector(`.wizard-progress li[data-task="${task}"]`);
  if (!li) return;
  li.classList.remove('active', 'done', 'failed');
  if (status) li.classList.add(status);
  const icon = li.querySelector('.wizard-progress-icon');
  if (icon) {
    if (status === 'done') icon.textContent = '✓';
    else if (status === 'failed') icon.textContent = '!';
    else if (status === 'active') icon.textContent = '…';
    else icon.textContent = '○';
  }
}

async function wizardPublishAll() {
  // Activate the new signer immediately so the rest of the page treats them as signed in
  activeSigner = {
    pubkey: signupState.pubkey,
    kind: 'nsec',
    signEvent: signupState.signEvent,
  };

  // Resolve which relays this user will write to
  let userRelays = config.fallbackRelays;
  let userDMRelays = config.fallbackDMRelays;
  if (relayTemplateHex) {
    try {
      const tmpl = await fetchRelayTemplate();
      if (tmpl.read?.length) userRelays = tmpl.read;
      if (tmpl.dm?.length) userDMRelays = tmpl.dm;
    } catch {
      // fall back silently
    }
  }

  // Always also publish to the site's relay set so the meetup can see the new user
  const publishTo = [...new Set([...userRelays, ...config.relays])];

  const now = () => Math.floor(Date.now() / 1000);
  let anyFailed = false;

  // ----- Kind 0: profile -----
  markWizardProgress('profile', 'active');
  try {
    const profile = {
      name: signupState.name,
      ...(signupState.displayName && { display_name: signupState.displayName }),
      ...(signupState.about && { about: signupState.about }),
      ...(signupState.lud16 && { lud16: signupState.lud16 }),
      ...(signupState.website && { website: signupState.website }),
      ...(signupState.pfpUrl && { picture: signupState.pfpUrl }),
      ...(signupState.bannerUrl && { banner: signupState.bannerUrl }),
    };
    const event = await signupState.signEvent({
      kind: 0,
      created_at: now(),
      content: JSON.stringify(profile),
      tags: [['client', 'westernmassbitcoin']],
    });
    await publishOrThrow(publishTo, event);
    markWizardProgress('profile', 'done');
    profiles.set(signupState.pubkey, profile);
  } catch (err) {
    anyFailed = true;
    markWizardProgress('profile', 'failed');
  }

  // ----- Kind 10002: outbox relays -----
  markWizardProgress('relays', 'active');
  try {
    const event = await signupState.signEvent({
      kind: 10002,
      created_at: now(),
      content: '',
      tags: [
        ...userRelays.map(r => ['r', r]),
        ['client', 'westernmassbitcoin'],
      ],
    });
    await publishOrThrow(publishTo, event);
    markWizardProgress('relays', 'done');
  } catch (err) {
    anyFailed = true;
    markWizardProgress('relays', 'failed');
  }

  // ----- Kind 10050: DM inbox relays -----
  markWizardProgress('dmrelays', 'active');
  try {
    const event = await signupState.signEvent({
      kind: 10050,
      created_at: now(),
      content: '',
      tags: [
        ...userDMRelays.map(r => ['relay', r]),
        ['client', 'westernmassbitcoin'],
      ],
    });
    await publishOrThrow(publishTo, event);
    markWizardProgress('dmrelays', 'done');
  } catch (err) {
    anyFailed = true;
    markWizardProgress('dmrelays', 'failed');
  }

  // ----- Kind 3: contacts (whitelist + meetup) -----
  markWizardProgress('contacts', 'active');
  try {
    const contacts = new Set();
    whitelistHex.forEach(p => contacts.add(p));
    if (meetupHex) contacts.add(meetupHex);
    // Don't include the user's own pubkey in their follow list
    contacts.delete(signupState.pubkey);

    const event = await signupState.signEvent({
      kind: 3,
      created_at: now(),
      content: '',
      tags: [
        ...[...contacts].map(p => ['p', p]),
        ['client', 'westernmassbitcoin'],
      ],
    });
    await publishOrThrow(publishTo, event);
    markWizardProgress('contacts', 'done');
  } catch (err) {
    anyFailed = true;
    markWizardProgress('contacts', 'failed');
  }

  // Reveal final card
  const errBox = document.getElementById('wizard-error');
  if (anyFailed) {
    errBox.style.display = 'block';
    errBox.textContent = 'Some steps couldn\'t reach every relay. Your account still works — you can try again from another Nostr client later.';
  }
  document.getElementById('wizard-final').style.display = 'block';
}

async function publishOrThrow(relays, event) {
  const results = await Promise.allSettled(pool.publish(relays, event));
  const ok = results.filter(r => r.status === 'fulfilled').length;
  if (ok === 0) throw new Error('No relays accepted the event.');
}

function fetchRelayTemplate() {
  return new Promise((resolve) => {
    if (!relayTemplateHex) return resolve({ read: null, dm: null });
    let kind10002 = null;
    let kind10050 = null;

    const finalize = () => {
      const read = kind10002
        ? kind10002.tags.filter(t => t[0] === 'r' && /^wss?:\/\//.test(t[1] || '')).map(t => t[1])
        : null;
      const dm = kind10050
        ? kind10050.tags.filter(t => t[0] === 'relay' && /^wss?:\/\//.test(t[1] || '')).map(t => t[1])
        : null;
      resolve({ read, dm });
    };

    const sub = pool.subscribeMany(
      config.relays,
      [{ kinds: [10002, 10050], authors: [relayTemplateHex] }],
      {
        onevent(event) {
          if (event.kind === 10002 && (!kind10002 || event.created_at > kind10002.created_at)) kind10002 = event;
          if (event.kind === 10050 && (!kind10050 || event.created_at > kind10050.created_at)) kind10050 = event;
        },
        oneose() {
          sub.close();
          finalize();
        }
      }
    );
    setTimeout(() => {
      sub.close();
      finalize();
    }, 5000);
  });
}

function wizardFinish() {
  cfCloseModal('signup-modal');
  renderUserChip();
  // Reset wizard so re-opening starts fresh
  setTimeout(resetWizard, 400);
}

function resetWizard() {
  signupState = null;
  document.getElementById('wizard-keygen-pre').style.display = '';
  document.getElementById('wizard-keygen-post').style.display = 'none';
  document.getElementById('wizard-saved-checkbox').checked = false;
  document.getElementById('wizard-step1-next').disabled = true;
  ['wizard-name', 'wizard-display-name', 'wizard-about', 'wizard-lud16', 'wizard-website'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.value = '';
  });
  document.querySelectorAll('#wizard-pfp-pick img, #wizard-banner-pick img').forEach(el => el.remove());
  document.querySelectorAll('.wizard-pfp-placeholder, .wizard-banner-placeholder').forEach(el => el.style.display = '');
  document.getElementById('wizard-pfp-pick').classList.remove('has-image');
  document.getElementById('wizard-banner-pick').classList.remove('has-image');
  document.querySelectorAll('.wizard-progress li').forEach(li => {
    li.classList.remove('active', 'done', 'failed');
    const icon = li.querySelector('.wizard-progress-icon');
    if (icon) icon.textContent = '○';
  });
  document.getElementById('wizard-final').style.display = 'none';
  document.getElementById('wizard-error').style.display = 'none';
  wizardGoToStep(1);
}
