/* ============================================================
   DM panel (UI shell)
   ============================================================
   Left slide-out panel for NIP-17 chat. Mounts its own DOM under
   <body>. Activates once a signer is available and the caller has
   fetched the user's own kind-10050 DM relays.

   Public API:
     mountDmPanelDOM()           — call once on page load
     activateDmPanel(ctx)        — call after login
     deactivateDmPanel()         — call on sign out
     openDmPanel()               — programmatic open
     openDmThreadWith(peerPk)    — open panel + jump to thread

   Wiring of WoT (Primary vs Requests) is on the caller:
     ctx.isApproved(peerPubkey) -> bool
   ============================================================ */

import { nip19 } from 'https://esm.sh/nostr-tools@2.7.2';
import { buildGiftWraps, unwrapGiftWrap, subscribeInbox } from './dm.js';
import { openDmCache } from './dm-cache.js';

// ============================================================
// Module state (single panel per page)
// ============================================================
let mounted = false;
let active = false;
let ctx = null;
let cache = null;
let inboxSub = null;
let openPeer = null;            // pubkey of currently-open thread, or null
let panelIsOpen = false;
let unseenWrapBuffer = [];      // wraps that arrived before activation completed
let pendingOpenPeer = null;     // openDmThreadWith() called before activation — dispatched on activate
let pendingOpenPanel = false;   // openDmPanel() called before activation — same

// DOM refs
let elPanel, elFab, elFabBadge, elBody, elOnboardingSlot, elListWrap, elThreadWrap, elTabs;
let originalTitle = document.title;
let titleFlashTimer = null;
let faviconDirty = false;

// Last-read timestamps per peer, persisted in localStorage so they
// survive a refresh (small, non-sensitive data — IDB would be overkill).
function lastReadKey(peerPk) {
  return `wmb-dm-lastread:${ctx?.signer?.pubkey || 'anon'}:${peerPk}`;
}
function getLastRead(peerPk) {
  const v = localStorage.getItem(lastReadKey(peerPk));
  return v ? +v : 0;
}
function setLastRead(peerPk, t) {
  localStorage.setItem(lastReadKey(peerPk), String(t));
}

// ============================================================
// DOM scaffolding
// ============================================================
export function mountDmPanelDOM() {
  if (mounted) return;
  mounted = true;

  // Floating action button (bottom-left, only visible when activated)
  elFab = document.createElement('button');
  elFab.id = 'dm-fab';
  elFab.className = 'dm-fab';
  elFab.setAttribute('aria-label', 'Open messages');
  elFab.style.display = 'none';
  elFab.innerHTML = `
    <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
      <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"></path>
    </svg>
    <span class="dm-fab-label">Messages</span>
    <span class="dm-fab-badge" id="dm-fab-badge" hidden>0</span>
  `;
  elFab.addEventListener('click', () => panelIsOpen ? closePanel() : openPanel());
  document.body.appendChild(elFab);
  elFabBadge = elFab.querySelector('#dm-fab-badge');

  // Panel
  elPanel = document.createElement('aside');
  elPanel.id = 'dm-panel';
  elPanel.className = 'dm-panel';
  elPanel.setAttribute('role', 'dialog');
  elPanel.setAttribute('aria-label', 'Direct messages');
  elPanel.innerHTML = `
    <div class="dm-panel-header">
      <h3>Messages</h3>
      <button class="dm-panel-close" aria-label="Close messages">×</button>
    </div>
    <div class="dm-panel-onboarding" id="dm-panel-onboarding" hidden></div>
    <div class="dm-panel-tabs" id="dm-panel-tabs" hidden>
      <button class="dm-tab active" data-tab="primary">Primary</button>
      <button class="dm-tab" data-tab="requests">Requests <span class="dm-tab-count" id="dm-tab-count-requests"></span></button>
    </div>
    <div class="dm-panel-body" id="dm-panel-body">
      <div class="dm-list" id="dm-list"></div>
      <div class="dm-thread" id="dm-thread" hidden></div>
    </div>
  `;
  document.body.appendChild(elPanel);

  elBody = elPanel.querySelector('#dm-panel-body');
  elOnboardingSlot = elPanel.querySelector('#dm-panel-onboarding');
  elListWrap = elPanel.querySelector('#dm-list');
  elThreadWrap = elPanel.querySelector('#dm-thread');
  elTabs = elPanel.querySelector('#dm-panel-tabs');

  elPanel.querySelector('.dm-panel-close').addEventListener('click', closePanel);
  elTabs.querySelectorAll('.dm-tab').forEach(btn => {
    btn.addEventListener('click', () => {
      elTabs.querySelectorAll('.dm-tab').forEach(t => t.classList.toggle('active', t === btn));
      renderList();
    });
  });

  // Click-outside closes panel
  document.addEventListener('click', (e) => {
    if (!panelIsOpen) return;
    if (elPanel.contains(e.target)) return;
    if (elFab.contains(e.target)) return;
    closePanel();
  });
  document.addEventListener('keydown', (e) => {
    if (panelIsOpen && e.key === 'Escape') closePanel();
  });
}

// ============================================================
// Activation / deactivation
// ============================================================
// ctx = {
//   pool,                             SimplePool from classifieds.js
//   signer,                           activeSigner with nip44Encrypt/Decrypt
//   profiles,                         shared kind-0 cache (Map)
//   fetchProfiles(pubkeys),           shared profile fetcher
//   ownDmRelays,                      string[] — user's kind-10050 relays
//   getDmRelaysFor(pubkey),           lookup peer's DM relays
//   isApproved(peerPubkey),           true if Primary, false if Requests
//   onSentMessageTo(peerPubkey),      called after a successful send (caller persists if needed)
//   onUnreadCountChange(count),       optional: notify caller when total unread changes
// }
export async function activateDmPanel(newCtx) {
  if (active) deactivateDmPanel();
  ctx = newCtx;

  if (!ctx.signer?.supportsNip44) {
    // Show panel button but with onboarding-like message
    renderUnsupportedSignerState();
    elFab.style.display = '';
    active = true;
    return;
  }

  try {
    cache = await openDmCache(ctx.signer.pubkey);
  } catch (err) {
    console.error('[dm] failed to open IDB cache; messages will not persist this session', err);
    cache = null;
  }

  active = true;
  elFab.style.display = '';

  renderOnboarding();
  renderList();

  if (cache) {
    // Pre-fetch profiles for all known peers so the list renders nicely.
    const peers = new Set();
    cache.getAllMessages().forEach(m => peers.add(m.peerPubkey));
    if (peers.size) ctx.fetchProfiles([...peers]);
  }

  await startInboxSubscription();
  // Drain any wraps that landed before activation finished
  if (unseenWrapBuffer.length) {
    const buffered = unseenWrapBuffer;
    unseenWrapBuffer = [];
    for (const wrap of buffered) handleWrap(wrap);
  }

  refreshUnreadIndicator();

  // Dispatch any open requests that arrived before activation finished —
  // most commonly: user clicked Message Seller during the brief post-login
  // (or session-restore) window when the panel was still spinning up.
  if (pendingOpenPeer) {
    const peer = pendingOpenPeer;
    pendingOpenPeer = null;
    openPanel();
    openThread(peer);
  } else if (pendingOpenPanel) {
    pendingOpenPanel = false;
    openPanel();
  }
}

export function deactivateDmPanel() {
  if (!active) return;
  active = false;

  try { inboxSub?.close(); } catch {}
  inboxSub = null;

  try { cache?.close(); } catch {}
  cache = null;

  pendingOpenPeer = null;
  pendingOpenPanel = false;

  ctx = null;
  openPeer = null;
  panelIsOpen = false;
  elPanel?.classList.remove('open');
  if (elFab) elFab.style.display = 'none';
  clearTitleFlash();
}

export function openDmPanel() {
  if (!active) {
    // Panel is still activating (e.g. just-restored session). Queue so we
    // open as soon as activation finishes.
    pendingOpenPanel = true;
    return;
  }
  openPanel();
}

export function openDmThreadWith(peerPubkey) {
  if (!active) {
    pendingOpenPeer = peerPubkey;
    return;
  }
  openPanel();
  openThread(peerPubkey);
}

// ============================================================
// Panel open/close
// ============================================================
function openPanel() {
  panelIsOpen = true;
  elPanel.classList.add('open');
  elFab.style.display = 'none';  // Panel covers where the FAB sits; hide to avoid overlap
  clearTitleFlash();
  // If we were on a thread, mark messages there as read
  if (openPeer) markThreadRead(openPeer);
  refreshUnreadIndicator();
}
function closePanel() {
  panelIsOpen = false;
  elPanel.classList.remove('open');
  if (active) elFab.style.display = '';
  // Stay on whatever view was last open; reset to list on next open is not needed
}

// ============================================================
// Onboarding card (no kind-10050 yet)
// ============================================================
function renderOnboarding() {
  if (!ctx?.getOnboardingState) {
    elOnboardingSlot.hidden = true;
    return;
  }
  const state = ctx.getOnboardingState();
  if (!state || !state.needsOnboarding) {
    elOnboardingSlot.hidden = true;
    elOnboardingSlot.innerHTML = '';
    return;
  }

  elOnboardingSlot.hidden = false;
  elOnboardingSlot.innerHTML = `
    <div class="dm-onboarding-card">
      <strong>Turn on Nostr DMs</strong>
      <p>To send and receive messages here, publish a small <code>kind:10050</code> event telling the network where your DMs should be delivered.</p>
      <ul class="dm-onboarding-relays"></ul>
      <button class="btn btn-orange" id="dm-onboarding-go">Publish DM relays</button>
      <div class="dm-onboarding-status" id="dm-onboarding-status"></div>
    </div>
  `;
  const ul = elOnboardingSlot.querySelector('.dm-onboarding-relays');
  state.relays.forEach(r => {
    const li = document.createElement('li');
    li.textContent = r;
    ul.appendChild(li);
  });
  const go = elOnboardingSlot.querySelector('#dm-onboarding-go');
  const status = elOnboardingSlot.querySelector('#dm-onboarding-status');
  go.addEventListener('click', async () => {
    go.disabled = true;
    status.textContent = 'Publishing…';
    try {
      await state.publish();
      status.textContent = 'Published. Reloading the panel…';
      // Caller will trigger a refresh that re-renders onboarding
    } catch (err) {
      status.textContent = 'Failed: ' + (err.message || err);
      go.disabled = false;
    }
  });
}

// Called by caller after onboarding succeeds + ownDmRelays is updated
export function refreshOnboarding() {
  if (!active) return;
  renderOnboarding();
}

function renderUnsupportedSignerState() {
  elOnboardingSlot.hidden = false;
  elOnboardingSlot.innerHTML = `
    <div class="dm-onboarding-card">
      <strong>Signer doesn't support NIP-44</strong>
      <p>Your current sign-in method can't encrypt DMs. Try signing in with a newer browser extension (Alby, nos2x, keys.band), a remote signer, or by pasting your nsec.</p>
    </div>
  `;
  elListWrap.hidden = true;
  elThreadWrap.hidden = true;
  elTabs.hidden = true;
}

// ============================================================
// Inbox subscription
// ============================================================
const SINCE_BUFFER = 3 * 24 * 60 * 60;   // 3 days, covers the ±2d randomization

async function startInboxSubscription() {
  if (!ctx?.ownDmRelays?.length) {
    // Without our own 10050, we can't usefully subscribe — onboarding card
    // is doing the work of nudging the user.
    return;
  }

  let since = 0;
  if (cache) {
    const hwm = cache.getHighWaterMark();
    if (hwm > 0) since = Math.max(0, hwm - SINCE_BUFFER);
  }

  inboxSub = subscribeInbox({
    pool: ctx.pool,
    relays: ctx.ownDmRelays,
    myPubkey: ctx.signer.pubkey,
    since,
    onWrap: (wrap) => handleWrap(wrap),
  });
}

async function handleWrap(wrap) {
  if (!active || !cache) {
    unseenWrapBuffer.push(wrap);
    return;
  }
  if (cache.hasSeenWrap(wrap.id)) return;
  await cache.markWrapSeen(wrap.id, wrap.created_at);
  await cache.setHighWaterMark(wrap.created_at);

  const unwrapped = await unwrapGiftWrap({ signer: ctx.signer, giftWrap: wrap });
  if (!unwrapped) return;

  const { rumor, senderPubkey } = unwrapped;
  const recipientPubkey = (rumor.tags.find(t => t[0] === 'p') || [])[1];
  if (!recipientPubkey) return;

  // peer = the other party in the conversation
  const myPk = ctx.signer.pubkey;
  const peerPubkey = senderPubkey === myPk ? recipientPubkey : senderPubkey;

  const msg = {
    id: rumor.id,
    senderPubkey,
    recipientPubkey,
    peerPubkey,
    created_at: rumor.created_at,
    content: rumor.content,
    tags: rumor.tags,
  };

  const inserted = await cache.putMessage(msg);
  if (!inserted) return;

  // Fetch the peer's profile if we don't have it
  if (!ctx.profiles.has(peerPubkey)) ctx.fetchProfiles([peerPubkey]);

  // Re-render whichever view is showing
  if (openPeer === peerPubkey) renderThread(peerPubkey);
  renderList();

  // Notification surface — only when incoming and panel isn't focused on this convo
  const incoming = senderPubkey !== myPk;
  const visibleInThread = panelIsOpen && openPeer === peerPubkey;
  if (incoming && !visibleInThread) flashTitleAndFavicon();
  refreshUnreadIndicator();
}

// ============================================================
// Conversation list
// ============================================================
function getCurrentTab() {
  const active = elTabs.querySelector('.dm-tab.active');
  return active?.dataset.tab || 'primary';
}

function buildConversations() {
  if (!cache) return [];
  // Group by peer
  const byPeer = new Map();
  for (const m of cache.getAllMessages()) {
    let arr = byPeer.get(m.peerPubkey);
    if (!arr) { arr = []; byPeer.set(m.peerPubkey, arr); }
    arr.push(m);
  }
  const convos = [];
  const myPk = ctx.signer.pubkey;
  for (const [peer, msgs] of byPeer) {
    msgs.sort((a, b) => a.created_at - b.created_at);
    const last = msgs[msgs.length - 1];
    const lastRead = getLastRead(peer);
    const unread = msgs.filter(m => m.senderPubkey !== myPk && m.created_at > lastRead).length;
    convos.push({
      peer,
      last,
      unread,
      approved: ctx.isApproved(peer),
    });
  }
  // Newest activity first
  convos.sort((a, b) => b.last.created_at - a.last.created_at);
  return convos;
}

function renderList() {
  if (!active || !cache) {
    elListWrap.innerHTML = '<div class="dm-empty">Loading…</div>';
    return;
  }

  const convos = buildConversations();
  const primary = convos.filter(c => c.approved);
  const requests = convos.filter(c => !c.approved);

  // Show tabs only if there are any requests
  if (requests.length) {
    elTabs.hidden = false;
    const reqCount = elTabs.querySelector('#dm-tab-count-requests');
    reqCount.textContent = requests.length;
  } else {
    elTabs.hidden = true;
  }

  const tab = getCurrentTab();
  const list = tab === 'requests' ? requests : primary;

  if (!list.length) {
    elListWrap.innerHTML = `<div class="dm-empty">${tab === 'requests' ? 'No message requests.' : 'No conversations yet. Open a listing and click <em>Message Seller</em> to start one.'}</div>`;
    return;
  }

  elListWrap.innerHTML = '';
  for (const c of list) {
    elListWrap.appendChild(renderConvoRow(c));
  }
}

function renderConvoRow(c) {
  const row = document.createElement('button');
  row.className = 'dm-convo-row';
  row.dataset.pubkey = c.peer;
  if (c.unread) row.classList.add('has-unread');

  const profile = ctx.profiles.get(c.peer) || {};
  const name = profile.display_name || profile.name || shortNpubFromHex(c.peer);
  const pic = profile.picture || transparentPx();

  const preview = previewText(c.last);
  const myPk = ctx.signer.pubkey;
  const prefix = c.last.senderPubkey === myPk ? 'You: ' : '';

  row.innerHTML = `
    <img class="dm-convo-avatar" alt="">
    <div class="dm-convo-meta">
      <div class="dm-convo-name"></div>
      <div class="dm-convo-preview"></div>
    </div>
    <div class="dm-convo-aside">
      <div class="dm-convo-time"></div>
      <div class="dm-convo-badge"${c.unread ? '' : ' hidden'}></div>
    </div>
  `;
  row.querySelector('.dm-convo-avatar').src = pic;
  row.querySelector('.dm-convo-name').textContent = name;
  row.querySelector('.dm-convo-preview').textContent = prefix + preview;
  row.querySelector('.dm-convo-time').textContent = timeAgoShort(c.last.created_at);
  if (c.unread) row.querySelector('.dm-convo-badge').textContent = c.unread > 99 ? '99+' : String(c.unread);

  row.addEventListener('click', () => openThread(c.peer));
  return row;
}

function previewText(msg) {
  const max = 80;
  const s = (msg.content || '').replace(/\s+/g, ' ').trim();
  return s.length > max ? s.slice(0, max - 1) + '…' : s;
}

// ============================================================
// Thread view
// ============================================================
function openThread(peerPubkey) {
  openPeer = peerPubkey;
  renderThread(peerPubkey);
  elListWrap.hidden = true;
  elThreadWrap.hidden = false;
  if (panelIsOpen) markThreadRead(peerPubkey);
}

function closeThread() {
  openPeer = null;
  elThreadWrap.hidden = true;
  elListWrap.hidden = false;
  renderList();
  refreshUnreadIndicator();
}

function markThreadRead(peerPubkey) {
  setLastRead(peerPubkey, Math.floor(Date.now() / 1000));
  refreshUnreadIndicator();
}

function renderThread(peerPubkey) {
  const profile = ctx.profiles.get(peerPubkey) || {};
  const name = profile.display_name || profile.name || shortNpubFromHex(peerPubkey);
  const msgs = cache ? cache.getMessagesWithPeer(peerPubkey) : [];
  const myPk = ctx.signer.pubkey;

  const peerHasDMRelays = (ctx.getDmRelaysFor(peerPubkey) || []).length > 0;

  elThreadWrap.innerHTML = `
    <div class="dm-thread-header">
      <button class="dm-thread-back" aria-label="Back to conversation list">←</button>
      <img class="dm-thread-avatar" alt="">
      <div class="dm-thread-id">
        <div class="dm-thread-name"></div>
        <div class="dm-thread-npub"></div>
      </div>
    </div>
    <div class="dm-thread-body" id="dm-thread-body"></div>
    <div class="dm-thread-compose">
      <textarea class="dm-thread-input" placeholder="Write a message…" rows="2"></textarea>
      <button class="btn btn-orange dm-thread-send">Send</button>
      <div class="dm-thread-status" id="dm-thread-status"></div>
    </div>
  `;

  elThreadWrap.querySelector('.dm-thread-avatar').src = profile.picture || transparentPx();
  elThreadWrap.querySelector('.dm-thread-name').textContent = name;
  elThreadWrap.querySelector('.dm-thread-npub').textContent = shortNpubFromHex(peerPubkey);
  elThreadWrap.querySelector('.dm-thread-back').addEventListener('click', closeThread);

  const body = elThreadWrap.querySelector('#dm-thread-body');
  if (!msgs.length) {
    body.innerHTML = '<div class="dm-empty">No messages yet. Say hi.</div>';
  } else {
    for (const m of msgs) {
      const b = document.createElement('div');
      b.className = 'dm-bubble' + (m.senderPubkey === myPk ? ' dm-bubble-mine' : ' dm-bubble-theirs');
      const text = document.createElement('div');
      text.className = 'dm-bubble-text';
      text.textContent = m.content;
      const meta = document.createElement('div');
      meta.className = 'dm-bubble-meta';
      meta.textContent = timeAgoShort(m.created_at);
      b.appendChild(text);
      b.appendChild(meta);
      body.appendChild(b);
    }
    // Scroll to bottom after layout
    requestAnimationFrame(() => { body.scrollTop = body.scrollHeight; });
  }

  const status = elThreadWrap.querySelector('#dm-thread-status');
  const input = elThreadWrap.querySelector('.dm-thread-input');
  const send = elThreadWrap.querySelector('.dm-thread-send');

  if (!peerHasDMRelays) {
    status.textContent = 'This user hasn\'t published NIP-17 DM relays yet — they can\'t receive messages.';
    status.className = 'dm-thread-status error';
    send.disabled = true;
    input.disabled = true;
    return;
  }

  const doSend = async () => {
    const text = input.value.trim();
    if (!text) return;
    send.disabled = true;
    input.disabled = true;
    status.textContent = 'Sending…';
    status.className = 'dm-thread-status';
    try {
      await sendMessage(peerPubkey, text);
      input.value = '';
      status.textContent = '';
    } catch (err) {
      status.textContent = 'Send failed: ' + (err.message || err);
      status.className = 'dm-thread-status error';
    } finally {
      send.disabled = false;
      input.disabled = false;
      input.focus();
    }
  };

  send.addEventListener('click', doSend);
  input.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      doSend();
    }
  });
  input.focus();
}

// ============================================================
// Sending
// ============================================================
async function sendMessage(peerPubkey, content) {
  if (!ctx?.signer?.supportsNip44) throw new Error('Your signer doesn\'t support NIP-44.');
  const peerRelays = ctx.getDmRelaysFor(peerPubkey) || [];
  if (!peerRelays.length) throw new Error('Recipient has no DM relays.');
  const myRelays = ctx.ownDmRelays || [];

  const { wrapForRecipient, wrapForSelf, rumor } = await buildGiftWraps({
    signer: ctx.signer,
    recipientPk: peerPubkey,
    content,
  });

  // Optimistically insert into local cache so the UI updates instantly
  if (cache) {
    await cache.putMessage({
      id: rumor.id,
      senderPubkey: ctx.signer.pubkey,
      recipientPubkey: peerPubkey,
      peerPubkey,
      created_at: rumor.created_at,
      content: rumor.content,
      tags: rumor.tags,
    });
    await cache.addSentTo(peerPubkey);
  }

  // Publish: recipient wrap to peer's relays, self wrap to ours.
  // Don't await aggressively — first ACK is enough for UI feedback.
  const pubs = [
    ...ctx.pool.publish(peerRelays, wrapForRecipient),
    ...(myRelays.length ? ctx.pool.publish(myRelays, wrapForSelf) : []),
  ];
  if (!pubs.length) throw new Error('No relays to publish to.');
  await firstAck(pubs, 8000);

  ctx.onSentMessageTo?.(peerPubkey);
  renderThread(peerPubkey);
  renderList();
  refreshUnreadIndicator();
}

function firstAck(promises, overallMs) {
  return new Promise((resolve, reject) => {
    let done = false;
    let settled = 0;
    const errors = [];
    promises.forEach(p => {
      Promise.resolve(p).then(() => {
        if (done) return;
        done = true;
        resolve();
      }).catch(err => {
        errors.push(err);
      }).finally(() => {
        settled++;
        if (settled === promises.length && !done) {
          done = true;
          reject(new Error('All relays rejected: ' + (errors[0]?.message || 'unknown')));
        }
      });
    });
    setTimeout(() => {
      if (done) return;
      done = true;
      reject(new Error('Publish timed out.'));
    }, overallMs);
  });
}

// ============================================================
// Notifications: tab title flash + favicon dot
// ============================================================
function flashTitleAndFavicon() {
  // Don't flash if the user is already looking at the panel
  if (panelIsOpen) return;
  if (titleFlashTimer) return;

  const flashTitle = '🔔 New message — ' + originalTitle;
  let toggle = false;
  document.title = flashTitle;
  titleFlashTimer = setInterval(() => {
    toggle = !toggle;
    document.title = toggle ? originalTitle : flashTitle;
  }, 1500);

  setFaviconDot(true);

  // Stop flashing on any tab focus / visibility change
  const stop = () => {
    clearTitleFlash();
    document.removeEventListener('visibilitychange', onVis);
    window.removeEventListener('focus', stop);
  };
  const onVis = () => { if (!document.hidden) stop(); };
  document.addEventListener('visibilitychange', onVis);
  window.addEventListener('focus', stop);
}

function clearTitleFlash() {
  if (titleFlashTimer) {
    clearInterval(titleFlashTimer);
    titleFlashTimer = null;
  }
  document.title = originalTitle;
  if (faviconDirty) setFaviconDot(false);
}

function setFaviconDot(on) {
  faviconDirty = on;
  let link = document.querySelector('link[rel="icon"]');
  if (!link) return;
  if (on) {
    if (!link.dataset.dmOriginalHref) link.dataset.dmOriginalHref = link.href;
    link.href = makeDottedFavicon(link.dataset.dmOriginalHref);
  } else if (link.dataset.dmOriginalHref) {
    link.href = link.dataset.dmOriginalHref;
    delete link.dataset.dmOriginalHref;
  }
}

function makeDottedFavicon(srcUrl) {
  // Generate a 32x32 favicon: original icon + orange dot bottom-right.
  // Cross-origin source images may taint the canvas — fall back silently if so.
  try {
    const canvas = document.createElement('canvas');
    canvas.width = 32; canvas.height = 32;
    const ctx2d = canvas.getContext('2d');
    // Draw a transparent base + orange dot only (skip image draw — keeps cross-origin safe)
    ctx2d.fillStyle = '#F7931A';
    ctx2d.beginPath();
    ctx2d.arc(22, 22, 8, 0, Math.PI * 2);
    ctx2d.fill();
    return canvas.toDataURL('image/png');
  } catch {
    return srcUrl;
  }
}

// ============================================================
// Unread indicator (FAB badge)
// ============================================================
function refreshUnreadIndicator() {
  if (!active || !cache) {
    elFabBadge.hidden = true;
    ctx?.onUnreadCountChange?.(0);
    return;
  }
  let count = 0;
  const myPk = ctx.signer.pubkey;
  const byPeer = new Map();
  for (const m of cache.getAllMessages()) {
    if (m.senderPubkey === myPk) continue;
    let arr = byPeer.get(m.peerPubkey);
    if (!arr) { arr = []; byPeer.set(m.peerPubkey, arr); }
    arr.push(m);
  }
  for (const [peer, msgs] of byPeer) {
    const lastRead = getLastRead(peer);
    count += msgs.filter(m => m.created_at > lastRead).length;
  }
  if (count > 0) {
    elFabBadge.hidden = false;
    elFabBadge.textContent = count > 99 ? '99+' : String(count);
  } else {
    elFabBadge.hidden = true;
  }
  ctx.onUnreadCountChange?.(count);
}

// ============================================================
// Helpers
// ============================================================
function shortNpubFromHex(hex) {
  try {
    const npub = nip19.npubEncode(hex);
    return `${npub.slice(0, 10)}…${npub.slice(-4)}`;
  } catch { return hex.slice(0, 10); }
}
function transparentPx() {
  return 'data:image/gif;base64,R0lGODlhAQABAAAAACH5BAEKAAEALAAAAAABAAEAAAICTAEAOw==';
}
function timeAgoShort(unixSec) {
  const s = Math.floor(Date.now() / 1000) - unixSec;
  if (s < 60) return 'now';
  if (s < 3600) return `${Math.floor(s / 60)}m`;
  if (s < 86400) return `${Math.floor(s / 3600)}h`;
  const d = Math.floor(s / 86400);
  if (d < 30) return `${d}d`;
  if (d < 365) return `${Math.floor(d / 30)}mo`;
  return `${Math.floor(d / 365)}y`;
}
