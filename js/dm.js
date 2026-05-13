/* ============================================================
   NIP-17 protocol module
   ============================================================
   Pure protocol — no DOM, no globals. Consumes a `signer` object
   shaped like classifieds.js's activeSigner, but with NIP-44
   methods attached:
     {
       pubkey,                                 // hex
       signEvent(unsignedEvent) -> signed,     // sign as the real user
       nip44Encrypt(peerPk, plaintext) -> ciphertext,
       nip44Decrypt(peerPk, ciphertext) -> plaintext,
     }

   Spec: NIP-17 (chat over gift-wrapped seals, NIP-44 v2 encryption).
     - kind 14: unsigned rumor (chat message). NEVER published.
     - kind 13: seal. Encrypts rumor JSON to recipient with sender's
       real key. Signed by sender. Has no tags (privacy).
     - kind 1059: gift wrap. Encrypts seal JSON to recipient with a
       fresh ephemeral key. Signed by the ephemeral key. Recipient
       is named in a single `p` tag.

   Sending: build rumor -> seal -> wrap, send wrap to recipient's
   kind-10050 relays. Build a SECOND seal+wrap targeting yourself
   (same rumor) so the message also lands in your own inbox for
   cross-device visibility — this is the standard NIP-17 pattern.
   ============================================================ */

import {
  generateSecretKey,
  getPublicKey,
  getEventHash,
  finalizeEvent,
} from 'https://esm.sh/nostr-tools@2.7.2';
import * as nip44 from 'https://esm.sh/nostr-tools@2.7.2/nip44';

const KIND_CHAT = 14;
const KIND_SEAL = 13;
const KIND_GIFT_WRAP = 1059;

// Per NIP-59: gift-wrap and seal timestamps must be randomized within
// the past two days to obscure metadata. Same window applies to seals.
const TWO_DAYS = 2 * 24 * 60 * 60;

function randomPastTimestamp() {
  const now = Math.floor(Date.now() / 1000);
  return now - Math.floor(Math.random() * TWO_DAYS);
}

// ============================================================
// NIP-44 adapters
// ============================================================
// Build an nsec-style nip44 adapter given the raw secret key bytes.
// Used by classifieds.js when constructing the activeSigner.
export function nip44AdapterFromSecretKey(secretKey) {
  return {
    supportsNip44: true,
    encrypt: async (peerPk, plaintext) => {
      const ck = nip44.v2.utils.getConversationKey(secretKey, peerPk);
      return nip44.v2.encrypt(plaintext, ck);
    },
    decrypt: async (peerPk, ciphertext) => {
      const ck = nip44.v2.utils.getConversationKey(secretKey, peerPk);
      return nip44.v2.decrypt(ciphertext, ck);
    },
  };
}

// NIP-07 (browser extension). Modern extensions (Alby, nos2x, keys.band)
// expose window.nostr.nip44.{encrypt,decrypt}. Older ones don't.
export function nip44AdapterFromNip07() {
  const supported = !!(window.nostr?.nip44?.encrypt && window.nostr?.nip44?.decrypt);
  return {
    supportsNip44: supported,
    encrypt: async (peerPk, plaintext) => {
      if (!supported) throw new Error('Your Nostr extension does not support NIP-44 (needed for DMs). Update Alby/nos2x/keys.band, or sign in with a different method.');
      return window.nostr.nip44.encrypt(peerPk, plaintext);
    },
    decrypt: async (peerPk, ciphertext) => {
      if (!supported) throw new Error('Your Nostr extension does not support NIP-44.');
      return window.nostr.nip44.decrypt(peerPk, ciphertext);
    },
  };
}

// NIP-46 (remote signer). nostr-tools BunkerSigner exposes
// nip44Encrypt / nip44Decrypt directly.
export function nip44AdapterFromBunker(bunkerSigner) {
  return {
    supportsNip44: true,
    encrypt: async (peerPk, plaintext) => bunkerSigner.nip44Encrypt(peerPk, plaintext),
    decrypt: async (peerPk, ciphertext) => bunkerSigner.nip44Decrypt(peerPk, ciphertext),
  };
}

// ============================================================
// Build a rumor (unsigned kind 14)
// ============================================================
// `extraTags` lets callers attach NIP-10 reply tags etc. Caller is
// responsible for the `p` tag for the recipient (we add it here).
function buildRumor({ senderPk, recipientPk, content, extraTags = [] }) {
  const rumor = {
    pubkey: senderPk,
    created_at: Math.floor(Date.now() / 1000),
    kind: KIND_CHAT,
    tags: [
      ['p', recipientPk],
      ...extraTags,
    ],
    content,
  };
  rumor.id = getEventHash(rumor);
  return rumor;
}

// ============================================================
// Wrap a rumor for one recipient (returns a signed gift wrap)
// ============================================================
// Steps:
//   1. seal = sign(kind 13 with content = nip44(rumor, sender->recipient))
//   2. wrap = sign(kind 1059 with content = nip44(seal, ephemeral->recipient))
//      pubkey = derived from a fresh ephemeral key
async function wrapForRecipient({ signer, rumor, recipientPk }) {
  // 1. Seal.
  const sealCiphertext = await signer.nip44Encrypt(recipientPk, JSON.stringify(rumor));
  const unsignedSeal = {
    kind: KIND_SEAL,
    pubkey: signer.pubkey,
    created_at: randomPastTimestamp(),
    tags: [],
    content: sealCiphertext,
  };
  const seal = await signer.signEvent(unsignedSeal);

  // 2. Gift wrap, signed by a fresh ephemeral key.
  const ephemeralSk = generateSecretKey();
  // nip44 v2 conversation key is computed from raw sk bytes + peer hex pk
  const ck = nip44.v2.utils.getConversationKey(ephemeralSk, recipientPk);
  const wrapCiphertext = nip44.v2.encrypt(JSON.stringify(seal), ck);

  const wrap = finalizeEvent({
    kind: KIND_GIFT_WRAP,
    created_at: randomPastTimestamp(),
    tags: [['p', recipientPk]],
    content: wrapCiphertext,
  }, ephemeralSk);

  return wrap;
}

// ============================================================
// Public: build a pair of gift wraps for sending one chat message
// ============================================================
// Returns { wrapForRecipient, wrapForSelf, rumor }. Caller chooses
// which relays to publish each wrap to (recipient's kind-10050 vs
// the sender's own kind-10050).
export async function buildGiftWraps({ signer, recipientPk, content, extraTags = [] }) {
  if (!signer.nip44Encrypt) throw new Error('Signer missing NIP-44 support.');

  const rumor = buildRumor({
    senderPk: signer.pubkey,
    recipientPk,
    content,
    extraTags,
  });

  const [wrapForRecipient_, wrapForSelf] = await Promise.all([
    wrapForRecipient({ signer, rumor, recipientPk }),
    wrapForRecipient({ signer, rumor, recipientPk: signer.pubkey }),
  ]);

  return { wrapForRecipient: wrapForRecipient_, wrapForSelf, rumor };
}

// ============================================================
// Public: unwrap an inbound gift wrap into a rumor
// ============================================================
// Returns { rumor, senderPubkey } on success, or null on any failure
// (bad ciphertext, wrong kind, sender mismatch). We never throw on
// individual wraps — the inbox stream is best-effort by design.
export async function unwrapGiftWrap({ signer, giftWrap }) {
  if (giftWrap.kind !== KIND_GIFT_WRAP) return null;

  let sealJson;
  try {
    sealJson = await signer.nip44Decrypt(giftWrap.pubkey, giftWrap.content);
  } catch {
    return null;
  }

  let seal;
  try { seal = JSON.parse(sealJson); } catch { return null; }
  if (!seal || seal.kind !== KIND_SEAL || typeof seal.content !== 'string' || typeof seal.pubkey !== 'string') {
    return null;
  }

  let rumorJson;
  try {
    rumorJson = await signer.nip44Decrypt(seal.pubkey, seal.content);
  } catch {
    return null;
  }

  let rumor;
  try { rumor = JSON.parse(rumorJson); } catch { return null; }
  if (!rumor || rumor.kind !== KIND_CHAT || typeof rumor.content !== 'string') return null;

  // NIP-17: rumor.pubkey MUST match seal.pubkey. The rumor is unsigned,
  // so this check is the only thing tying the inner message to a real
  // sender — without it, anyone could spoof a sender field.
  if (rumor.pubkey !== seal.pubkey) return null;

  return { rumor, senderPubkey: seal.pubkey };
}

// ============================================================
// Public: subscribe to your gift-wrap inbox
// ============================================================
// Long-lived. `onWrap` is called once per kind-1059 event addressed
// to you. The caller does the unwrap (which is async + may want to
// dedupe + cache). Returns the subscription so callers can close it.
export function subscribeInbox({ pool, relays, myPubkey, onWrap, onEose, since }) {
  const filter = {
    kinds: [KIND_GIFT_WRAP],
    '#p': [myPubkey],
  };
  if (since) filter.since = since;

  return pool.subscribeMany(relays, [filter], {
    onevent(event) { onWrap(event); },
    oneose() { onEose?.(); },
  });
}

// ============================================================
// Helper exports for callers
// ============================================================
export const DM_KINDS = {
  CHAT: KIND_CHAT,
  SEAL: KIND_SEAL,
  GIFT_WRAP: KIND_GIFT_WRAP,
};
