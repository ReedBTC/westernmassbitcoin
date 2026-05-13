/* ============================================================
   DM cache (IndexedDB)
   ============================================================
   Per-account storage of decrypted DMs plus a set of "seen" gift
   wrap ids so we don't re-decrypt the same wrap twice. Gift-wrap
   created_at is randomized within ±2 days for metadata obfuscation,
   so we can't rely on a simple `since` filter for dedup — we need
   wrap-id-level memory.

   One DB per account: `wmb-dm-<ownerPubkey>`. Switching accounts
   uses a different DB, so logging out + back in as someone else
   never mixes plaintext.

   Object stores:
     - wraps:    { id, created_at }   — keyed by wrap id (string)
     - messages: { id, senderPubkey, recipientPubkey, peerPubkey,
                   created_at, content, tags }   — keyed by rumor id
       index: by_peer (peerPubkey + created_at)
     - meta:     simple kv store keyed by string
   ============================================================ */

const DB_VERSION = 1;

function dbName(ownerPubkey) {
  return `wmb-dm-${ownerPubkey}`;
}

function openDb(ownerPubkey) {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(dbName(ownerPubkey), DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains('wraps')) {
        db.createObjectStore('wraps', { keyPath: 'id' });
      }
      if (!db.objectStoreNames.contains('messages')) {
        const store = db.createObjectStore('messages', { keyPath: 'id' });
        store.createIndex('by_peer', ['peerPubkey', 'created_at']);
      }
      if (!db.objectStoreNames.contains('meta')) {
        db.createObjectStore('meta');
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

function tx(db, stores, mode = 'readonly') {
  return db.transaction(stores, mode);
}

function reqPromise(req) {
  return new Promise((resolve, reject) => {
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

export async function openDmCache(ownerPubkey) {
  const db = await openDb(ownerPubkey);

  // Small in-memory mirrors so hot reads (rendering the conversation
  // list, checking dedup) don't hit IDB on every call. IDB is the
  // source of truth — the mirrors are repopulated on open.
  const seenWraps = new Set();
  const messages = new Map();          // rumor id -> message record
  const sentToSet = new Set();
  let highWaterMark = 0;

  // Hydrate.
  {
    const t = tx(db, ['wraps', 'messages', 'meta']);
    const wrapStore = t.objectStore('wraps');
    const msgStore = t.objectStore('messages');
    const metaStore = t.objectStore('meta');

    await Promise.all([
      new Promise((resolve, reject) => {
        const req = wrapStore.openCursor();
        req.onsuccess = () => {
          const c = req.result;
          if (!c) return resolve();
          seenWraps.add(c.value.id);
          c.continue();
        };
        req.onerror = () => reject(req.error);
      }),
      new Promise((resolve, reject) => {
        const req = msgStore.openCursor();
        req.onsuccess = () => {
          const c = req.result;
          if (!c) return resolve();
          messages.set(c.value.id, c.value);
          c.continue();
        };
        req.onerror = () => reject(req.error);
      }),
      reqPromise(metaStore.get('highWaterMark')).then(v => {
        if (typeof v === 'number') highWaterMark = v;
      }),
      reqPromise(metaStore.get('sentTo')).then(v => {
        if (Array.isArray(v)) v.forEach(p => sentToSet.add(p));
      }),
    ]);
  }

  return {
    // ---- Wraps (dedup) ----
    hasSeenWrap(wrapId) { return seenWraps.has(wrapId); },
    async markWrapSeen(wrapId, createdAt) {
      if (seenWraps.has(wrapId)) return;
      seenWraps.add(wrapId);
      const t = tx(db, ['wraps'], 'readwrite');
      await reqPromise(t.objectStore('wraps').put({ id: wrapId, created_at: createdAt }));
    },

    // ---- Messages ----
    // Idempotent: same rumor id seen twice (e.g. self-copy delivered
    // before recipient-copy decrypted) won't duplicate.
    async putMessage(msg) {
      if (messages.has(msg.id)) return false;
      messages.set(msg.id, msg);
      const t = tx(db, ['messages'], 'readwrite');
      await reqPromise(t.objectStore('messages').put(msg));
      return true;
    },
    getAllMessages() {
      return [...messages.values()];
    },
    getMessagesWithPeer(peerPubkey) {
      return [...messages.values()]
        .filter(m => m.peerPubkey === peerPubkey)
        .sort((a, b) => a.created_at - b.created_at);
    },

    // ---- High-water mark (max wrap.created_at observed) ----
    // We subscribe with `since = max(0, highWaterMark - buffer)` so
    // the ±2-day randomization window stays covered.
    getHighWaterMark() { return highWaterMark; },
    async setHighWaterMark(t) {
      if (t <= highWaterMark) return;
      highWaterMark = t;
      const txn = tx(db, ['meta'], 'readwrite');
      await reqPromise(txn.objectStore('meta').put(t, 'highWaterMark'));
    },

    // ---- Sent-to set (Primary filter input) ----
    hasSentTo(pubkey) { return sentToSet.has(pubkey); },
    getSentTo() { return [...sentToSet]; },
    async addSentTo(pubkey) {
      if (sentToSet.has(pubkey)) return;
      sentToSet.add(pubkey);
      const txn = tx(db, ['meta'], 'readwrite');
      await reqPromise(txn.objectStore('meta').put([...sentToSet], 'sentTo'));
    },

    close() { db.close(); },
  };
}
