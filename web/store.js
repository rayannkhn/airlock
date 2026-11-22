// Device storage (IndexedDB). Holds this device's identity, its paired contacts,
// and the replay store of transfers already received.
//
// The identity's private keys are non-extractable CryptoKey objects. IndexedDB
// can store them, but no script (including a malicious one) can export their bytes.

const DB_NAME = "airlock";
const DB_VERSION = 1;

function openDb() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      db.createObjectStore("kv");    // "identity" -> identity, "peers" -> [peer]
      db.createObjectStore("used");  // session id (hex) -> timestamp
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function tx(store, mode, fn) {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const t = db.transaction(store, mode);
    const result = fn(t.objectStore(store));
    t.oncomplete = () => { db.close(); resolve(result instanceof IDBRequest ? result.result : result); };
    t.onerror = () => { db.close(); reject(t.error); };
  });
}

export const getIdentity = () => tx("kv", "readonly", (s) => s.get("identity"));
export const saveIdentity = (identity) => tx("kv", "readwrite", (s) => s.put(identity, "identity"));
export async function getPeers() { return (await tx("kv", "readonly", (s) => s.get("peers"))) || []; }
export const savePeers = (peers) => tx("kv", "readwrite", (s) => s.put(peers, "peers"));

export async function isUsed(sidHex) { return (await tx("used", "readonly", (s) => s.get(sidHex))) !== undefined; }
export async function markUsed(sidHex, timestamp) {
  await tx("used", "readwrite", (s) => s.put(timestamp, sidHex));
  // Prune entries older than the replay window: those SEALs are rejected by their timestamp anyway.
  const cutoff = Date.now() / 1000 - 2 * 24 * 3600;
  await tx("used", "readwrite", (s) => {
    const req = s.openCursor();
    req.onsuccess = () => { const c = req.result; if (c) { if (c.value < cutoff) c.delete(); c.continue(); } };
  });
}

/** Wipe everything on this device (new identity, no contacts, empty replay store). */
export function wipe() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.deleteDatabase(DB_NAME);
    req.onsuccess = () => resolve();
    req.onerror = () => reject(req.error);
    req.onblocked = () => resolve();
  });
}
