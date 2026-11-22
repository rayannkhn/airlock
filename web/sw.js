// Service worker: stores every app file on the device at install time, then serves
// them from that cache. After the first visit AirLock works with no network at all.
// Bump CACHE when any app file changes, so devices pick up the new version.
const CACHE = "airlock-v1.0.0";
const FILES = [
  "./", "index.html", "app.css", "app.js", "airlock-core.js", "store.js", "manifest.webmanifest",
  "vendor/qrcode-generator-1.4.4.js", "vendor/jsqr-1.4.0.js",
  "icons/icon-192.png", "icons/icon-512.png", "icons/icon-maskable-512.png",
];

self.addEventListener("install", (event) => {
  event.waitUntil(caches.open(CACHE).then((c) => c.addAll(FILES)).then(() => self.skipWaiting()));
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim()),
  );
});

// Cache first: the installed copy is used even when online. That avoids
// silently running new server code (see the "hosted crypto" note in the report).
self.addEventListener("fetch", (event) => {
  if (event.request.method !== "GET") return;
  event.respondWith(caches.match(event.request, { ignoreSearch: true }).then((hit) => hit || fetch(event.request)));
});
