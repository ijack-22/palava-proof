/**
 * Palava Proof — sw.js
 * Service Worker: caches the app for offline use
 */

const CACHE_NAME = 'palava-proof-v1';

// Files to cache on install (the app shell)
const STATIC_ASSETS = [
  '/',
  '/index.html',
  '/styles.css',
  '/app.js',
  '/manifest.json',
  '/icons/icon-192.png',
  '/icons/icon-512.png',
];

// ── Install: cache all static assets ──────────────────────
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => cache.addAll(STATIC_ASSETS))
      .then(() => self.skipWaiting())
  );
});

// ── Activate: delete old caches ────────────────────────────
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then(keys =>
      Promise.all(
        keys
          .filter(key => key !== CACHE_NAME)
          .map(key => caches.delete(key))
      )
    ).then(() => self.clients.claim())
  );
});

// ── Fetch: serve from cache, fall back to network ──────────
self.addEventListener('fetch', (event) => {
  const { request } = event;
  const url = new URL(request.url);

  // For API calls — always try network first, no caching
  if (url.pathname.startsWith('/api/')) {
    event.respondWith(
      fetch(request)
        .catch(() => new Response(
          JSON.stringify({
            is_scam: false,
            confidence: 0,
            warnings: [],
            tips: ['You are offline. Connect to the internet for full scam detection.'],
            _offline: true,
          }),
          { headers: { 'Content-Type': 'application/json' } }
        ))
    );
    return;
  }

  // For everything else — cache first, fall back to network
  event.respondWith(
    caches.match(request)
      .then(cached => cached || fetch(request).then(response => {
        // Cache new static assets we haven't seen before
        if (response.ok && request.method === 'GET') {
          const clone = response.clone();
          caches.open(CACHE_NAME).then(cache => cache.put(request, clone));
        }
        return response;
      }))
      .catch(() => {
        // Offline fallback for navigation requests
        if (request.mode === 'navigate') {
          return caches.match('/index.html');
        }
      })
  );
});
