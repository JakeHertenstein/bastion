/**
 * Service Worker for Seed Card PWA
 * 
 * Strategy: Cache-on-install for offline operation
 * - Caches essential files during installation
 * - Network-first for HTML/CSS (always get latest)
 * - Cache-first for static assets (JS, WASM, icons)
 * - No persistent storage - cache cleared on SW update
 * 
 * Version: Update CACHE_NAME when deploying new versions
 */

const CACHE_NAME = 'seedcard-v1';

// Files to cache for offline operation
// NOTE: Keep this list in sync with production build output
const CACHE_FILES = [
  '/',
  '/index.html',
  '/manifest.json',
  '/icons/icon-192.png',
  '/icons/icon-512.png',
  // CSS files
  '/spa-styles.css',
  '/threat-analysis.css',
  '/card-compromise.css',
  '/rfc-legend.css',
  // Argon2 vendor files for offline KDF
  '/vendor/argon2/argon2-bundled.min.js',
  '/vendor/argon2/argon2.wasm',
  '/vendor/argon2/argon2.js',
  '/vendor/argon2/argon2-lib.js',
  // App JavaScript files
  '/app.js',
  '/crypto.js',
  '/generator.js',
  '/router.js',
  '/argon2-loader.js',
  '/argon2-worker.js',
  '/argon2-worker-safe.js',
  // Extracted inline scripts
  '/spa-init.js',
  '/pwa-registration.js',
  '/seed-validation.js',
  // BIP-39 wordlist for validation
  '/assets/bip39-wordlist.js'
];

// Install event - cache essential files
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then((cache) => {
        console.log('[SW] Caching app shell');
        return cache.addAll(CACHE_FILES);
      })
      .then(() => self.skipWaiting())
      .catch((err) => {
        console.error('[SW] Cache install failed:', err);
      })
  );
});

// Activate event - clean up old caches
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys()
      .then((cacheNames) => {
        return Promise.all(
          cacheNames
            .filter((name) => name !== CACHE_NAME)
            .map((name) => {
              console.log('[SW] Deleting old cache:', name);
              return caches.delete(name);
            })
        );
      })
      .then(() => self.clients.claim())
  );
});

// Fetch event - cache first, network fallback
self.addEventListener('fetch', (event) => {
  // Only handle GET requests
  if (event.request.method !== 'GET') {
    return;
  }

  event.respondWith(
    caches.match(event.request)
      .then((cachedResponse) => {
        if (cachedResponse) {
          return cachedResponse;
        }
        
        // Not in cache - fetch from network
        return fetch(event.request)
          .then((response) => {
            // Don't cache non-successful responses
            if (!response || response.status !== 200) {
              return response;
            }
            
            // Clone response for caching
            const responseToCache = response.clone();
            
            caches.open(CACHE_NAME)
              .then((cache) => {
                cache.put(event.request, responseToCache);
              });
            
            return response;
          });
      })
      .catch(() => {
        // Network failed and not in cache
        // Return a basic offline page for navigation requests
        if (event.request.mode === 'navigate') {
          return caches.match('/');
        }
        return new Response('Offline', { status: 503 });
      })
  );
});
