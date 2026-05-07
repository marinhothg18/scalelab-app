// Service Worker do Axcend — Fase 1 (PWA instalável, sem push ainda)
// Cache leve de shell + estratégia "network-first" pra HTML (sempre busca novo, fallback cache)
const CACHE_NAME = 'axcend-v1';
const SHELL = [
  '/',
  '/ScaleLab.html',
  '/manifest.json',
  '/icon-192.png',
  '/icon-512.png',
  '/apple-touch-icon.png'
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(SHELL).catch(() => {}))
  );
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) => Promise.all(
      keys.filter((k) => k !== CACHE_NAME).map((k) => caches.delete(k))
    ))
  );
  self.clients.claim();
});

self.addEventListener('fetch', (event) => {
  const req = event.request;
  // Só GET. POST/PUT/DELETE passam direto pra rede.
  if (req.method !== 'GET') return;
  // /api/* sempre rede (dados em tempo real, nunca cache)
  if (req.url.includes('/api/')) return;
  // Stream SSE: deixa passar
  if (req.url.includes('/sync/stream')) return;

  // HTML/page: network-first com fallback pro cache
  if (req.destination === 'document' || req.url.endsWith('.html')) {
    event.respondWith(
      fetch(req).then((r) => {
        const copy = r.clone();
        caches.open(CACHE_NAME).then((c) => c.put(req, copy)).catch(() => {});
        return r;
      }).catch(() => caches.match(req))
    );
    return;
  }

  // Assets (icone, css externo): cache-first
  event.respondWith(
    caches.match(req).then((cached) => {
      if (cached) return cached;
      return fetch(req).then((r) => {
        if (r.ok && r.type === 'basic') {
          const copy = r.clone();
          caches.open(CACHE_NAME).then((c) => c.put(req, copy)).catch(() => {});
        }
        return r;
      });
    })
  );
});
