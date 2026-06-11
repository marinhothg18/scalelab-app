// Service Worker da TMX Digital — Fase 1 (PWA instalável, sem push ainda)
// v2 (novo design 2026): bumpou cache pra invalidar versões antigas
const CACHE_NAME = 'tmx-v3';
const SHELL = [
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

  // HTML/page: network-ONLY (sempre busca novo, não cacheia mais o HTML).
  // Isso evita que o app fique preso em versão antiga depois de deploy.
  if (req.destination === 'document' || req.url.endsWith('.html')) {
    event.respondWith(
      fetch(req).catch(() => caches.match(req) || new Response('Offline', { status: 503 }))
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
