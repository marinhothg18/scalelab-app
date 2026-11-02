// Service Worker da TMX Digital — PWA instalável + aviso de venda (push)
// v2 (novo design 2026): bumpou cache pra invalidar versões antigas
const CACHE_NAME = 'tmx-v4';
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

// Aviso de venda: chega mesmo com o app fechado. O iPhone exige mostrar uma
// notificação a cada push, então isso nunca sai sem mostrar.
self.addEventListener('push', (event) => {
  let d = {};
  try { d = event.data ? event.data.json() : {}; } catch (e) {}
  event.waitUntil(self.registration.showNotification(d.titulo || 'TMX Digital', {
    body: d.corpo || '', icon: '/icon-192.png', badge: '/icon-192.png', tag: d.tag
  }));
});

// Tocou no aviso: traz o app pra frente, ou abre se estiver fechado
self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  event.waitUntil(self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then((abertas) => {
    for (const c of abertas) { if ('focus' in c) return c.focus(); }
    return self.clients.openWindow('/ScaleLab.html');
  }));
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
