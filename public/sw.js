// Service Worker da TMX Digital: só o aviso de venda (push).
// Não intercepta a rede de propósito. O registro nunca rodava, por um erro em
// _pwaInit, então o app vinha funcionando sem esse cache. Ligar agora o cache
// antigo faria imagens e scripts ficarem velhos só por causa do aviso.
const CACHE_NAME = 'tmx-v5';

self.addEventListener('install', () => { self.skipWaiting(); });

// Limpa o cache que aparelhos antigos ainda tenham guardado
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((k) => k !== CACHE_NAME).map((k) => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

// Aviso de venda: chega mesmo com o app fechado. O iPhone exige mostrar uma
// notificação a cada push, então isso nunca sai sem mostrar.
self.addEventListener('push', (event) => {
  let d = {};
  try { d = event.data ? event.data.json() : {}; } catch (e) {}
  event.waitUntil(self.registration.showNotification(d.titulo || 'SCALROI', {
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
