// TAP dashboard service worker — Web Push for approval notifications.
//
// Scope is "/" (served from the root path) so a single registration covers the
// dashboard. The worker does no caching: its only job is to surface push
// notifications and deep-link clicks back into the approvals inbox.

self.addEventListener('push', (event) => {
  let data = {};
  try {
    data = event.data ? event.data.json() : {};
  } catch (e) {
    data = { title: 'Approval needed', body: 'A request is waiting for your approval.' };
  }
  const title = data.title || 'Approval needed';
  const options = {
    body: data.body || 'A request is waiting for your approval.',
    // Coalesce repeated pushes for the same request into one notification.
    tag: data.txn_id || 'tap-approval',
    renotify: true,
    requireInteraction: true,
    data: { url: data.url || '/#/approvals', txn_id: data.txn_id || null },
  };
  event.waitUntil(self.registration.showNotification(title, options));
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  const targetPath = (event.notification.data && event.notification.data.url) || '/#/approvals';
  const targetUrl = new URL('/dashboard' + targetPath, self.location.origin).href;
  event.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then((wins) => {
      // Focus an existing dashboard tab if one is open; else open a new one.
      for (const client of wins) {
        if (client.url.includes('/dashboard') && 'focus' in client) {
          client.navigate(targetUrl).catch(() => {});
          return client.focus();
        }
      }
      if (clients.openWindow) return clients.openWindow(targetUrl);
    })
  );
});
