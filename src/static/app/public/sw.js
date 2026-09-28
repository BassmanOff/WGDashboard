/*
 * WGDashboard Service Worker
 * Отвечает за приём Web Push уведомлений и их отображение.
 */
self.addEventListener('install', (event) => {
	self.skipWaiting();
});

self.addEventListener('activate', (event) => {
	event.waitUntil(self.clients.claim());
});

self.addEventListener('push', (event) => {
	let data = {};
	if (event.data) {
		try {
			data = event.data.json();
		} catch (e) {
			data = {title: 'WGDashboard', body: event.data.text()};
		}
	}

	const title = data.title || 'WGDashboard';
	const options = {
		body: data.body || '',
		// tag: перезаписывает предыдущее уведомление с тем же тегом,
		// чтобы не плодить одинаковые оповещения
		tag: data.tag || 'wgd',
		renotify: true,
		icon: './img/Logo-2-128x128.png',
		badge: './img/Logo-2-128x128.png',
		data: {
			url: data.url || './clients'
		}
	};

	event.waitUntil(
		self.registration.showNotification(title, options).catch((err) => {
			// Например, на iOS требовалось разрешение на показ уведомлений
			console.error('[WGDashboard] showNotification failed', err);
		})
	);
});

self.addEventListener('notificationclick', (event) => {
	event.notification.close();

	const targetUrl = new URL(
		event.notification.data?.url || './clients',
		self.registration.scope
	).href;

	event.waitUntil(
		self.clients.matchAll({type: 'window', includeUncontrolled: true})
			.then((clientList) => {
				// Если панель уже открыта - переводим фокус на неё
				for (const client of clientList) {
					if (client.url.startsWith(self.registration.scope) && 'focus' in client) {
						client.navigate(targetUrl);
						return client.focus();
					}
				}
				return self.clients.openWindow(targetUrl);
			})
	);
});
