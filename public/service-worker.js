importScripts("https://storage.googleapis.com/workbox-cdn/releases/6.2.0/workbox-sw.js");
const cacheName = "pwa-cache-v1";
workbox.routing.registerRoute(({ request }) => request.destination === "image", new workbox.strategies.NetworkFirst());
self.addEventListener("activate", (event) => {
  console.log("SW Activated");
});
self.addEventListener("install", function (event) {
  console.log("[Service Worker] Install");
  event.waitUntil(async () => {
    const ASSETS = ["/css/style.css", "/cache/index.html", "/cache/pregame.html", "/cache/offline.html"];
    const cache = await caches.open(cacheName);
    console.log("[Service Worker] Caching all: app shell and content");
    await cache.addAll(ASSETS);
  });
});
