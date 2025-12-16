/**
 * PWA Service Worker Registration
 * 
 * Handles progressive web app installation and service worker lifecycle.
 * Development mode bypasses SW registration to avoid caching issues.
 */

// PWA Service Worker Registration
if ('serviceWorker' in navigator) {
    // Skip service worker registration in development mode
    const isDev = window.location.hostname === 'localhost' || 
                  window.location.hostname === '127.0.0.1' ||
                  window.location.port === '5173';  // Vite dev server port
    
    if (isDev) {
        console.log('PWA: Development mode - skipping service worker registration');
        // Clear existing service worker caches in dev mode
        if ('caches' in window) {
            caches.keys().then(function(names) {
                for (let name of names) {
                    if (name.startsWith('seedcard-')) {
                        caches.delete(name);
                        console.log('PWA: Cleared dev cache:', name);
                    }
                }
            });
        }
    } else {
        // Production: register the service worker
        window.addEventListener('load', function() {
            navigator.serviceWorker.register('./sw.js')
                .then(function(registration) {
                    console.log('PWA: Service Worker registered with scope:', registration.scope);
                    
                    // Check for updates
                    registration.addEventListener('updatefound', function() {
                        const newWorker = registration.installing;
                        if (newWorker) {
                            newWorker.addEventListener('statechange', function() {
                                if (newWorker.state === 'installed' && navigator.serviceWorker.controller) {
                                    // New content available
                                    console.log('PWA: New content available, please refresh');
                                    // Optional: show update notification to user
                                    if (window.dispatchEvent) {
                                        window.dispatchEvent(new CustomEvent('pwa-update-available'));
                                    }
                                }
                            });
                        }
                    });
                })
                .catch(function(error) {
                    console.error('PWA: Service Worker registration failed:', error);
                });
        });
    }
}
