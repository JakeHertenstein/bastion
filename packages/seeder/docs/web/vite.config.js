import { defineConfig } from 'vite'

export default defineConfig({
  root: 'src',
  server: {
    port: 3000,
    open: true,
    cors: true,
    strictPort: false
  },
  // Ensure SPA mode for history API fallback (default, but explicit)
  appType: 'spa',
  build: {
    sourcemap: true,
    outDir: '../dev-build',
    emptyOutDir: true,
    rollupOptions: {
      input: 'src/index.html'
    }
  },
  // Restore public directory for working JavaScript files
  publicDir: '../public'
})
