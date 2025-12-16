import { defineConfig } from 'vite'
import { viteSingleFile } from 'vite-plugin-singlefile'

export default defineConfig({
  root: 'src',
  plugins: [viteSingleFile()],
  build: {
    outDir: '../dist',
    emptyOutDir: true,
    minify: false,  // Preserve readability for security audits
    cssMinify: false,
    rollupOptions: {
      input: 'src/index.html',
      output: {
        inlineDynamicImports: true,
        manualChunks: undefined
      }
    },
    assetsInlineLimit: 10000000 // Inline all assets (10MB limit)
  },
  publicDir: '../public'
})
