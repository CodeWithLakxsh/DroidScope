// vitest's defineConfig accepts the `test` block as well as Vite's own options.
import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';
import path from 'node:path';

// Shared by the dev server and the production preview: the browser sees a
// single origin, so no CORS configuration is needed for local use.
const apiProxy = {
  '/api': {
    target: process.env.DROIDSCOPE_API_URL ?? 'http://127.0.0.1:8000',
    changeOrigin: true,
  },
};

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: { '@': path.resolve(__dirname, './src') },
  },
  server: {
    port: 5173,
    strictPort: false,
    proxy: apiProxy,
  },
  // `preview` does not inherit `server.proxy`, so the production preview needs
  // it declared separately. Without this the built bundle is served correctly
  // but every /api request 404s, which is how the end-to-end suite runs in CI.
  preview: {
    port: 5173,
    strictPort: true,
    proxy: apiProxy,
  },
  build: {
    outDir: 'dist',
    sourcemap: true,
    rollupOptions: {
      output: {
        // Monaco and the charting library are large and not needed on first
        // paint; splitting them keeps the initial bundle small.
        manualChunks: {
          react: ['react', 'react-dom', 'react-router-dom'],
          query: ['@tanstack/react-query'],
          charts: ['recharts'],
          flow: ['@xyflow/react'],
          editor: ['@monaco-editor/react'],
        },
      },
    },
  },
  test: {
    globals: true,
    environment: 'jsdom',
    setupFiles: './tests/setup.ts',
    css: false,
    include: ['tests/**/*.test.{ts,tsx}', 'src/**/*.test.{ts,tsx}'],
  },
});
