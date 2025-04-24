import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    open: true,
    proxy: {
      '/scan': {
        target: 'http://localhost:5000',
        changeOrigin: true,
      },
    },
  },
  build: {
    outDir: 'dist',
    rollupOptions: {
      // Remove or correct the input option; Vite uses src/main.jsx by default
      // input: 'public/index.html', // Remove this line
    },
  },
  publicDir: 'public', // Ensures public assets (e.g., hi.png) are copied to dist
});

