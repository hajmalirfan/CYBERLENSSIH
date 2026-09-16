import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  server: {
    port: 3000,
    proxy: {
      '/graph': {
        target: 'http://localhost:8010',
        changeOrigin: true,
      },
      '/api': {
        target: 'http://localhost:8010',
        changeOrigin: true,
      }
    }
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
  }
});
