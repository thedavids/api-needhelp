import { defineConfig } from 'vite';
import path from 'path';

export default defineConfig({
  root: './',
  build: {
    rollupOptions: {
      input: 'default.html'
    },
    outDir: 'dist',
  },
  server: {
    open: '/default.html'
  },
  resolve: {
    alias: {
      shared: path.resolve(__dirname, './shared')
    }
  }
});
