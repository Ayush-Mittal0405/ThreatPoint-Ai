import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 3000,
    proxy: {
      '/api': {
        // Backend runs over HTTPS with a self-signed dev cert; secure:false lets
        // the dev proxy accept it. Switch back to http:// if you run the backend
        // without TLS.
        target: 'https://127.0.0.1:8008',
        changeOrigin: true,
        secure: false,
      },
    },
  },
})

