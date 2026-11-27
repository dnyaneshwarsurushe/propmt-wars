import { defineConfig, type Plugin } from 'vite';
import react from '@vitejs/plugin-react';

/**
 * Injects a strict Content Security Policy (connect-src 'none') into the production
 * HTML bundle so the browser guarantees zero outbound network requests.
 */
function strictOfflineCspPlugin(): Plugin {
  return {
    name: 'strict-offline-csp',
    apply: 'build',
    transformIndexHtml(html) {
      const cspTag =
        '    <meta http-equiv="Content-Security-Policy" content="default-src \'self\'; script-src \'self\'; style-src \'self\' \'unsafe-inline\'; worker-src \'self\' blob:; connect-src \'none\'; img-src \'self\' data:; object-src \'none\'; base-uri \'self\';" />';
      return html.replace('</head>', `${cspTag}\n  </head>`);
    },
  };
}

export default defineConfig({
  plugins: [react(), strictOfflineCspPlugin()],
  base: './',
});
