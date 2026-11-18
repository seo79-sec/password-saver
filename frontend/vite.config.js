import {defineConfig} from 'vite'
import {svelte} from '@sveltejs/vite-plugin-svelte'
import {installThemeRuntime} from './src/theme-runtime.js'
import {createHash} from 'node:crypto'

// A classic external script blocks the parser before the theme stylesheet/App.
// Emit exactly the shared runtime, without a separate handwritten theme policy.
function earlyTheme() {
  const source = '(' + installThemeRuntime.toString() + ')(globalThis);';
  const fileName = 'theme-bootstrap.' + createHash('sha256').update(source).digest('hex').slice(0,12) + '.js';
  return {
    name: 'passwordsaver-early-theme',
    configureServer(server) {
      server.middlewares.use((request, response, next) => {
        if (request.url?.split('?')[0] !== '/' + fileName) return next();
        response.setHeader('Content-Type', 'application/javascript; charset=utf-8');
        response.setHeader('Cache-Control', 'no-store');
        response.end(source);
      });
    },
    generateBundle() {
      this.emitFile({type:'asset', fileName, source});
    },
    transformIndexHtml() {
      return [{tag:'script', attrs:{src:'./' + fileName}, injectTo:'head-prepend'}];
    },
  };
}

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [svelte(), earlyTheme()]
})
