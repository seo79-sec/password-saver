import { defineConfig } from '@playwright/test';
export default defineConfig({
  testDir: './e2e', fullyParallel: false, workers: 1,
  timeout: 30000, reporter: 'list',
  use: { baseURL:'http://127.0.0.1:5173', viewport:{ width:1440,height:900 }, locale:'ru-RU', reducedMotion:'reduce',
    launchOptions: process.env.CHROMIUM_PATH ? { executablePath: process.env.CHROMIUM_PATH, args:['--no-sandbox'] } : {},
  },
  webServer: { command:'npm run dev -- --host 127.0.0.1 --port 5173 --strictPort', url:'http://127.0.0.1:5173', reuseExistingServer:!process.env.CI },
});
