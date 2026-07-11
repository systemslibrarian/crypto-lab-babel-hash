import { defineConfig, devices } from '@playwright/test';

/**
 * Accessibility gate. Tests run against the production build served by
 * `vite preview`, so what passes here is what actually ships to Pages.
 * Run `npm run build` first (CI does).
 */
export default defineConfig({
  testDir: './e2e',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? 'list' : [['list'], ['html', { open: 'never' }]],
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
  webServer: {
    command: 'npm run preview -- --port 4221 --strictPort',
    port: 4221,
    reuseExistingServer: !process.env.CI,
    timeout: 30_000,
  },
  use: {
    baseURL: 'http://localhost:4221/crypto-lab-babel-hash/',
  },
});
