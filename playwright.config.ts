import { defineConfig, devices } from '@playwright/test'

// Tests run against the production build served by `vite preview`, never the dev server.
const PORT = Number(process.env.E2E_PORT ?? 4390)
const origin = `http://127.0.0.1:${PORT}`

export default defineConfig({
  testDir: 'e2e',
  fullyParallel: true,
  // Hosted runners have two or four cores; more workers than that only make every test slower.
  workers: process.env.CI ? 2 : undefined,
  timeout: 60_000,
  expect: { timeout: 10_000 },
  forbidOnly: !!process.env.CI,
  retries: 0,
  reporter: process.env.CI ? [['list'], ['html', { open: 'never' }]] : 'list',
  use: { baseURL: origin, trace: 'retain-on-failure', serviceWorkers: 'block' },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
  webServer: {
    command: `node node_modules/vite/bin/vite.js preview --host 127.0.0.1 --port ${PORT} --strictPort`,
    url: origin,
    reuseExistingServer: false,
    timeout: 30_000,
  },
})
