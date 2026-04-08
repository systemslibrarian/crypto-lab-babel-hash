import { defineConfig } from 'vitest/config';

export default defineConfig({
  base: '/crypto-lab-babel-hash/',
  test: {
    environment: 'node',
    include: ['src/__tests__/**/*.test.ts']
  }
});
