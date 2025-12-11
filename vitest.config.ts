import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    // Define your workspace projects here
    projects: ['packages/*/vitest.config.mts'],

    // Global test configuration (applies to all projects)
    globals: true,
    coverage: {
      enabled: false, // Can be enabled via CLI flag
      include: ['packages/*/src/**'],
      exclude: [
        '**/node_modules/**',
        '**/dist/**',
        '**/*.test.ts',
        '**/*.spec.ts',
      ],
      reporter: ['text', 'json', 'html', 'lcov'],
    },
  },
});
