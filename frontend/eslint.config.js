import js from '@eslint/js'
import globals from 'globals'
import reactHooks from 'eslint-plugin-react-hooks'
import reactRefresh from 'eslint-plugin-react-refresh'
import tseslint from 'typescript-eslint'
import { defineConfig, globalIgnores } from 'eslint/config'

export default defineConfig([
  globalIgnores(['dist']),
  {
    files: ['**/*.{ts,tsx}'],
    extends: [
      js.configs.recommended,
      tseslint.configs.recommended,
      reactHooks.configs.flat.recommended,
      reactRefresh.configs.vite,
    ],
    languageOptions: {
      globals: globals.browser,
    },
    rules: {
      // shadcn/ui components export variant helpers alongside the component;
      // this only affects dev-time Fast Refresh, never production.
      'react-refresh/only-export-components': 'warn',
      // Setting loading/error state at the start of a data-fetching effect is
      // idiomatic here; keep it visible as a hint rather than a hard error.
      'react-hooks/set-state-in-effect': 'warn',
    },
  },
])
