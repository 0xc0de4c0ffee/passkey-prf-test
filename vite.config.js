import { defineConfig } from 'vite'

// Compute base path for GitHub Pages project sites automatically.
// - user/organization site: <user>.github.io => base: '/'
// - project site: <user>/<repo> => base: '/<repo>/'
const repo = process.env.GITHUB_REPOSITORY?.split('/')[1] || ''
const isUserSite = repo.endsWith('.github.io')

export default defineConfig({
  base: '/passkey-prf-test/',
})
