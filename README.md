# Passkey + PRF (Ethereum wallet demo)

Repo: https://github.com/0xc0de4c0ffee/passkey-prf-test
Live: https://0xc0de4c0ffee.github.io/passkey-prf-test/

Minimal Vite app that derives an Ethereum wallet from a platform Passkey using the WebAuthn PRF extension. No private keys are stored; the PRF output is used in-memory for address derivation and signing.

## Quick start

- Install: `npm install`
- Dev: `npm run dev` (use HTTPS or localhost)
- Build: `npm run build`

## Use

- Register: type a label and click Register (creates a platform passkey, derives address)
- Login: type a label (or leave blank) and click Login (shows passkey picker if mapping is missing)
- Saved wallets: pick a saved label from the dropdown
- Sign: type a message and click Sign (EIP‑191); signature is verified and pubkey shown

## Tech

- WebAuthn PRF (32‑byte output per credential)
- micro-eth-signer for addresses and EIP‑191 signing
- Constant PRF salt for login so recovery doesn’t depend on the label

## Deploy (GitHub Pages)

- CI: [.github/workflows/deploy-pages.yml](.github/workflows/deploy-pages.yml)
- Vite base auto‑config: [vite.config.js](vite.config.js)
- Push to `main` to deploy; Pages Source should be “GitHub Actions”

## License

MIT
