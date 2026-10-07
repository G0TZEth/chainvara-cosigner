# Chainvara co-signer

Your own machine gets the last word on every transfer from your Chainvara organization, and holds half of every split key (2-of-2).

- **Approves or refuses** each transfer by your rules: per-transfer and daily USD limits, allowed networks, **allowed destinations only**, blocked destinations, instant pause.
- **In-person approval** above an amount you choose: the transfer waits until someone approves it on this machine (local page on `127.0.0.1:8788`, never exposed).
- **MPC wallets (2-of-2 FROST)**: holds your share of every MPC wallet (Solana Ed25519, Bitcoin Taproot). Before adding its share it rebuilds the transaction itself — destination, amount, change, fee and every signature hash — and refuses anything that differs from what it approved.
- **Split keys 2-of-2**: stores your half of each key, encrypted at rest (Windows DPAPI, or 0600 files on macOS/Linux), and releases it only for a transfer it approved, with the same intent hash, encrypted to a single-use key.
- **Fail-closed**: every request must carry Chainvara's HMAC signature (5-minute window, no replays); anything unexpected is refused, and a transfer never signs without an answer.
- **Encrypted backups** of the key shares (scrypt + AES-256-GCM), with a `verify` command.

## Verify the file

The SHA-256 of each release is published here **and** in your Chainvara console (Developers → API co-signer). Both must match.

```
# Windows (PowerShell)
Get-FileHash chainvara-cosigner.mjs
# macOS / Linux
shasum -a 256 chainvara-cosigner.mjs
```

## Quick start (Node.js 20+)

1. Publish `127.0.0.1:8787` over HTTPS (Tailscale Funnel `tailscale funnel --bg 8787`, Cloudflare Tunnel, or your reverse proxy).
2. Chainvara → Developers → API co-signer: paste the HTTPS address, activate, copy the secret (shown once).
3. `node chainvara-cosigner.mjs setup` and paste the secret.
4. `node chainvara-cosigner.mjs serve` under a service manager (Windows Startup / Task Scheduler, systemd `Restart=always`, launchd).
5. Edit `policy.json` (path shown by `node chainvara-cosigner.mjs status`): set `allowedDestinations` and `humanApprovalAboveUsd`.
6. After each new split-key wallet: `node chainvara-cosigner.mjs backup <file>` then `verify <file>`. Keep it offline. A lost share means the funds of that wallet are lost.

Commands: `setup | serve | status | pause | resume | approvals | approve <id> | reject <id> | backup <file> | verify <file> | restore <file>`

Full guide: in your Chainvara console, Guides → *Run your co-signer*.
