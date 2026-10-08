# Chainvara co-signer

Your own machine gets the last word on every transfer from your Chainvara organization, and holds half of every split key (2-of-2).

- **Approves or refuses** each transfer by your rules: per-transfer and daily USD limits, allowed networks, **allowed destinations only**, blocked destinations, instant pause.
- **Your own approval server**: set `callbackUrl` in policy.json and the co-signer asks your server before approving each transfer, with every detail; both directions are HMAC-signed with the secret from `node chainvara-cosigner.mjs callback-secret` and bound to the request id. A down, slow or forged answer approves nothing — the transfer waits.
- **In-person approval** above an amount you choose: the transfer waits until someone approves it on this machine (local page on `127.0.0.1:8788`, never exposed).
- **MPC wallets (2-of-2)**: holds your share of every MPC wallet — FROST for Solana, the XRP Ledger, Stellar, Aptos, Sui and TON (Ed25519) and Bitcoin Taproot, threshold ECDSA (DKLs23) for Ethereum, every EVM chain, Tron (TRX, USDT), the Cosmos Hub, Osmosis, Celestia, Noble (USDC), Akash and dYdX (it decodes the Cosmos SignDoc: one bank send, recipient, amount, memo, fee, chain id and key), Litecoin and Dogecoin (on Dogecoin it reads the spent amounts from the previous transactions, whose ids it recomputes). Before adding its share it decodes the transaction itself — chain, destination, amount, token, change, fee and every signature hash — and refuses anything that differs from what it approved.
- **Stuck transactions**: a speed-up is the same EVM transaction with a higher fee (same nonce, fee cap still applies); a cancellation (0-value transaction to the wallet itself, 21,000 gas) is accepted only for a nonce this approval already signed.
- **Cosmos staking**: delegate, undelegate and claim-rewards messages are decoded too — this wallet as delegator, exactly the approved validator(s) and amount, no memo.
- **NFT transfers**: for an ERC-721 or ERC-1155 transfer it checks the collection, the token id, the quantity and that the recipient is the approved destination, byte for byte, before adding its share.
- **Split keys 2-of-2**: stores your half of each key, encrypted at rest (Windows DPAPI, or 0600 files on macOS/Linux), and releases it only for a transfer it approved, with the same intent hash, encrypted to a single-use key.
- **Proactive key-share refresh**: renews its share of an MPC key together with Chainvara (FROST and threshold ECDSA). The address never changes and a share copied before the refresh becomes useless; the new share is only used once both sides confirmed the same key. Make a new backup after each refresh.
- **No public address needed**: it connects to Chainvara by itself (outbound HTTPS, like Fireblocks' API Co-Signer) — no tunnel, no open port, works behind any router or firewall.
- **Fail-closed**: every request must carry Chainvara's HMAC signature (5-minute window, no replays); anything unexpected is refused, and a transfer never signs without an answer.
- **Encrypted backups** of every key share — split keys and MPC wallets (scrypt + AES-256-GCM), with a `verify` command.

## Exit plan: chainvara-recovery.mjs

If Chainvara were ever unavailable, rebuild every private key yourself, offline, with Node.js 20+ and this single dependency-free file:

1. `node chainvara-recovery.mjs keygen recovery-key.json` — once; paste the printed public key in Chainvara (Settings → Recovery kit).
2. Download a recovery kit from the console (owners, with 2FA) after creating wallets; keep it with your co-signer backup.
3. `node chainvara-recovery.mjs recover kit.json recovery-key.json cosigner-backup.json keys.json` — each key is rebuilt from Chainvara's share (sealed to your recovery key) and your co-signer's, then checked against the wallet's public key. MPC ECDSA keys come out as ordinary private keys (WIF for Bitcoin-family chains), Taproot as `tr(WIF)`, FROST Ed25519 keys as the secret scalar.

## Verify the file

The SHA-256 of each release is published here **and** in your Chainvara console (Developers → API co-signer). Both must match.

```
# Windows (PowerShell)
Get-FileHash chainvara-cosigner.mjs
# macOS / Linux
shasum -a 256 chainvara-cosigner.mjs
```

## Quick start (Node.js 20+)

1. Chainvara → Developers → API co-signer: leave the address empty (outbound connection), activate, copy the secret (shown once).
2. Only if you prefer inbound calls: publish `127.0.0.1:8787` over HTTPS and paste that address instead.
3. `node chainvara-cosigner.mjs setup` and paste the secret.
4. `node chainvara-cosigner.mjs serve` under a service manager (Windows Startup / Task Scheduler, systemd `Restart=always`, launchd).
5. Edit `policy.json` (path shown by `node chainvara-cosigner.mjs status`): set `allowedDestinations` and `humanApprovalAboveUsd`.
6. After each new split-key or MPC wallet: `node chainvara-cosigner.mjs backup <file>` then `verify <file>`. Keep it offline. A lost share means the funds of that wallet are lost.

Commands: `setup | serve | status | pause | resume | approvals | approve <id> | reject <id> | backup <file> | verify <file> | restore <file>`

Full guide: in your Chainvara console, Guides → *Run your co-signer*.
