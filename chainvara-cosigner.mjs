#!/usr/bin/env node
/**
 * Chainvara co-signer for an always-on Windows PC.
 *
 * Chainvara asks this program before signing anything, and it holds half of every split key (2-of-2):
 *   transfer.sign_request → approve or reject, using your local rules (policy.json)
 *   key_share.store       → receive and keep share B of a new split-key wallet
 *   key_share.request     → release share B only for a transfer this co-signer approved (same intent hash)
 *
 * Security
 *   - Every request must carry a valid Chainvara HMAC signature (shared secret, 5-minute window, no replays).
 *   - The shared secret and the local master key are protected by Windows DPAPI (bound to this Windows user); on
 *     macOS/Linux they are files readable only by this user (0600) — use full-disk encryption on that machine.
 *     Shares are encrypted at rest with AES-256-GCM under the master key.
 *   - Listens on 127.0.0.1 only; expose it over HTTPS with Tailscale Funnel, Cloudflare Tunnel or your reverse proxy.
 *   - Fail-closed: anything unexpected is refused. Every decision is logged (decisions.jsonl), never a secret.
 *   - BACK UP YOUR SHARES (node chainvara-cosigner.mjs backup <file>): losing them loses the funds of split-key wallets.
 *
 * Commands
 *   node chainvara-cosigner.mjs setup             store the co-signer secret shown once by Chainvara (Developers page)
 *   node chainvara-cosigner.mjs serve             run the co-signer (default; tools/start-cosigner.cmd keeps it running)
 *   node chainvara-cosigner.mjs status            shares held, rules, today's approved volume
 *   node chainvara-cosigner.mjs pause | resume    refuse every request instantly / resume
 *   node chainvara-cosigner.mjs backup <file>     passphrase-encrypted backup of every share
 *   node chainvara-cosigner.mjs restore <file>    restore shares from a backup
 *   node chainvara-cosigner.mjs verify <file>     check that a backup opens and holds every current share (writes nothing)
 *   node chainvara-cosigner.mjs approvals         transfers waiting for a person (humanApprovalAboveUsd) + the local approval page
 *   node chainvara-cosigner.mjs approve|reject <transfer_id>
 * Environment: COSIGNER_PORT (default 8787; never expose COSIGNER_APPROVAL_PORT, default 8788), COSIGNER_DATA_DIR (default %LOCALAPPDATA%Chainvaracosigner or ~/.local/share/Chainvara/cosigner).
 */
import http from "node:http";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import readline from "node:readline";
import { execFileSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
// Replaced by an embedded copy of the SDK in the downloadable single-file build (tools/build-cosigner.mjs).
const sdk = await import("data:text/javascript;base64,LyoqCiAqIEZpbmFuY2lhbCBPUyDigJQgb2ZmaWNpYWwgVHlwZVNjcmlwdCBjbGllbnQuCiAqCiAqICAgY29uc3QgZm9zID0gbmV3IEZpbmFuY2lhbE9TKHByb2Nlc3MuZW52LkZPU19BUElfS0VZISwgeyBiYXNlVXJsOiAiaHR0cHM6Ly95b3VyLWhvc3QiIH0pOwogKiAgIGNvbnN0IHdhbGxldCA9IGF3YWl0IGZvcy53YWxsZXRzLmNyZWF0ZSh7IG5ldHdvcms6ICJiYXNlLXNlcG9saWEiLCBleHRlcm5hbF91c2VyX2lkOiB1c2VyLmlkIH0pOwogKiAgIGNvbnN0IHQgPSBhd2FpdCBmb3MudHJhbnNmZXJzLmNyZWF0ZSh7IHdhbGxldF9pZDogd2FsbGV0LmlkLCBhc3NldDogIlVTREMiLCBhbW91bnQ6ICIyNS4wMCIsIGRlc3RpbmF0aW9uOiAiMHjigKYiIH0pOwogKgogKiBaZXJvIGRlcGVuZGVuY2llczsgcnVucyBvbiBOb2RlIDE4KywgRGVubywgQnVuIGFuZCBlZGdlIHJ1bnRpbWVzIChmZXRjaCArIFdlYiBDcnlwdG8pLgogKiBFdmVyeSBQT1NUIGNhcnJpZXMgYW4gSWRlbXBvdGVuY3ktS2V5IChnZW5lcmF0ZWQgaWYgeW91IGRvIG5vdCBwYXNzIG9uZSksIHNvIGF1dG9tYXRpYyByZXRyaWVzIG9uCiAqIG5ldHdvcmsgZXJyb3JzLCA0MjkgYW5kIDV4eCBuZXZlciBjcmVhdGUgYSBzZWNvbmQgd2FsbGV0IG9yIHRyYW5zZmVyLgogKi8KLyoqIEZpbmFsIHN0YXR1c2VzOiBhIHRyYW5zZmVyIGluIG9uZSBvZiB0aGVzZSB3aWxsIG5vdCBjaGFuZ2UgYWdhaW4uICovCmV4cG9ydCBjb25zdCBGSU5BTF9UUkFOU0ZFUl9TVEFUVVNFUyA9IFsiY29uZmlybWVkIiwgImZhaWxlZCIsICJyZWplY3RlZCIsICJibG9ja2VkIiwgImNhbmNlbGVkIiwgImV4cGlyZWQiXTsKLy8gLS0tLS0tLS0tLSBFcnJvcnMgLS0tLS0tLS0tLQpleHBvcnQgY2xhc3MgRmluYW5jaWFsT1NFcnJvciBleHRlbmRzIEVycm9yIHsKICAgIHN0YXR1czsKICAgIHR5cGU7CiAgICBjb2RlOwogICAgcmVxdWVzdElkOwogICAgY29uc3RydWN0b3IobWVzc2FnZSwgc3RhdHVzLCB0eXBlLCBjb2RlLCByZXF1ZXN0SWQpIHsKICAgICAgICBzdXBlcihtZXNzYWdlKTsKICAgICAgICB0aGlzLm5hbWUgPSAiRmluYW5jaWFsT1NFcnJvciI7CiAgICAgICAgdGhpcy5zdGF0dXMgPSBzdGF0dXM7CiAgICAgICAgdGhpcy50eXBlID0gdHlwZTsKICAgICAgICB0aGlzLmNvZGUgPSBjb2RlOwogICAgICAgIHRoaXMucmVxdWVzdElkID0gcmVxdWVzdElkOwogICAgfQp9CmNvbnN0IEtFWV9SRSA9IC9eZm9zXyh0ZXN0fGxpdmUpX1swLTlhLWZdezEyfV9bMC05YS1mXXs2NH0kLzsKZXhwb3J0IGNsYXNzIEZpbmFuY2lhbE9TIHsKICAgIG1vZGU7CiAgICBiYXNlOwogICAgbWF4UmV0cmllczsKICAgIHRpbWVvdXRNczsKICAgIGZldGNoSW1wbDsKICAgIGFwaUtleTsKICAgIGNvbnN0cnVjdG9yKGFwaUtleSwgb3B0cyA9IHt9KSB7CiAgICAgICAgdGhpcy5hcGlLZXkgPSBhcGlLZXk7CiAgICAgICAgY29uc3QgbSA9IEtFWV9SRS5leGVjKGFwaUtleSA/PyAiIik7CiAgICAgICAgaWYgKCFtKQogICAgICAgICAgICB0aHJvdyBuZXcgRXJyb3IoIkZpbmFuY2lhbE9TOiBpbnZhbGlkIEFQSSBrZXkuIEV4cGVjdGVkIGZvc190ZXN0X+KApiBvciBmb3NfbGl2ZV/igKYgKGNyZWF0ZSBvbmUgaW4gRGV2ZWxvcGVycykuIik7CiAgICAgICAgaWYgKHR5cGVvZiB3aW5kb3cgIT09ICJ1bmRlZmluZWQiICYmIHR5cGVvZiBkb2N1bWVudCAhPT0gInVuZGVmaW5lZCIpIHsKICAgICAgICAgICAgdGhyb3cgbmV3IEVycm9yKCJGaW5hbmNpYWxPUzogbmV2ZXIgdXNlIGEgc2VjcmV0IEFQSSBrZXkgaW4gdGhlIGJyb3dzZXIuIENhbGwgeW91ciBvd24gYmFja2VuZCBpbnN0ZWFkLiIpOwogICAgICAgIH0KICAgICAgICB0aGlzLm1vZGUgPSBtWzFdOwogICAgICAgIHRoaXMuYmFzZSA9IChvcHRzLmJhc2VVcmwgPz8gImh0dHA6Ly9sb2NhbGhvc3Q6MzAwMCIpLnJlcGxhY2UoL1wvKyQvLCAiIikgKyAiL2FwaS92MSI7CiAgICAgICAgdGhpcy5tYXhSZXRyaWVzID0gb3B0cy5tYXhSZXRyaWVzID8/IDI7CiAgICAgICAgdGhpcy50aW1lb3V0TXMgPSBvcHRzLnRpbWVvdXRNcyA/PyAzMF8wMDA7CiAgICAgICAgdGhpcy5mZXRjaEltcGwgPSBvcHRzLmZldGNoID8/IGdsb2JhbFRoaXMuZmV0Y2guYmluZChnbG9iYWxUaGlzKTsKICAgIH0KICAgIC8vIC0tLS0tIFJlc291cmNlcyAtLS0tLQogICAgd2FsbGV0cyA9IHsKICAgICAgICAvKiogTmV3IGtleSBnZW5lcmF0ZWQgaW4gdGhlIHZhdWx0LiBXaXRoIGV4dGVybmFsX3VzZXJfaWQsIGlkZW1wb3RlbnQgcGVyIChuZXR3b3JrLCB1c2VyKTogcmV0dXJucyB0aGUgZXhpc3Rpbmcgd2FsbGV0LiAqLwogICAgICAgIGNyZWF0ZTogKHAsIG8pID0+IHRoaXMucmVxdWVzdCgiUE9TVCIsICIvd2FsbGV0cyIsIHAsIHVuZGVmaW5lZCwgbyksCiAgICAgICAgLyoqIFdhdGNoLW9ubHk6IHRyYWNrIGFueSBhZGRyZXNzLCBubyBrZXkuICovCiAgICAgICAgd2F0Y2g6IChwLCBvKSA9PiB0aGlzLnJlcXVlc3QoIlBPU1QiLCAiL3dhbGxldHMiLCBwLCB1bmRlZmluZWQsIG8pLAogICAgICAgIGxpc3Q6IChxID0ge30pID0+IHRoaXMucmVxdWVzdCgiR0VUIiwgIi93YWxsZXRzIiwgdW5kZWZpbmVkLCBxKSwKICAgICAgICBnZXQ6IChpZCkgPT4gdGhpcy5yZXF1ZXN0KCJHRVQiLCBgL3dhbGxldHMvJHtlbmMoaWQpfWApLAogICAgICAgIGJhbGFuY2VzOiAoaWQsIHEgPSB7fSkgPT4gdGhpcy5yZXF1ZXN0KCJHRVQiLCBgL3dhbGxldHMvJHtlbmMoaWQpfS9iYWxhbmNlc2AsIHVuZGVmaW5lZCwgcSksCiAgICAgICAgdHJhbnNhY3Rpb25zOiAoaWQsIHEgPSB7fSkgPT4gdGhpcy5yZXF1ZXN0KCJHRVQiLCBgL3dhbGxldHMvJHtlbmMoaWQpfS90cmFuc2FjdGlvbnNgLCB1bmRlZmluZWQsIHEpLAogICAgICAgIC8qKgogICAgICAgICAqIENvbnZlbmllbmNlOiBvbmUgd2FsbGV0IHBlciB1c2VyIHBlciBuZXR3b3JrLCBjcmVhdGVkIG9uIGZpcnN0IGNhbGwgYW5kIHJldHVybmVkIGFmdGVyd2FyZHMuCiAgICAgICAgICogVGhlIHNlcnZlciBkZWR1cGxpY2F0ZXMgb24gKG5ldHdvcmssIGV4dGVybmFsX3VzZXJfaWQpLCBzbyBubyBmaXhlZCBJZGVtcG90ZW5jeS1LZXkgaXMgbmVlZGVkCiAgICAgICAgICogKGEgZml4ZWQga2V5IHdvdWxkIGNvbmZsaWN0IHdoZW4gdGhlIGxhYmVsIGRpZmZlcnMgYmV0d2VlbiBjYWxscykuCiAgICAgICAgICovCiAgICAgICAgZm9yVXNlcjogYXN5bmMgKGV4dGVybmFsVXNlcklkLCBuZXR3b3JrLCBsYWJlbCkgPT4gdGhpcy53YWxsZXRzLmNyZWF0ZSh7IG5ldHdvcmssIGV4dGVybmFsX3VzZXJfaWQ6IGV4dGVybmFsVXNlcklkLCAuLi4obGFiZWwgPyB7IGxhYmVsIH0gOiB7fSkgfSksCiAgICB9OwogICAgdHJhbnNmZXJzID0gewogICAgICAgIC8qKiBFdmFsdWF0ZWQgYWdhaW5zdCB5b3VyIHBvbGljeTsgZXhlY3V0ZWQgb25jZSBhcHByb3ZlZCBhbmQgZXhlY3V0aW9uIGlzIGVuYWJsZWQuICovCiAgICAgICAgY3JlYXRlOiAocCwgbykgPT4gdGhpcy5yZXF1ZXN0KCJQT1NUIiwgIi90cmFuc2ZlcnMiLCBwLCB1bmRlZmluZWQsIG8pLAogICAgICAgIC8qKiBTaW11bGF0aW9uOiBwb2xpY3kgZGVjaXNpb24sIG5ldHdvcmsgZmVlIGFuZCBhIGRyeSBydW4gYWdhaW5zdCB0aGUgY2hhaW4uIE5vdGhpbmcgaXMgY3JlYXRlZCBvciBzaWduZWQuICovCiAgICAgICAgcHJldmlldzogKHApID0+IHRoaXMucmVxdWVzdCgiUE9TVCIsICIvdHJhbnNmZXJzL3ByZXZpZXciLCBwKSwKICAgICAgICBsaXN0OiAocSA9IHt9KSA9PiB0aGlzLnJlcXVlc3QoIkdFVCIsICIvdHJhbnNmZXJzIiwgdW5kZWZpbmVkLCBxKSwKICAgICAgICBnZXQ6IChpZCkgPT4gdGhpcy5yZXF1ZXN0KCJHRVQiLCBgL3RyYW5zZmVycy8ke2VuYyhpZCl9YCksCiAgICAgICAgY2FuY2VsOiAoaWQsIG8pID0+IHRoaXMucmVxdWVzdCgiUE9TVCIsIGAvdHJhbnNmZXJzLyR7ZW5jKGlkKX0vY2FuY2VsYCwgdW5kZWZpbmVkLCB1bmRlZmluZWQsIG8pLAogICAgICAgIC8qKiBQb2xscyB1bnRpbCB0aGUgdHJhbnNmZXIgcmVhY2hlcyBhIGZpbmFsIHN0YXR1cyAob3IgYHVudGlsYCByZXR1cm5zIHRydWUpLCB0aGVuIHJldHVybnMgaXQuICovCiAgICAgICAgd2FpdDogYXN5bmMgKGlkLCBvcHRzID0ge30pID0+IHsKICAgICAgICAgICAgY29uc3QgZGVhZGxpbmUgPSBEYXRlLm5vdygpICsgKG9wdHMudGltZW91dE1zID8/IDEwICogNjBfMDAwKTsKICAgICAgICAgICAgZm9yICg7OykgewogICAgICAgICAgICAgICAgY29uc3QgdCA9IGF3YWl0IHRoaXMudHJhbnNmZXJzLmdldChpZCk7CiAgICAgICAgICAgICAgICBpZiAob3B0cy51bnRpbCA/IG9wdHMudW50aWwodCkgOiBGSU5BTF9UUkFOU0ZFUl9TVEFUVVNFUy5pbmNsdWRlcyh0LnN0YXR1cykpCiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIHQ7CiAgICAgICAgICAgICAgICBpZiAoRGF0ZS5ub3coKSA+IGRlYWRsaW5lKQogICAgICAgICAgICAgICAgICAgIHRocm93IG5ldyBGaW5hbmNpYWxPU0Vycm9yKGBUcmFuc2ZlciAke2lkfSBzdGlsbCAke3Quc3RhdHVzfSBhZnRlciB0aW1lb3V0LmAsIDQwOCwgInRpbWVvdXQiLCAid2FpdF90aW1lb3V0IiwgbnVsbCk7CiAgICAgICAgICAgICAgICBhd2FpdCBzbGVlcChvcHRzLmludGVydmFsTXMgPz8gNV8wMDApOwogICAgICAgICAgICB9CiAgICAgICAgfSwKICAgIH07CiAgICBwYXlvdXRzID0gewogICAgICAgIC8qKiBVcCB0byA1MDAgcGF5b3V0cyBpbiBvbmUgYmF0Y2guIEFsbCBsaW5lcyBhcmUgdmFsaWRhdGVkIGZpcnN0OyBzZW5kIGFuIElkZW1wb3RlbmN5LUtleSBzbyBhIHJldHJ5IG5ldmVyIHBheXMgdHdpY2UuICovCiAgICAgICAgY3JlYXRlOiAocCwgbykgPT4gdGhpcy5yZXF1ZXN0KCJQT1NUIiwgIi9wYXlvdXRzIiwgcCwgdW5kZWZpbmVkLCBvKSwKICAgICAgICBnZXQ6IChpZCkgPT4gdGhpcy5yZXF1ZXN0KCJHRVQiLCBgL3BheW91dHMvJHtlbmMoaWQpfWApLAogICAgICAgIGxpc3Q6IChxID0ge30pID0+IHRoaXMucmVxdWVzdCgiR0VUIiwgIi9wYXlvdXRzIiwgdW5kZWZpbmVkLCBxKSwKICAgIH07CiAgICBzY3JlZW5pbmcgPSB7CiAgICAgICAgLyoqIFNhbmN0aW9ucyBzY3JlZW5pbmcgKE9GQUMgU0ROKSBvZiBhbnkgYWRkcmVzcy4gKi8KICAgICAgICBjaGVjazogKG5ldHdvcmssIGFkZHJlc3MpID0+IHRoaXMucmVxdWVzdCgiR0VUIiwgIi9zY3JlZW5pbmciLCB1bmRlZmluZWQsIHsgbmV0d29yaywgYWRkcmVzcyB9KSwKICAgIH07CiAgICAvKiogU2VjdXJpdHkgcG9zdHVyZSBvZiB0aGUga2V5J3MgZW52aXJvbm1lbnQ6IHNjb3JlIDDigJMxMDAgYW5kIGV2ZXJ5IGNoZWNrIHdpdGggaXRzIGZpeC4gKi8KICAgIHNlY3VyaXR5ID0gewogICAgICAgIHBvc3R1cmU6ICgpID0+IHRoaXMucmVxdWVzdCgiR0VUIiwgIi9zZWN1cml0eSIpLAogICAgfTsKICAgIG5ldHdvcmtzID0geyBsaXN0OiAoKSA9PiB0aGlzLnJlcXVlc3QoIkdFVCIsICIvbmV0d29ya3MiKSB9OwogICAgLyoqIFBheW1lbnQgbmV0d29yazogY29ubmVjdGVkIG9yZ2FuaXphdGlvbnMgeW91IGNhbiBwYXkgd2l0aCBgZGVzdGluYXRpb246ICJAaGFuZGxlImAuICovCiAgICBwYXllZXMgPSB7IGxpc3Q6ICgpID0+IHRoaXMucmVxdWVzdCgiR0VUIiwgIi9wYXllZXMiKSB9OwogICAgcHJpY2VzID0geyBsaXN0OiAoKSA9PiB0aGlzLnJlcXVlc3QoIkdFVCIsICIvcHJpY2VzIikgfTsKICAgIGV2ZW50cyA9IHsgbGlzdDogKHEgPSB7fSkgPT4gdGhpcy5yZXF1ZXN0KCJHRVQiLCAiL2V2ZW50cyIsIHVuZGVmaW5lZCwgcSkgfTsKICAgIC8vIC0tLS0tIFRyYW5zcG9ydCAtLS0tLQogICAgYXN5bmMgcmVxdWVzdChtZXRob2QsIHBhdGgsIGJvZHksIHF1ZXJ5LCBvID0ge30pIHsKICAgICAgICBjb25zdCB1cmwgPSBuZXcgVVJMKHRoaXMuYmFzZSArIHBhdGgpOwogICAgICAgIGZvciAoY29uc3QgW2ssIHZdIG9mIE9iamVjdC5lbnRyaWVzKHF1ZXJ5ID8/IHt9KSkKICAgICAgICAgICAgaWYgKHYgIT09IHVuZGVmaW5lZCAmJiB2ICE9PSBudWxsKQogICAgICAgICAgICAgICAgdXJsLnNlYXJjaFBhcmFtcy5zZXQoaywgU3RyaW5nKHYpKTsKICAgICAgICBjb25zdCBoZWFkZXJzID0geyBhdXRob3JpemF0aW9uOiBgQmVhcmVyICR7dGhpcy5hcGlLZXl9YCwgYWNjZXB0OiAiYXBwbGljYXRpb24vanNvbiIsICJ1c2VyLWFnZW50IjogImZvcy1zZGstdHMvMC4xLjAiIH07CiAgICAgICAgaWYgKG1ldGhvZCA9PT0gIlBPU1QiKSB7CiAgICAgICAgICAgIGhlYWRlcnNbImNvbnRlbnQtdHlwZSJdID0gImFwcGxpY2F0aW9uL2pzb24iOwogICAgICAgICAgICBoZWFkZXJzWyJpZGVtcG90ZW5jeS1rZXkiXSA9IG8uaWRlbXBvdGVuY3lLZXkgPz8gYHNka18ke2dsb2JhbFRoaXMuY3J5cHRvLnJhbmRvbVVVSUQoKX1gOwogICAgICAgIH0KICAgICAgICBjb25zdCBwYXlsb2FkID0gYm9keSA9PT0gdW5kZWZpbmVkID8gdW5kZWZpbmVkIDogSlNPTi5zdHJpbmdpZnkoYm9keSk7CiAgICAgICAgbGV0IGF0dGVtcHQgPSAwOwogICAgICAgIGZvciAoOzspIHsKICAgICAgICAgICAgY29uc3QgY3RsID0gbmV3IEFib3J0Q29udHJvbGxlcigpOwogICAgICAgICAgICBjb25zdCB0aW1lciA9IHNldFRpbWVvdXQoKCkgPT4gY3RsLmFib3J0KCksIHRoaXMudGltZW91dE1zKTsKICAgICAgICAgICAgY29uc3Qgb25BYm9ydCA9ICgpID0+IGN0bC5hYm9ydCgpOwogICAgICAgICAgICBvLnNpZ25hbD8uYWRkRXZlbnRMaXN0ZW5lcigiYWJvcnQiLCBvbkFib3J0LCB7IG9uY2U6IHRydWUgfSk7CiAgICAgICAgICAgIGxldCByZXMgPSBudWxsOwogICAgICAgICAgICBsZXQgbmV0RXJyID0gbnVsbDsKICAgICAgICAgICAgdHJ5IHsKICAgICAgICAgICAgICAgIHJlcyA9IGF3YWl0IHRoaXMuZmV0Y2hJbXBsKHVybCwgeyBtZXRob2QsIGhlYWRlcnMsIC4uLihwYXlsb2FkICE9PSB1bmRlZmluZWQgPyB7IGJvZHk6IHBheWxvYWQgfSA6IHt9KSwgc2lnbmFsOiBjdGwuc2lnbmFsIH0pOwogICAgICAgICAgICB9CiAgICAgICAgICAgIGNhdGNoIChlKSB7CiAgICAgICAgICAgICAgICBuZXRFcnIgPSBlOwogICAgICAgICAgICB9CiAgICAgICAgICAgIGZpbmFsbHkgewogICAgICAgICAgICAgICAgY2xlYXJUaW1lb3V0KHRpbWVyKTsKICAgICAgICAgICAgICAgIG8uc2lnbmFsPy5yZW1vdmVFdmVudExpc3RlbmVyKCJhYm9ydCIsIG9uQWJvcnQpOwogICAgICAgICAgICB9CiAgICAgICAgICAgIGlmIChvLnNpZ25hbD8uYWJvcnRlZCkKICAgICAgICAgICAgICAgIHRocm93IG5ldyBGaW5hbmNpYWxPU0Vycm9yKCJSZXF1ZXN0IGFib3J0ZWQuIiwgMCwgImFib3J0ZWQiLCAiYWJvcnRlZCIsIG51bGwpOwogICAgICAgICAgICBjb25zdCByZXRyeWFibGUgPSBuZXRFcnIgIT09IG51bGwgfHwgKHJlcyAhPT0gbnVsbCAmJiAocmVzLnN0YXR1cyA9PT0gNDI5IHx8IHJlcy5zdGF0dXMgPj0gNTAwKSk7CiAgICAgICAgICAgIGlmIChyZXRyeWFibGUgJiYgYXR0ZW1wdCA8IHRoaXMubWF4UmV0cmllcykgewogICAgICAgICAgICAgICAgY29uc3QgcmEgPSBOdW1iZXIocmVzPy5oZWFkZXJzLmdldCgicmV0cnktYWZ0ZXIiKSk7CiAgICAgICAgICAgICAgICBhd2FpdCBzbGVlcChOdW1iZXIuaXNGaW5pdGUocmEpICYmIHJhID4gMCA/IE1hdGgubWluKHJhLCA2MCkgKiAxMDAwIDogNTAwICogMiAqKiBhdHRlbXB0ICsgTWF0aC5yYW5kb20oKSAqIDI1MCk7CiAgICAgICAgICAgICAgICBhdHRlbXB0Kys7CiAgICAgICAgICAgICAgICBjb250aW51ZTsKICAgICAgICAgICAgfQogICAgICAgICAgICBpZiAoIXJlcykKICAgICAgICAgICAgICAgIHRocm93IG5ldyBGaW5hbmNpYWxPU0Vycm9yKGBOZXR3b3JrIGVycm9yOiAke25ldEVyciBpbnN0YW5jZW9mIEVycm9yID8gbmV0RXJyLm1lc3NhZ2UgOiBTdHJpbmcobmV0RXJyKX1gLCAwLCAiY29ubmVjdGlvbl9lcnJvciIsICJuZXR3b3JrX2Vycm9yIiwgbnVsbCk7CiAgICAgICAgICAgIGNvbnN0IHJlcXVlc3RJZCA9IHJlcy5oZWFkZXJzLmdldCgicmVxdWVzdC1pZCIpOwogICAgICAgICAgICBjb25zdCB0ZXh0ID0gYXdhaXQgcmVzLnRleHQoKTsKICAgICAgICAgICAgbGV0IGpzb24gPSBudWxsOwogICAgICAgICAgICB0cnkgewogICAgICAgICAgICAgICAganNvbiA9IHRleHQgPyBKU09OLnBhcnNlKHRleHQpIDogbnVsbDsKICAgICAgICAgICAgfQogICAgICAgICAgICBjYXRjaCB7CiAgICAgICAgICAgICAgICAvKiBub24tSlNPTiBib2R5IGhhbmRsZWQgYmVsb3cgKi8KICAgICAgICAgICAgfQogICAgICAgICAgICBpZiAoIXJlcy5vaykgewogICAgICAgICAgICAgICAgY29uc3QgZXJyID0ganNvbj8uZXJyb3I7CiAgICAgICAgICAgICAgICB0aHJvdyBuZXcgRmluYW5jaWFsT1NFcnJvcihlcnI/Lm1lc3NhZ2UgPz8gYEhUVFAgJHtyZXMuc3RhdHVzfWAsIHJlcy5zdGF0dXMsIGVycj8udHlwZSA/PyAiYXBpX2Vycm9yIiwgZXJyPy5jb2RlID8/ICJodHRwX2Vycm9yIiwgZXJyPy5yZXF1ZXN0X2lkID8/IHJlcXVlc3RJZCk7CiAgICAgICAgICAgIH0KICAgICAgICAgICAgcmV0dXJuIGpzb247CiAgICAgICAgfQogICAgfQp9Ci8qKgogKiBWZXJpZmllcyB0aGUgYGZvcy1zaWduYXR1cmVgIGhlYWRlciAodD08dW5peD4sdjE9PGhleCBITUFDLVNIQTI1NiBvZiAidC5yYXdCb2R5Ij4pIGFuZCByZXR1cm5zIHRoZSBwYXJzZWQgZXZlbnQuCiAqIFBhc3MgdGhlIFJBVyByZXF1ZXN0IGJvZHkgZXhhY3RseSBhcyByZWNlaXZlZCAobm90IHJlLXNlcmlhbGl6ZWQgSlNPTikuIFRocm93cyBvbiBhbnkgbWlzbWF0Y2guCiAqLwpleHBvcnQgYXN5bmMgZnVuY3Rpb24gdmVyaWZ5V2ViaG9vayhyYXdCb2R5LCBzaWduYXR1cmVIZWFkZXIsIHNlY3JldCwgb3B0cyA9IHt9KSB7CiAgICBpZiAoIXNpZ25hdHVyZUhlYWRlcikKICAgICAgICB0aHJvdyBuZXcgRmluYW5jaWFsT1NFcnJvcigiTWlzc2luZyBmb3Mtc2lnbmF0dXJlIGhlYWRlci4iLCA0MDAsICJzaWduYXR1cmVfZXJyb3IiLCAibWlzc2luZ19zaWduYXR1cmUiLCBudWxsKTsKICAgIGNvbnN0IHBhcnRzID0gT2JqZWN0LmZyb21FbnRyaWVzKHNpZ25hdHVyZUhlYWRlci5zcGxpdCgiLCIpLm1hcCgocCkgPT4gcC50cmltKCkuc3BsaXQoIj0iLCAyKSkpOwogICAgY29uc3QgdCA9IE51bWJlcihwYXJ0cy50KTsKICAgIGNvbnN0IHYxID0gcGFydHMudjEgPz8gIiI7CiAgICBpZiAoIU51bWJlci5pc0ludGVnZXIodCkgfHwgIS9eWzAtOWEtZl17NjR9JC8udGVzdCh2MSkpCiAgICAgICAgdGhyb3cgbmV3IEZpbmFuY2lhbE9TRXJyb3IoIk1hbGZvcm1lZCBmb3Mtc2lnbmF0dXJlIGhlYWRlci4iLCA0MDAsICJzaWduYXR1cmVfZXJyb3IiLCAibWFsZm9ybWVkX3NpZ25hdHVyZSIsIG51bGwpOwogICAgY29uc3Qgbm93ID0gb3B0cy5ub3cgPz8gTWF0aC5mbG9vcihEYXRlLm5vdygpIC8gMTAwMCk7CiAgICBpZiAoTWF0aC5hYnMobm93IC0gdCkgPiAob3B0cy50b2xlcmFuY2VTZWNvbmRzID8/IDMwMCkpCiAgICAgICAgdGhyb3cgbmV3IEZpbmFuY2lhbE9TRXJyb3IoIldlYmhvb2sgc2lnbmF0dXJlIHRpbWVzdGFtcCBpcyBvdXRzaWRlIHRoZSB0b2xlcmFuY2Ugd2luZG93LiIsIDQwMCwgInNpZ25hdHVyZV9lcnJvciIsICJ0aW1lc3RhbXBfb3V0X29mX3JhbmdlIiwgbnVsbCk7CiAgICBjb25zdCBleHBlY3RlZCA9IGF3YWl0IGhtYWNTaGEyNTZIZXgoc2VjcmV0LCBgJHt0fS4ke3Jhd0JvZHl9YCk7CiAgICBpZiAoIXRpbWluZ1NhZmVFcXVhbEhleChleHBlY3RlZCwgdjEpKQogICAgICAgIHRocm93IG5ldyBGaW5hbmNpYWxPU0Vycm9yKCJXZWJob29rIHNpZ25hdHVyZSBkb2VzIG5vdCBtYXRjaC4iLCA0MDAsICJzaWduYXR1cmVfZXJyb3IiLCAiaW52YWxpZF9zaWduYXR1cmUiLCBudWxsKTsKICAgIHJldHVybiBKU09OLnBhcnNlKHJhd0JvZHkpOwp9Ci8qKiBDb21wdXRlcyBhIHNpZ25hdHVyZSBoZWFkZXIsIGZvciB0ZXN0aW5nIHlvdXIgd2ViaG9vayBlbmRwb2ludCBsb2NhbGx5LiAqLwpleHBvcnQgYXN5bmMgZnVuY3Rpb24gc2lnbldlYmhvb2tQYXlsb2FkKHJhd0JvZHksIHNlY3JldCwgdGltZXN0YW1wID0gTWF0aC5mbG9vcihEYXRlLm5vdygpIC8gMTAwMCkpIHsKICAgIHJldHVybiBgdD0ke3RpbWVzdGFtcH0sdjE9JHthd2FpdCBobWFjU2hhMjU2SGV4KHNlY3JldCwgYCR7dGltZXN0YW1wfS4ke3Jhd0JvZHl9YCl9YDsKfQphc3luYyBmdW5jdGlvbiBobWFjU2hhMjU2SGV4KHNlY3JldCwgZGF0YSkgewogICAgY29uc3QgdGUgPSBuZXcgVGV4dEVuY29kZXIoKTsKICAgIGNvbnN0IGtleSA9IGF3YWl0IGdsb2JhbFRoaXMuY3J5cHRvLnN1YnRsZS5pbXBvcnRLZXkoInJhdyIsIHRlLmVuY29kZShzZWNyZXQpLCB7IG5hbWU6ICJITUFDIiwgaGFzaDogIlNIQS0yNTYiIH0sIGZhbHNlLCBbInNpZ24iXSk7CiAgICBjb25zdCBzaWcgPSBuZXcgVWludDhBcnJheShhd2FpdCBnbG9iYWxUaGlzLmNyeXB0by5zdWJ0bGUuc2lnbigiSE1BQyIsIGtleSwgdGUuZW5jb2RlKGRhdGEpKSk7CiAgICByZXR1cm4gQXJyYXkuZnJvbShzaWcsIChiKSA9PiBiLnRvU3RyaW5nKDE2KS5wYWRTdGFydCgyLCAiMCIpKS5qb2luKCIiKTsKfQpmdW5jdGlvbiB0aW1pbmdTYWZlRXF1YWxIZXgoYSwgYikgewogICAgaWYgKGEubGVuZ3RoICE9PSBiLmxlbmd0aCkKICAgICAgICByZXR1cm4gZmFsc2U7CiAgICBsZXQgZGlmZiA9IDA7CiAgICBmb3IgKGxldCBpID0gMDsgaSA8IGEubGVuZ3RoOyBpKyspCiAgICAgICAgZGlmZiB8PSBhLmNoYXJDb2RlQXQoaSkgXiBiLmNoYXJDb2RlQXQoaSk7CiAgICByZXR1cm4gZGlmZiA9PT0gMDsKfQpjb25zdCBlbmMgPSAocykgPT4gZW5jb2RlVVJJQ29tcG9uZW50KHMpOwpjb25zdCBzbGVlcCA9IChtcykgPT4gbmV3IFByb21pc2UoKHIpID0+IHNldFRpbWVvdXQociwgbXMpKTsKLyoqIEJyYW5kIGFsaWFzOiBgbmV3IENoYWludmFyYShrZXkpYCBpcyB0aGUgc2FtZSBjbGllbnQgYXMgYG5ldyBGaW5hbmNpYWxPUyhrZXkpYC4gKi8KZXhwb3J0IHsgRmluYW5jaWFsT1MgYXMgQ2hhaW52YXJhLCBGaW5hbmNpYWxPU0Vycm9yIGFzIENoYWludmFyYUVycm9yIH07Ci8qKiBWZXJpZmllcyB0aGUgZm9zLXNpZ25hdHVyZSBvZiBhbiBpbmNvbWluZyBjby1zaWduZXIgcmVxdWVzdCAocmF3IGJvZHkhKSBhbmQgcmV0dXJucyBpdCBwYXJzZWQuICovCmV4cG9ydCBhc3luYyBmdW5jdGlvbiB2ZXJpZnlDb3NpZ25lclJlcXVlc3QocmF3Qm9keSwgc2lnbmF0dXJlSGVhZGVyLCBzZWNyZXQsIG9wdHMgPSB7fSkgewogICAgY29uc3QgcGFyc2VkID0gKGF3YWl0IHZlcmlmeVdlYmhvb2socmF3Qm9keSwgc2lnbmF0dXJlSGVhZGVyLCBzZWNyZXQsIG9wdHMpKTsKICAgIGlmIChwYXJzZWQudHlwZSAhPT0gInRyYW5zZmVyLnNpZ25fcmVxdWVzdCIpCiAgICAgICAgdGhyb3cgbmV3IEZpbmFuY2lhbE9TRXJyb3IoIk5vdCBhIGNvLXNpZ25lciByZXF1ZXN0LiIsIDQwMCwgInNpZ25hdHVyZV9lcnJvciIsICJ1bmV4cGVjdGVkX3R5cGUiLCBudWxsKTsKICAgIHJldHVybiBwYXJzZWQ7Cn0KLyoqCiAqIEJ1aWxkcyB0aGUgc2lnbmVkIGFuc3dlciB0byByZXR1cm4gd2l0aCBIVFRQIDIwMDogc2VuZCBgYm9keWAgYXMgdGhlIHJlc3BvbnNlIGJvZHkgYW5kIGBoZWFkZXJzYCBhcyBoZWFkZXJzLgogKiAgIGNvbnN0IHsgYm9keSwgaGVhZGVycyB9ID0gYXdhaXQgY29zaWduZXJSZXNwb25zZShyZXEsICJhcHByb3ZlIiwgc2VjcmV0KTsKICovCmV4cG9ydCBhc3luYyBmdW5jdGlvbiBjb3NpZ25lclJlc3BvbnNlKHJlcXVlc3QsIGFjdGlvbiwgc2VjcmV0LCByZWFzb24pIHsKICAgIGNvbnN0IGJvZHkgPSBKU09OLnN0cmluZ2lmeSh7IHJlcXVlc3RfaWQ6IHJlcXVlc3QucmVxdWVzdF9pZCwgdHJhbnNmZXJfaWQ6IHJlcXVlc3QuZGF0YS5pZCwgYWN0aW9uLCAuLi4ocmVhc29uID8geyByZWFzb24gfSA6IHt9KSB9KTsKICAgIHJldHVybiB7IGJvZHksIGhlYWRlcnM6IHsgImNvbnRlbnQtdHlwZSI6ICJhcHBsaWNhdGlvbi9qc29uIiwgImZvcy1zaWduYXR1cmUiOiBhd2FpdCBzaWduV2ViaG9va1BheWxvYWQoYm9keSwgc2VjcmV0KSB9IH07Cn0KY29uc3QgdGUgPSBuZXcgVGV4dEVuY29kZXIoKTsKLyoqIFRTIDUuNysgdHlwZXMgVWludDhBcnJheSBvdmVyIEFycmF5QnVmZmVyTGlrZTsgV2ViQ3J5cHRvIHdhbnRzIEFycmF5QnVmZmVyLWJhY2tlZCB2aWV3cy4gKi8KY29uc3QgYnMgPSAodSkgPT4gdTsKY29uc3QgYjY0ID0gKHUpID0+IGJ0b2EoU3RyaW5nLmZyb21DaGFyQ29kZSguLi51KSk7CmNvbnN0IHVuYjY0ID0gKHMpID0+IFVpbnQ4QXJyYXkuZnJvbShhdG9iKHMpLCAoYykgPT4gYy5jaGFyQ29kZUF0KDApKTsKYXN5bmMgZnVuY3Rpb24gaGtkZihpa20sIHNhbHQsIGluZm8pIHsKICAgIGNvbnN0IGJhc2UgPSBhd2FpdCBnbG9iYWxUaGlzLmNyeXB0by5zdWJ0bGUuaW1wb3J0S2V5KCJyYXciLCBicyhpa20pLCAiSEtERiIsIGZhbHNlLCBbImRlcml2ZUJpdHMiXSk7CiAgICBjb25zdCBiaXRzID0gYXdhaXQgZ2xvYmFsVGhpcy5jcnlwdG8uc3VidGxlLmRlcml2ZUJpdHMoeyBuYW1lOiAiSEtERiIsIGhhc2g6ICJTSEEtMjU2Iiwgc2FsdDogdGUuZW5jb2RlKHNhbHQpLCBpbmZvOiB0ZS5lbmNvZGUoaW5mbykgfSwgYmFzZSwgMjU2KTsKICAgIHJldHVybiBnbG9iYWxUaGlzLmNyeXB0by5zdWJ0bGUuaW1wb3J0S2V5KCJyYXciLCBiaXRzLCAiQUVTLUdDTSIsIGZhbHNlLCBbImVuY3J5cHQiLCAiZGVjcnlwdCJdKTsKfQovKiogVmVyaWZpZXMgYSBrZXktc2hhcmUgcmVxdWVzdCAocmF3IGJvZHkhKSBhbmQgcmV0dXJucyBpdCBwYXJzZWQuICovCmV4cG9ydCBhc3luYyBmdW5jdGlvbiB2ZXJpZnlLZXlTaGFyZVJlcXVlc3QocmF3Qm9keSwgc2lnbmF0dXJlSGVhZGVyLCBzZWNyZXQsIG9wdHMgPSB7fSkgewogICAgY29uc3QgcGFyc2VkID0gKGF3YWl0IHZlcmlmeVdlYmhvb2socmF3Qm9keSwgc2lnbmF0dXJlSGVhZGVyLCBzZWNyZXQsIG9wdHMpKTsKICAgIGlmIChwYXJzZWQudHlwZSAhPT0gImtleV9zaGFyZS5zdG9yZSIgJiYgcGFyc2VkLnR5cGUgIT09ICJrZXlfc2hhcmUucmVxdWVzdCIpCiAgICAgICAgdGhyb3cgbmV3IEZpbmFuY2lhbE9TRXJyb3IoIk5vdCBhIGtleS1zaGFyZSByZXF1ZXN0LiIsIDQwMCwgInNpZ25hdHVyZV9lcnJvciIsICJ1bmV4cGVjdGVkX3R5cGUiLCBudWxsKTsKICAgIHJldHVybiBwYXJzZWQ7Cn0KLyoqIERlY3J5cHRzIHNoYXJlIEIgcmVjZWl2ZWQgaW4gYSBrZXlfc2hhcmUuc3RvcmUgcmVxdWVzdC4gU3RvcmUgdGhlIHJldHVybmVkIDMyIGJ5dGVzIHNlY3VyZWx5LiAqLwpleHBvcnQgYXN5bmMgZnVuY3Rpb24gb3BlblN0b3JlZFNoYXJlKHJlcXVlc3QsIHNlY3JldCkgewogICAgY29uc3Qga2V5ID0gYXdhaXQgaGtkZih0ZS5lbmNvZGUoc2VjcmV0KSwgcmVxdWVzdC5yZXF1ZXN0X2lkLCBgY2hhaW52YXJhLWtleS1zaGFyZS12MXxzdG9yZXwke3JlcXVlc3QuZGF0YS5rZXlfaWR9YCk7CiAgICBjb25zdCBwbGFpbiA9IGF3YWl0IGdsb2JhbFRoaXMuY3J5cHRvLnN1YnRsZS5kZWNyeXB0KHsgbmFtZTogIkFFUy1HQ00iLCBpdjogYnModW5iNjQocmVxdWVzdC5kYXRhLnNoYXJlLml2KSksIGFkZGl0aW9uYWxEYXRhOiB0ZS5lbmNvZGUocmVxdWVzdC5kYXRhLmtleV9pZCkgfSwga2V5LCBicyh1bmI2NChyZXF1ZXN0LmRhdGEuc2hhcmUuY3QpKSk7CiAgICByZXR1cm4gbmV3IFVpbnQ4QXJyYXkocGxhaW4pOwp9Ci8qKiBTaWduZWQgYW5zd2VyIHByb3ZpbmcgdGhlIHNoYXJlIHdhcyBzdG9yZWQgKENoYWludmFyYSBjaGVja3MgaXRzIFNIQS0yNTYpLiAqLwpleHBvcnQgYXN5bmMgZnVuY3Rpb24ga2V5U2hhcmVTdG9yZWRSZXNwb25zZShyZXF1ZXN0LCBzaGFyZSwgc2VjcmV0KSB7CiAgICBjb25zdCBkaWdlc3QgPSBuZXcgVWludDhBcnJheShhd2FpdCBnbG9iYWxUaGlzLmNyeXB0by5zdWJ0bGUuZGlnZXN0KCJTSEEtMjU2IiwgYnMoc2hhcmUpKSk7CiAgICBjb25zdCBib2R5ID0gSlNPTi5zdHJpbmdpZnkoeyByZXF1ZXN0X2lkOiByZXF1ZXN0LnJlcXVlc3RfaWQsIGtleV9pZDogcmVxdWVzdC5kYXRhLmtleV9pZCwgYWN0aW9uOiAic3RvcmVkIiwgc2hhcmVfc2hhMjU2OiBBcnJheS5mcm9tKGRpZ2VzdCwgKGIpID0+IGIudG9TdHJpbmcoMTYpLnBhZFN0YXJ0KDIsICIwIikpLmpvaW4oIiIpIH0pOwogICAgcmV0dXJuIHsgYm9keSwgaGVhZGVyczogeyAiY29udGVudC10eXBlIjogImFwcGxpY2F0aW9uL2pzb24iLCAiZm9zLXNpZ25hdHVyZSI6IGF3YWl0IHNpZ25XZWJob29rUGF5bG9hZChib2R5LCBzZWNyZXQpIH0gfTsKfQovKiogUmVsZWFzZXMgc2hhcmUgQiBmb3Igb25lIGFwcHJvdmVkIGludGVudCwgZW5jcnlwdGVkIHRvIENoYWludmFyYSdzIHNpbmdsZS11c2UgWDI1NTE5IGtleS4gKi8KZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGtleVNoYXJlUmVsZWFzZVJlc3BvbnNlKHJlcXVlc3QsIHNoYXJlLCBzZWNyZXQpIHsKICAgIGNvbnN0IHN1YnRsZSA9IGdsb2JhbFRoaXMuY3J5cHRvLnN1YnRsZTsKICAgIGNvbnN0IHJlY2lwaWVudCA9IGF3YWl0IHN1YnRsZS5pbXBvcnRLZXkoInJhdyIsIGJzKHVuYjY0KHJlcXVlc3QuZGF0YS5yZWNpcGllbnRfcHVibGljX2tleSkpLCB7IG5hbWU6ICJYMjU1MTkiIH0sIGZhbHNlLCBbXSk7CiAgICBjb25zdCBlcGggPSAoYXdhaXQgc3VidGxlLmdlbmVyYXRlS2V5KHsgbmFtZTogIlgyNTUxOSIgfSwgdHJ1ZSwgWyJkZXJpdmVCaXRzIl0pKTsKICAgIGNvbnN0IHNoYXJlZCA9IG5ldyBVaW50OEFycmF5KGF3YWl0IHN1YnRsZS5kZXJpdmVCaXRzKHsgbmFtZTogIlgyNTUxOSIsIHB1YmxpYzogcmVjaXBpZW50IH0sIGVwaC5wcml2YXRlS2V5LCAyNTYpKTsKICAgIGNvbnN0IGluZm8gPSBgcmVsZWFzZXwke3JlcXVlc3QuZGF0YS5rZXlfaWR9YDsKICAgIGNvbnN0IGtleSA9IGF3YWl0IGhrZGYoc2hhcmVkLCByZXF1ZXN0LnJlcXVlc3RfaWQsIGBjaGFpbnZhcmEta2V5LXNoYXJlLXYxfCR7aW5mb31gKTsKICAgIGNvbnN0IGl2ID0gZ2xvYmFsVGhpcy5jcnlwdG8uZ2V0UmFuZG9tVmFsdWVzKG5ldyBVaW50OEFycmF5KDEyKSk7CiAgICBjb25zdCBjdCA9IG5ldyBVaW50OEFycmF5KGF3YWl0IHN1YnRsZS5lbmNyeXB0KHsgbmFtZTogIkFFUy1HQ00iLCBpdjogYnMoaXYpLCBhZGRpdGlvbmFsRGF0YTogdGUuZW5jb2RlKGluZm8pIH0sIGtleSwgYnMoc2hhcmUpKSk7CiAgICBjb25zdCBlcGsgPSBuZXcgVWludDhBcnJheShhd2FpdCBzdWJ0bGUuZXhwb3J0S2V5KCJyYXciLCBlcGgucHVibGljS2V5KSk7CiAgICBjb25zdCBib2R5ID0gSlNPTi5zdHJpbmdpZnkoeyByZXF1ZXN0X2lkOiByZXF1ZXN0LnJlcXVlc3RfaWQsIGtleV9pZDogcmVxdWVzdC5kYXRhLmtleV9pZCwgYWN0aW9uOiAicmVsZWFzZSIsIGVudmVsb3BlOiB7IGVwazogYjY0KGVwayksIGl2OiBiNjQoaXYpLCBjdDogYjY0KGN0KSB9IH0pOwogICAgcmV0dXJuIHsgYm9keSwgaGVhZGVyczogeyAiY29udGVudC10eXBlIjogImFwcGxpY2F0aW9uL2pzb24iLCAiZm9zLXNpZ25hdHVyZSI6IGF3YWl0IHNpZ25XZWJob29rUGF5bG9hZChib2R5LCBzZWNyZXQpIH0gfTsKfQpleHBvcnQgYXN5bmMgZnVuY3Rpb24ga2V5U2hhcmVSZWplY3RSZXNwb25zZShyZXF1ZXN0LCByZWFzb24sIHNlY3JldCkgewogICAgY29uc3QgYm9keSA9IEpTT04uc3RyaW5naWZ5KHsgcmVxdWVzdF9pZDogcmVxdWVzdC5yZXF1ZXN0X2lkLCBrZXlfaWQ6IHJlcXVlc3QuZGF0YS5rZXlfaWQsIGFjdGlvbjogInJlamVjdCIsIHJlYXNvbiB9KTsKICAgIHJldHVybiB7IGJvZHksIGhlYWRlcnM6IHsgImNvbnRlbnQtdHlwZSI6ICJhcHBsaWNhdGlvbi9qc29uIiwgImZvcy1zaWduYXR1cmUiOiBhd2FpdCBzaWduV2ViaG9va1BheWxvYWQoYm9keSwgc2VjcmV0KSB9IH07Cn0K");

export const DIR = process.env.COSIGNER_DATA_DIR ?? path.join(process.env.LOCALAPPDATA ?? path.join(os.homedir(), ".local", "share"), "Chainvara", "cosigner");
const PORT = Number(process.env.COSIGNER_PORT ?? 8787);
const F = {
  secret: path.join(DIR, "secret.dpapi"),
  master: path.join(DIR, "master.dpapi"),
  shares: path.join(DIR, "shares.json"),
  approvals: path.join(DIR, "approvals.json"),
  policy: path.join(DIR, "policy.json"),
  log: path.join(DIR, "decisions.jsonl"),
  human: path.join(DIR, "human-approvals.json"),
  token: path.join(DIR, "local.token"),
};
const DEFAULT_POLICY = {
  paused: false,
  maxUsdPerTransfer: 10000,
  maxUsdPerDay: 50000,
  allowUnpricedAssets: true,
  allowedNetworks: [],
  allowedDestinations: [],
  blockedDestinations: [],
  humanApprovalAboveUsd: null,
  _help: "Amounts in US dollars. Empty allowedNetworks / allowedDestinations = any. allowedDestinations: only these addresses (with ?dt= / ?memo= where used) can receive. humanApprovalAboveUsd: above this amount (and for unpriced assets) a person approves on this machine. Changes apply to the next request.",
};
const APPROVAL_WINDOW_MS = 6 * 3600_000;
const MAX_BODY = 64 * 1024;

// ---------------------------------------------------------------- storage helpers

function ensureDir() {
  fs.mkdirSync(DIR, { recursive: true, mode: 0o700 });
  if (process.platform !== "win32") fs.chmodSync(DIR, 0o700);
  if (process.platform === "win32" && process.env.COSIGNER_TEST_NO_DPAPI !== "1") {
    // Only this Windows user (and SYSTEM) may read the folder.
    try {
      execFileSync("icacls", [DIR, "/inheritance:r", "/grant:r", `${process.env.USERNAME}:(OI)(CI)F`, "/grant:r", "SYSTEM:(OI)(CI)F"], { stdio: "ignore" });
    } catch {
      /* best effort */
    }
  }
}
const readJson = (file, fallback) => {
  try {
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch {
    return fallback;
  }
};
function writeJson(file, value) {
  const tmp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(value, null, 2));
  fs.renameSync(tmp, file);
}
const log = (entry) => fs.appendFileSync(F.log, `${JSON.stringify({ at: new Date().toISOString(), ...entry })}\n`);

/** Windows DPAPI (CurrentUser) through PowerShell. Elsewhere the files themselves are 0600 (tests: COSIGNER_TEST_NO_DPAPI=1). */
function dpapi(op, data) {
  if (process.env.COSIGNER_TEST_NO_DPAPI === "1" || process.platform !== "win32") return data;
  const script = `Add-Type -AssemblyName System.Security; $b=[Convert]::FromBase64String([Console]::In.ReadToEnd().Trim()); [Convert]::ToBase64String([Security.Cryptography.ProtectedData]::${op}($b,$null,'CurrentUser'))`;
  const out = execFileSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", script], { input: data.toString("base64") });
  return Buffer.from(out.toString().trim(), "base64");
}
const protect = (buf) => dpapi("Protect", buf);
const unprotect = (buf) => dpapi("Unprotect", buf);

function masterKey() {
  if (!fs.existsSync(F.master)) {
    const k = crypto.randomBytes(32);
    fs.writeFileSync(F.master, protect(k), { mode: 0o600 });
    return k;
  }
  return unprotect(fs.readFileSync(F.master));
}
function sealShare(master, keyId, share) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv("aes-256-gcm", master, iv);
  c.setAAD(Buffer.from(keyId));
  const ct = Buffer.concat([c.update(share), c.final(), c.getAuthTag()]);
  return { iv: iv.toString("base64"), ct: ct.toString("base64") };
}
function openShare(master, keyId, sealed) {
  const ct = Buffer.from(sealed.ct, "base64");
  const d = crypto.createDecipheriv("aes-256-gcm", master, Buffer.from(sealed.iv, "base64"));
  d.setAAD(Buffer.from(keyId));
  d.setAuthTag(ct.subarray(ct.length - 16));
  return Buffer.concat([d.update(ct.subarray(0, ct.length - 16)), d.final()]);
}

// ---------------------------------------------------------------- decisions

const today = () => new Date().toISOString().slice(0, 10);

/** Rules for transfer.sign_request. Returns null to approve, or a refusal reason. */
export function evaluateTransfer(policy, approvals, data) {
  if (policy.paused) return "Co-signer is paused.";
  if (Array.isArray(policy.allowedNetworks) && policy.allowedNetworks.length && !policy.allowedNetworks.includes(data.network)) return `Network ${data.network} is not allowed by the co-signer.`;
  const dest = String(data.destination ?? "").toLowerCase();
  if ((policy.blockedDestinations ?? []).some((d) => String(d).toLowerCase() === dest)) return "Destination is blocked by the co-signer.";
  const allowed = Array.isArray(policy.allowedDestinations) ? policy.allowedDestinations : [];
  if (allowed.length && !allowed.some((d) => sameDestination(d, data.destination))) return "Destination is not on the co-signer's allowed list.";
  const usd = typeof data.usd_value_cents === "number" ? data.usd_value_cents / 100 : null;
  if (usd === null) return policy.allowUnpricedAssets ? null : "Asset has no USD price and unpriced assets are not allowed.";
  if (usd > Number(policy.maxUsdPerTransfer)) return `Amount $${usd.toFixed(2)} is above the co-signer limit of $${policy.maxUsdPerTransfer} per transfer.`;
  const day = today();
  const already = approvals.some((a) => a.transfer_id === data.id && a.intent_hash === data.intent_hash);
  const spent = approvals.filter((a) => a.day === day).reduce((n, a) => n + (a.usd ?? 0), 0);
  if (!already && spent + usd > Number(policy.maxUsdPerDay)) return `Daily co-signer limit of $${policy.maxUsdPerDay} would be exceeded ($${spent.toFixed(2)} already approved today).`;
  return null;
}

/** EVM addresses compare case-insensitively; every other format (base58, tags, memos) must match exactly. */
export function sameDestination(a, b) {
  const x = String(a ?? "").trim();
  const y = String(b ?? "").trim();
  return /^0x[0-9a-fA-F]{40}$/.test(x) ? x.toLowerCase() === y.toLowerCase() : x === y;
}

/** Above humanApprovalAboveUsd (or for an asset without a USD price), a person must approve on this machine. */
export function needsHuman(policy, data) {
  const limit = policy.humanApprovalAboveUsd;
  if (limit === null || limit === undefined || limit === "") return false;
  if (typeof data.usd_value_cents !== "number") return true;
  return data.usd_value_cents / 100 > Number(limit);
}

/** Pending human approvals and decisions (decisions bind to the transfer id AND its intent hash). */
export function humanState() {
  const h = readJson(F.human, { pending: [], decided: [] });
  const now = Date.now();
  h.pending = (h.pending ?? []).filter((p) => Date.parse(p.at) > now - 86_400_000);
  h.decided = (h.decided ?? []).filter((d) => Date.parse(d.at) > now - 7 * 86_400_000);
  return h;
}

/** Records a person's decision for a pending transfer. Returns the entry, or null when nothing is pending for it. */
export function recordHumanDecision(transferId, action, by = os.userInfo().username, intentHash = null) {
  if (action !== "approve" && action !== "reject") throw new Error("action must be approve or reject");
  const h = humanState();
  const matches = h.pending.filter((x) => x.transfer_id === transferId && (intentHash === null || x.intent_hash === intentHash));
  if (matches.length > 1) throw new Error("Several versions of this transfer are waiting (amount or destination changed): decide on the approval page, which shows each one.");
  const p = matches[0];
  if (!p) return null;
  h.pending = h.pending.filter((x) => x !== p);
  const entry = { transfer_id: p.transfer_id, intent_hash: p.intent_hash, action, by, at: new Date().toISOString() };
  h.decided.push(entry);
  writeJson(F.human, h);
  log({ type: "human_decision", transfer_id: p.transfer_id, decision: action, by });
  return entry;
}

function localToken() {
  if (!fs.existsSync(F.token)) fs.writeFileSync(F.token, crypto.randomBytes(24).toString("base64url"), { mode: 0o600 });
  return fs.readFileSync(F.token, "utf8").trim();
}

export function createHandler({ secret, master, onPending }) {
  const seen = new Map(); // request_id → expiry (replay protection)
  return async function handle(rawBody, signature) {
    for (const [id, exp] of seen) if (exp < Date.now()) seen.delete(id);
    let type;
    try {
      type = JSON.parse(rawBody).type;
    } catch {
      return { status: 400, body: "bad request" };
    }
    let req;
    try {
      req = type === "transfer.sign_request" ? await sdk.verifyCosignerRequest(rawBody, signature, secret) : await sdk.verifyKeyShareRequest(rawBody, signature, secret);
    } catch (e) {
      log({ type, decision: "refused", reason: `signature: ${e?.code ?? e?.message ?? "invalid"}` });
      return { status: 401, body: "invalid signature" };
    }
    if (seen.has(req.request_id)) return { status: 409, body: "replay" };
    seen.set(req.request_id, Date.now() + 10 * 60_000);

    const policy = { ...DEFAULT_POLICY, ...readJson(F.policy, {}) };
    const approvals = readJson(F.approvals, []).filter((a) => Date.parse(a.at) > Date.now() - 2 * 86_400_000);

    if (req.type === "transfer.sign_request") {
      const d = req.data;
      const refusal = evaluateTransfer(policy, approvals, d);
      const base = { type: req.type, request_id: req.request_id, transfer_id: d.id, network: d.network, asset: d.asset?.symbol ?? d.asset?.id, amount: d.amount, usd: d.usd_value_cents ?? null, destination: d.destination };
      if (refusal) {
        log({ ...base, decision: "reject", reason: refusal });
        return { status: 200, ...(await sdk.cosignerResponse(req, "reject", secret, refusal)) };
      }
      if (needsHuman(policy, d)) {
        const h = humanState();
        const decided = h.decided.find((x) => x.transfer_id === d.id && x.intent_hash === d.intent_hash);
        if (decided?.action === "reject") {
          log({ ...base, decision: "reject", reason: `rejected by ${decided.by}` });
          return { status: 200, ...(await sdk.cosignerResponse(req, "reject", secret, "Rejected by a person on the co-signer.")) };
        }
        if (!decided) {
          if (!h.pending.some((x) => x.transfer_id === d.id && x.intent_hash === d.intent_hash)) {
            h.pending.push({ transfer_id: d.id, intent_hash: d.intent_hash, network: d.network, asset: d.asset?.symbol ?? d.asset?.id ?? "", amount: d.amount, usd: typeof d.usd_value_cents === "number" ? d.usd_value_cents / 100 : null, destination: d.destination, note: d.note ?? null, at: new Date().toISOString() });
            writeJson(F.human, h);
            log({ ...base, decision: "pending", reason: "waiting for a person" });
            onPending?.(d);
          }
          // Not 200: Chainvara keeps the transfer waiting and asks again until a person decides.
          return { status: 202, body: "Waiting for a person to approve on the co-signer." };
        }
      }
      if (!approvals.some((a) => a.transfer_id === d.id && a.intent_hash === d.intent_hash)) {
        approvals.push({ transfer_id: d.id, intent_hash: d.intent_hash, usd: typeof d.usd_value_cents === "number" ? d.usd_value_cents / 100 : 0, day: today(), at: new Date().toISOString() });
      }
      writeJson(F.approvals, approvals);
      log({ ...base, decision: "approve" });
      return { status: 200, ...(await sdk.cosignerResponse(req, "approve", secret)) };
    }

    const shares = readJson(F.shares, {});
    if (req.type === "key_share.store") {
      const d = req.data;
      const share = Buffer.from(await sdk.openStoredShare(req, secret));
      try {
        if (share.length !== 32) throw new Error("share must be 32 bytes");
        const existing = shares[d.key_id];
        if (existing && !openShare(master, d.key_id, existing.sealed).equals(share)) {
          log({ type: req.type, request_id: req.request_id, key_id: d.key_id, decision: "refused", reason: "a different share is already stored for this key" });
          return { status: 409, body: "conflict" };
        }
        if (!existing) {
          shares[d.key_id] = { network: d.network, address: d.address, stored_at: new Date().toISOString(), sealed: sealShare(master, d.key_id, share) };
          writeJson(F.shares, shares);
        }
        log({ type: req.type, request_id: req.request_id, key_id: d.key_id, network: d.network, address: d.address, decision: "stored" });
        return { status: 200, ...(await sdk.keyShareStoredResponse(req, share, secret)) };
      } finally {
        share.fill(0);
      }
    }

    // key_share.request
    const d = req.data;
    const reject = async (reason) => {
      log({ type: req.type, request_id: req.request_id, key_id: d.key_id, transfer_id: d.transfer_id, decision: "reject", reason });
      return { status: 200, ...(await sdk.keyShareRejectResponse(req, reason, secret)) };
    };
    if (policy.paused) return reject("Co-signer is paused.");
    const held = shares[d.key_id];
    if (!held) return reject("This co-signer does not hold a share for that key.");
    if (held.network !== d.network || held.address !== d.address) return reject("The key share does not belong to that wallet.");
    const ok = approvals.some((a) => a.transfer_id === d.transfer_id && a.intent_hash === d.intent_hash && Date.parse(a.at) > Date.now() - APPROVAL_WINDOW_MS);
    if (!ok) return reject("This co-signer has not approved that transfer.");
    const share = openShare(master, d.key_id, held.sealed);
    try {
      log({ type: req.type, request_id: req.request_id, key_id: d.key_id, transfer_id: d.transfer_id, decision: "release" });
      return { status: 200, ...(await sdk.keyShareReleaseResponse(req, share, secret)) };
    } finally {
      share.fill(0);
    }
  };
}

// ---------------------------------------------------------------- commands

function ask(question, { hidden = false } = {}) {
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: true });
    if (hidden) rl._writeToOutput = (s) => rl.output.write(s.includes(question) ? s : "*");
    rl.question(question, (a) => {
      rl.close();
      if (hidden) process.stdout.write("\n");
      resolve(a.trim());
    });
  });
}

/** Local approval page: 127.0.0.1 only, its own port (never exposed by the tunnel), secret token, same-host checks. */
function startApprovalServer(port) {
  const token = localToken();
  const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
  const okToken = (t) => typeof t === "string" && t.length === token.length && crypto.timingSafeEqual(Buffer.from(t), Buffer.from(token));
  const headers = { "content-type": "text/html; charset=utf-8", "cache-control": "no-store", "x-frame-options": "DENY", "referrer-policy": "no-referrer", "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'" };
  const page = () => {
    const h = humanState();
    const rows = h.pending.map((p) => `<tr><td>${esc(p.at.slice(0, 19).replace("T", " "))}</td><td>${esc(p.network)}</td><td><b>${esc(p.amount)} ${esc(p.asset)}</b>${p.usd !== null ? ` · $${esc(p.usd.toFixed(2))}` : " · no USD price"}</td><td class="m">${esc(p.destination)}</td><td>${esc(p.note ?? "")}</td><td><form method="post" action="/decide"><input type="hidden" name="t" value="${esc(token)}"><input type="hidden" name="transfer_id" value="${esc(p.transfer_id)}"><input type="hidden" name="intent_hash" value="${esc(p.intent_hash)}"><button name="action" value="approve" class="ok">Approve</button> <button name="action" value="reject">Reject</button></form></td></tr>`).join("");
    const done = h.decided.slice(-10).reverse().map((x) => `<li>${esc(x.at.slice(0, 19).replace("T", " "))} · ${esc(x.action)} · ${esc(x.transfer_id)} · ${esc(x.by)}</li>`).join("");
    return `<!doctype html><html><head><meta charset="utf-8"><meta http-equiv="refresh" content="10"><title>Chainvara co-signer approvals</title><style>body{font:14px system-ui,sans-serif;margin:32px;color:#111}table{border-collapse:collapse;width:100%}td,th{border-bottom:1px solid #ddd;padding:8px;text-align:left;vertical-align:top}.m{font-family:monospace;word-break:break-all}button{padding:6px 12px;border-radius:6px;border:1px solid #999;cursor:pointer}.ok{background:#127a4f;color:#fff;border-color:#127a4f}</style></head><body><h1>Transfers waiting for your approval</h1><p>Check the amount and the destination before approving. Nothing is signed until you approve.</p>${rows ? `<table><tr><th>Asked</th><th>Network</th><th>Amount</th><th>Destination</th><th>Note</th><th></th></tr>${rows}</table>` : "<p><i>Nothing waiting.</i></p>"}<h2>Recent decisions</h2><ul>${done || "<li>None</li>"}</ul></body></html>`;
  };
  const server = http.createServer((req, res) => {
    const host = String(req.headers.host ?? "");
    if (host !== `127.0.0.1:${port}` && host !== `localhost:${port}`) {
      res.writeHead(421);
      return res.end();
    }
    const url = new URL(req.url ?? "/", `http://${host}`);
    if (req.method === "GET" && url.pathname === "/") {
      if (!okToken(url.searchParams.get("t"))) {
        res.writeHead(403, headers);
        return res.end("Open the link printed by: node chainvara-cosigner.mjs approvals");
      }
      res.writeHead(200, headers);
      return res.end(page());
    }
    if (req.method === "POST" && url.pathname === "/decide") {
      let body = "";
      req.on("data", (c) => {
        body += c;
        if (body.length > 4096) req.destroy();
      });
      req.on("end", () => {
        const f = new URLSearchParams(body);
        if (!okToken(f.get("t") ?? "")) {
          res.writeHead(403, headers);
          return res.end("Forbidden");
        }
        const action = f.get("action");
        if (action === "approve" || action === "reject") recordHumanDecision(f.get("transfer_id") ?? "", action, `${os.userInfo().username} (approval page)`, f.get("intent_hash") ?? "");
        res.writeHead(303, { location: `/?t=${encodeURIComponent(token)}` });
        res.end();
      });
      return;
    }
    res.writeHead(404);
    res.end();
  });
  server.listen(port, "127.0.0.1");
  return `http://127.0.0.1:${port}/?t=${token}`;
}

async function serve() {
  if (!fs.existsSync(F.secret)) {
    console.error("No co-signer secret yet. Run: node chainvara-cosigner.mjs setup");
    process.exit(2);
  }
  const secret = unprotect(fs.readFileSync(F.secret)).toString("utf8");
  const master = masterKey();
  const approvalUrl = startApprovalServer(Number(process.env.COSIGNER_APPROVAL_PORT ?? PORT + 1));
  const onPending = (d) => console.log(`
>>> Approval needed: ${d.amount} ${d.asset?.symbol ?? ""} on ${d.network} to ${d.destination}
    Open ${approvalUrl}
    or run: node chainvara-cosigner.mjs approve ${d.id}`);
  const handle = createHandler({ secret, master, onPending });
  const server = http.createServer((req, res) => {
    if (req.method === "GET" && req.url === "/healthz") {
      const policy = { ...DEFAULT_POLICY, ...readJson(F.policy, {}) };
      res.writeHead(200, { "content-type": "application/json", "cache-control": "no-store" });
      return res.end(JSON.stringify({ ok: true, paused: Boolean(policy.paused) }));
    }
    if (req.method !== "POST" || (req.url !== "/" && req.url !== "/cosigner")) {
      res.writeHead(404);
      return res.end();
    }
    let size = 0;
    const chunks = [];
    req.on("data", (c) => {
      size += c.length;
      if (size > MAX_BODY) {
        res.writeHead(413);
        res.end();
        req.destroy();
      } else chunks.push(c);
    });
    req.on("end", async () => {
      if (res.writableEnded) return;
      try {
        const out = await handle(Buffer.concat(chunks).toString("utf8"), req.headers["fos-signature"]);
        res.writeHead(out.status, out.headers ?? { "content-type": "text/plain" });
        res.end(out.body);
      } catch (e) {
        log({ decision: "error", reason: String(e?.message ?? e).slice(0, 200) });
        res.writeHead(500);
        res.end("error");
      }
    });
  });
  server.listen(PORT, "127.0.0.1", () => console.log(`Chainvara co-signer listening on http://127.0.0.1:${PORT} · data in ${DIR}`));
}

async function main() {
  const [cmd = "serve", arg] = process.argv.slice(2);
  ensureDir();
  if (!fs.existsSync(F.policy)) writeJson(F.policy, DEFAULT_POLICY);
  if (cmd === "serve") return serve();
  if (cmd === "setup") {
    console.log("Paste the co-signer secret Chainvara showed you (Developers → API co-signer). It starts with cosk_.");
    const s = await ask("Secret: ", { hidden: true });
    if (!/^cosk_[A-Za-z0-9_-]{32}$/.test(s)) {
      console.error("That does not look like a Chainvara co-signer secret (cosk_ followed by 32 characters).");
      process.exit(1);
    }
    fs.writeFileSync(F.secret, protect(Buffer.from(s, "utf8")), { mode: 0o600 });
    masterKey();
    console.log(`Saved, protected by Windows for this user. Restart the co-signer window to use it.\nRules: ${F.policy}`);
    return;
  }
  if (cmd === "status") {
    const shares = readJson(F.shares, {});
    const approvals = readJson(F.approvals, []);
    const spent = approvals.filter((a) => a.day === today()).reduce((n, a) => n + (a.usd ?? 0), 0);
    console.log(JSON.stringify({ dataDir: DIR, secretConfigured: fs.existsSync(F.secret), sharesHeld: Object.keys(shares).length, approvedTodayUsd: spent, policy: readJson(F.policy, {}) }, null, 2));
    return;
  }
  if (cmd === "approvals") {
    const h = humanState();
    const port = Number(process.env.COSIGNER_APPROVAL_PORT ?? PORT + 1);
    console.log(h.pending.length ? h.pending.map((p) => `${p.transfer_id} · ${p.amount} ${p.asset} on ${p.network} → ${p.destination}${p.usd !== null ? ` ($${p.usd.toFixed(2)})` : ""}`).join("\n") : "Nothing waiting for approval.");
    console.log(`\nApproval page (this machine only): http://127.0.0.1:${port}/?t=${localToken()}`);
    return;
  }
  if (cmd === "approve" || cmd === "reject") {
    if (!arg) throw new Error(`Usage: node chainvara-cosigner.mjs ${cmd} <transfer_id>`);
    const r = recordHumanDecision(arg, cmd);
    console.log(r ? `${cmd === "approve" ? "Approved" : "Rejected"}: Chainvara picks it up at its next check (within a minute).` : "Nothing is waiting for that transfer id (see: approvals).");
    return;
  }
  if (cmd === "pause" || cmd === "resume") {
    writeJson(F.policy, { ...DEFAULT_POLICY, ...readJson(F.policy, {}), paused: cmd === "pause" });
    console.log(cmd === "pause" ? "Paused: every request is refused." : "Resumed.");
    return;
  }
  if (cmd === "backup") {
    if (!arg) throw new Error("Usage: node chainvara-cosigner.mjs backup <file>");
    const pass = await ask("Backup passphrase (12+ characters): ", { hidden: true });
    if (pass.length < 12 || pass !== (await ask("Repeat passphrase: ", { hidden: true }))) throw new Error("Passphrases are too short or do not match.");
    const master = masterKey();
    const shares = readJson(F.shares, {});
    const plain = Buffer.from(JSON.stringify(Object.fromEntries(Object.entries(shares).map(([k, v]) => [k, { network: v.network, address: v.address, share: openShare(master, k, v.sealed).toString("base64") }]))));
    const salt = crypto.randomBytes(16);
    const key = crypto.scryptSync(pass, salt, 32, { N: 2 ** 17, r: 8, p: 1, maxmem: 256 * 1024 * 1024 });
    const iv = crypto.randomBytes(12);
    const c = crypto.createCipheriv("aes-256-gcm", key, iv);
    const ct = Buffer.concat([c.update(plain), c.final(), c.getAuthTag()]);
    plain.fill(0);
    fs.writeFileSync(arg, JSON.stringify({ format: "chainvara-cosigner-backup-v1", kdf: "scrypt-N131072-r8-p1", salt: salt.toString("base64"), iv: iv.toString("base64"), ct: ct.toString("base64"), shares: Object.keys(shares).length }));
    console.log(`Backup written: ${arg} (${Object.keys(shares).length} shares). Keep it offline (USB key) and the passphrase somewhere else.`);
    return;
  }
  const openBackup = async (file) => {
    const b = JSON.parse(fs.readFileSync(file, "utf8"));
    if (b.format !== "chainvara-cosigner-backup-v1") throw new Error("Not a Chainvara co-signer backup.");
    const pass = await ask("Backup passphrase: ", { hidden: true });
    const key = crypto.scryptSync(pass, Buffer.from(b.salt, "base64"), 32, { N: 2 ** 17, r: 8, p: 1, maxmem: 256 * 1024 * 1024 });
    const ct = Buffer.from(b.ct, "base64");
    const d = crypto.createDecipheriv("aes-256-gcm", key, Buffer.from(b.iv, "base64"));
    d.setAuthTag(ct.subarray(ct.length - 16));
    try {
      return JSON.parse(Buffer.concat([d.update(ct.subarray(0, ct.length - 16)), d.final()]).toString("utf8"));
    } catch {
      throw new Error("Wrong passphrase, or the backup file is damaged.");
    }
  };
  if (cmd === "verify") {
    if (!arg) throw new Error("Usage: node chainvara-cosigner.mjs verify <file>");
    const entries = await openBackup(arg);
    const master = masterKey();
    const shares = readJson(F.shares, {});
    const missing = Object.keys(shares).filter((k) => !entries[k] || !openShare(master, k, shares[k].sealed).equals(Buffer.from(entries[k].share, "base64")));
    console.log(missing.length ? `Backup opens, but ${missing.length} current share(s) are missing or different: make a new backup.` : `Backup OK: it opens and holds all ${Object.keys(shares).length} current share(s).`);
    process.exit(missing.length ? 1 : 0);
  }
  if (cmd === "restore") {
    if (!arg) throw new Error("Usage: node chainvara-cosigner.mjs restore <file>");
    const entries = await openBackup(arg);
    const master = masterKey();
    const shares = readJson(F.shares, {});
    let added = 0;
    for (const [k, v] of Object.entries(entries)) {
      if (shares[k]) continue;
      shares[k] = { network: v.network, address: v.address, stored_at: new Date().toISOString(), sealed: sealShare(master, k, Buffer.from(v.share, "base64")) };
      added++;
    }
    writeJson(F.shares, shares);
    console.log(`Restored ${added} share(s).`);
    return;
  }
  console.error("Commands: setup | serve | status | pause | resume | backup <file> | restore <file> | verify <file> | approvals | approve <id> | reject <id>");
  process.exit(1);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((e) => {
    console.error(e?.message ?? e);
    process.exit(1);
  });
}
