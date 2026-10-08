#!/usr/bin/env node
/**
 * Chainvara recovery tool — your exit plan. Runs offline, on your own machine, with Node.js 20+ and nothing else.
 *
 * Every wallet's key is split between Chainvara's vault and your co-signer. If Chainvara ever became unavailable, this
 * tool rebuilds each private key from:
 *   1. a recovery kit exported from the console (Settings → Recovery kit): Chainvara's share of every wallet,
 *      encrypted to YOUR recovery key — Chainvara cannot open it;
 *   2. your recovery key file (created here, protected by your passphrase);
 *   3. your co-signer backup (node chainvara-cosigner.mjs backup <file>) and its passphrase.
 * Each rebuilt key is checked against the wallet's public key before it is written out.
 *
 *   node chainvara-recovery.mjs keygen <recovery-key.json>         create your recovery key (once; keep it offline)
 *   node chainvara-recovery.mjs inspect <kit.json>                  list the wallets in a kit (no secret needed)
 *   node chainvara-recovery.mjs recover <kit.json> <recovery-key.json> <cosigner-backup.json> <out.json>
 *   node chainvara-recovery.mjs recover-cosigner <cosigner-backup.json> <recovery-key.json> <out.json>
 *       wallets with a backup share (2-of-3) only: rebuilt from your co-signer backup and its backup shares, no kit
 *
 * A wallet created with a backup share (2-of-3) needs any two of: Chainvara's share (in the kit), the co-signer's
 * share (in its backup) and the backup share (sealed to your recovery key, in both the kit and the co-signer backup).
 *
 * The output file holds plain private keys: write it to an encrypted disk, import what you need, then destroy it.
 */
import fs from "node:fs";
import crypto from "node:crypto";
import readline from "node:readline";
import { fileURLToPath } from "node:url";

export const KIT_FORMAT = "chainvara-recovery-kit-v1";
export const KEY_FORMAT = "chainvara-recovery-key-v1";
const KEY_PREFIX = "chainvara-recovery-key:";

// ---------------------------------------------------------------- encoding helpers

const b64url = (b) => Buffer.from(b).toString("base64url");
const sha256 = (b) => crypto.createHash("sha256").update(b).digest();
export const fingerprintOf = (publicKey) => sha256(Buffer.from(publicKey)).subarray(0, 8).toString("hex");

/** "chainvara-recovery-key:<base64url of the 32-byte X25519 public key>" → the key bytes, or null. */
export function parseRecoveryPublicKey(s) {
  const v = String(s ?? "").trim();
  if (!v.startsWith(KEY_PREFIX)) return null;
  const raw = Buffer.from(v.slice(KEY_PREFIX.length), "base64url");
  return raw.length === 32 && b64url(raw) === v.slice(KEY_PREFIX.length) ? raw : null;
}

const SPKI_X25519 = Buffer.from("302a300506032b656e032100", "hex");
const PKCS8_X25519 = Buffer.from("302e020100300506032b656e04220420", "hex");
const x25519Public = (raw) => crypto.createPublicKey({ key: Buffer.concat([SPKI_X25519, raw]), format: "der", type: "spki" });
const x25519Private = (raw) => crypto.createPrivateKey({ key: Buffer.concat([PKCS8_X25519, raw]), format: "der", type: "pkcs8" });

/** ECIES: ephemeral X25519, HKDF-SHA256 (info binds the wallet), AES-256-GCM. Same construction as the console. */
export function openForRecovery(privateRaw, sealed, info) {
  const shared = crypto.diffieHellman({ privateKey: x25519Private(privateRaw), publicKey: x25519Public(Buffer.from(sealed.epk, "base64")) });
  const key = Buffer.from(crypto.hkdfSync("sha256", shared, Buffer.from(sealed.epk, "base64"), Buffer.from(`chainvara-recovery|${info}`), 32));
  const ct = Buffer.from(sealed.ct, "base64");
  const d = crypto.createDecipheriv("aes-256-gcm", key, Buffer.from(sealed.iv, "base64"));
  d.setAuthTag(ct.subarray(ct.length - 16));
  return Buffer.concat([d.update(ct.subarray(0, ct.length - 16)), d.final()]);
}

export function sealForRecovery(publicRaw, plaintext, info) {
  const eph = crypto.generateKeyPairSync("x25519");
  const epk = eph.publicKey.export({ format: "der", type: "spki" }).subarray(-32);
  const shared = crypto.diffieHellman({ privateKey: eph.privateKey, publicKey: x25519Public(Buffer.from(publicRaw)) });
  const key = Buffer.from(crypto.hkdfSync("sha256", shared, epk, Buffer.from(`chainvara-recovery|${info}`), 32));
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv("aes-256-gcm", key, iv);
  const ct = Buffer.concat([c.update(plaintext), c.final(), c.getAuthTag()]);
  return { epk: epk.toString("base64"), iv: iv.toString("base64"), ct: ct.toString("base64") };
}

// ---------------------------------------------------------------- curve arithmetic (BigInt)

const mod = (a, m) => ((a % m) + m) % m;
function inv(a, m) {
  let [r0, r1, s0, s1] = [mod(a, m), m, 1n, 0n];
  while (r1 !== 0n) {
    const q = r0 / r1;
    [r0, r1] = [r1, r0 - q * r1];
    [s0, s1] = [s1, s0 - q * s1];
  }
  if (r0 !== 1n) throw new Error("not invertible");
  return mod(s0, m);
}
const beToBig = (b) => BigInt(`0x${Buffer.from(b).toString("hex") || "0"}`);
const leToBig = (b) => beToBig(Buffer.from(b).reverse());
const bigToBe = (n, len = 32) => Buffer.from(n.toString(16).padStart(len * 2, "0"), "hex");
const bigToLe = (n, len = 32) => bigToBe(n, len).reverse();

// secp256k1
const SECP_N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
/** Compressed public key of a secp256k1 scalar (Node's own implementation). */
export function secpPublicKey(scalar) {
  const e = crypto.createECDH("secp256k1");
  e.setPrivateKey(bigToBe(scalar));
  return e.getPublicKey(null, "compressed");
}

// ed25519 (RFC 8032 group arithmetic, extended coordinates)
const P = 2n ** 255n - 19n;
const L = 2n ** 252n + 27742317777372353535851937790883648493n;
const D = mod(-121665n * inv(121666n, P), P);
const BX = 15112221349535400772501151409588531511454012693041857206046113283949847762202n;
const BY = 46316835694926478169428394003475163141307993866256225615783033603165251855960n;
const BASE = [BX, BY, 1n, mod(BX * BY, P)];
function edAdd([X1, Y1, Z1, T1], [X2, Y2, Z2, T2]) {
  const A = mod((Y1 - X1) * (Y2 - X2), P), B = mod((Y1 + X1) * (Y2 + X2), P), C = mod(2n * D * T1 * T2, P), Dd = mod(2n * Z1 * Z2, P);
  const E = B - A, F = Dd - C, G = Dd + C, H = B + A;
  return [mod(E * F, P), mod(G * H, P), mod(F * G, P), mod(E * H, P)];
}
function edMul(n, pt = BASE) {
  let r = [0n, 1n, 1n, 0n];
  let q = pt;
  for (let k = mod(n, L); k > 0n; k >>= 1n) {
    if (k & 1n) r = edAdd(r, q);
    q = edAdd(q, q);
  }
  return r;
}
function edEncode([X, Y, Z]) {
  const zi = inv(Z, P);
  const x = mod(X * zi, P), y = mod(Y * zi, P);
  const out = bigToLe(y);
  if (x & 1n) out[31] |= 0x80;
  return out;
}
/** Ed25519 public key of a raw scalar (what FROST shares combine into). */
export const edPublicKey = (scalar) => edEncode(edMul(scalar));

/**
 * A standard Ed25519 signature made directly from the scalar (no seed exists for a FROST key): nonce r derived from
 * the scalar and the message, R = rB, S = r + H(R‖A‖M)·a mod L. Every Ed25519 verifier accepts it.
 */
export function edSignWithScalar(scalarLeHex, message) {
  const a = mod(leToBig(Buffer.from(scalarLeHex, "hex")), L);
  const A = edPublicKey(a);
  const r = mod(leToBig(crypto.createHash("sha512").update(Buffer.concat([Buffer.from("chainvara-recovery-nonce"), bigToLe(a), Buffer.from(message)])).digest()), L);
  const R = edEncode(edMul(r));
  const k = mod(leToBig(crypto.createHash("sha512").update(Buffer.concat([R, A, Buffer.from(message)])).digest()), L);
  return Buffer.concat([R, bigToLe(mod(r + k * a, L))]);
}

// ---------------------------------------------------------------- share recombination (2-of-2, participants 1 and 2)

function invMod(a, m) {
  let [r0, r1, s0, s1] = [mod(a, m), m, 1n, 0n];
  while (r1 !== 0n) {
    const q = r0 / r1;
    [r0, r1, s0, s1] = [r1, r0 - q * r1, s1, s0 - q * s1];
  }
  if (r0 !== 1n) throw new Error("not invertible");
  return mod(s0, m);
}

/** Secret at 0 from two Shamir shares of participants i and j (for 1 and 2: 2·s1 − s2). */
const lagrange = (a, b, n) => mod(a.share * b.id * invMod(b.id - a.id, n) + b.share * a.id * invMod(a.id - b.id, n), n);

/** One participant's share of an MPC key (ECDSA party JSON, or a FROST key package). */
function mpcShare(material, suite) {
  if (suite === "ecdsa") {
    const p = JSON.parse(material.party ?? material.key_package);
    return { id: BigInt(p.party_index), share: beToBig(Buffer.from(p.poly_point, "hex")) };
  }
  return frostShare(material.key_package, suite);
}

/** FROST key package (binary, frost-core 3): 5-byte header, identifier, signing share, verifying share, verifying key. */
function frostShare(keyPackageHex, suite) {
  const b = Buffer.from(keyPackageHex, "hex");
  const id = b.subarray(5, 37), share = b.subarray(37, 69);
  return suite === "taproot" ? { id: beToBig(id), share: beToBig(share) } : { id: leToBig(id), share: leToBig(share) };
}

/**
 * Rebuilds one wallet's private key from Chainvara's material (vault) and the co-signer's (backup entry), and checks it
 * against the wallet's public key. Returns { kind, secretHex, publicKey } or throws.
 */
export function rebuildKey(wallet, vault, cosigner, backup = null) {
  const mode = wallet.share_mode;
  if (mode === "single") {
    return checked(wallet, wallet.curve === "ed25519" ? "ed25519-seed" : "secp256k1", Buffer.from(vault.secret, "base64"));
  }
  if (mode === "split_cosigner") {
    if (!cosigner?.share) throw new Error("the co-signer backup has no share for this key");
    const a = Buffer.from(vault.shareA, "base64"), b = Buffer.from(cosigner.share, "base64");
    if (a.length !== 32 || b.length !== 32) throw new Error("unexpected split share length");
    return checked(wallet, wallet.curve === "ed25519" ? "ed25519-seed" : "secp256k1", Buffer.from(a.map((x, i) => x ^ b[i])));
  }
  if (mode === "mpc_cosigner") {
    // Any two distinct participants: 1 = Chainvara (kit), 2 = co-signer (its backup), 3 = backup share (2-of-3 keys).
    const materials = [vault, cosigner?.key_package ? cosigner : null, backup].filter(Boolean);
    const suite = materials.some((m) => m.suite === "ecdsa") ? "ecdsa" : materials.some((m) => m.suite === "taproot") ? "taproot" : "ed25519";
    const shares = [];
    for (const m of materials) {
      const sh = mpcShare(m, suite);
      if (!shares.some((x) => x.id === sh.id)) shares.push(sh);
    }
    if (shares.length < 2) throw new Error(cosigner?.key_package || backup ? "two different shares are needed" : "the co-signer backup has no MPC share for this key");
    const [a, b] = shares;
    if (suite === "ecdsa") return checked(wallet, "secp256k1", bigToBe(lagrange(a, b, SECP_N)));
    if (suite === "taproot") return checked(wallet, "taproot", bigToBe(lagrange(a, b, SECP_N)));
    return checked(wallet, "ed25519-scalar", bigToLe(lagrange(a, b, L)));
  }
  throw new Error(`share mode ${mode} is not recoverable with this kit`);
}

/** BIP-341 key-path tweak with no script tree (BIP-86): the output key's secret and x-only public key. */
export function taprootTweak(internalSecret) {
  let d = beToBig(internalSecret);
  const P = secpPublicKey(d);
  if (P[0] === 0x03) d = SECP_N - d; // BIP-340: the internal key is taken with an even y
  const tag = sha256(Buffer.from("TapTweak"));
  const t = beToBig(sha256(Buffer.concat([tag, tag, P.subarray(1)])));
  if (t >= SECP_N) throw new Error("invalid tweak");
  const q = mod(d + t, SECP_N);
  return { secret: bigToBe(q), outputKey: secpPublicKey(q).subarray(1) };
}

function checked(wallet, kind, secret) {
  if (kind === "taproot") {
    const expected = String(wallet.public_key ?? "").toLowerCase().slice(-64);
    const internal = secpPublicKey(beToBig(secret)).subarray(1).toString("hex");
    if (taprootTweak(secret).outputKey.toString("hex") !== expected && internal !== expected) {
      throw new Error("the rebuilt key does not match the wallet's public key (a share is from another generation: use the co-signer backup made after the last refresh)");
    }
    return { kind, secretHex: secret.toString("hex"), publicKey: internal };
  }
  const pub = kind === "ed25519-seed"
    ? crypto.createPublicKey(crypto.createPrivateKey({ key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), secret]), format: "der", type: "pkcs8" })).export({ format: "der", type: "spki" }).subarray(-32)
    : kind === "ed25519-scalar" ? edPublicKey(leToBig(secret))
    : secpPublicKey(beToBig(secret));
  const expected = String(wallet.public_key ?? "").toLowerCase();
  const got = pub.toString("hex");
  if (got !== expected) throw new Error("the rebuilt key does not match the wallet's public key (a share is from another generation: use the co-signer backup made after the last refresh)");
  return { kind, secretHex: secret.toString("hex"), publicKey: got };
}

// ---------------------------------------------------------------- output formats

const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function base58check(payload) {
  const data = Buffer.concat([payload, sha256(sha256(payload)).subarray(0, 4)]);
  let n = beToBig(data);
  let s = "";
  while (n > 0n) {
    s = B58[Number(n % 58n)] + s;
    n /= 58n;
  }
  for (const byte of data) {
    if (byte !== 0) break;
    s = `1${s}`;
  }
  return s;
}
const WIF_VERSION = { bitcoin: 0x80, litecoin: 0xb0, dogecoin: 0x9e, "bitcoin-testnet4": 0xef, "litecoin-testnet": 0xef };

/** What to import where, per kind of key. */
export function formats(network, r) {
  const hex = r.secretHex;
  if (r.kind === "ed25519-seed") return { seed_hex: hex, note: "Ed25519 seed: import it as the private key in a wallet for this network." };
  if (r.kind === "ed25519-scalar") {
    return { scalar_hex_le: hex, note: "FROST keys have no seed: this is the Ed25519 secret scalar. Sign with it directly (this tool's edSignWithScalar, or any library that accepts an expanded Ed25519 secret key)." };
  }
  const wif = WIF_VERSION[network] !== undefined ? base58check(Buffer.concat([Buffer.from([WIF_VERSION[network]]), Buffer.from(hex, "hex"), Buffer.from([1])])) : null;
  if (r.kind === "taproot") return { private_key_hex: hex, wif, descriptor: wif ? `tr(${wif})` : null, note: "Bitcoin Taproot (BIP-86 key path): import the descriptor tr(WIF) in Bitcoin Core or Sparrow." };
  return { private_key_hex: hex, ...(wif ? { wif } : {}), note: wif ? "Import the WIF in a wallet for this network." : "Import the hex private key (MetaMask, TronLink, Keplr…)." };
}

/** Opens a kit with the recovery private key and recombines every wallet with the co-signer backup content. */
export function recoverAll(kit, recoveryPrivateRaw, backupContent) {
  if (kit.format !== KIT_FORMAT) throw new Error("Not a Chainvara recovery kit.");
  const out = [];
  for (const w of kit.wallets) {
    try {
      const vault = JSON.parse(openForRecovery(recoveryPrivateRaw, w.sealed, `${kit.organization_id}|${w.key_id}`).toString("utf8"));
      const cos = w.share_mode === "split_cosigner" ? backupContent?.split?.[w.key_id] : w.share_mode === "mpc_cosigner" ? backupContent?.mpc?.[w.key_id] : null;
      // 2-of-3: the backup share in the kit (or in the co-signer backup) stands in for a missing co-signer share.
      const sealedBackup = w.backup_share ?? cos?.backup_share ?? null;
      const backup = sealedBackup ? JSON.parse(openForRecovery(recoveryPrivateRaw, sealedBackup, `backup|${w.key_id}`).toString("utf8")) : null;
      const r = rebuildKey(w, vault, w.share_mode === "mpc_cosigner" && !cos?.key_package ? null : cos, backup);
      out.push({ wallet_id: w.wallet_id, label: w.label, network: w.network, address: w.address, public_key: r.publicKey, key_kind: r.kind, ...formats(w.network, r) });
    } catch (e) {
      out.push({ wallet_id: w.wallet_id, label: w.label, network: w.network, address: w.address, error: String(e?.message ?? e) });
    }
  }
  return out;
}

/**
 * Without a kit (Chainvara gone and no kit exported): every 2-of-3 wallet of a co-signer backup is rebuilt from the
 * co-signer's share and the backup share stored next to it, sealed to the recovery key.
 */
export function recoverFromCosigner(backupContent, recoveryPrivateRaw) {
  const out = [];
  for (const [keyId, m] of Object.entries(backupContent?.mpc ?? {})) {
    if (!m.backup_share) continue;
    const wallet = { network: m.network, address: m.address, public_key: m.public_key, share_mode: "mpc_cosigner" };
    try {
      const backup = JSON.parse(openForRecovery(recoveryPrivateRaw, m.backup_share, `backup|${keyId}`).toString("utf8"));
      const r = rebuildKey(wallet, backup, m);
      out.push({ key_id: keyId, network: m.network, address: m.address, public_key: r.publicKey, key_kind: r.kind, ...formats(m.network, r) });
    } catch (e) {
      out.push({ key_id: keyId, network: m.network, address: m.address, error: String(e?.message ?? e) });
    }
  }
  return out;
}

// ---------------------------------------------------------------- recovery key file (passphrase-protected)

const SCRYPT = { N: 2 ** 17, r: 8, p: 1, maxmem: 256 * 1024 * 1024 };
export function writeRecoveryKey(pass) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("x25519");
  const pub = publicKey.export({ format: "der", type: "spki" }).subarray(-32);
  const priv = privateKey.export({ format: "der", type: "pkcs8" }).subarray(-32);
  const salt = crypto.randomBytes(16), iv = crypto.randomBytes(12);
  const key = crypto.scryptSync(pass, salt, 32, SCRYPT);
  const c = crypto.createCipheriv("aes-256-gcm", key, iv);
  const ct = Buffer.concat([c.update(priv), c.final(), c.getAuthTag()]);
  priv.fill(0);
  const publicText = `${KEY_PREFIX}${b64url(pub)}`;
  return { file: { format: KEY_FORMAT, public_key: publicText, fingerprint: fingerprintOf(pub), kdf: "scrypt-N131072-r8-p1", salt: salt.toString("base64"), iv: iv.toString("base64"), ct: ct.toString("base64") }, publicKey: publicText };
}
export function openRecoveryKey(file, pass) {
  if (file.format !== KEY_FORMAT) throw new Error("Not a Chainvara recovery key file.");
  const key = crypto.scryptSync(pass, Buffer.from(file.salt, "base64"), 32, SCRYPT);
  const ct = Buffer.from(file.ct, "base64");
  const d = crypto.createDecipheriv("aes-256-gcm", key, Buffer.from(file.iv, "base64"));
  d.setAuthTag(ct.subarray(ct.length - 16));
  try {
    return Buffer.concat([d.update(ct.subarray(0, ct.length - 16)), d.final()]);
  } catch {
    throw new Error("Wrong passphrase, or the recovery key file is damaged.");
  }
}
export function openCosignerBackup(b, pass) {
  if (b.format !== "chainvara-cosigner-backup-v1" && b.format !== "chainvara-cosigner-backup-v2") throw new Error("Not a Chainvara co-signer backup.");
  const key = crypto.scryptSync(pass, Buffer.from(b.salt, "base64"), 32, SCRYPT);
  const ct = Buffer.from(b.ct, "base64");
  const d = crypto.createDecipheriv("aes-256-gcm", key, Buffer.from(b.iv, "base64"));
  d.setAuthTag(ct.subarray(ct.length - 16));
  let content;
  try {
    content = JSON.parse(Buffer.concat([d.update(ct.subarray(0, ct.length - 16)), d.final()]).toString("utf8"));
  } catch {
    throw new Error("Wrong co-signer backup passphrase, or the backup is damaged.");
  }
  return "split" in content || "mpc" in content ? { split: content.split ?? {}, mpc: content.mpc ?? {} } : { split: content, mpc: {} };
}

// ---------------------------------------------------------------- command line

function ask(q, hidden = false) {
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: true });
    if (hidden) rl._writeToOutput = (s) => rl.output.write(s.includes(q) ? q : "");
    rl.question(q, (a) => {
      rl.close();
      if (hidden) process.stdout.write("\n");
      resolve(a);
    });
  });
}

async function main([cmd, ...args]) {
  if (cmd === "keygen") {
    const [file] = args;
    if (!file) throw new Error("Usage: keygen <recovery-key.json>");
    if (fs.existsSync(file)) throw new Error(`${file} already exists.`);
    const pass = await ask("Passphrase for the recovery key (16+ characters): ", true);
    if (pass.length < 16 || pass !== (await ask("Repeat: ", true))) throw new Error("Passphrases are too short or do not match.");
    const { file: content, publicKey } = writeRecoveryKey(pass);
    fs.writeFileSync(file, JSON.stringify(content, null, 2), { mode: 0o600 });
    console.log(`Recovery key written to ${file} (fingerprint ${content.fingerprint}). Keep it offline, the passphrase elsewhere.\nPaste this public key in Chainvara (Settings → Recovery kit):\n\n${publicKey}\n`);
    return;
  }
  if (cmd === "inspect") {
    const kit = JSON.parse(fs.readFileSync(args[0], "utf8"));
    if (kit.format !== KIT_FORMAT) throw new Error("Not a Chainvara recovery kit.");
    console.log(`Kit for ${kit.organization_name} (${kit.environment}), made ${kit.created_at}, for recovery key ${kit.recovery_key_fingerprint}: ${kit.wallets.length} wallet(s)`);
    for (const w of kit.wallets) console.log(`  ${w.network.padEnd(18)} ${w.address}  ${w.share_mode}  ${w.label}`);
    return;
  }
  if (cmd === "recover") {
    const [kitFile, keyFile, backupFile, outFile] = args;
    if (!outFile) throw new Error("Usage: recover <kit.json> <recovery-key.json> <cosigner-backup.json> <out.json>");
    const kit = JSON.parse(fs.readFileSync(kitFile, "utf8"));
    const priv = openRecoveryKey(JSON.parse(fs.readFileSync(keyFile, "utf8")), await ask("Recovery key passphrase: ", true));
    const backup = openCosignerBackup(JSON.parse(fs.readFileSync(backupFile, "utf8")), await ask("Co-signer backup passphrase: ", true));
    const out = recoverAll(kit, priv, backup);
    priv.fill(0);
    fs.writeFileSync(outFile, JSON.stringify({ warning: "PLAIN PRIVATE KEYS. Import what you need, then destroy this file.", recovered_at: new Date().toISOString(), wallets: out }, null, 2), { mode: 0o600 });
    const bad = out.filter((w) => w.error);
    console.log(`${out.length - bad.length} of ${out.length} key(s) rebuilt and checked against their public keys → ${outFile}`);
    for (const w of bad) console.log(`  not recovered: ${w.network} ${w.address}: ${w.error}`);
    return;
  }
  if (cmd === "recover-cosigner") {
    const [backupFile, keyFile, outFile] = args;
    if (!outFile) throw new Error("Usage: recover-cosigner <cosigner-backup.json> <recovery-key.json> <out.json>");
    const backup = openCosignerBackup(JSON.parse(fs.readFileSync(backupFile, "utf8")), await ask("Co-signer backup passphrase: ", true));
    const priv = openRecoveryKey(JSON.parse(fs.readFileSync(keyFile, "utf8")), await ask("Recovery key passphrase: ", true));
    const out = recoverFromCosigner(backup, priv);
    priv.fill(0);
    fs.writeFileSync(outFile, JSON.stringify({ warning: "PLAIN PRIVATE KEYS. Import what you need, then destroy this file.", recovered_at: new Date().toISOString(), wallets: out }, null, 2), { mode: 0o600 });
    const bad = out.filter((w) => w.error);
    console.log(`${out.length - bad.length} of ${out.length} key(s) with a backup share rebuilt and checked → ${outFile}`);
    for (const w of bad) console.log(`  not recovered: ${w.network} ${w.address}: ${w.error}`);
    return;
  }
  console.log("Commands: keygen <file> · inspect <kit> · recover <kit> <recovery-key> <cosigner-backup> <out> · recover-cosigner <cosigner-backup> <recovery-key> <out>");
}

if (process.argv[1] && fileURLToPath(import.meta.url) === fs.realpathSync(process.argv[1])) {
  main(process.argv.slice(2)).catch((e) => {
    console.error(`Error: ${e.message}`);
    process.exit(1);
  });
}
