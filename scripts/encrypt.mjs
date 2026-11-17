// Encrypts plan.json with a passcode (PBKDF2-SHA256 + AES-256-GCM).
// Usage: PASSCODE=... node encrypt.mjs <input.json> <output.json>
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { randomBytes, pbkdf2Sync, createCipheriv } from "node:crypto";

const [, , inPath, outPath] = process.argv;
const passcode = process.env.PASSCODE;
if (!passcode) throw new Error("PASSCODE env var required");

const iterations = 600000;
// Keep the existing salt so the passcode key stays the same between updates:
// remembered phones stay unlocked, and nothing keyed to it changes.
let salt = randomBytes(16);
if (existsSync(outPath)) {
  try { salt = Buffer.from(JSON.parse(readFileSync(outPath, "utf8")).salt, "base64"); } catch { /* new salt */ }
}
const iv = randomBytes(12);
const key = pbkdf2Sync(passcode, salt, iterations, 32, "sha256");

const cipher = createCipheriv("aes-256-gcm", key, iv);
const plaintext = readFileSync(inPath);
const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
const tag = cipher.getAuthTag();

writeFileSync(
  outPath,
  JSON.stringify(
    {
      v: 1,
      kdf: "PBKDF2-SHA256",
      iterations,
      salt: salt.toString("base64"),
      iv: iv.toString("base64"),
      tag: tag.toString("base64"),
      data: ciphertext.toString("base64"),
    },
    null,
    2
  ) + "\n"
);
console.log("Encrypted", inPath, "->", outPath);
