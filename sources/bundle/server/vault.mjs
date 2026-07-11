/* ============================================================
   Vantage server — secret vault (hosted-design §5.2)
   AES-256-GCM envelope encryption for instance tokens and OSINT
   keys. Sealed blobs carry their key_id so the master key can be
   rotated: add the new key, re-seal on read, retire the old id.
   Format: v1.<key_id>.<iv>.<tag>.<ciphertext>  (base64url parts)
   ============================================================ */
import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";

const IV_BYTES = 12;

export function makeVault(masterKey, keyId = "k1") {
  if (!Buffer.isBuffer(masterKey) || masterKey.length !== 32) throw new Error("vault: master key must be a 32-byte Buffer");
  if (!/^[A-Za-z0-9_-]+$/.test(keyId)) throw new Error("vault: key_id must be base64url-safe");

  function seal(plaintext) {
    const iv = randomBytes(IV_BYTES);
    const cipher = createCipheriv("aes-256-gcm", masterKey, iv);
    cipher.setAAD(Buffer.from(keyId, "utf8")); // binds the blob to its key_id — a swapped id fails to open
    const ct = Buffer.concat([cipher.update(Buffer.from(plaintext, "utf8")), cipher.final()]);
    const tag = cipher.getAuthTag();
    return ["v1", keyId, iv.toString("base64url"), tag.toString("base64url"), ct.toString("base64url")].join(".");
  }

  function open(sealed) {
    const parts = String(sealed).split(".");
    if (parts.length !== 5 || parts[0] !== "v1") throw new Error("vault: unrecognized sealed format");
    const [, blobKeyId, ivB64, tagB64, ctB64] = parts;
    if (blobKeyId !== keyId) throw new Error(`vault: blob sealed with key_id "${blobKeyId}", vault holds "${keyId}"`);
    const decipher = createDecipheriv("aes-256-gcm", masterKey, Buffer.from(ivB64, "base64url"));
    decipher.setAAD(Buffer.from(blobKeyId, "utf8"));
    decipher.setAuthTag(Buffer.from(tagB64, "base64url"));
    return Buffer.concat([decipher.update(Buffer.from(ctB64, "base64url")), decipher.final()]).toString("utf8");
  }

  return { seal, open, keyId };
}
