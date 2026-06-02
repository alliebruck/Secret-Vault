import crypto from "node:crypto";

const ENCODING = "base64url";
const KEY_BYTES = 32;
const IV_BYTES = 12;
const SCRYPT_COST = 131072;

export function randomToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString(ENCODING);
}

export function hashToken(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
}

export function derivePasswordKey(password, salt) {
  return crypto.scryptSync(password, Buffer.from(salt, ENCODING), KEY_BYTES, {
    N: SCRYPT_COST,
    r: 8,
    p: 1,
    maxmem: 160 * 1024 * 1024
  });
}

export function encryptJson(value, key) {
  const iv = crypto.randomBytes(IV_BYTES);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const ciphertext = Buffer.concat([
    cipher.update(JSON.stringify(value), "utf8"),
    cipher.final()
  ]);
  const tag = cipher.getAuthTag();

  return JSON.stringify({
    v: 1,
    alg: "AES-256-GCM",
    iv: iv.toString(ENCODING),
    tag: tag.toString(ENCODING),
    ciphertext: ciphertext.toString(ENCODING)
  });
}

export function decryptJson(payload, key) {
  const parsed = JSON.parse(payload);
  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    key,
    Buffer.from(parsed.iv, ENCODING)
  );
  decipher.setAuthTag(Buffer.from(parsed.tag, ENCODING));
  const plaintext = Buffer.concat([
    decipher.update(Buffer.from(parsed.ciphertext, ENCODING)),
    decipher.final()
  ]);

  return JSON.parse(plaintext.toString("utf8"));
}

export function makeVaultKeyEnvelope(password, vaultKey = crypto.randomBytes(KEY_BYTES)) {
  const salt = crypto.randomBytes(16).toString(ENCODING);
  const wrappingKey = derivePasswordKey(password, salt);

  return {
    vaultKey,
    salt,
    encryptedVaultKey: encryptJson(vaultKey.toString(ENCODING), wrappingKey)
  };
}

export function unwrapVaultKey(password, salt, encryptedVaultKey) {
  const wrappingKey = derivePasswordKey(password, salt);
  const vaultKeyText = decryptJson(encryptedVaultKey, wrappingKey);
  return Buffer.from(vaultKeyText, ENCODING);
}
