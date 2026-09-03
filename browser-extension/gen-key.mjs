// Generates the RSA keypair that gives this extension a stable ID for
// self-hosted / enterprise-forced installs (bypasses each browser's web
// store entirely). Same algorithm Chrome/Edge use to derive an extension ID
// from its public key -- ported from extension/scripts/gen-key.mjs +
// extension-id.mjs rather than shared with that (older, unrelated)
// codebase, since this is a standalone extension with no other dependency
// on it.
//
// Run once: node gen-key.mjs
// Keep key.pem private -- losing it changes the extension ID and every
// enrolled machine's local-API allow-list needs re-pointing.
import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync } from 'crypto';
import { existsSync, writeFileSync, readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import path from 'path';

function extensionIdFromKeyPem(privateKeyPem) {
  const privateKeyObj = createPrivateKey(privateKeyPem);
  const publicKeyDer = createPublicKey(privateKeyObj).export({ type: 'spki', format: 'der' });
  const hash = createHash('sha256').update(publicKeyDer).digest();
  const idBytes = hash.subarray(0, 16);
  let id = '';
  for (const byte of idBytes) {
    id += String.fromCharCode(97 + (byte >> 4));
    id += String.fromCharCode(97 + (byte & 0xf));
  }
  return id;
}

const root = path.dirname(fileURLToPath(import.meta.url));
const keyPath = path.join(root, 'key.pem');

let privateKeyPem;
if (existsSync(keyPath)) {
  console.log(`key.pem already exists at ${keyPath} -- reusing it.`);
  privateKeyPem = readFileSync(keyPath, 'utf8');
} else {
  const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  privateKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' });
  writeFileSync(keyPath, privateKeyPem, { mode: 0o600 });
  console.log(`Generated new key.pem at ${keyPath}`);
}

const publicKeyDer = createPublicKey(createPrivateKey(privateKeyPem)).export({ type: 'spki', format: 'der' });
const extensionId = extensionIdFromKeyPem(privateKeyPem);

console.log(`\nExtension ID: ${extensionId}`);
console.log(`Origin for the agent's allow-list: chrome-extension://${extensionId}`);
console.log('\nmanifest.json "key" field (base64 SPKI DER public key):');
console.log(publicKeyDer.toString('base64'));
