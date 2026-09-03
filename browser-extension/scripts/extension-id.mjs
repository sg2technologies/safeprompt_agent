// Same ID-derivation algorithm Chrome/Edge use internally (SHA-256 of the
// SPKI DER public key, first 16 bytes mapped to a-p) -- ported from
// extension/scripts/extension-id.mjs, and also duplicated inline in
// ../gen-key.mjs (that file predates this one and works standalone; left
// untouched rather than refactored to import this, to avoid touching a
// script that's already correct and in use). This copy exists so
// gen-update-manifest.mjs and get-extension-id.mjs below don't each need
// their own copy of the same math.
import { createHash, createPrivateKey, createPublicKey } from 'crypto';

export function extensionIdFromKeyPem(privateKeyPem) {
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
