/**
 * Prints the extension ID derived from key.pem. Requires gen-key.mjs to
 * have been run first -- key.pem isn't part of this repository (it's a
 * private signing key each build generates for itself), so run
 * `node gen-key.mjs` before this if key.pem doesn't exist yet.
 *
 * Run:  node scripts/get-extension-id.mjs
 */
import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import path from 'path';
import { extensionIdFromKeyPem } from './extension-id.mjs';

const extRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const keyPath = path.join(extRoot, 'key.pem');

const privateKeyPem = readFileSync(keyPath, 'utf8');
console.log(extensionIdFromKeyPem(privateKeyPem));
