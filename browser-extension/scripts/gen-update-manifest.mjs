/**
 * Generates update_manifest.xml -- the file Chrome/Edge poll (per the
 * ExtensionInstallForcelist update_url) to discover new versions of a
 * self-hosted extension. This is the piece that lets SafePrompt force-
 * install browser-extension/ via GPO/Intune with NO Chrome Web Store
 * listing at all -- ported from extension/scripts/gen-update-manifest.mjs
 * (see that file's own doc comment: this is exactly what a $5 Chrome Web
 * Store developer registration fee that can't be paid from a given country
 * needs to route around). Host this file and the .crx pack-crx.ps1
 * produces on the same HTTPS origin you control.
 *
 * Run:  node scripts/gen-update-manifest.mjs <https://your-host/safeprompt-extension.crx>
 */
import { readFileSync, writeFileSync } from 'fs';
import { fileURLToPath } from 'url';
import path from 'path';
import { extensionIdFromKeyPem } from './extension-id.mjs';

const crxUrl = process.argv[2];
if (!crxUrl) {
  console.error('Usage: node scripts/gen-update-manifest.mjs <https://your-host/safeprompt-extension.crx>');
  process.exit(1);
}

const extRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const keyPath = path.join(extRoot, 'key.pem');
// No dist/ build step here, unlike extension/ -- browser-extension/'s
// manifest.json at the root IS what gets packed (see pack-crx.ps1).
const manifestPath = path.join(extRoot, 'manifest.json');

const privateKeyPem = readFileSync(keyPath, 'utf8');
const extensionId = extensionIdFromKeyPem(privateKeyPem);
const { version } = JSON.parse(readFileSync(manifestPath, 'utf8'));

const xml = `<?xml version='1.0' encoding='UTF-8'?>
<gupdate xmlns='http://www.google.com/update2/response' protocol='2.0'>
  <app appid='${extensionId}'>
    <updatecheck codebase='${crxUrl}' version='${version}' />
  </app>
</gupdate>
`;

const outPath = path.join(extRoot, 'update_manifest.xml');
writeFileSync(outPath, xml);

console.log(`Wrote ${outPath}`);
console.log(`\nExtension ID: ${extensionId}`);
console.log(`Version:      ${version}`);
console.log(`Codebase URL: ${crxUrl}`);
console.log('\nHost both update_manifest.xml and the .crx at these URLs, then set');
console.log(`ExtensionInstallForcelist to:  ${extensionId};<https-url-to-this-update_manifest.xml>`);
console.log('\nThis ID must also match SAFEPROMPT_EXTENSION_ORIGINS on the agent');
console.log(`(default is already this ID -- see agent/apps/service/src/main.rs).`);
