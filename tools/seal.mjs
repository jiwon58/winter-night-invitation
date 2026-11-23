import { webcrypto } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';

if (!process.argv[2]) throw new Error('Usage: node tools/seal.mjs <invitation.json>');
const password = (await readFile('/dev/stdin', 'utf8')).replace(/\r?\n$/, '');
if (!password || password.length > 256) throw new Error('Enter a password of 1–256 characters.');
const invitation = JSON.parse(await readFile(process.argv[2], 'utf8'));
if (![invitation.greeting, invitation.body, invitation.signature].every(value => typeof value === 'string')
    || !Array.isArray(invitation.venues) || !invitation.venues.length
    || !invitation.venues.every(venue => typeof venue?.name === 'string' && typeof venue.description === 'string')) {
  throw new Error('Invalid invitation content.');
}

const { subtle } = webcrypto;
const encoder = new TextEncoder();
const salt = webcrypto.getRandomValues(new Uint8Array(16));
const iv = webcrypto.getRandomValues(new Uint8Array(12));
const iterations = 600_000;
const material = await subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveKey']);
const key = await subtle.deriveKey({ name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
  material, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
const ciphertext = await subtle.encrypt({ name: 'AES-GCM', iv }, key, encoder.encode(JSON.stringify(invitation)));
const b64 = bytes => Buffer.from(bytes).toString('base64');
const sealed = { salt: b64(salt), iv: b64(iv), iterations, ciphertext: b64(ciphertext) };
const page = new URL('../docs/index.html', import.meta.url);
const html = await readFile(page, 'utf8');
const data = /(<script id="sealed-data" type="application\/json">)[^<]*(<\/script>)/;
if (!data.test(html)) throw new Error('Missing sealed-data element.');
await writeFile(page, html.replace(data, (_, start, end) => start + JSON.stringify(sealed) + end));
