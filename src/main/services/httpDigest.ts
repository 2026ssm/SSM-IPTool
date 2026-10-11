import { createHash, randomBytes } from 'crypto';

function md5(value: string): string {
  return createHash('md5').update(value).digest('hex');
}

// The Digest challenge to answer from a reply's WWW-Authenticate headers
// (see deviceHttpRequest), preferring MD5 — or no algorithm, which means
// MD5 — since that's what digestAuthorization computes. Undefined when the
// device offered no Digest challenge.
export function pickDigestChallenge(challenges: string[]): string | undefined {
  const digest = challenges.filter((c) => /^\s*digest\s/i.test(c));
  return digest.find((c) => !/algorithm="?(?!md5\b)[\w-]+/i.test(c)) ?? digest[0];
}

// HTTP Digest (RFC 2617, MD5, qop=auth when offered) for a challenge from a
// WWW-Authenticate header — used by ONVIF cameras that want HTTP Digest
// instead of WS-Security, and by Uniview's LAPI (the same scheme its own
// web UI computes in utils.js web_Digest).
export function digestAuthorization(challenge: string, method: string, uri: string, username: string, password: string): string {
  // Quoted values in full (a realm may contain commas), else a bare token.
  const param = (name: string): string | undefined => {
    const quoted = challenge.match(new RegExp(`\\b${name}="([^"]*)"`, 'i'));
    return quoted ? quoted[1] : challenge.match(new RegExp(`\\b${name}=([^,\\s]+)`, 'i'))?.[1];
  };
  const realm = param('realm') ?? '';
  const nonce = param('nonce') ?? '';
  const opaque = param('opaque');
  const qop = param('qop')?.split(',')[0]?.trim();
  const ha1 = md5(`${username}:${realm}:${password}`);
  const ha2 = md5(`${method}:${uri}`);
  const cnonce = randomBytes(8).toString('hex');
  const nc = '00000001';
  const response = qop ? md5(`${ha1}:${nonce}:${nc}:${cnonce}:${qop}:${ha2}`) : md5(`${ha1}:${nonce}:${ha2}`);
  return (
    `Digest username="${username}", realm="${realm}", nonce="${nonce}", uri="${uri}", algorithm=MD5, response="${response}"` +
    (qop ? `, qop=${qop}, nc=${nc}, cnonce="${cnonce}"` : '') +
    (opaque ? `, opaque="${opaque}"` : '')
  );
}
