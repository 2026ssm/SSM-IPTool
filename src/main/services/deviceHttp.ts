import { request as httpRequestRaw } from 'http';

export interface DeviceHttpResponse {
  status: number;
  body: string;
  // Every WWW-Authenticate header value, separately — joined into one
  // string they can't be told apart (a Basic challenge before a Digest one,
  // or a comma inside a quoted realm).
  challenges: string[];
}

// One HTTP request to a device on the LAN (ONVIF, Uniview LAPI).
//
// Node's `http` rather than the global fetch: fetch refuses the WHATWG
// "bad ports" (87, 95, 6000, ...) outright, so a device whose web/ONVIF
// service sits on one could never be read or changed. The lenient parser
// is for embedded camera web servers, whose HTTP isn't always strictly
// well-formed (one camera's plain web page already failed under fetch);
// these are requests to the user's own LAN devices, not the internet.
//
// The whole exchange — connect, send, and reading the full body — is
// bounded by one timeout and settles exactly once, so a reply cut off
// mid-body (a camera switching address right after answering) surfaces as
// a rejection here, like any other transport failure.
export function deviceHttpRequest(
  url: string,
  options: { method: 'GET' | 'POST' | 'PUT'; headers?: Record<string, string>; body?: string; timeoutMs: number },
): Promise<DeviceHttpResponse> {
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (error: Error | undefined, response?: DeviceHttpResponse): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (error) reject(error);
      else resolve(response as DeviceHttpResponse);
    };

    const headers: Record<string, string | number> = { ...options.headers };
    if (options.body !== undefined) headers['Content-Length'] = Buffer.byteLength(options.body);

    const req = httpRequestRaw(url, { method: options.method, headers, insecureHTTPParser: true }, (res) => {
      const chunks: Buffer[] = [];
      let ended = false;
      res.on('data', (chunk: Buffer) => chunks.push(chunk));
      res.on('end', () => {
        ended = true;
        const challenges: string[] = [];
        for (let i = 0; i + 1 < res.rawHeaders.length; i += 2) {
          if (res.rawHeaders[i].toLowerCase() === 'www-authenticate') challenges.push(res.rawHeaders[i + 1]);
        }
        finish(undefined, { status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString('utf8'), challenges });
      });
      res.on('error', (error) => finish(error));
      res.on('close', () => {
        if (!ended) finish(new Error('the connection closed before the reply was complete'));
      });
    });
    const timer = setTimeout(() => req.destroy(new Error(`timed out after ${options.timeoutMs / 1000} s`)), options.timeoutMs);
    req.on('error', (error) => finish(error));
    if (options.body !== undefined) req.write(options.body);
    req.end();
  });
}
