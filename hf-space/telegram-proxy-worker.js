// ═══════════════════════════════════════════════════════
//  Telegram Bot API Proxy — Cloudflare Worker
// ═══════════════════════════════════════════════════════
// Routes all requests to api.telegram.org, bypassing
// network restrictions on platforms like HuggingFace Spaces.
//
// FREE deployment: https://workers.cloudflare.com
// No server, no cost — handles unlimited requests.
// ═══════════════════════════════════════════════════════

export default {
  async fetch(request) {
    const url = new URL(request.url);
    
    // Only proxy /bot* and /file* paths (Telegram Bot API endpoints)
    const path = url.pathname;
    if (!path.startsWith('/bot') && !path.startsWith('/file')) {
      // Health check endpoint
      if (path === '/' || path === '/health') {
        return new Response(
          JSON.stringify({ status: 'ok', service: 'telegram-api-proxy' }),
          { 
            status: 200, 
            headers: { 
              'Content-Type': 'application/json',
              'Access-Control-Allow-Origin': '*'
            } 
          }
        );
      }
      return new Response(
        JSON.stringify({ error: 'Not found. Use /bot<token>/... endpoints.' }),
        { status: 404, headers: { 'Content-Type': 'application/json' } }
      );
    }

    // Build the target URL — decode the path first because httpx
    // URL-encodes characters like ':' (%3A) and '_' (%5F) in paths.
    const decodedPath = decodeURIComponent(path);
    const targetUrl = `https://api.telegram.org${decodedPath}${url.search}`;

    // Copy headers (excluding host)
    const headers = new Headers(request.headers);
    headers.delete('host');
    headers.delete('cf-connecting-ip');
    headers.delete('cf-ray');
    headers.delete('cf-visitor');
    headers.delete('cf-worker');

    try {
      const response = await fetch(targetUrl, {
        method: request.method,
        headers: headers,
        body: request.method !== 'GET' && request.method !== 'HEAD' ? request.body : undefined,
      });

      // Copy response back
      const responseHeaders = new Headers(response.headers);
      responseHeaders.set('Access-Control-Allow-Origin', '*');

      return new Response(response.body, {
        status: response.status,
        statusText: response.statusText,
        headers: responseHeaders,
      });
    } catch (err) {
      return new Response(
        JSON.stringify({ 
          ok: false, 
          error_code: 500, 
          description: `Proxy error: ${err.message}` 
        }),
        { 
          status: 502, 
          headers: { 
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
          } 
        }
      );
    }
  },
};
