export async function openReporterWebSocket(wsUrl, label = 'reporter') {
  const safeUrl = safeWebSocketUrl(wsUrl);
  if (typeof fetch === 'function') {
    try {
      const res = await fetch(wsUrl.replace(/^ws/i, 'http'), { headers: { Upgrade: 'websocket' } });
      if (res.webSocket) {
        res.webSocket.accept?.();
        console.log(`[vKomari] ${label} ws upgrade ok: ${safeUrl}`);
        return res.webSocket;
      }
      console.log(`[vKomari] ${label} ws upgrade no socket: ${safeUrl} status=${res.status}`);
    } catch (err) {
      console.log(`[vKomari] ${label} ws upgrade error: ${safeUrl} ${err?.name || err}`);
    }
  }
  return typeof WebSocket === 'undefined' ? null : new WebSocket(wsUrl);
}

function safeWebSocketUrl(wsUrl) {
  try {
    const url = new URL(wsUrl);
    url.search = '';
    return url.toString();
  } catch {
    return String(wsUrl).split('?')[0];
  }
}
