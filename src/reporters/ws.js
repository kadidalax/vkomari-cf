export async function openReporterWebSocket(wsUrl) {
  if (typeof fetch === 'function') {
    try {
      const res = await fetch(wsUrl.replace(/^ws/i, 'http'), { headers: { Upgrade: 'websocket' } });
      if (res.webSocket) {
        res.webSocket.accept?.();
        return res.webSocket;
      }
    } catch {}
  }
  return typeof WebSocket === 'undefined' ? null : new WebSocket(wsUrl);
}
