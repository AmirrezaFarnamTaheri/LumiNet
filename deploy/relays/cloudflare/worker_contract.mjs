export function jsonResponse(payload, statusOrInit = 200) {
  const init = typeof statusOrInit === "number" ? { status: statusOrInit } : statusOrInit;
  return new Response(JSON.stringify(payload), {
    ...init,
    headers: { "Content-Type": "application/json", ...init.headers },
  });
}

export function healthResponse(worker) {
  return jsonResponse({ status: "ok", worker });
}

export function stripRoutePrefix(request, prefix) {
  const url = new URL(request.url);
  if (url.pathname !== prefix && !url.pathname.startsWith(`${prefix}/`)) {
    return null;
  }
  url.pathname = url.pathname.slice(prefix.length) || "/";
  return new Request(url, request);
}
