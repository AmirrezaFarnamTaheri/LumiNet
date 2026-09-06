// Cloudflare Worker Uptime prober template.
// Deploys to serverless edge to report latency and availability metrics.
addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request))
})

async function handleRequest(request) {
  const url = new URL(request.url)
  const target = url.searchParams.get('target')
  if (!target) {
    return new Response(JSON.stringify({ error: "missing target url" }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' }
    })
  }

  const start = Date.now()
  try {
    const res = await fetch(target, { method: 'GET', timeout: 5000 })
    const latency = Date.now() - start
    return new Response(JSON.stringify({
      status: res.status,
      ok: res.ok,
      latency_ms: latency,
      node: "cloudflare-edge"
    }), {
      headers: { 'Content-Type': 'application/json' }
    })
  } catch (err) {
    return new Response(JSON.stringify({
      ok: false,
      error: err.message,
      node: "cloudflare-edge"
    }), {
      status: 502,
      headers: { 'Content-Type': 'application/json' }
    })
  }
}
