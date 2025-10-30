/**
 * Firebase Geo Proxy
 * (patched to properly stream Firebase SSE / long-poll responses)
 *
 * Original: https://github.com/marked/firebase-geo-proxy (index.mjs)
 */

/// @ts-check
import express from 'express'
import fetch from 'node-fetch'
import compression from 'compression'

const SERVER_PORT = process.env.SERVER_PORT || 3000
const REMOTE_URI_PREFIX = process.env.REMOTE_URI_PREFIX
const FIREBASE_RTDB_ID = process.env.FIREBASE_RTDB_ID

if (!REMOTE_URI_PREFIX) throw new Error('Missing REMOTE_URI_PREFIX')
if (!FIREBASE_RTDB_ID) throw new Error('Missing FIREBASE_RTDB_ID')

const app = express()

// Do NOT enable compression globally — it breaks streaming for Firebase.
// We'll mount compression() AFTER the firebase-proxy route for website assets only.

if (process.env.TRUST_PROXY === '1') app.set('trust proxy')

/**
 * Copy upstream headers to client response,
 * skipping hop-by-hop or buffering-related headers.
 */
const copyHeaders = (remoteRes, res) => {
  remoteRes.headers.forEach((v, k) => {
    if (!['strict-transport-security', 'accept-ranges', 'content-encoding', 'content-length'].some(x => x === k)) {
      res.setHeader(k, v)
    }
  })
}

app.use(express.raw({ type: '*/*' }))

/**
 * Firebase proxy (streaming-friendly)
 * Example:
 *   /firebase-proxy/https://<project>.firebaseio.com/endpoint.json
 */
app.all('/firebase-proxy/*tmp', async (req, res) => {
  /** @type {URL} */
  let remoteUrl
  try {
    // Strip the /firebase-proxy/ prefix and interpret the remainder as a full URL
    remoteUrl = new URL(req.url.replace(/^\/firebase-proxy\//, ''))

    // Optionally restrict to your RTDB project to prevent abuse (kept as in original)
    // if (
    //   !remoteUrl.hostname.endsWith('.firebaseio.com') ||
    //   (remoteUrl.pathname !== '/.lp' && remoteUrl.searchParams.get('ns') !== FIREBASE_RTDB_ID)
    // ) {
    //   throw new Error(`This host is not proxiable! URI=${remoteUrl.href}`)
    // }
  } catch (error) {
    console.error(error)
    res.status(400).json({ error: /** @type {Error} */(error).message })
    return
  }

  console.log('[FIREBASE PROXY]', req.method, remoteUrl.href)
  console.log(' > ', (typeof req.body === 'undefined') ? 'undef' : Buffer.isBuffer(req.body) ? req.body.toString('ascii') : String(req.body))

  // Ask upstream for identity encoding to avoid gzip-induced buffering
  const upstreamHeaders = {
    'User-Agent': req.headers['user-agent'],
    'Content-Type': req.headers['content-type'],
    'Accept-Encoding': 'identity',
    'Accept': req.headers['accept'] || 'application/json',
    // 'X-Forwarded-For': req.ip, /* Not provided to avoid geo-bans */
    'X-Firebase-Geo-Proxy': '1'
  }

  const remoteRes = await fetch(remoteUrl.href, {
    method: req.method,
    body: req.body,
    headers: upstreamHeaders
  })

  // Forward headers but ensure downstream is not compressed and suitable for streaming
  copyHeaders(remoteRes, res)
  res.setHeader('Content-Encoding', 'identity')

  const upstreamCT = remoteRes.headers.get('content-type') || ''
  const wantsSSE = upstreamCT.includes('text/event-stream') ||
                   ((req.headers.accept || '').includes('text/event-stream'))

  if (wantsSSE) {
    res.setHeader('Content-Type', 'text/event-stream')
    res.setHeader('Cache-Control', 'no-cache')
    res.setHeader('Connection', 'keep-alive')
    // Useful with some reverse proxies; harmless otherwise
    res.setHeader('X-Accel-Buffering', 'no')
    // Keep the socket open indefinitely
    req.setTimeout(0)
    // Flush headers early if supported
    if (typeof res.flushHeaders === 'function') res.flushHeaders()
  }

  // Stream the upstream body directly; do not buffer
  if (remoteRes.body) {
    remoteRes.body.on('error', (err) => {
      console.error('Upstream stream error:', err)
      // End client stream; client can reconnect
      res.end()
    })

    // If client disconnects, stop reading upstream to free resources
    res.on('close', () => {
      try {
        remoteRes.body?.destroy?.()
      } catch {}
    })

    remoteRes.body.pipe(res)
  } else {
    // Fallback (non-streaming response)
    const text = await remoteRes.text()
    console.log(' < ', text)
    res.send(text)
  }
})

/**
 * Website proxy (keeps original behavior)
 * We mount compression() AFTER the Firebase route so it only applies here.
 */
app.use(compression())

app.all('/*tmp', async (req, res) => {
  console.log('[WEBSITE PROXY ]', req.url)

  const remoteRes = await fetch(`${REMOTE_URI_PREFIX}${req.url}`, {
    headers: {
      'User-Agent': req.headers['user-agent'],
      'X-Forwarded-For': req.ip,
      'X-Firebase-Geo-Proxy': '1'
    }
  })

  copyHeaders(remoteRes, res)

  // Handle binary assets
  if (['jpeg', 'png', 'ico'].some(x => req.url.endsWith(x))) {
    const buffer = await remoteRes.buffer()
    res.send(buffer)
    return
  }

  let content = await remoteRes.text()

  // Edit main script, may be at another path!
  if (req.url.match(/^\/assets\/index\.\w+\.js$/)) {
    console.log('[WEBSITE MITM ]', req.url)
    // Proxy Firebase HTTP calls (Rewrite Firebase URI to proxy)
    // `http://host/firebase-proxy/https://<project>.firebaseio.com/some-query`
    content = content.replace(
      /i=\(n\.secure\?"https:\/\/":"http:\/\/"\)\+n\.internalHost\+"\/\.lp\?"/,
      'i = document.location.protocol + "//" + document.location.host + "/firebase-proxy/" + (n.secure ? "https://" : "http://") + n.internalHost + "/.lp?"'
    )
    // Remove Firebase Websocket connection open
    content = content.replace(
      /this\.mySock=new jt\(this\.connURL,\[\],i\)/,
      'throw new Error("Proxy - Do not call firebase");this.mySock=new jt(this.connURL,[],i)'
    )
  }

  res.send(content)
})

app.use((err, req, res, next) => {
  console.error(err)
  res.status(500).json({ error: err.message }).end()
})

app.listen(SERVER_PORT, () => console.log(`Proxy is listening at http://localhost:${SERVER_PORT}`))
