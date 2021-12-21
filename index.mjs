/**
 * Firebase Geo Proxy
 *
 * Quick and simple MITM proxy to let end users bypass Firebase geo restrictions
 * by serving requests for them.
 *
 * Copyright (C) 2021  rigwild <me@rigwild.dev> (https://github.com/rigwild)
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

// @ts-check
import express from 'express'
import fetch from 'node-fetch'
import compression from 'compression'

const SERVER_PORT = process.env.SERVER_PORT || 3000
const REMOTE_URI_PREFIX = process.env.REMOTE_URI_PREFIX
const FIREBASE_RTDB_ID = process.env.FIREBASE_RTDB_ID

if (!REMOTE_URI_PREFIX) throw new Error('Missing REMOTE_URI_PREFIX')
if (!FIREBASE_RTDB_ID) throw new Error('Missing FIREBASE_RTDB_ID')

const app = express()
app.use(compression())

if (process.env.TRUST_PROXY === '1') app.set('trust proxy')

const copyHeaders = (remoteRes, res) => {
  remoteRes.headers.forEach((v, k) => {
    if (!['strict-transport-security', 'accept-ranges', 'content-encoding'].some(x => x === k)) {
      res.setHeader(k, v)
    }
  })
}

app.all('/firebase-proxy/*', async (req, res, next) => {
  /** @type {URL} */
  let remoteUrl
  try {
    remoteUrl = new URL(req.url.replace(/^\/firebase-proxy\//, ''))
    // Only proxy Firebase URIs of project (limit abuse)
    if (
      !remoteUrl.hostname.endsWith('.firebaseio.com') ||
      (remoteUrl.pathname !== '/.lp' && remoteUrl.searchParams.get('ns') !== FIREBASE_RTDB_ID)
    ) {
      throw new Error(`This host is not proxiable! URI=${remoteUrl.href}`)
    }
  } catch (error) {
    console.error(error)
    res.status(400).json({ error: error.message })
    return
  }

  console.log('[FIREBASE PROXY]', remoteUrl.href)
  const remoteRes = await fetch(remoteUrl.href, {
    headers: {
      'User-Agent': req.headers['user-agent'],
      // 'X-Forwarded-For': req.ip, /* Not provided to not be geo-banned */
      'X-Firebase-Geo-Proxy': '1'
    }
  })

  copyHeaders(remoteRes, res)

  let content = await remoteRes.text()
  // console.log(content)

  res.send(content)
})

app.all('/*', async (req, res) => {
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
    console.log('[WEBSITE MITM  ]', req.url)

    // Proxy Firebase HTTP calls (Rewrite Firebase URI to proxy `http://host.example/firebase-proxy/https://blabla.firebaseio.com/some-query`)
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
