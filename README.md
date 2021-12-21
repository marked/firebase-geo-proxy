# Firebase Geo Proxy

Quick and simple MITM proxy to let end users bypass Firebase geo restrictions by serving requests for them.

Will MITM your JavaScript file to:

- Rewrite Firebase Realtime Database requests to this proxy server's URI (at `https://this-proxy.my-website.dev/firebase-proxy/https://firebase-stuff.firebase.io`)
- Prevent the Firebase Websocket connection from opening

All the requests to Firebase are then intercepted, replayed from the server then the result is sent back to the client, its IP never reaching Google Firebase (full HTTP MITM).

This only works for Firebase Realtime Database to fit my personal use case. Adding Firebase Firestore support should be quite easy to add if you need it.

## Install

```
pnpm i
```

## Run

Available environment variables:

| Variable            | Description                                                                        | Example                                  |
| ------------------- | ---------------------------------------------------------------------------------- | ---------------------------------------- |
| `SERVER_PORT`       | Server port, default is 3000                                                       | `3000`                                   |
| `REMOTE_URI_PREFIX` | App to proxy requests from                                                         | `https://my-website.dev`                 |
| `FIREBASE_RTDB_ID`  | Firebase Realtime Database ID                                                      | `my-firebase-project-cc048-default-rtdb` |
| `TRUST_PROXY`       | Should the server trust the proxy? (client IP will never be forwarded to Firebase) | `1`                                      |

```
pnpm start
```

## License

[GNU Affero General Public License v3.0](./LICENSE)
