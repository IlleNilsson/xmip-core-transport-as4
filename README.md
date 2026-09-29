# xmip-core-transport-as4

AS4 transport: the OASIS ebMS 3.0 AS4 profile over HTTP — one User Message is one Stream, its parties and collaboration beside it, answered with a Receipt signal; a Receive Location answers Parties, a Send Location posts to one. A technology of [xmip-core-transport](https://github.com/IlleNilsson/xmip-core-transport).

Requests go on connections kept between them (`http::endpoint::Connections`, offering HTTP/1.1): the transport holds them and hands them to every client it makes, so a call costs one exchange and not a connect, a TLS handshake and a `Connection: close`, as it did until 2026-09-27.

A Receive Location keeps its listener, bound on the first receive, and the connections senders keep open on it (`http::inbound::Inbound`): each receive takes the next request from whichever sends first, where until 2026-09-27 each receive bound a listener of its own, answered one request with `Connection: close`, and refused a request that came between two receives. `As4Transport::take_next` is that receive with the message it carried, which Peppol's access point takes through, and `listening` binds the listener before the first receive and says where. The peer an origin names comes from `http::server` (`serve_one_from`, and the `Inbound`), where AS4 accepted and read its own connection until then.

The Party's endpoint is kept as written and read by `net::Endpoint` in [xmip-core-library-net](https://github.com/IlleNilsson/xmip-core-library-net) under the schemes this technology declares, `as4::SCHEMES` — `as4://` is `http://`, `as4s://` is `https://` — which Peppol reads its access point under too. Until 2026-09-28 an `as_http` function rewrote the URL before it was read.

## Toolchain

`rust-toolchain.toml` pins the toolchain for the whole estate. Do not change it
here.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.
