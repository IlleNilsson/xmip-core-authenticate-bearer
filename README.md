# xmip-core-authenticate-bearer

Authenticate by bearer token: verifies an opaque token against a token store, hashed at rest, with its expiry. A technology of [xmip-core-authenticate](https://github.com/IlleNilsson/xmip-core-authenticate).

The store is the capability's hashed secret store, `authenticate::secret`, which
`api-key` and `bearer` share; until 2026-09-24 each carried one of its own.

## Toolchain

`rust-toolchain.toml` pins the toolchain for the whole estate. Do not change it
here.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.
