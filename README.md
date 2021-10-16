<div align="center"><h1>Actix Authentication Middleware</h1>

[![Documentation](https://img.shields.io/badge/docs-master-blue)](https://realaravinth.github.io/actix-auth-middleware/actix_auth_middleware/)
[![Build](https://github.com/realaravinth/actix-auth-middleware/actions/workflows/linux.yml/badge.svg)](https://github.com/realaravinth/actix-auth-middleware/actions/workflows/linux.yml)
[![codecov](https://codecov.io/gh/realaravinth/actix-auth-middleware/branch/master/graph/badge.svg?token=TYZXLOOHYQ)](https://codecov.io/gh/realaravinth/actix-auth-middleware)

[![dependency status](https://deps.rs/repo/github/realaravinth/actix-auth-middleware/status.svg)](https://deps.rs/repo/github/realaravinth/actix-auth-middleware)

  <p>
    <strong>Checks if session is authenticated</strong>
  </p>
<br /></div>

## What

This library provides a generic middleware to protect authenticated
routes from unauthenticated access. The middleware provides options to
customise authentication checking mechanism, which enables it to
support a wide range of session management mechanisms.

If a session is authenticated, then the request will be dispatched to
the matching handler and if unauthenticated, it will be redirected to a
user specified route, ideally a sign in route.

## Usage

Add this to your `Cargo.toml`:

```toml
actix-auth-middleware = { version = "0.1", git = "https://github.com/realaravinth/actix-auth-middleware" }
```

## Example

1. Cookie session management:
   source : [`cookie-identity.rs`]("./examples/cookie-identity.rs)
    ```bash
    cargo run --example cookie-identity
    ```
