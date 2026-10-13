# web-auth

[![CI](https://github.com/turinglambdaai/web-auth/actions/workflows/ci.yml/badge.svg)](https://github.com/turinglambdaai/web-auth/actions/workflows/ci.yml)

Authentication guards for Racket's web-server: API key, bearer token,
and HTTP Basic, sized for small APIs. A guard is a procedure from a
request to `#f` (allow) or a response (reject) — composable with plain
dispatchers, testable without a server.

## Install

```
raco pkg install web-auth
```

## Use

```racket
(require web-auth
         net/url
         web-server/http
         web-server/web)

(define key-guard
  (make-api-key-guard
   #:verify (λ (k) (timing-safe-equal? k (api-key-from-env)))
   #:query "token"))            ; ?token= escape hatch, publy-style

(define (api-dispatch req) ...)

(define app (guard-with api-dispatch key-guard))
;; responses from the guard: 401 + Cache-Control: no-store
```

Bearer and Basic:

```racket
(define bearer (make-bearer-guard #:verify token-in-db?))
(define basic  (make-basic-auth-guard
                #:check (λ (user pass) (check-creds user pass))))
```

- `timing-safe-equal?` for every secret comparison — constant-time
  content check, no early exit
- Basic decoding splits on the first colon (passwords may contain
  colons) and carries a proper `WWW-Authenticate` challenge
- every guard takes `#:on-unauthorized` for custom 401s

## Development

```
raco pkg install --auto --link .
raco test tests
raco setup --check-pkg-deps -l web-auth
```

## License

[MIT](LICENSE)
