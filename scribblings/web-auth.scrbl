#lang scribble/manual

@(require (for-label web-auth
                     racket/base
                     web-server/http)
          scribble/example)

@title{web-auth: Authentication Guards for web-server}
@defmodule[web-auth]

Authentication guards for @racketmodname[web-server] dispatchers, sized
to the patterns small APIs actually ship: a fixed API key (header,
with an optional query-parameter escape hatch), bearer tokens backed
by a verifier you own, and HTTP Basic. A guard is a procedure from a
request to @racket[#f] (allow) or a response (reject), so it composes
with plain dispatchers and stays trivially testable without a server.

@section{Guards}

@defproc[(make-api-key-guard [#:verify verify (-> string? boolean?)]
                             [#:header header string? "X-API-Key"]
                             [#:query query (or/c string? #f) #f]
                             [#:on-unauthorized on-unauthorized (-> request? response?)
                              unauthorized-response])
         guard?]

Checks @racket[header] (and, when @racket[query] is named, that query
parameter as an escape hatch). Compare keys with
@racket[timing-safe-equal?] inside @racket[verify].

@defproc[(make-bearer-guard [#:verify verify (-> string? boolean?)]
                            [#:realm realm string? "api"]
                            [#:on-unauthorized on-unauthorized (-> request? response?)
                             unauthorized-response])
         guard?]

Parses @tt{Authorization: Bearer <token>} (scheme matched
case-insensitively) and hands the token to @racket[verify]. Rejections
carry @tt{WWW-Authenticate: Bearer realm="..."}.

@defproc[(make-basic-auth-guard [#:check check (-> string? string? boolean?)]
                                [#:realm realm string? "restricted"]
                                [#:on-unauthorized on-unauthorized (-> request? response?)
                                 unauthorized-response])
         guard?]

Decodes @tt{Authorization: Basic <base64>} and calls @racket[check]
with user and password. Passwords may contain colons — the split is on
the first one.

@defproc[(parse-basic-credentials [req request?]) (or/c (cons/c string? string?) #f)]

The decoder behind the Basic guard; exported for tests and custom
flows.

@defproc[(guard? [v any/c]) boolean?]

Guards are directly applicable procedures.

@defproc[(guard-with [dispatcher (-> request? response?)] [g guard?])
         (-> request? response?)]

Runs @racket[g] in front of @racket[dispatcher]; a rejection
short-circuits.

@section{Building blocks}

@defproc[(timing-safe-equal? [a (or/c string? bytes?)] [b (or/c string? bytes?)]) boolean?]

Constant-time content comparison for secrets: the loop folds XOR over
every byte and decides at the end. Length inequality still leaks
(standard caveat) but content differences do not.

@defproc[(request-header [req request?] [name string?]) (or/c string? #f)]

Case-insensitive header lookup, decoded to a string.

@defproc[(query-param [req request?] [name string?]) (or/c string? #f)]

Query parameter lookup.

@defproc[(unauthorized-response [#:challenge challenge (or/c bytes? #f) #f]
                                [#:body body bytes? #"unauthorized"])
         response?]

The default rejection: @racket[401], @tt{WWW-Authenticate} when a
challenge is given, @tt{Cache-Control: no-store}. Pass
@racket[#:on-unauthorized] to any constructor for custom responses
(JSON bodies, redirects, logging).
