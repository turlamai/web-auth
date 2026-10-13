# AGENTS.md

## What this is

`web-auth` — authentication guards for Racket web-server dispatchers.
Single-collection package (`web-auth` = collection = package name).
Family web line (websocket, server-sent-events, feed, validate).

## Layout

- `timing.rkt` — constant-time secret comparison
- `guard.rkt` — request-header/query helpers, the three guard
  constructors, guard-with middleware
- `main.rkt` — re-exports guard.rkt (which already re-exports
  timing-safe-equal?; do not require timing.rkt here too —
  "identifier already required")

## Invariants

- A guard returns #f to allow, a response to reject — never both, and
  never throws on missing headers.
- Secret comparisons go through timing-safe-equal?; the check loop is
  constant-time over the first operand's length.
- Basic credentials split on the FIRST colon (passwords may contain
  colons); index-of does not work on bytes — scan explicitly.
- Header lookups normalize both sides to lowercase bytes (synthetic
  requests skip web-server's own lowercasing).
- response/full argument order: code message seconds MIME-TYPE headers
  body — the 4th slot is a mime-type, not a header list.

## Quality gates (before any release)

1. `raco test tests` — all green
2. `raco setup --check-pkg-deps -l web-auth` — zero violations
3. `raco setup -l web-auth` — docs build clean, zero undefined tags
