#lang racket/base

;; Guards for web-server dispatchers.  A guard is a procedure from a
;; request to #f (allow) or a response (reject); guard-with wires one
;; in front of an existing dispatcher.  The three constructors cover
;; the patterns this family actually ships: fixed API keys (header,
;; with an optional query-parameter escape hatch like ?token=), bearer
;; tokens backed by a verifier, and HTTP Basic.

(require racket/contract
         racket/list
         racket/string
         net/base64
         web-server/http
         web-server/http/request-structs
         web-server/http/response-structs
         net/url
         "timing.rkt")

(provide (contract-out
          [timing-safe-equal? (-> (or/c string? bytes?) (or/c string? bytes?) boolean?)]
          [request-header (-> request? string? (or/c string? #f))]
          [query-param (-> request? string? (or/c string? #f))]
          [unauthorized-response
           (->* () (#:challenge (or/c bytes? #f) #:body bytes?) response?)]
          [make-api-key-guard
           (->* (#:verify (-> string? boolean?))
                (#:header string? #:query (or/c string? #f)
                 #:on-unauthorized (-> request? response?))
               guard?)]
          [make-bearer-guard
           (->* (#:verify (-> string? boolean?))
                (#:realm string? #:on-unauthorized (-> request? response?))
               guard?)]
          [make-basic-auth-guard
           (->* (#:check (-> string? string? boolean?))
                (#:realm string? #:on-unauthorized (-> request? response?))
               guard?)]
          [parse-basic-credentials (-> request? (or/c (cons/c string? string?) #f))]
          [guard? (-> any/c boolean?)]
          [guard-with (-> (-> request? response?) guard? (-> request? response?))]))

;; A guard: request -> #f (allow) | response (reject).
(struct guard (proc) #:reflection-name 'guard
  #:property prop:procedure 0)

;; ASCII downcase for header field bytes (fields are ASCII per spec;
;; this Racket has no bytes-downcase)
(define (header-bytes-downcase b)
  (define out (make-bytes (bytes-length b)))
  (for ([i (in-range (bytes-length b))])
    (define x (bytes-ref b i))
    (bytes-set! out i (if (and (>= x 65) (<= x 90)) (+ x 32) x)))
  out)

;; case-insensitive header lookup, decoded latin-1 (headers are bytes;
;; normalize both sides — synthetic requests skip web-server's own
;; lowercasing)
(define (request-header req name)
  (define nb (string->bytes/latin-1 (string-downcase name)))
  (for/first ([h (in-list (request-headers/raw req))]
              #:when (equal? (header-bytes-downcase (header-field h)) nb))
    (bytes->string/latin-1 (header-value h))))

(define (query-param req name)
  (define ns (string->symbol name))
  (for/first ([pair (in-list (url-query (request-uri req)))]
              #:when (equal? (car pair) ns))
    (cdr pair)))

;; jsexpr-ish removed: response bodies are bytes

(define (unauthorized-response #:challenge [challenge #f] #:body [body #"unauthorized"])
  (response/full
   401 #"Unauthorized"
   (current-seconds)
   #"text/plain; charset=utf-8"
   (append (if challenge
               (list (header #"WWW-Authenticate" challenge))
               '())
           (list (header #"Cache-Control" #"no-store")))
   (list body)))

(define (default-401 challenge)
  (λ (_req) (unauthorized-response #:challenge challenge)))

;; ---- guards ------------------------------------------------------------------

(define (make-api-key-guard #:verify verify
                            #:header [header "X-API-Key"]
                            #:query [query #f]
                            #:on-unauthorized [on-unauthorized (default-401 #f)])
  (guard
   (λ (req)
     (define supplied (or (request-header req header)
                          (and query (query-param req query))))
     (cond
       [(and supplied (string? supplied) (verify supplied)) #f]
       [else (on-unauthorized req)]))))

(define (make-bearer-guard #:verify verify
                           #:realm [realm "api"]
                           #:on-unauthorized [on-unauthorized
                                              (default-401
                                                (string->bytes/latin-1
                                                 (format "Bearer realm=\"~a\"" realm)))])
  (guard
   (λ (req)
     (define auth (request-header req "Authorization"))
     (define token
       (and auth
            (let* ([s (string-trim auth)]
                   [parts (string-split s " " #:trim? #t)])
              (and (= (length parts) 2)
                   (string-ci=? (first parts) "Bearer")
                   (second parts)))))
     (cond
       [(and token (verify token)) #f]
       [else (on-unauthorized req)]))))

;; Authorization: Basic base64(user:pass) — split on the FIRST colon,
;; passwords may contain colons.
(define (parse-basic-credentials req)
  (define auth (request-header req "Authorization"))
  (and auth
       (let* ([s (string-trim auth)]
              [parts (string-split s " " #:trim? #t)])
         (and (= (length parts) 2)
              (string-ci=? (first parts) "Basic")
              (with-handlers ([exn:fail? (λ (_) #f)])
                (define decoded (base64-decode (string->bytes/latin-1 (second parts))))
                (and decoded
                     (let ([sep (for/first ([i (in-range (bytes-length decoded))]
                                            #:when (= (bytes-ref decoded i) (char->integer #\:)))
                                  i)])
                       (and sep
                            (cons (bytes->string/utf-8 (subbytes decoded 0 sep))
                                  (bytes->string/utf-8 (subbytes decoded (add1 sep))))))))))))

(define (make-basic-auth-guard #:check check
                               #:realm [realm "restricted"]
                               #:on-unauthorized [on-unauthorized
                                                  (default-401
                                                    (string->bytes/latin-1
                                                     (format "Basic realm=\"~a\", charset=\"UTF-8\"" realm)))])
  (guard
   (λ (req)
     (define creds (parse-basic-credentials req))
     (cond
       [(and creds (check (car creds) (cdr creds))) #f]
       [else (on-unauthorized req)]))))

;; ---- middleware ----------------------------------------------------------------

(define (guard-with dispatcher g)
  (λ (req)
    (define rejection ((guard-proc g) req))
    (if rejection
        rejection
        (dispatcher req))))
