#lang racket/base

(require rackunit
         racket/list
         racket/promise
         racket/string
         net/base64
         net/url
         web-server/http
         web-server/http/request-structs
         web-auth)

(define (h field value)
  (header (string->bytes/latin-1 field) (string->bytes/utf-8 value)))

(define (test-req #:headers [headers '()] #:query [query '()])
  (make-request
   #"GET"
   (struct-copy url (string->url "http://x.example/path") [query query])
   headers
   (delay '())
   #f
   "127.0.0.1"
   8080
   "127.0.0.1"))

(test-case "timing-safe comparison"
  (check-true (timing-safe-equal? "secret" "secret"))
  (check-false (timing-safe-equal? "secret" "secreT"))
  (check-false (timing-safe-equal? "short" "a-much-longer-secret"))
  (check-true (timing-safe-equal? #"bytes" #"bytes"))
  (check-true (timing-safe-equal? "str" #"str")))

(test-case "request-header is case-insensitive"
  (define req (test-req #:headers (list (h "X-API-Key" "abc"))))
  (check-equal? (request-header req "x-api-key") "abc")
  (check-equal? (request-header req "X-API-KEY") "abc")
  (check-false (request-header req "Missing")))

(test-case "query-param"
  (define req (test-req #:query (list (cons 'token "t1") (cons 'x "y"))))
  (check-equal? (query-param req "token") "t1")
  (check-false (query-param req "nope")))

(test-case "api-key guard"
  (define g (make-api-key-guard #:verify (λ (k) (timing-safe-equal? k "k1"))))
  (check-false (g (test-req #:headers (list (h "X-API-Key" "k1")))))     ; allowed
  (check-true (response? (g (test-req))))                                ; missing
  (check-true (response? (g (test-req #:headers (list (h "X-API-Key" "wrong"))))))
  (define gq (make-api-key-guard #:verify (λ (k) (timing-safe-equal? k "k1"))
                                 #:query "token"))
  (check-false (gq (test-req #:query (list (cons 'token "k1"))))))       ; escape hatch

(test-case "api-key guard: 401 response shape"
  (define g (make-api-key-guard #:verify (λ (k) #f)))
  (define r (g (test-req)))
  (check-equal? (response-code r) 401))

(test-case "bearer guard"
  (define g (make-bearer-guard #:verify (λ (t) (timing-safe-equal? t "tok1"))))
  (check-false (g (test-req #:headers (list (h "Authorization" "Bearer tok1")))))
  (check-false (g (test-req #:headers (list (h "Authorization" "bearer tok1"))))) ; ci scheme
  (check-true (response? (g (test-req #:headers (list (h "Authorization" "tok1"))))))
  (check-true (response? (g (test-req))))
  (define r (g (test-req)))
  (check-equal? (response-code r) 401)
  (check-true (for/or ([hd (in-list (response-headers r))])
                (equal? (header-field hd) #"WWW-Authenticate"))))

(test-case "basic auth guard"
  (define creds64
    (bytes->string/latin-1 (base64-encode (string->bytes/utf-8 "admin:s3:cret") #"")))
  (define g (make-basic-auth-guard
             #:check (λ (user pass)
                       (and (timing-safe-equal? user "admin")
                            (timing-safe-equal? pass "s3:cret")))))
  (check-false (g (test-req #:headers (list (h "Authorization" (string-append "Basic " creds64))))))
  ;; password may contain colons: split on the first one only
  (define wrong (bytes->string/latin-1 (base64-encode (string->bytes/utf-8 "admin:wrong") #"")))
  (check-true (response? (g (test-req #:headers (list (h "Authorization" (string-append "Basic " wrong)))))))
  (check-true (response? (g (test-req))))
  (check-false (parse-basic-credentials (test-req #:headers (list (h "Authorization" "Basic !!!garbage"))))))

(test-case "guard-with middleware"
  (define g (make-api-key-guard #:verify (λ (k) (timing-safe-equal? k "k1"))))
  (define app (guard-with (λ (_req) (response/full 200 #"OK" (current-seconds) #"text/plain" '() (list #"hi"))) g))
  (check-equal? (response-code (app (test-req #:headers (list (h "X-API-Key" "k1"))))) 200)
  (check-equal? (response-code (app (test-req))) 401))

(test-case "guards are directly applicable"
  (define g (make-bearer-guard #:verify (λ (t) #t)))
  (check-false (g (test-req #:headers (list (h "Authorization" "Bearer x"))))))
