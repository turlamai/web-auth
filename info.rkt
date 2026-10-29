#lang info

(define collection "web-auth")
(define version "0.1")
(define deps '("base" "web-server-lib"))
(define build-deps '("scribble-lib" "racket-doc" "rackunit-lib" "web-server-doc"))
(define scribblings '(("scribblings/web-auth.scrbl" ())))
(define pkg-desc "Authentication guards for Racket web-server dispatchers")
(define license 'MIT)
(define pkg-authors '(turlamai))
(define test-omit-paths '("scribblings"))
