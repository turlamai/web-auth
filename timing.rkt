#lang racket/base

;; Constant-time secret comparison: equalize on the first operand's
;; length, fold XOR over every byte, decide at the end.  Length
;; inequality still leaks (standard caveat, documented) but content
;; differences do not.

(require racket/contract)

(provide (contract-out
          [timing-safe-equal? (-> (or/c string? bytes?) (or/c string? bytes?) boolean?)]))

(define (as-bytes v)
  (if (string? v) (string->bytes/utf-8 v) v))

(define (timing-safe-equal? a b)
  (define ba (as-bytes a))
  (define bb (as-bytes b))
  (define la (bytes-length ba))
  (define lb (bytes-length bb))
  ;; compare against a same-length buffer either way so the loop cost
  ;; does not discriminate content
  (define target (if (= la lb) bb ba))
  (let loop ([i 0] [diff 0])
    (cond
      [(= i la)
       (and (= diff 0) (= la lb))]
      [else
       (loop (add1 i)
             (bitwise-ior diff (bitwise-xor (bytes-ref ba i) (bytes-ref target i))))])))
