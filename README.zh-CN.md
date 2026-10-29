# web-auth

[English](README.md) · **中文**

[![CI](https://github.com/turlamai/web-auth/actions/workflows/ci.yml/badge.svg)](https://github.com/turlamai/web-auth/actions/workflows/ci.yml)

Racket web-server 的认证守卫：API key、Bearer token、HTTP Basic，为小型 API 而做。守卫是「请求 → #f（放行）或响应（拒绝）」的过程——与普通 dispatcher 自由组合，不用起服务器就能测。

## 安装

```
raco pkg install web-auth
```

## 使用

```racket
(require web-auth
         net/url
         web-server/http
         web-server/web)

(define key-guard
  (make-api-key-guard
   #:verify (λ (k) (timing-safe-equal? k (api-key-from-env)))
   #:query "token"))            ; ?token= 逃生门，publy 同款

(define (api-dispatch req) ...)

(define app (guard-with api-dispatch key-guard))
;; 拒绝响应：401 + Cache-Control: no-store
```

Bearer 与 Basic：

```racket
(define bearer (make-bearer-guard #:verify token-in-db?))
(define basic  (make-basic-auth-guard
                #:check (λ (user pass) (check-creds user pass))))
```

- 所有密钥比较用 `timing-safe-equal?`——常数时间内容比较，无提前退出
- Basic 解码按第一个冒号切分（密码可含冒号），带规范的 `WWW-Authenticate` 质询
- 每个守卫都接 `#:on-unauthorized`，401 内容随你定制

## 开发

```
raco pkg install --auto --link .
raco test tests
raco setup --check-pkg-deps -l web-auth
```

## 许可

[MIT](LICENSE)
