# jolt-x509

A minimal DER (X.690) codec and X.509 Name / Validity / AlgorithmIdentifier / Certificate parsing for [Jolt](https://github.com/jolt-lang/jolt). Pure Clojure — no JVM, no native libraries.

## Use

```clojure
;; deps.edn
{:deps {racklr-dev/jolt-x509
        {:git/url "https://github.com/racklr-dev/jolt-x509"
         :git/sha "f33074768e4a7305fbff3881612114c5ac890a69"}}}
```

```clojure
(require '[jolt.der :as der]
         '[jolt.x509 :as x])

(der/encode [:seq [:int 5] [:utf8 "hi"]])
(x/encode-name [[[[2 5 4 3] [:utf8 "example.com"]]]])
```

## What's here

- `jolt.der` — DER encode/decode: INTEGER, OCTET STRING, OID, SEQUENCE, SET, BOOLEAN, the string types, UTCTime/GeneralizedTime, BIT STRING, RELATIVE-OID, context tags
- `jolt.tls` — big-endian TLS-presentation primitives (uint8..64, length-prefixed vectors)
- `jolt.x509` — Name / Validity / AlgorithmIdentifier codec, trust-anchor-ID distinguished names, X.509 Certificate / TBSCertificate parsing

## Test

```bash
for t in test/jolt/*_test.clj; do jolt run "$t"; done
```
