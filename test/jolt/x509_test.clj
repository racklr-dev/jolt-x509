;; jolt.x509 Name/Validity/AlgorithmIdentifier round-trips.
;; Run: cd mtc && jolt run test/mtc/x509_test.clj
(ns jolt.test.x509
  (:require [jolt.x509 :as x]
            [jolt.der :as der]))

(defn check [label expected got]
  (if (= expected got)
    (println (str "PASS " label))
    (do (println (str "FAIL " label)) (println (str "  expected " (pr-str expected))) (println (str "  got      " (pr-str got))) (System/exit 1))))

;; Name: CN + O in one RDN, then a second RDN
(let [rdns [[[ [2 5 4 3] [:utf8 "example.com"]]
             [ [2 5 4 10] [:utf8 "MTC"]]]
            [[ [2 5 4 11] [:printable "eng"]]]]
      enc (x/encode-name rdns)
      dec (x/decode-name enc)]
  (check "name rdn count" 2 (count dec))
  (check "name rdn0 atv count" 2 (count (first dec)))
  (check "name rdn0[0]" [ [2 5 4 3] [:utf8 "example.com"]] (first (first dec)))
  (check "name rdn0[1]" [ [2 5 4 10] [:utf8 "MTC"]] (second (first dec)))
  (check "name rdn1[0]" [ [2 5 4 11] [:printable "eng"]] (first (second dec))))

;; Validity
(let [nb [:utc "240101000000Z"]
      na [:gentime "20260101000000Z"]
      enc (x/encode-validity nb na)
      dec (x/decode-validity enc)]
  (check "validity not-before" nb (first dec))
  (check "validity not-after" na (second dec)))

;; AlgorithmIdentifier
(let [enc (x/encode-alg-id [1 2 840 113549 1 1 1] nil)
      dec (x/decode-alg-id enc)]
  (check "alg-id oid" [1 2 840 113549 1 1 1] (first dec))
  (check "alg-id params null" [:null] (second dec)))

;; AlgorithmIdentifier with parameters omitted (id-alg-mtcProof)
(let [enc (der/encode [:seq [:oid [1 3 6 1 5 5 7 6 67]]])
      dec (x/decode-alg-id enc)]
  (check "alg-id omitted-params oid" [1 3 6 1 5 5 7 6 67] (first dec))
  (check "alg-id omitted-params nil" nil (second dec)))

;; Trust anchor ID distinguished name (trust-anchor-ids Section 4.1)
;; The DER RELATIVE-OID for 32473.1 is 0d 04 81 fd 59 01.
(let [name (x/encode-trust-anchor-name [32473 1])
      dec (x/decode-trust-anchor-name name)]
  (check "trust-anchor name roundtrip" [32473 1] dec))

(println "All X.509 tests passed")
