;; DER encode/decode known-answer + round-trip tests.
;; Run: cd mtc && jolt run test/mtc/der_test.clj
(ns jolt.test.der
  (:require [jolt.der :as der]
            [jolt.merkle :as m]))

(defn hex [b] (apply str (map (fn [x] (format "%02x" (bit-and x 0xff))) b)))

(defn check [label expected got]
  (if (= expected got)
    (println (str "PASS " label))
    (do (println (str "FAIL " label)) (println (str "  expected " (pr-str expected))) (println (str "  got      " (pr-str got))) (System/exit 1))))

;; Known DER encodings (hand-checked).
(check "INTEGER 0" "020100" (hex (der/encode [:int 0])))
(check "INTEGER 127" "02017f" (hex (der/encode [:int 127])))
(check "INTEGER 128" "02020080" (hex (der/encode [:int 128])))
(check "INTEGER 256" "02020100" (hex (der/encode [:int 256])))
(check "NULL" "0500" (hex (der/encode [:null])))
(check "OCTET STRING" "04026869" (hex (der/encode [:octets (.getBytes "hi" "UTF-8")])))
(check "OID sha256WithRSA" "06092a864886f70d01010b" (hex (der/encode [:oid [1 2 840 113549 1 1 11]])))
(check "OID id-alg-mtcProof" "06082b06010505070643" (hex (der/encode [:oid [1 3 6 1 5 5 7 6 67]])))
(check "SEQUENCE" "30050201000500" (hex (der/encode [:seq [:int 0] [:null]])))

(defn der= [a b]
  (if (and (vector? a) (vector? b))
    (let [tag (first a)]
      (and (= tag (first b))
           (case tag
             :octets (m/bytes= (second a) (second b))
             :ctx* (and (= (second a) (second b)) (m/bytes= (nth a 2) (nth b 2)))
             :ctx (der= (nth a 2) (nth b 2))
             :seq (and (= (count a) (count b))
                       (every? identity (map der= (rest a) (rest b))))
             (= a b))))
    (= a b)))

;; Round-trips.
(doseq [v [[:int 0] [:int 127] [:int 128] [:int 256] [:int 65536]
           [:octets (.getBytes "hello" "UTF-8")]
           [:oid [1 2 840 113549 1 1 11]]
           [:oid [1 3 6 1 5 5 7 6 67]]
           [:null]
           [:seq [:int 1] [:octets (.getBytes "x" "UTF-8")]]
           [:ctx 0 [:int 2]]
           [:ctx* 3 (.getBytes "abc" "UTF-8")]]]
  (let [[decoded rest] (der/decode (der/encode v))]
    (if (der= v decoded)
      (println (str "PASS roundtrip " (pr-str v)))
      (do (println (str "FAIL roundtrip " (pr-str v)))
          (println (str "  got " (pr-str decoded)))
          (System/exit 1)))
    (check (str "rest empty " (pr-str v)) 0 (alength rest))))

(println "All DER tests passed")
