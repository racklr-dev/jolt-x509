;; Minimal X.509 DER codec: Name, Validity, AlgorithmIdentifier.
(ns jolt.x509
  "Minimal X.509 DER codec for the fields MTC needs.

  A Name is a SEQUENCE of RDNs; each RDN is a SET of AttributeTypeAndValue;
  each ATV is a SEQUENCE of {OID, value}.  Values are DER string types
  (:utf8 :printable :ia5).  Validity is a SEQUENCE of two Time values
  (:utc or :gentime).  AlgorithmIdentifier is a SEQUENCE of {OID, params}.

  Full RFC5280 name/value surface is out of scope — enough to build and
  parse the structured names and validity a test CA and relying party use."
  (:require [jolt.der :as der]))

;; --- Name -------------------------------------------------------------------
;; A Name is a vector of RDNs.  An RDN is a vector of [oid value] pairs.

(defn encode-name
  "Encode a Name from a vector of RDNs (each a vector of [oid value])."
  [rdns]
  (der/encode
    (into [:seq]
          (map (fn [rdn]
                 (into [:set]
                       (map (fn [[oid value]] [:seq [:oid oid] value]) rdn)))
               rdns))))

(defn decode-name
  "Decode a DER Name into a vector of RDNs (each a vector of [oid value])."
  [bytes]
  (let [[v _] (der/decode bytes)]
    (when-not (= :seq (first v))
      (throw (ex-info "Name must be a SEQUENCE" {})))
    (mapv (fn [rdn]
            (when-not (= :set (first rdn))
              (throw (ex-info "RDN must be a SET" {})))
            (mapv (fn [atv]
                    (when-not (= :seq (first atv))
                      (throw (ex-info "ATV must be a SEQUENCE" {})))
                    (let [oid-v (second atv)
                          value (nth atv 2)]
                      (when-not (= :oid (first oid-v))
                        (throw (ex-info "ATV type must be an OID" {})))
                      [(second oid-v) value]))
                  (rest rdn)))
          (rest v))))

;; --- Validity ---------------------------------------------------------------

(defn encode-validity
  "Encode a Validity from two Time values, each [:utc s] or [:gentime s]."
  [not-before not-after]
  (der/encode [:seq not-before not-after]))

(defn decode-validity
  "Decode a DER Validity into [not-before not-after] Time values."
  [bytes]
  (let [[v _] (der/decode bytes)]
    (when-not (= :seq (first v))
      (throw (ex-info "Validity must be a SEQUENCE" {})))
    [(second v) (nth v 2)]))

;; --- AlgorithmIdentifier ----------------------------------------------------

(defn encode-alg-id
  "Encode an AlgorithmIdentifier from OID arcs and a params DER value
  (nil -> NULL)."
  [oid-arcs params]
  (der/encode [:seq [:oid oid-arcs] (or params [:null])]))

(defn decode-alg-id
  "Decode a DER AlgorithmIdentifier into [oid-arcs params]."
  [bytes]
  (let [[v _] (der/decode bytes)]
    (when-not (= :seq (first v))
      (throw (ex-info "AlgorithmIdentifier must be a SEQUENCE" {})))
    (let [oid-v (second v)
          params (when (< 2 (count v)) (nth v 2))]
      (when-not (= :oid (first oid-v))
        (throw (ex-info "AlgorithmIdentifier algorithm must be an OID" {})))
      [(second oid-v) params])))

;; --- Certificate / TBSCertificate parsing (minimal) -------------------------

(defn- u8 [b] (bit-and b 0xFF))

(defn- slice [bytes off len]
  (let [out (byte-array len)]
    (dotimes [i len] (aset out i (aget bytes (+ off i))))
    out))



(defn parse-certificate
  "Parse a DER X.509 Certificate into {:tbs-certificate :signature-algorithm
  :signature-value} (the first two as full DER blobs, signature-value as the
  BIT STRING content bytes)."
  [bytes]
  (when-not (= 0x30 (u8 (aget bytes 0)))
    (throw (ex-info "Certificate must be a SEQUENCE" {})))
  (let [[_ body _] (der/read-tlv bytes 0)
        [tag1 _ off1] (der/read-tlv body 0)
        [tag2 _ off2] (der/read-tlv body off1)
        [tag3 sv off3] (der/read-tlv body off2)]
    (when-not (= 0x30 tag1) (throw (ex-info "tbsCertificate must be a SEQUENCE" {:tag tag1})))
    (when-not (= 0x30 tag2) (throw (ex-info "signatureAlgorithm must be a SEQUENCE" {:tag tag2})))
    (when-not (= 0x03 tag3) (throw (ex-info "signatureValue must be a BIT STRING" {:tag tag3})))
    {:tbs-certificate (slice body 0 off1)
     :signature-algorithm (slice body off1 (- off2 off1))
     :signature-value sv}))



(defn- spki-algorithm-field [spki-body]
  (let [[tag _ off] (der/read-tlv spki-body 0)]
    (when-not (= 0x30 tag) (throw (ex-info "SPKI algorithm must be a SEQUENCE" {:tag tag})))
    (slice spki-body 0 off)))

(defn parse-tbs-certificate
  "Parse a DER TBSCertificate into a map. Opaque fields (issuer, validity,
  subject, spki, spki-algorithm, signature) are full DER blobs; serial-number
  and version are parsed; unique-ids/extensions are content bytes."
  [bytes]
  (when-not (= 0x30 (u8 (aget bytes 0)))
    (throw (ex-info "TBSCertificate must be a SEQUENCE" {})))
  (let [[_ body _] (der/read-tlv bytes 0)]
    (loop [off 0 acc {} saw30 0]
      (if (>= off (alength body))
        acc
        (let [[tag fbody fend] (der/read-tlv body off)
              field (slice body off (- fend off))]
          (case tag
            0xA0 (let [[dv _] (der/decode fbody)]
                   (recur fend (assoc acc :version (second dv)) saw30))
            0x02 (recur fend (assoc acc :serial-number (der/decode-int fbody)) saw30)
            0x30 (case saw30
                   0 (recur fend (assoc acc :signature field) 1)
                   1 (recur fend (assoc acc :issuer field) 2)
                   2 (recur fend (assoc acc :validity field) 3)
                   3 (recur fend (assoc acc :subject field) 4)
                   4 (recur fend (assoc acc :spki field
                                           :spki-algorithm (spki-algorithm-field fbody)) 5)
                   (recur fend acc (inc saw30)))
            0x81 (recur fend (assoc acc :issuer-unique-id fbody) saw30)
            0x82 (recur fend (assoc acc :subject-unique-id fbody) saw30)
            0xA3 (recur fend (assoc acc :extensions fbody) saw30)
            (throw (ex-info "unexpected TBSCertificate field tag" {:tag tag}))))))))







;; --- Trust anchor ID distinguished name (trust-anchor-ids Section 4.1) ------

(def id-rdna-trust-anchor-id
  "id-rdna-trustAnchorID: 1.3.6.1.5.5.7.25.3."
  [1 3 6 1 5 5 7 25 3])

(defn encode-trust-anchor-name
  "Encode a trust anchor ID (PEN-relative arcs) as a PKIX distinguished name:
  a single RDN whose single attribute has type id-rdna-trustAnchorID and value
  a RELATIVE-OID holding the trust anchor ID."
  [arcs]
  (encode-name [[[id-rdna-trust-anchor-id [:relative-oid arcs]]]]))

(defn decode-trust-anchor-name
  "Decode a trust anchor ID distinguished name back to its PEN-relative arcs."
  [name-der]
  (let [rdns (decode-name name-der)]
    (when-not (and (= 1 (count rdns)) (= 1 (count (first rdns))))
      (throw (ex-info "trust anchor name must be one RDN with one attribute" {})))
    (let [[oid value] (first (first rdns))]
      (when-not (= id-rdna-trust-anchor-id oid)
        (throw (ex-info "trust anchor name has wrong attribute type" {:oid oid})))
      (when-not (= :relative-oid (first value))
        (throw (ex-info "trust anchor name value must be a RELATIVE-OID" {})))
      (second value))))
