;; Big-endian TLS presentation-language byte primitives (RFC 9846).
(ns jolt.tls
  "Big-endian TLS presentation language primitives (RFC 9846).

  uint8/16/24/48/64 encode/decode and variable-length vectors with a
  width-n length prefix (opaque ...<0..2^(8n)-1>).  uint64 values are
  carried as Longs (two's complement), so pass unsigned 64-bit values
  through mtc.bit/u64 when they come from hex literals.")

(defn concat-bytes
  "Concatenate byte arrays, single byte ints, or seqs of byte ints into one
  byte array."
  [& xs]
  (let [parts (mapv (fn [x]
                      (cond
                        (number? x) (byte-array [(unchecked-byte x)])
                        (sequential? x) (byte-array (mapv unchecked-byte x))
                        :else x))
                    xs)
        total (reduce + 0 (map alength parts))
        out (byte-array total)]
    (loop [off 0 ps (seq parts)]
      (when-let [p (first ps)]
        (dotimes [i (alength p)] (aset out (+ off i) (aget p i)))
        (recur (+ off (alength p)) (next ps))))
    out))

(defn u8 [n]
  (byte-array [(unchecked-byte (bit-and n 0xFF))]))

(defn uint-bytes
  "Big-endian `width` bytes of unsigned n (a Long, possibly representing a
  uint64)."
  [n width]
  (let [n (unchecked-long n)]
    (byte-array (map (fn [i] (unchecked-byte (bit-and (bit-shift-right n (* 8 (- (dec width) i))) 0xFF)))
                     (range width)))))

(defn u16 [n] (uint-bytes n 2))
(defn u24 [n] (uint-bytes n 3))
(defn u48 [n] (uint-bytes n 6))
(defn u64 [n] (uint-bytes n 8))

(defn read-uint
  "Read a big-endian unsigned integer of `width` bytes at offset off.
  Returns [n next-offset] with n coerced back to Long (uint64 space)."
  [bytes off width]
  (loop [i 0 n 0]
    (if (= i width)
      [(unchecked-long n) (+ off width)]
      (recur (inc i) (+ (* n 256) (bit-and (aget bytes (+ off i)) 0xFF))))))

(defn varlen
  "Variable-length vector: a width-n length prefix followed by content bytes."
  [n content]
  (concat-bytes (uint-bytes (alength content) n) content))

(defn read-varlen
  "Read a variable-length vector with a width-n length prefix. Returns
  [content next-offset]."
  [bytes off n]
  (let [[len off] (read-uint bytes off n)]
    [(byte-array (map (fn [i] (aget bytes (+ off i))) (range len))) (+ off len)]))
