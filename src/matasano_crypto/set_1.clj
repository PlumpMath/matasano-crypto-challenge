(ns matasano-crypto.set-1
  (:import [org.apache.shiro.codec Base64 CodecSupport Hex]))

;; Challenge 1: hex to base64

(defn hex->base64 [s]
  (let [raw (Hex/decode s)]
    (Base64/encodeToString raw)))

(defn base64->hex [s]
  (let [raw (Base64/decode s)]
    (Hex/encodeToString raw)))

;; Challenge 2: Fixed XOR

(defn inplace-xor [^bytes a ^bytes b ^bytes out]
  (dotimes [i (alength a)]
    (aset-byte out i
               (bit-xor (aget a i) (aget b i)))))

(defn hex-xor [a b]
  (let [a-bytes (Hex/decode a)
        b-bytes (Hex/decode b)
        out (byte-array (alength a-bytes))]
    (inplace-xor a-bytes b-bytes out)
    (Hex/encodeToString out)))

(CodecSupport/toString (Hex/decode "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"))
;; => "I'm killing your brain like a poisonous mushroom"

;; Challenge 3: Single-byte XOR cipher

(def etaoin-shrdlu "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")

(defn mask-xor
  "Given a byte-array and a single-byte mask, returns the xor result."
  [a mask]
  (let [a-bytes (Hex/decode a)
        m-bytes (byte-array (alength a-bytes) mask)
        out (byte-array (alength a-bytes))]
    (inplace-xor a-bytes m-bytes out)
    (CodecSupport/toString out)))

(defn etaoin-score
  "Given a char, returns its score indicating likelyhood of being part of an
  English word."
  [c]
  (let [weights {\e 16782 \a 12574 \i 11674 \r 11042 \t 10959
                 \o 10466 \n 9413 \s 8154 \l 8114 \c 6968
                 \u 5373 \p 4809 \m 4735 \d 4596 \h 4058
                 \g 3380 \b 3121 \y 2938 \f 2157 \v 1574
                 \w 1388 \k 1235 \x 507 \z 356 \q 343 \j 220}]
    (weights c)))

(defn score-text
  "Takes a plaintext string, checks each char against a word frequencies map and
  returns the sum of its char scores."
  [s]
  (reduce + (replace {nil 0} (map etaoin-score s))))

(defn find-most-english
  "Takes an encoded string XOR'd against a single character. Returns decoded
  string among candidates judged most likely to be English by `score-text'."
  [s]
  (let [cand-strings (for [i (range 128)] (mask-xor s (byte i)))
        str-score-pairs (into {} (map-indexed (fn [i x] [i (score-text x)])
                                              cand-strings))
        sorted (sort-by val > str-score-pairs)]
    (mask-xor s (byte (-> sorted first key)))))

(find-most-english etaoin-shrdlu)
;; => "Cooking MC's like a pound of bacon"
