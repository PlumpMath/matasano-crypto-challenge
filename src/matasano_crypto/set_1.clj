(ns matasano-crypto.set-1
  (:import [org.apache.shiro.codec Base64 CodecSupport Hex])
  (:require [clojure.string :as str]))

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

(defn single-byte-xor
  "Given a string of bytes and a single-byte mask, returns the xor result."
  [s mask]
  (let [s-bytes (Hex/decode s)
        m-bytes (byte-array (alength s-bytes) mask)
        out (byte-array (alength s-bytes))]
    (inplace-xor s-bytes m-bytes out)
    (CodecSupport/toString out)))

(defn etaoin-score
  "Given a char, returns its score indicating likelyhood of being part of an
  English word."
  [c]
  (let [weights {\e 16782 \a 12574 \i 11674 \r 11042 \t 10959
                 \o 10466 \n 9413 \s 8154 \l 8114 \c 6968
                 \u 5373 \p 4809 \m 4735 \d 4596 \h 4058
                 \g 3380 \b 3121 \y 2938 \f 2157 \v 1574
                 \w 1388 \k 1235 \x 507 \z 356 \q 343 \j 220
                 \space 6000}]
    (weights c)))

(defn score-text
  "Takes a plaintext string, checks each char against a word frequencies map and
  returns the sum of its char scores."
  [s]
  (reduce + (replace {nil -6000} (map etaoin-score s))))

(defn xor-permute-strings
  "Takes an string of bytes XOR'd against a single character. Returns all
  permutations of this string XOR'd against a single byte."
  [s]
  (for [i (range 128)] (single-byte-xor s (byte i))))

(defn find-most-english
  "Takes a list of strings and returns the most English of them all."
  [v]
  (let [str-score-pairs (into {} (map-indexed (fn [_ x] [x (score-text x)]) v))
        sorted (sort-by val > str-score-pairs)]
    (-> sorted first key)))


;; Challenge 4: Detect single-character XOR

(def c4-data
  (read-string
   (-> (slurp "resources/4.txt")
       (str/trim-newline) ;; don't want final \n to be surrounded by \"
       (str/replace #"\n" "\"\n \"")
       (str/join ["[\"" "\"]"]))))

#_(find-most-english
   (map (comp find-most-english xor-permute-strings) c4-data))

;; Challenge 5: Repeating-key XOR

(def ice-ice-lyrics
  "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal")

(defn repeat-key-xor
  [a k]
  (let [a-bytes (CodecSupport/toBytes a)
        len (alength a-bytes)
        k-bytes (->> (CodecSupport/toBytes k)
                     cycle
                     (take len)
                     byte-array)
        out (byte-array len)]
    (inplace-xor a-bytes k-bytes out)
    (Hex/encodeToString out)))
