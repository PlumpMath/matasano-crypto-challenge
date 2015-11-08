(ns matasano-crypto.set-1
  (:import [org.apache.commons.codec.binary Base64 Hex BinaryCodec StringUtils])
  (:require [clojure.string :as str]))

;; Challenge 1: hex to base64

(defn decode-hex [s]
  (Hex/decodeHex (char-array s)))

(defn hex->base64 [s]
  (Base64/encodeBase64String (decode-hex s)))


;; Challenge 2: Fixed XOR

(defn byte-xor
  "Take two arrays of bytes, bit-xors each corresponding byte and returns the
  resulting byte-array"
  [^bytes a ^bytes b]
  (let [out (byte-array (alength a))]
    (dotimes [i (alength a)]
      (aset-byte out i
                 (bit-xor (aget a i) (aget b i))))
    out))

(defn hex-xor [a b]
  (let [a-bytes (decode-hex a)
        b-bytes (decode-hex b)]
    (-> (byte-xor a-bytes b-bytes)
        Hex/encodeHexString)))


;; Challenge 3: Single-byte XOR cipher

(def etaoin-shrdlu "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")

(defn single-byte-xor
  "Given a string of bytes and a single-byte mask, returns the xor result."
  [s mask]
  (let [s-bytes (decode-hex s)
        m-bytes (byte-array (alength s-bytes) mask)]
    (-> (byte-xor s-bytes m-bytes)
        (StringUtils/newStringUtf8))))

(defn etaoin-score
  "Given a char, returns its score indicating likelyhood of comprising an
  English word."
  [c]
  (let [weights {\e 0.1202 \t 0.091 \a 0.0812 \o 0.0768 \i 0.0731
                 \n 0.0695 \s 0.0628 \r 0.0602 \h 0.0592 \d 0.0432
                 \l 0.0398 \u 0.0288 \c 0.0271 \m 0.0261 \f 0.023
                 \y 0.0211 \w 0.0209 \g 0.0203 \p 0.0182 \b 0.0149
                 \v 0.0111 \k 0.0069 \x 0.0017 \q 0.0011 \j 0.001
                 \z 0.0007 \space 0.15}]
    (weights c)))

(defn score-text
  "Takes a plaintext string, checks each char against a word frequencies map and
  returns the sum of its char scores."
  [s]
  (reduce + (replace {nil -0.1} (map etaoin-score s))))

(defn xor-permutations
  "Takes a string of bytes. Returns all permutations of this string XOR'd
  against a single byte."
  [s]
  (for [i (range 128)] (single-byte-xor s (byte i))))

(defn englishest
  "Takes a list of strings and returns the most English of them all."
  [v]
  (let [str-score-pairs (into {} (map-indexed (fn [_ x] [x (score-text x)]) v))
        sorted (sort-by val > str-score-pairs)]
    (-> sorted first key)))


;; Challenge 4: Detect single-character XOR

(def c4-data (str/split (slurp "resources/4.txt") #"\n"))


;; Challenge 5: Repeating-key XOR

(def ice-ice-lyrics
  "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal")

(defn repeat-key-xor
  [a k]
  (let [a-bytes (StringUtils/getBytesUtf8 a)
        len (alength a-bytes)
        k-bytes (->> (StringUtils/getBytesUtf8 k)
                     cycle
                     (take len)
                     byte-array)
        out (byte-array len)]
    (-> (byte-xor a-bytes k-bytes)
        Hex/encodeHexString)))


;; Challenge 6: Break repeating key XOR

(def c6 (str/split (slurp "resources/6.txt") #"\n"))
(def cipher-string (Base64/decodeBase64 (str/join c6)))

(defn hamming
  "Given two strings, computes their bitwise hamming distance."
  [^String a ^String b]
  (let [as (StringUtils/getBytesUtf8 a)
        bs (StringUtils/getBytesUtf8 b)]
    (->> (map bit-xor as bs)
         (map #(Integer/bitCount %))    ; number of 1s in each byte
         (reduce +))))

(defn normalized-hamming [a b keysize]
  (/ (hamming a b)
     keysize))

(for [keysize (range 2 40)]
  (let [take-chunk (fn [s] (apply str (take keysize s)))
        a (take-chunk cipher-string)
        b (take-chunk (drop keysize cipher-string))
        c (take-chunk (drop (* 2 keysize) cipher-string))
        d (take-chunk (drop (* 3 keysize) cipher-string))
        e (take-chunk (drop (* 4 keysize) cipher-string))
        f (take-chunk (drop (* 5 keysize) cipher-string))
        g (take-chunk (drop (* 6 keysize) cipher-string))
        h (take-chunk (drop (* 7 keysize) cipher-string))
        ]
    (/ (+ (normalized-hamming a b keysize)
          (normalized-hamming c d keysize)
          (normalized-hamming e f keysize)
          (normalized-hamming g h keysize))
       4.0)))

(def blocked-cipher (partition 4 cipher-string))
(def transposed-ciphers (map (comp ;; #(Hex/encodeToString %)
                              ;; vec
                              ;; #(CodecSupport/toBytes %)
                              (partial apply str))
                             [(map first blocked-cipher)
                              (map second blocked-cipher)
                              (map #(nth % 2) blocked-cipher)
                              (map last blocked-cipher)]))

;; (englishest (xor-permutations (first transposed-ciphers)))

(bit-xor 4 3)
;; => 7
(bit-xor 2r100 2r011)
;; => 7
(Integer/toBinaryString 7)
;; => "111"
(Integer/bitCount 7)
;; => 3

(Integer/toHexString 100)
;; => "64"
(Integer/toBinaryString 100)
;; => "1100100"
(Integer/bitCount 100)
;; => 3
