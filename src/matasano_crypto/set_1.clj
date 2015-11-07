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

(defn byte-xor [^bytes a ^bytes b]
  (let [out (byte-array (alength a))]
    (dotimes [i (alength a)]
      (aset-byte out i
                 (bit-xor (aget a i) (aget b i))))
    out))

(defn hex-xor [a b]
  (let [a-bytes (Hex/decode a)
        b-bytes (Hex/decode b)]
    (-> (byte-xor a-bytes b-bytes)
        Hex/encodeToString)))

(CodecSupport/toString (Hex/decode "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"))
;; => "I'm killing your brain like a poisonous mushroom"


;; Challenge 3: Single-byte XOR cipher

(def etaoin-shrdlu "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")

(defn single-byte-xor
  "Given a string of bytes and a single-byte mask, returns the xor result."
  [s mask]
  (let [s-bytes (Hex/decode s)
        m-bytes (byte-array (alength s-bytes) mask)]
    (-> (byte-xor s-bytes m-bytes)
        CodecSupport/toString)))

(defn etaoin-score
  "Given a char, returns its score indicating likelyhood of being part of an
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

(defn import-lines-of-txt
  [filepath]
  (read-string
   (-> (slurp filepath)
       (str/trim-newline) ;; don't want final \n to be surrounded by \"
       (str/replace #"\n" "\"\n \"")
       (str/join ["[\"" "\"]"]))))

(def c4-data (import-lines-of-txt "resources/4.txt"))


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
    (-> (byte-xor a-bytes k-bytes)
        Hex/encodeToString)))


;; Challenge 6: Break repeating key XOR

(def c6 (import-lines-of-txt "resources/6.txt"))
(def cipher-string (Base64/decode (str/join c6)))

(defn hamming
  "Given two strings, computes their bitwise hamming distance."
  [^String a ^String b]
  (let [as (CodecSupport/toBytes a)
        bs (CodecSupport/toBytes b)]
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
