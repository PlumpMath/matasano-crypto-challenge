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
  "Given a byte-array a single-byte mask, returns the
  xor result."
  [b-array mask]
  (let [m-bytes (byte-array (alength b-array) mask)]
    (-> (byte-xor b-array m-bytes)
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
  "Takes a byte-array. XOR this byte-array against key byte values in (range
  128) and return a map of the key used and the result decoded to plaintext."
  [s]
  (into {}
        (for [i (range 128)]
          [i (single-byte-xor s (byte i))])))

(defn englishest
  "Takes a list of strings and returns the most English of them all."
  [v]
  (let [str-score-pairs (into {} (map-indexed (fn [_ x] [x (score-text x)]) v))
        sorted (sort-by val > str-score-pairs)]
    (-> sorted first key)))


;; Challenge 4: Detect single-character XOR

(def c4-data (str/split (slurp "resources/4.txt") #"\n"))

(def chal-4-answer
  (delay (englishest (->> c4-data
                          (map decode-hex)
                          (map (comp vals xor-permutations))
                          (map englishest)))))

;; Challenge 5: Repeating-key XOR

(defn repeat-key-xor
  [a k]
  (let [len (alength a)
        k-bytes (->> (StringUtils/getBytesUtf8 k)
                     cycle
                     (take len)
                     byte-array)]
    (byte-xor a k-bytes)))

(defn repeat-key-xor-hex-out
  [a k]
  (Hex/encodeHexString (repeat-key-xor a k)))


;; Challenge 6: Break repeating key XOR

(def c6 (str/split (slurp "resources/6.txt") #"\n"))

(def cipher-bytes (Base64/decodeBase64 (str/join c6)))

(defn hamming
  "Given two byte-arrays, computes their bitwise hamming distance."
  [a b]
  (->> (byte-xor a b)
       (map #(Integer/bitCount %))      ; number of 1s in each byte
       (reduce +)))

(defn str-hamming [str1 str2]
  (hamming (StringUtils/getBytesUtf8 str1)
           (StringUtils/getBytesUtf8 str2)))

(defn normalized-hamming [a b keysize]
  (/ (hamming a b)
     keysize))

(defn- chunks [cipher keysize]
  (map byte-array (partition keysize cipher)))

(defn key-hamming-pairs
  "Takes a cipher byte-array and returns a map of keysizes to the average
  weighted hamming distances between chunks of keysize length."
  [cipher]
  (for [keysize (range 2 40)]
    (let [chunks (take 12 (partition 2 1 (chunks cipher keysize)))
          key-dist-pairs [keysize (map (partial apply hamming) chunks)]
          normalize (fn [[l v]]
                      [l (float (/ (reduce + v) (count v) l))])]
      (normalize key-dist-pairs))))

(defn guess-keysize [cipher]
  (keys (take 5 (sort-by val < (into {} (key-hamming-pairs cipher))))))

(defn transpose-every-n [cipher n]
  (for [i (range n)]
    (byte-array (take-nth n (drop i cipher)))))

(defn- find-key [cipher keysize]
  (byte-array (map ffirst (for [block (transpose-every-n cipher keysize)]
                            (->> block
                                 xor-permutations
                                 (map (fn [x] [(key x) (score-text (val x))]))
                                 (into {})
                                 (sort-by val >))))))

(def challenge-6-keys
  (delay (for [keysize (guess-keysize cipher-bytes)]
           [(StringUtils/newStringUtf8 (find-key cipher-bytes keysize)) keysize])
         ;; =>
         ;; (["Terminator X: Bring the noise" 29]
         ;;  ["ninin" 5]
         ;;  ["noenniininnenii" 15]
         ;;  ["nnntionniinoinrinrhninetnniieie" 31]
         ;;  ["ni" 2])
         ))

(StringUtils/newStringUtf8 (let [key (ffirst @challenge-6-keys)]
                             (repeat-key-xor cipher-bytes key)))

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
