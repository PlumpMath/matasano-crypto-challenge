(ns matasano-crypto.set-1
  (:import [org.apache.commons.codec.binary Base64 Hex]
           javax.crypto.spec.SecretKeySpec
           javax.crypto.Cipher)
  ;; http://commons.apache.org/proper/commons-codec/archives/1.10/apidocs/index.html
  (:require [clojure.string :as str]))

;;; Challenge 1: hex to base64

;; Remember, bytes are 8 bits (ex: 2r11010011), representing integers between 0
;; and 255. So an array of bytes looks something like [73 39 109 32 107 105].

(defn get-bytes
  "Takes a UTF-8 string and returns a [B of the bytes representing each char."
  [s]
  (.getBytes s "UTF-8"))

(defn decode-hex
  "Takes a string representing a hexadecimal value, where each pair of chars is
  the hex encoding of a character. Returns a [B where each byte is the value of
  that hexadecimal (hex to byte conversion: 0x49 -> 73)."
  [s]
  (Hex/decodeHex (char-array s)))

(defn hex->base64
  "Takes a hexadecimal string, decodes it into a [B, then returns that binary
  data encoded with base64.

  Hex pairs, such as 0x4d, are encoded in bytes. Base64 takes 6 bits at a time
  and encodes them as one of 64 different characters (A-Z, a-z, 0-9, +, /)."
  [s]
  (Base64/encodeBase64String (decode-hex s)))


;;; Challenge 2: Fixed XOR

(defn byte-xor
  "Take two equal length arrays of bytes, bit-xors each corresponding byte and
  returns the resulting byte-array"
  [a b]
  (byte-array (map bit-xor a b)))

(defn hex-xor [a b]
  (let [a-bytes (decode-hex a)
        b-bytes (decode-hex b)]
    (-> (byte-xor a-bytes b-bytes)
        Hex/encodeHexString)))


;;; Challenge 3: Single-byte XOR cipher

(def etaoin-shrdlu "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")

(defn single-byte-xor
  "Given a byte-array a single-byte mask, returns the xor result."
  [b-array mask]
  (let [m-bytes (byte-array (alength b-array) mask)]
    (-> (byte-xor b-array m-bytes)
        String.)))

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


;;; Challenge 4: Detect single-character XOR

(def c4-data (str/split-lines (slurp "resources/4.txt")))

(def chal-4-answer
  (delay
   (englishest (->> c4-data
                    (map decode-hex)
                    (map (comp vals xor-permutations))
                    (map englishest)))))

;;; Challenge 5: Repeating-key XOR

(defn repeat-key-xor
  [a k]
  (let [len (alength a)
        k-bytes (->> (cycle k)
                     (take len)
                     byte-array)]
    (byte-xor a k-bytes)))


;;; Challenge 6: Break repeating key XOR

(def file6 (str/split-lines (slurp "resources/6.txt")))

(def cipher-bytes-6 (Base64/decodeBase64 (str/join file6)))

(defn hamming
  "Given two byte-arrays, computes their bitwise hamming distance."
  [a b]
  (->> (byte-xor a b)
       (map #(Integer/bitCount %))      ; number of 1s in each byte
       (reduce +)))

(defn normalized-hamming [a b keysize]
  (/ (hamming a b)
     keysize))

(defn- chunks [cipher len]
  (map byte-array (partition len cipher)))

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

(defn find-key
  [cipher keysize]
  (byte-array
   (map ffirst (for [block (transpose-every-n cipher keysize)]
                 (->> block
                      xor-permutations
                      (map (fn [x] [(key x) (score-text (val x))]))
                      (into {})
                      (sort-by val >))))))

(def challenge-6-keys
  (delay (for [keysize (guess-keysize cipher-bytes-6)]
           [(String. (find-key cipher-bytes-6 keysize)) keysize])
         ;; =>
         ;; (["Terminator X: Bring the noise" 29]
         ;;  ["ninin" 5]
         ;;  ["noenniininnenii" 15]
         ;;  ["nnntionniinoinrinrhninetnniieie" 31]
         ;;  ["ni" 2])
         ))

(defn decrypt-vigenere
  [cipher]
  (let [ks (for [k (guess-keysize cipher)]
             [(find-key cipher k) k])
        k (ffirst ks)]
    (String. (repeat-key-xor cipher k))))


;;; Challenge 7: AES in ECB mode

(def file7 (slurp "resources/7.txt"))

(def key7 (get-bytes "YELLOW SUBMARINE"))

(defn get-cipher [mode seed trans]
  (let [key-spec (SecretKeySpec. (get-bytes seed) "AES")
        cipher (Cipher/getInstance trans)]
    (.init cipher mode key-spec)
    cipher))

(defn encrypt [text key trans]
  (let [bytes (get-bytes text)
        cipher (get-cipher Cipher/ENCRYPT_MODE key trans)]
    (Base64/encodeBase64String (.doFinal cipher bytes))))

(defn decrypt [text key trans]
  (let [cipher (get-cipher Cipher/DECRYPT_MODE key trans)]
    (String. (.doFinal cipher (Base64/decodeBase64 text)))))


;;; Challenge 8: Detect AES in ECB mode

(def file8 (str/split-lines (slurp "resources/8.txt")))

(def file8-b64 (map hex->base64 (str/split-lines (slurp "resources/8.txt"))))

(defn detect-aes-ecb [b-array]
  (let [chunks (chunks b-array 16)]
    (- (count chunks) (count (set chunks)))))

(->> file8
     (map get-bytes)
     (map detect-aes-ecb))
