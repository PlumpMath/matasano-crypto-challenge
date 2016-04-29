(ns matasano-crypto.set-2
  (:import [org.apache.commons.codec.binary Base64 Hex]
           javax.crypto.spec.SecretKeySpec
           javax.crypto.Cipher)
  (:require [matasano-crypto.set-1 :refer :all]
            [clojure.string :as str]))

;; Challenge 9: Implement PKCS #7 padding

(defn- pad-size
  "Returns the required pad size for a given input and block size. An input of
  18 bytes with a block size of 16 requires 14 bytes of padding."
  [input-size block-size]
  (let [block-multiples (map #(* block-size %) (range))
        breakpoint (some #(when (>= % input-size) %) block-multiples)]
    (- breakpoint input-size)))

(defn pkcs7-pad [bytes block-size]
  (byte-array
   (let [pad-size (pad-size (count bytes) block-size)]
     (concat bytes (repeat pad-size (byte pad-size))))))


;; Challenge 10: Implement CBC mode

(def file10 (str/join (str/split-lines (slurp "resources/10.txt"))))

(def file10-bytes (Base64/decodeBase64 file10))

(def iv (byte-array 16))

(defn encrypt-aes-cbc [plain key iv]
  (let [block-size (count key)
        padded (pkcs7-pad plain (count key))
        blocks (partition block-size padded)]
    (-> (reduce (fn [[acc prev] next]
                  (let [result (encrypt-aes (xor prev next) key)]
                    [(concat acc result) result]))
                [[] iv]
                blocks)
        first
        byte-array)))

(defn decrypt-aes-cbc [cipher key iv]
  (let [block-size (count key)
        padded (pkcs7-pad cipher (count key))
        blocks (partition block-size padded)]
    (-> (reduce (fn [[acc prev] next]
                  (let [result (xor
                                (decrypt-aes (byte-array next) key)
                                prev)]
                    [(concat acc result) next]))
                [[] iv]
                blocks)
        first
        byte-array)))


;; Challenge 11: ECB/CBC detection oracle

(defn rand-key
  "Random key of 16 bytes."
  []
  (byte-array (repeatedly 16 #(rand-int 256))))

(defn encrypt-cbc-or-ecb [plain]
  (let [pad #(pkcs7-pad % (+ (count %) (+ 5 (rand-int 5))))
        padded (-> plain pad reverse pad reverse byte-array)]
    (condp = (get [:ecb :cbc] (rand-int 2))
      :ecb (encrypt-aes padded (rand-key))
      :cbc (encrypt-aes-cbc padded (rand-key) (rand-key)))))
