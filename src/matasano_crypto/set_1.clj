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

(mask-xor etaoin-shrdlu (byte 88))
;; => "Cooking MC's like a pound of bacon"

(CodecSupport/toString (Hex/decode etaoin-shrdlu))
;; => "77316?x+x413=x9x(7-6<x7>x:9;76"
