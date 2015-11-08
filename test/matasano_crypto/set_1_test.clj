(ns matasano-crypto.set-1-test
  (:require [clojure.test :refer :all]
            [matasano-crypto.set-1 :refer :all]))

(deftest challenge-1
  (let [input "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"]
    (is (= (hex->base64 input)
           "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"))))

(deftest challenge-2
  (let [input "1c0111001f010100061a024b53535009181c"
        target "686974207468652062756c6c277320657965"]
    (is (= (hex-xor input target)
           "746865206b696420646f6e277420706c6179"))))

(deftest challenge-3
  (let [input "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"]
    (is (= (single-byte-xor (decode-hex input) (byte 88))
           "Cooking MC's like a pound of bacon"))
    (is (= (englishest (xor-permutations (decode-hex input)))
           "Cooking MC's like a pound of bacon"))))

(deftest challenge-4
  (is (= (deref chal-4-answer)
         "Now that the party is jumping\n")))

(deftest challenge-5
  (is (= (repeat-key-xor ice-ice-lyrics "ICE")
         "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f")))

(deftest challenge-6
  (is (= (hamming "this is a test" "wokka wokka!!!")
         37)))
