(ns matasano-crypto.set-1-test
  (:require [clojure.test :refer :all]
            [matasano-crypto.set-1 :refer :all]))

(deftest challenge-1
  (let [input "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"]
    (is (= "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
           (hex->base64 input)))))

(deftest challenge-2
  (let [input "1c0111001f010100061a024b53535009181c"
        target "686974207468652062756c6c277320657965"]
    (is (= "746865206b696420646f6e277420706c6179"
           (hex-xor input target)))))

(deftest challenge-3
  (let [input "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"]
    (is (= "Cooking MC's like a pound of bacon"
           (mask-xor input (byte 88))))))
