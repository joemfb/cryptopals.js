/**
 * Detect single-character XOR
 *
 * Detection and bruteforce decryption of XOR'd ciphertext
 *
 * http://cryptopals.com/sets/1/challenges/4/
 */

var fs = require('fs')

var input = fs.readFileSync(__dirname + '/inputs/4.txt', 'utf-8')

var alphabet = 'abcdefghijklmnopqrstuvwxyz'
var alphabetBuffer = new Buffer(alphabet.concat(alphabet.toUpperCase()))

// subsequently adapted and moved to utils
function score(input) {
  var score = 0

  for (var i = 0; i < input.length; i++) {
    if (alphabetBuffer.indexOf(input[i]) > -1 || input[i] === 32) {
      score++
    }
  }

  return score
}

// this computes single-charactor xor
// see challenge5 for the n-character version
function xor(payload, key) {
  var results = []
  var index

  for (var i = 0; i < payload.length; i++) {
    results.push(payload[i] ^ key[0])
  }

  return new Buffer(results)
}

// subsequently adapted and moved to utils
function breakSingleKeyXor(ciphertext) {
  var candidates = []
  var payload

  for (var i = 0; i < 200; i++) {
    payload = xor(ciphertext, [i])
    candidates.push({
      payload: payload,
      string: payload.toString(),
      score: score(payload)
    })
  }

  return candidates.sort(function(a, b) {
    return b.score - a.score
  })
}

var candidates = input.split('\n')
.map(function(ciphertext) {
  var b = new Buffer(ciphertext, 'hex')
  return breakSingleKeyXor(b)[0]
})
.sort(function(a, b) {
  return b.score - a.score
})

console.log(candidates[0])
