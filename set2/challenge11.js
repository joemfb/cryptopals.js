/**
 * An ECB/CBC detection oracle
 *
 * http://cryptopals.com/sets/2/challenges/11/
 */

var crypto = require('crypto')
var utils = require('../lib/utils.js')
var cryptoLib = require('../lib/crypto.js')

function rand(min, max) {
  if (max === undefined) {
    max = min
    min = 0
  }
  return Math.floor(Math.random() * (max - min)) + min
}

function createEncryptor() {
  var randomIv = crypto.randomBytes(16)
  var randomKey = crypto.randomBytes(16)
  var prefix = crypto.randomBytes(rand(5, 11))

  if (rand(2)) {
    return function(plaintext) {
      var prepared = Buffer.concat([prefix, plaintext, prefix])
      return {
        mode: 'ecb',
        ciphertext: cryptoLib.encryptECB(prepared, randomKey)
      }
    }
  } else {
    return function(plaintext) {
      var prepared = Buffer.concat([prefix, plaintext, prefix])
      return {
        mode: 'cbc',
        ciphertext: cryptoLib.encryptCBC(prepared, randomKey, randomIv)
      }
    }
  }
}

function guessMode(ciphertext) {
  for (var i = 5; i < 11; i++) {
    if (utils.hasDuplicateBlocks(ciphertext.slice(i), 16)) {
      return 'ecb'
    }
  }
  return 'cbc'
}

function detectMode(encryptor) {
  var magicInput = 'aaaabbbbccccddddaaaabbbbccccddddaaaabbbbccccddddaaaabbbbccccdddd'
  var oracle = encryptor(new Buffer(magicInput))
  var guess = guessMode(oracle.ciphertext)

  return { mode: oracle.mode, correct: oracle.mode === guess }
}

function test(guesses) {
  var correct = 0
  var incorrect = 0
  var modes = { ecb: 0, cbc: 0 }
  var guess

  for (var i = 0; i < guesses; i++) {
    guess = detectMode(createEncryptor())
    guess.correct ? correct++ : incorrect++
    guess.mode === 'ecb' ? modes.ecb++ : modes.cbc++
  }

  if (correct === guesses) {
    console.log('guessed all correctly!')
  } else {
    console.log(incorrect + ' incorrect guesses :(')
  }
  console.log(modes.ecb + ' ecb; ' + modes.cbc + ' cbc')
}

test(1000)
