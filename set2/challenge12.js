/**
 * Byte-at-a-time ECB decryption (Simple)
 *
 * http://cryptopals.com/sets/2/challenges/12/
 */

var fs = require('fs')
var crypto = require('crypto')
var utils = require('../lib/utils.js')
var cryptoLib = require('../lib/crypto.js')

var input = fs.readFileSync(__dirname + '/inputs/12.txt', 'utf-8').replace(/\s/g, '')
var inputBuffer = new Buffer(input, 'base64')
var randomKey

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
  var ciphertext = encryptor(new Buffer(magicInput))
  return guessMode(ciphertext)
}

function encryptECBUnknownKey(plaintext) {
  if (!randomKey) {
    randomKey = crypto.randomBytes(16)
  }

  return cryptoLib.encryptECB(Buffer.concat([plaintext, inputBuffer]), randomKey)
}

function duplicateBlockSize(ciphertext) {
  var a, b

  // 8 guessed to be smallest block size, 64 guessed to be largest ...
  for (var i = 8; i < 65; i++) {
    a = ciphertext.slice(0, i)
    b = ciphertext.slice(i, i * 2)

    if (a.indexOf(b) === 0) {
      return i
    }
  }

  return -1
}

function getBlockSize() {
  var plaintext, ciphertext, size

  // 50 chosen for no particular reason
  for (var i = 0; i < 50; i++) {
    plaintext = (new Array(i + 1).fill('A')).join('')
    ciphertext = encryptECBUnknownKey(new Buffer(plaintext))
    size = duplicateBlockSize(ciphertext)

    if (size > -1) {
      return size
    }
  }

  console.error('couldn\'t find block size')
  return -1
}

function detectECB() {
  return detectMode(encryptECBUnknownKey) === 'ecb'
}

function bufferEqual(a, b) {
  if (a.length !== b.length) return false

  for (var i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) {
      return false
    }
  }

  return true
}

function bruteForceByte(blockSize, finalLength, guessedBytes) {
  // finalLength = finalLength || encryptECBUnknownKey(new Buffer(0)).length
  // use inputBuffer.length to ignore padding
  finalLength = finalLength || inputBuffer.length
  guessedBytes = guessedBytes || []

  var guessedBuffer = new Buffer(guessedBytes)

  if (finalLength === guessedBytes.length) {
    return guessedBuffer
  }

  var paddingLength = blockSize - (guessedBytes.length % blockSize) - 1
  var targetBlock = guessedBytes.length - (guessedBytes.length % blockSize)
  var target = {
    from: targetBlock,
    to: targetBlock + blockSize
  }

  var padding = new Buffer(new Array(paddingLength).fill('A').join(''))
  var paddedBlock = encryptECBUnknownKey(padding).slice(target.from, target.to)

  var plaintext, permutation
  var found = false

  for (var i = 0; i < 256; i++) {
    plaintext = Buffer.concat([padding, guessedBuffer, new Buffer([i])])
    permutation = encryptECBUnknownKey(plaintext).slice(target.from, target.to)

    if (bufferEqual(permutation, paddedBlock)) {
      guessedBytes.push(i)
      found = true
      break
    }
  }

  if (!found) {
    throw new Error('couldn\'t guess byte: ' + (guessedBytes.length + 1))
  }

  return bruteForceByte(blockSize, finalLength, guessedBytes)
}

function breakECB() {
  var blockSize = getBlockSize()
  var isECB = detectECB()

  return bruteForceByte(blockSize)
}

console.log('block size: ' + getBlockSize())
console.log('detected ECB: ' + detectECB())
console.log()
console.log('brute forced plaintext:\n')
var plaintext = breakECB()
console.log(plaintext.toString())

// strip padding
var matches = bufferEqual(plaintext.slice(0, inputBuffer.length), inputBuffer)
console.log('plaintext matches input: ' + matches)
