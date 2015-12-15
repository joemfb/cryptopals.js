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

function createEncryptor(target) {
  var randomKey = crypto.randomBytes(16)

  return function(plaintext) {
    return cryptoLib.encryptECB(Buffer.concat([plaintext, target]), randomKey)
  }
}

// from 11
// TODO: document range
// also, should block size be a parameter; and isn't that a check-egg problem???
function guessMode(ciphertext) {
  for (var i = 5; i < 11; i++) {
    if (utils.hasDuplicateBlocks(ciphertext.slice(i), 16)) {
      return 'ecb'
    }
  }

  return 'cbc'
}

// from 11
function detectMode(encryptor) {
  var magicInput = 'aaaabbbbccccddddaaaabbbbccccddddaaaabbbbccccddddaaaabbbbccccdddd'
  var ciphertext = encryptor(new Buffer(magicInput))
  return guessMode(ciphertext)
}

function detectECB(encryptor) {
  return detectMode(encryptor) === 'ecb'
}

// subsequently moved to utils
function indexOfDuplicateBlock(buffer, size) {
  var blocks = utils.getBlocks(buffer, size)

  for (var i = 0; i < blocks.length; i++) {
    if (buffer.indexOf(blocks[i], (i * size) + size) > -1) {
      return i
    }
  }
  return -1
}

// get the largest duplicate blockSize (assumed to be between 8-64)
// subsequently moved to utils
function sizeOfDuplicateBlock(buffer) {
  for (var i = 64; i >= 8; i--) {
    if (indexOfDuplicateBlock(buffer, i) > -1) {
      return i
    }
  }
  return -1
}

// get the blockSize for `encryptor` (assumed to be between 8-64)
// subsequently moved to cryptoLib
function getBlockSize(encryptor) {
  var ciphertext, size

  // test 3 * blockSize, to ensure at least 2 whole blocks are duplicated
  for (var i = 24; i <= 192; i++) {
    ciphertext = encryptor(utils.makeBuffer(i, 'A'.charCodeAt(0)))
    size = sizeOfDuplicateBlock(ciphertext)

    if (size > -1) {
      return size
    }
  }

  throw new Error('couldn\'t find block size')
}

// find the next byte from `encryptor`
// paddedBlock is a ciphertext block aligned to target the last byte
// prefix is padding + guessedBytes, one less than the target byte
// target is the bounds of the target block
// subsequently moved to cryptoLib
function bruteForceECBByte(encryptor, padding, guessedBuffer, target) {
  var ciphertext = encryptor(padding)
  var paddedBlock = ciphertext.slice(target.from, target.to)
  var plaintext, permutation

  for (var i = 0; i < 256; i++) {
    plaintext = Buffer.concat([padding, guessedBuffer, new Buffer([i])])
    permutation = encryptor(plaintext).slice(target.from, target.to)

    if (permutation.equals(paddedBlock)) {
      return i
    }
  }

  return -1
}

// find the secret bytes from `encryptor`
function bruteForceECB(encryptor, blockSize, guessedBytes) {
  guessedBytes = guessedBytes || []

  var guessedBuffer = new Buffer(guessedBytes)
  var targetByte = guessedBytes.length
  var targetBlock = Math.floor(targetByte / blockSize) * blockSize
  var target = {
    from: targetBlock,
    to: targetBlock + blockSize
  }

  var paddingLength = blockSize - (targetByte % blockSize) - 1
  var padding = utils.makeBuffer(paddingLength, 'A'.charCodeAt(0))
  var guessedByte = bruteForceECBByte(encryptor, padding, guessedBuffer, target)

  if (guessedByte === -1) {
    // if we have less than a block left, assume it's padding
    // Note: the "right" thing would be to validate and strip padding
    if (encryptor(new Buffer(0)).length - targetByte < blockSize) {
      return guessedBuffer
    }

    console.log(guessedBuffer)
    console.log(guessedBuffer.toString())
    throw new Error('couldn\'t guess byte: ' + targetByte)
  }

  guessedBytes.push(guessedByte)

  return bruteForceECB(encryptor, blockSize, guessedBytes)
}

function breakECB(encryptor) {
  var blockSize = getBlockSize(encryptor)
  var plaintext = bruteForceECB(encryptor, blockSize)

  return {
    isECB: detectECB(encryptor),
    blockSize: blockSize,
    plaintext: plaintext
  }
}

var encryptor = createEncryptor(inputBuffer)
var result = breakECB(encryptor)

console.log('detected ECB: ' + result.isECB)
console.log('block size: ' + result.blockSize)
console.log()
console.log('brute forced plaintext:\n')
console.log(result.plaintext.toString())

// strip padding
var matches = result.plaintext.slice(0, inputBuffer.length).equals(inputBuffer)
console.log('plaintext matches input: ' + matches)
