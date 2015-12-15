/**
 * Byte-at-a-time ECB decryption (Harder)
 *
 * http://cryptopals.com/sets/2/challenges/14/
 */

var fs = require('fs')
var crypto = require('crypto')
var utils = require('../lib/utils.js')
var cryptoLib = require('../lib/crypto.js')

// reuse input from challenge 12
var input = fs.readFileSync(__dirname + '/inputs/12.txt', 'utf-8').replace(/\s/g, '')
var inputBuffer = new Buffer(input, 'base64')

function createEncryptor(target) {
  var randomCount = utils.rand(99) + 1
  var randomPrefix = crypto.randomBytes(randomCount)
  var randomKey = crypto.randomBytes(16)

  return function(plaintext) {
    var x = Buffer.concat([randomPrefix, plaintext, target])
    return cryptoLib.encryptECB(x, randomKey)
  }
}

function indexOfDuplicateBlock(buffer, size) {
  var blocks = utils.getBlocks(buffer, size)

  for (var i = 0; i < blocks.length; i++) {
    if (buffer.indexOf(blocks[i], (i * size) + size) > -1) {
      return i
    }
  }
  return -1
}

// from 12
function sizeOfDuplicateBlock(buffer) {
  // blockSize assumed to be between 8-64; get the largest
  for (var i = 64; i >= 8; i--) {
    if (indexOfDuplicateBlock(buffer, i) > -1) {
      return i
    }
  }
  return -1
}

// from 12
function getBlockSize(encryptor) {
  var ciphertext, size

  // i = 3 * blockSize, to ensure at least 2 whole blocks are duplicated
  for (var i = 24; i <= 192; i++) {
    ciphertext = encryptor(utils.makeBuffer(i, 'A'.charCodeAt(0)))
    size = sizeOfDuplicateBlock(ciphertext)

    if (size > -1) {
      return size
    }
  }

  throw new Error('couldn\'t find block size')
}

function getPrefixLength(encryptor, blockSize) {
  var paddingLength = 3 * blockSize
  var plaintext = utils.makeBuffer(paddingLength, 'A'.charCodeAt(0))
  var ciphertext = encryptor(plaintext)
  var index = indexOfDuplicateBlock(ciphertext, blockSize)
  var lastIndex

  // shrink the padding size until we don't have duplicate blocks
  while (index > -1) {
    lastIndex = index
    paddingLength--
    plaintext = utils.makeBuffer(paddingLength, 'A'.charCodeAt(0))
    ciphertext = encryptor(plaintext)
    index = indexOfDuplicateBlock(ciphertext, blockSize)
  }

  // the smallist padding length that resulted in duplicate blocks
  var lastPadding = paddingLength + 1
  var minPadding = lastPadding - (blockSize * 2)

  return (lastIndex * blockSize) - minPadding
}

function bruteForceByte(encryptor, blockSize, start, finalLength, guessedBytes) {
  // TODO: find some other way to figure out that we're done
  // finalLength = finalLength || encryptor(new Buffer(0)).length
  // for now, use inputBuffer.length to ignore padding
  finalLength = finalLength || inputBuffer.length
  guessedBytes = guessedBytes || []

  var guessedBuffer = new Buffer(guessedBytes)

  if (finalLength === guessedBytes.length) {
    return guessedBuffer
  }

  var paddingPrefix = blockSize - (start % blockSize || blockSize)
  var paddingLength = paddingPrefix + blockSize - (guessedBytes.length % blockSize) - 1

  var targetPrefix = Math.ceil(start / blockSize) * blockSize
  var targetBlock = targetPrefix + guessedBytes.length - (guessedBytes.length % blockSize)
  var target = {
    from: targetBlock,
    to: targetBlock + blockSize
  }

  var padding = utils.makeBuffer(paddingLength, 'A'.charCodeAt(0))
  var paddedBlock = encryptor(padding).slice(target.from, target.to)

  var plaintext, permutation
  var found = false

  for (var i = 0; i < 256; i++) {
    plaintext = Buffer.concat([padding, guessedBuffer, new Buffer([i])])
    permutation = encryptor(plaintext).slice(target.from, target.to)

    if (permutation.equals(paddedBlock)) {
      guessedBytes.push(i)
      found = true
      break
    }
  }

  if (!found) {
    console.log(guessedBuffer)
    throw new Error('couldn\'t guess byte: ' + (guessedBytes.length + 1))
  }

  return bruteForceByte(encryptor, blockSize, start, finalLength, guessedBytes)
}

var encryptor = createEncryptor(inputBuffer)
var blockSize = getBlockSize(encryptor)
var prefixLength = getPrefixLength(encryptor, blockSize)
var plaintext = bruteForceByte(encryptor, blockSize, prefixLength)

console.log('block size: ' + blockSize)
console.log()
console.log('brute forced plaintext:\n')
console.log(plaintext.toString())

// strip padding
var matches = plaintext.slice(0, inputBuffer.length).equals(inputBuffer)
console.log('plaintext matches input: ' + matches)
