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

// get the lenth of the random prefix for `encryptor`
function getPrefixLength(encryptor, blockSize) {
  var paddingLength = 3 * blockSize + 1
  var index, lastIndex, plaintext, ciphertext

  // shrink the padding size until we don't have duplicate blocks
  do {
    lastIndex = index
    paddingLength--
    plaintext = utils.makeBuffer(paddingLength, 'A'.charCodeAt(0))
    ciphertext = encryptor(plaintext)
    index = utils.indexOfDuplicateBlock(ciphertext, blockSize)
  } while (index > -1)

  if (!lastIndex) {
    throw new Error('couldn\'t find duplicate blocks')
  }

  // the smallist padding length that resulted in duplicate blocks
  var lastPadding = paddingLength + 1
  var minPadding = lastPadding - (blockSize * 2)

  return (lastIndex * blockSize) - minPadding
}

// find the secret bytes from `encryptor`
// adapted from set2/challenge12 (to account for random-length random prefix)
function bruteForceECB(encryptor, blockSize, start, guessedBytes) {
  guessedBytes = guessedBytes || []

  var guessedBuffer = new Buffer(guessedBytes)
  var targetByte = guessedBytes.length
  var targetPrefix = Math.ceil(start / blockSize) * blockSize
  var targetBlock = Math.floor(targetByte / blockSize) * blockSize
  var target = {
    from: targetPrefix + targetBlock,
    to: targetPrefix + targetBlock + blockSize
  }

  var paddingPrefix = blockSize - (start % blockSize || blockSize)
  var paddingLength = blockSize - (targetByte % blockSize) - 1
  var padding = utils.makeBuffer(paddingPrefix + paddingLength, 'A'.charCodeAt(0))
  var guessedByte = cryptoLib.bruteForceECBByte(encryptor, padding, guessedBuffer, target)

  if (guessedByte === -1) {
    // if we have less than a block left, assume it's padding
    // Note: the "right" thing would be to validate and strip padding
    if (encryptor(new Buffer(0)).length - targetByte - start < blockSize) {
      return guessedBuffer
    }

    console.log(guessedBuffer)
    console.log(guessedBuffer.toString())
    throw new Error('couldn\'t guess byte: ' + targetByte)
  }

  guessedBytes.push(guessedByte)

  return bruteForceECB(encryptor, blockSize, start, guessedBytes)
}

function breakECB(encryptor) {
  var blockSize = cryptoLib.getECBBlockSize(encryptor)
  var prefixLength = getPrefixLength(encryptor, blockSize)
  var plaintext = bruteForceECB(encryptor, blockSize, prefixLength)

  return { blockSize: blockSize, plaintext: plaintext }
}

var encryptor = createEncryptor(inputBuffer)
var result = breakECB(encryptor)

console.log('block size: ' + result.blockSize)
console.log()
console.log('brute forced plaintext:\n')
console.log(result.plaintext.toString())

// strip padding
var matches = result.plaintext.slice(0, inputBuffer.length).equals(inputBuffer)
console.log('plaintext matches input: ' + matches)
