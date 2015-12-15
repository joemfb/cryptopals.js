'use strict'

var crypto = require('crypto')
var utils = require('./utils.js')

// NOTE: ecb doesn't use an iv, but node/crypto derives a "password" from `key` without one

// adapted from set2/challenge10
function encryptECB(plaintext, key) {
  var iv = ''
  var cipher = crypto.createCipheriv('aes-128-ecb', key, iv)
  cipher.setAutoPadding(false)

  var mod = plaintext.length % key.length
  var padLength

  if (mod) {
    padLength = plaintext.length + key.length - mod
    plaintext = utils.pad(plaintext, padLength)
  }

  return Buffer.concat([cipher.update(plaintext), cipher.final()])
}

// from set2/challenge10
function decryptECB(ciphertext, key) {
  var iv = ''
  var decipher = crypto.createDecipheriv('aes-128-ecb', key, iv)
  decipher.setAutoPadding(false)
  return Buffer.concat([decipher.update(ciphertext), decipher.final()])
}

// from set2/challenge10
function encryptCBC(plaintext, key, iv) {
  var blockLength = 16
  var blocks = utils.getBlocks(plaintext, blockLength)
  var ciphertext = []

  ciphertext.push(
    encryptECB(utils.xor(blocks[0], iv), key)
  )

  blocks.slice(1).forEach(function(block, i) {
    ciphertext.push(
      encryptECB(utils.xor(block, ciphertext[i]), key)
    )
  })

  return Buffer.concat(ciphertext)
}

// from set2/challenge10
function decryptCBC(ciphertext, key, iv) {
  var blockLength = 16
  var blocks = utils.getBlocks(ciphertext, blockLength)
  var plaintext = []

  plaintext.push(
    utils.xor(decryptECB(blocks[0], key), iv)
  )

  blocks.slice(1).forEach(function(block, i) {
    plaintext.push(
      utils.xor(decryptECB(block, key), blocks[i])
    )
  })

  return Buffer.concat(plaintext)
}

// get the blockSize for `encryptor` (assumed to be between 8-64)
// from set2/challenge12
function getECBBlockSize(encryptor) {
  var ciphertext, size

  // test 3 * blockSize, to ensure at least 2 whole blocks are duplicated
  for (var i = 24; i <= 192; i++) {
    ciphertext = encryptor(utils.makeBuffer(i, 'A'.charCodeAt(0)))
    size = utils.sizeOfDuplicateBlock(ciphertext)

    if (size > -1) {
      return size
    }
  }

  throw new Error('couldn\'t find block size')
}

// find the next byte from `encryptor`
// `padding` is aligned that (`padding` + `guessedBuffer` + 1 byte) ends a block
// target is the bounds of the target block
// from set2/challenge12
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

module.exports = exports = {
  encryptECB: encryptECB,
  decryptECB: decryptECB,
  encryptCBC: encryptCBC,
  decryptCBC: decryptCBC,
  getECBBlockSize: getECBBlockSize,
  bruteForceECBByte: bruteForceECBByte
}
