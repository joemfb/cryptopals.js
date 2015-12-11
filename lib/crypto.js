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

module.exports = exports = {
  encryptECB: encryptECB,
  decryptECB: decryptECB,
  encryptCBC: encryptCBC,
  decryptCBC: decryptCBC
}
