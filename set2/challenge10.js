/**
 * Implement CBC mode
 *
 * http://cryptopals.com/sets/2/challenges/10/
 */

var fs = require('fs')
var crypto = require('crypto')
var utils = require('../lib/utils.js')

var input = fs.readFileSync(__dirname + '/inputs/10.txt', 'utf-8').replace(/\s/g, '')

// NOTE: ecb doesn't use an iv, but node/crypto derives a "password" from `key` without one

// subsequently adapted and moved to cryptoLib
function encryptECB(plaintext, key) {
  var iv = ''
  var cipher = crypto.createCipheriv('aes-128-ecb', key, iv)
  // Trying to find this was fun ... :|
  cipher.setAutoPadding(false)
  return Buffer.concat([cipher.update(plaintext), cipher.final()])
}

// subsequently adapted and moved to cryptoLib
function decryptECB(ciphertext, key) {
  var iv = ''
  var decipher = crypto.createDecipheriv('aes-128-ecb', key, iv)
  decipher.setAutoPadding(false)
  return Buffer.concat([decipher.update(ciphertext), decipher.final()])
}

// subsequently adapted and moved to cryptoLib
function encryptCBC(plaintext, key) {
  var blockLength = 16
  var iv = new Buffer(new Array(blockLength).fill(0))
  var blocks = utils.getBlocks(plaintext, blockLength)

  // TODO: pad last block?

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

// subsequently adapted and moved to cryptoLib
function decryptCBC(ciphertext, key) {
  var blockLength = 16
  var iv = new Buffer(new Array(blockLength).fill(0))
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

function test() {
  var msg = 'aaaabbbbccccddddaaaabbbbccccdddd'
  var plaintext = new Buffer(msg)
  var key = new Buffer('abcdabcdabcdabcd')

  return decryptECB(encryptECB(plaintext, key), key).toString() === msg &&
         decryptCBC(encryptCBC(plaintext, key), key).toString() === msg
}

console.log('tests pass: ' + test())
console.log('decrypted plaintext: \n')

var decrypted = decryptCBC(new Buffer(input, 'base64'), new Buffer('YELLOW SUBMARINE'))
console.log(decrypted.toString())

console.log()
console.log('re-encrypted plaintext matches input: ')
console.log( encryptCBC(decrypted, new Buffer('YELLOW SUBMARINE')).toString('base64') === input )
