/**
 * CBC bitflipping attacks
 *
 * http://cryptopals.com/sets/2/challenges/16/
 */

var crypto = require('crypto')
var utils = require('../lib/utils.js')
var cryptoLib = require('../lib/crypto.js')

function createEncryptor() {
  var randomKey = crypto.randomBytes(16)
  var iv = utils.makeBuffer(16, 0)
  var prefix = new Buffer('comment1=cooking%20MCs;userdata=')
  var suffix = new Buffer(';comment2=%20like%20a%20pound%20of%20bacon')
  return {
    encrypt: function(plaintext) {
      var x = Buffer.concat([prefix, utils.pad(plaintext, 16), suffix])
      return cryptoLib.encryptCBC(x, randomKey, iv)
    },
    decrypt: function(ciphertext) {
      return cryptoLib.decryptCBC(ciphertext, randomKey, iv)
    }
  }
}

function encryptInput(encryptor, input) {
  return encryptor.encrypt(
    new Buffer(input.replace(/=/g, '%3D').replace(/;/g, '%3B'))
  )
}

function testCiphertext(encryptor, ciphertext) {
  return encryptor.decrypt(ciphertext).toString().indexOf(';admin=true;') > -1
}

function replaceByteAt(buffer, index, val) {
  var before = buffer.slice(0, index)
  var after = buffer.slice(index + 1)

  return Buffer.concat([before, val, after])
}

function findTargetBlock(encryptor) {
  var a = utils.makeBuffer(16, 'A'.charCodeAt(0))
  var b = replaceByteAt(a, 0, new Buffer('B'))

  var blocksA = utils.getBlocks(encryptor.encrypt(a), 16)
  var blocksB = utils.getBlocks(encryptor.encrypt(b), 16)

  for (var i = 0; i < blocksA.length; i++) {
    if (!blocksA[i].equals(blocksB[i])) {
      return i
    }
  }

  return -1
}

function breakCBC(encryptor, targetBlock, targetString) {
  var targetBuffer = new Buffer(targetString)
  var ciphertext = encryptInput(encryptor, targetString)
  var blocks = utils.getBlocks(ciphertext, 16)
  var mutateBlock = targetBlock - 1
  var index = 0
  var lastIndex = -1

  var testBlock, mutatedCiphertext

  while (!testCiphertext(encryptor, Buffer.concat(blocks))) {
    if (index > lastIndex) {
      lastIndex = index
    } else {
      console.log(JSON.stringify(encryptor.decrypt(Buffer.concat(blocks)).toString()))
      throw new Error('couldn\'t find byte: ' + index)
    }

    for (var i = 0; i < 256; i++) {
      blocks[mutateBlock] = replaceByteAt(blocks[mutateBlock], index, new Buffer([i]))

      mutatedCiphertext = encryptor.decrypt(Buffer.concat(blocks))
      testBlock = utils.getBlocks(mutatedCiphertext, 16)[targetBlock]

      if (testBlock[index] === targetBuffer[index]) {
        console.log('found byte: ' + index)
        index++
        break
      }
    }
  }

  console.log('matched!')

  return encryptor.decrypt(Buffer.concat(blocks))
}

var encryptor = createEncryptor()
var targetBlock = findTargetBlock(encryptor)
var targetString = ';admin=true;'

var result = breakCBC(encryptor, targetBlock, targetString).toString()

console.log(JSON.stringify(
  result.slice(
    result.indexOf(';admin'),
    result.indexOf(';admin') + targetString.length
  )
))
console.log(JSON.stringify(result))
