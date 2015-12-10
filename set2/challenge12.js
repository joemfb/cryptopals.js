var fs = require('fs')
var crypto = require('crypto')

var input = fs.readFileSync(__dirname + '/inputs/12.txt', 'utf-8').replace(/\s/g, '')
var inputBuffer = new Buffer(input, 'base64')
var randomKey

function pad(block, len) {
  if (len <= block.length) return block

  var padding = new Buffer(
    new Array(len - block.length).fill(4)
  )
  return Buffer.concat([block, padding])
}

function encryptECB(plaintext, key) {
  var iv = ''
  var cipher = crypto.createCipheriv('aes-128-ecb', key, iv)
  cipher.setAutoPadding(false)

  var mod = plaintext.length % key.length
  var padLength

  if (mod) {
    padLength = plaintext.length + key.length - mod
    plaintext = pad(plaintext, padLength)
  }

  return Buffer.concat([cipher.update(plaintext), cipher.final()])
}

function getBlocks(input, size) {
  var max = Math.ceil(input.length / size)
  var results = []
  for (var i = 0; i < max; i++) {
    results.push(
      input.slice(size * i, size * (i + 1))
    )
  }
  return results
}

function checkDuplicateBlocks(buffer, size) {
  var blocks = getBlocks(buffer, size, buffer.length)

  for (var i = 0; i < blocks.length; i++) {
    index = buffer.indexOf(blocks[i])
    if (index > -1 && index !== (i * size)) {
      return { hasDuplicate: true, block: blocks[i] };
    }
  }
  return { hasDuplicate: false };
}

function guessMode(ciphertext) {
  for (var i = 5; i < 11; i++) {
    if (checkDuplicateBlocks(ciphertext.slice(i), 16).hasDuplicate) {
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

  return encryptECB(Buffer.concat([plaintext, inputBuffer]), randomKey)
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
  finalLength = finalLength || encryptECBUnknownKey(new Buffer(0)).length
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
