var crypto = require('crypto')

function xor(payload, key) {
  var results = []
  var index

  for (var i = 0; i < payload.length; i++) {
    index = i % key.length
    results.push(payload[i] ^ key[index])
  }

  return new Buffer(results)
}

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

function decryptECB(ciphertext, key) {
  var iv = ''
  var decipher = crypto.createDecipheriv('aes-128-ecb', key, iv)
  decipher.setAutoPadding(false)
  return Buffer.concat([decipher.update(ciphertext), decipher.final()])
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

function encryptCBC(plaintext, key, iv) {
  var blockLength = 16
  var blocks = getBlocks(plaintext, blockLength)
  var ciphertext = []

  ciphertext.push(
    encryptECB(xor(blocks[0], iv), key)
  )

  blocks.slice(1).forEach(function(block, i) {
    ciphertext.push(
      encryptECB(xor(block, ciphertext[i]), key)
    )
  })

  return Buffer.concat(ciphertext)
}

function decryptCBC(ciphertext, key, iv) {
  var blockLength = 16
  var blocks = getBlocks(ciphertext, blockLength)
  var plaintext = []

  plaintext.push(
    xor(decryptECB(blocks[0], key), iv)
  )

  blocks.slice(1).forEach(function(block, i) {
    plaintext.push(
      xor(decryptECB(block, key), blocks[i])
    )
  })

  return Buffer.concat(plaintext)
}


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
      // this.mode = 'ecb'
      return {
        mode: 'ecb',
        ciphertext: encryptECB(prepared, randomKey)
      }
    }
  } else {
    return function(plaintext) {
      var prepared = Buffer.concat([prefix, plaintext, prefix])
      // this.mode = 'cbc'
      return {
        mode: 'cbc',
        ciphertext: encryptCBC(prepared, randomKey, randomIv)
      }
    }
  }
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
