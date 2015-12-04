var fs = require('fs')

var input = fs.readFileSync(__dirname + '/inputs/6.txt', 'utf-8')

var alphabet = 'abcdefghijklmnopqrstuvwxyz'
 var alphabetBuffer = new Buffer(alphabet.concat(alphabet.toUpperCase()))

// n-character xor
function xor(payload, key) {
  var results = []
  var index

  for (var i = 0; i < payload.length; i++) {
    index = i % key.length
    results.push(payload[i] ^ key[index])
  }

  return new Buffer(results)
}

function xorStrings(ciphertext, key) {
  return xor(new Buffer(ciphertext), new Buffer(key))
}

function score(input) {
  var score = 0

  for (var i = 0; i < input.length; i++) {
    if (alphabetBuffer.indexOf(input[i]) > -1 || input[i] === 32) {
      score++
    }
  }

  return score
}

function breakSingleKeyXor(ciphertext) {
  var candidates = []
  var payload

  for (var i = 0; i < 200; i++) {
    payload = xor(ciphertext, [i])
    candidates.push({
      ciphertext: ciphertext.toString('hex'),
      keyChar: i,
      key: String.fromCharCode(i),
      key: i,
      payload: payload,
      string: payload.toString(),
      score: score(payload)
    })
  }

  return candidates.sort(function(a, b) {
    return b.score - a.score
  })
}

function popCount(x) {
  var count = 0
  while (x > 0) {
    if ((x & 1) === 1) {
      count++
    }
    x >>= 1
  }
  return count
}

function bufferPopCount(b) {
  var results = []
  for (var i = 0; i < b.length; i++) {
    results.push(popCount(b[i]))
  }

  return results.reduce(function(a, b) {
    return a + b
  })
}

function hammingsDistance(x, y) {
  return bufferPopCount(xorStrings(x, y))
}

function getSlices(input, size, n) {
  var results = []
  for (var i = 0; i < n; i++) {
    results.push(
      input.slice(size * i, size * (i + 1))
    )
  }
  return results
}

function testKeySize(input, size) {
  var distances = []

  getSlices(input, size, 10)
  .reduce(function(a, b) {
    distances.push(bufferPopCount(xor(a, b)))
    return b
  })

  var distance = distances
  .reduce(function(a, b) {
    return a + b
  }) / distances.length

  return {
    size: size,
    distance: distance,
    normalize: distance / size
  }
}

function findKeySizes(input) {
  var results = []

  for (var i = 2; i <= 40; i++) {
    results.push(testKeySize(input, i))
  }

  return results
  .sort(function(a, b) {
    return a.normalize - b.normalize
  })
  .slice(0, 3)
}

function getBlocks(input, size) {
  var max = Math.ceil(input.length / size)
  var blocks = []
  var index

  for (var i = 0; i < max; i++) {
    index = i * size
    blocks.push(input.slice(index, index + size))
  }

  return blocks
}

function transposeBlocks(blocks) {
  var max = blocks[0].length
  var transposed = []
  var block

  for (var i = 0; i < max; i++) {
    block = []
    for (var x = 0; x < blocks.length; x++) {
      block.push(blocks[x][i])
    }
    transposed.push(new Buffer(block))
  }

  return transposed
}

function breakXor(input, keySizes) {
  return keySizes.map(function(keySize) {
    var blocks = getBlocks(input, keySize.size)
    var transposedBlocks = transposeBlocks(blocks)

    var key = transposedBlocks.map(function(block) {
      return breakSingleKeyXor(block)[0].key
    })

    var keyBuffer = new Buffer(key)

    return {
      keySize: keySize,
      key: key,
      keyString: keyBuffer.toString(),
      decrypted: xor(input, keyBuffer).toString()
    }
  })
}

// console.log( hammingsDistance('this is a test', 'wokka wokka!!!') === 37 )

var b = new Buffer(input, 'base64')
var keySizes = findKeySizes(b)

var decrypted = breakXor(b, keySizes)[0]

console.log('key: ' + decrypted.keyString)
console.log()
console.log(decrypted.decrypted)
