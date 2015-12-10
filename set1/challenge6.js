/**
 * Break repeating-key XOR
 *
 * http://cryptopals.com/sets/1/challenges/6/
 */

var fs = require('fs')
var utils = require('../lib/utils.js')

var input = fs.readFileSync(__dirname + '/inputs/6.txt', 'utf-8')

// count the set bits of a number (the '1's in base-2 string)
function popCount(x) {
  var count = 0
  while (x > 0) {
    count += x & 1
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
  return bufferPopCount(utils.xor(x, y))
}

// subsequently moved to utils
function getBlocks(input, size, n) {
  var blocks = []
  var index

  if (n === undefined) {
    n = Math.ceil(input.length / size)
  }

  for (var i = 0; i < n; i++) {
    index = i * size
    blocks.push(input.slice(index, index + size))
  }

  return blocks
}

// returns the normalized edit distance between blocks of `size`
function testKeySize(input, size, nBlocks) {
  var blocks = getBlocks(input, size, nBlocks)
  var distances = utils.mapPairs(blocks, hammingsDistance)

  return utils.avg(distances) / size
}

// returns the 3 most likely key sizes for input
function findKeySizes(input) {
  var nBlocks = 10 // number of blocks to compare
  var results = []

  for (var i = 2; i <= 40; i++) {
    results.push({
      size: i,
      distance: testKeySize(input, i, nBlocks)
    })
  }

  return results
  .sort(function(a, b) {
    return a.distance - b.distance
  })
  .slice(0, 3)
}

// transposes blocks into a block for each index (a la lodash.zip)
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

function breakXor(input, keySize) {
  var blocks = getBlocks(input, keySize)
  var transposedBlocks = transposeBlocks(blocks)

  var keyBytes = transposedBlocks.map(utils.breakSingleByteXor)
  var key = new Buffer(keyBytes)

  return {
    keySize: keySize,
    key: key,
    plaintext: utils.xor(input, key)
  }
}

// console.log( hammingsDistance(new Buffer('this is a test'), new Buffer('wokka wokka!!!')) === 37 )

var b = new Buffer(input, 'base64')
var keySizes = findKeySizes(b)
var decrypted = breakXor(b, keySizes[0].size)

console.log('key: ' + decrypted.key.toString())
console.log()
console.log(decrypted.plaintext.toString())
