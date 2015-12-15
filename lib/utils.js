'use strict'

var alphabet = 'abcdefghijklmnopqrstuvwxyz'
var alphabetBuffer = Buffer.concat([
  new Buffer(alphabet),
  new Buffer(alphabet.toUpperCase()),
  new Buffer(' ')
])

// returns a length-normalized score of alphabetical characters or spaces
// adapted from set1/challenge4
function scoreText(input) {
  var score = 0

  for (var i = 0; i < input.length; i++) {
    score += alphabetBuffer.indexOf(input[i]) > -1
  }

  return score / input.length
}

// returns the highest scoring byte
// adapted from set1/challenge4
function breakSingleByteXor(ciphertext) {
  var candidates = []
  var payload

  for (var i = 0; i < 256; i++) {
    payload = xor(ciphertext, [i])
    candidates.push({ key: i, score: scoreText(payload) })
  }

  return candidates.sort(function(a, b) {
    return b.score - a.score
  })[0].key
}

// from set1/challenge5
function xor(payload, key) {
  var results = []
  var index

  for (var i = 0; i < payload.length; i++) {
    index = i % key.length
    results.push(payload[i] ^ key[index])
  }

  return new Buffer(results)
}

// from set1/challenge6
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

// adapted from set1/challenge8
function hasDuplicateBlocks(buffer, size) {
  var blocks = getBlocks(buffer, size)
  var index

  for (var i = 0; i < blocks.length; i++) {
    index = buffer.indexOf(blocks[i])
    if (index > -1 && index !== (i * size)) {
      return true
    }
  }
  return false
}

// pkcs#7 padding
// from set2/challenge9
function pad(block, len) {
  var padLength = len - block.length

  if (padLength <= 0) return block

  return Buffer.concat([block, makeBuffer(padLength, padLength)])
}

// from set2/challenge11
function rand(min, max) {
  if (max === undefined) {
    max = min
    min = 0
  }
  return Math.floor(Math.random() * (max - min)) + min
}

// general utility functions

function makeBuffer(len, fill) {
  return new Buffer(new Array(len).fill(fill))
}

// apply `fn` to overlapping pairs in an array
function forEachPair(coll, fn) {
  coll.reduce(function(a, b) {
    fn(a, b)
    return b
  })
}

// apply `fn` to overlapping pairs in an array, accumulating the result
function mapPairs(coll, fn) {
  var result = []

  forEachPair(coll, function(a, b) {
    result.push(fn(a, b))
  })

  return result
}

function avg(coll) {
  var sum = coll.reduce(function(a, b) {
    return a + b
  })

  return sum / coll.length
}

module.exports = exports = {
  scoreText: scoreText,
  breakSingleByteXor: breakSingleByteXor,
  xor: xor,
  getBlocks: getBlocks,
  hasDuplicateBlocks: hasDuplicateBlocks,
  pad: pad,
  rand: rand,
  makeBuffer: makeBuffer,
  forEachPair: forEachPair,
  mapPairs: mapPairs,
  avg: avg
}
