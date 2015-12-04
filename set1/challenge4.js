var fs = require('fs')

var input = fs.readFileSync(__dirname + '/inputs/4.txt', 'utf-8')

var alphabet = 'abcdefghijklmnopqrstuvwxyz'
var alphabetArray = alphabet.split('').concat(alphabet.toUpperCase().split(''))

function score(input) {
  return input.split('')
  .map(function(c) {
    if (alphabetArray.indexOf(c) > -1 || c === ' ') {
      return 1
    } else {
      return 0
    }
  })
  .reduce(function(a, b) {
    return a + b
  })
}

function xor(input, key) {
  var results = []
  for (var i = 0; i < input.length; i++) {
    results.push(input[i] ^ key)
  }

  return new Buffer(results).toString()
}

var candidates = input.split('\n')
.map(function(ciphertext) {
  var b = new Buffer(ciphertext, 'hex')
  var candidates = []
  var payload

  for (var i = 0; i < 200; i++) {
    payload = xor(b, i)
    candidates.push({
      payload: payload,
      score: score(payload)
    })
  }

  return candidates.sort(function(a, b) {
    return b.score - a.score
  })[0]
})
.sort(function(a, b) {
  return b.score - a.score
})

console.log( JSON.stringify(candidates[0], null, 2) )
