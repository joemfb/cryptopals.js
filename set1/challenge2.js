/**
 * Fixed XOR
 *
 * http://cryptopals.com/sets/1/challenges/2/
 */

var input = '1c0111001f010100061a024b53535009181c'
var key = '686974207468652062756c6c277320657965'
var solution = '746865206b696420646f6e277420706c6179'

var a = new Buffer(input, 'hex')
var b = new Buffer(key, 'hex')
var results = []

for (var i = 0; i < a.length; i++) {
  results.push(a[i] ^ b[i])
}

console.log('xor\'d matches solution: ' + (new Buffer(results).toString('hex') === solution))
