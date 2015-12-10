/**
 * Implement repeating-key XOR
 *
 * http://cryptopals.com/sets/1/challenges/5/
 */

var input = 'Burning \'em, if you ain\'t quick and nimble\nI go crazy when I hear a cymbal'
var key = 'ICE'
var solution = '0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f'

// subsequently moved to utils
function xor(payload, key) {
  var results = []
  var index

  for (var i = 0; i < payload.length; i++) {
    index = i % key.length
    results.push(payload[i] ^ key[index])
  }

  return new Buffer(results)
}

console.log('xor\'d matches solution: ' + (xor(new Buffer(input), new Buffer(key)).toString('hex') === solution))
