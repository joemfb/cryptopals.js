var input = 'Burning \'em, if you ain\'t quick and nimble\nI go crazy when I hear a cymbal'
var key = 'ICE'
var solution = '0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f'

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

console.log( xorStrings(input, key).toString('hex') === solution )
