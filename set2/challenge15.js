/**
 * PKCS#7 padding validation
 *
 * http://cryptopals.com/sets/2/challenges/15/
 */

var utils = require('../lib/utils.js')

function stripPadding(plaintext) {
  var lastByte = plaintext[ plaintext.length - 1 ]
  var isPadded = utils.scoreText([lastByte]) === 0
  var valid

  if (!isPadded) {
    console.log('not padded')
    return plaintext
  }

  var index = plaintext.length - lastByte
  var isValid = plaintext.slice(index).equals(
    utils.makeBuffer(lastByte, lastByte)
  )

  if (isValid) {
    return plaintext.slice(0, index)
  }

  throw new Error('bad padding')
}

var input = new Buffer('ICE ICE BABY')

var valid = stripPadding(Buffer.concat([input, utils.makeBuffer(4, 4)]))

console.log('strips valid padding: ' + (valid.length === input.length))

try {
  stripPadding(Buffer.concat([input, utils.makeBuffer(4, 5)]))
} catch(err) {
  console.log('throws error on invalid padding: ' + /bad padding/.test(err))
}
