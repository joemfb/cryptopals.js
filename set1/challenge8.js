/**
 * Detect AES in ECB mode
 *
 * http://cryptopals.com/sets/1/challenges/8/
 */

var fs = require('fs')
var utils = require('../lib/utils.js')

var input = fs.readFileSync(__dirname + '/inputs/8.txt', 'utf-8')

var buffers = input.split('\n')
.map(function(line) {
  return new Buffer(line, 'hex')
})

function checkDuplicateBlocks(buffer, size) {
  var blocks = utils.getBlocks(buffer, size)

  for (var i = 0; i < blocks.length; i++) {
    index = buffer.indexOf(blocks[i])
    if (index > -1 && index !== (i * size)) {
      return { hasDuplicate: true, block: blocks[i] };
    }
  }
  return { hasDuplicate: false };
}

var size = 16

buffers.forEach(function(buffer, i) {
  var dup = checkDuplicateBlocks(buffer, size)
  // var positions = []

  if (dup.hasDuplicate) {
    console.log('found duplicate block in input at line: ' + i)
    console.log('block:')
    console.log(dup.block.toString('hex'))
    console.log('line: ')
    console.log(buffer.toString('hex'))
    // TODO: log positions
  }
})
