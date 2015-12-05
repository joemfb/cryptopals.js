var fs = require('fs')

var input = fs.readFileSync(__dirname + '/inputs/8.txt', 'utf-8')

var buffers = input.split('\n')
.map(function(line) {
  return new Buffer(line, 'hex')
})

function getSlices(input, size, n) {
  var results = []
  for (var i = 0; i < n; i++) {
    if (input[size * i] === undefined) {
      break
    }
    results.push(
      input.slice(size * i, size * (i + 1))
    )
  }
  return results
}

function checkDuplicateBlocks(buffer, size) {
  var blocks = getSlices(buffer, size, input.length)

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

