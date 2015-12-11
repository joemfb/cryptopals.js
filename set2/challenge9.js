/**
 * Implement PKCS#7 padding
 *
 * http://cryptopals.com/sets/2/challenges/9/
 */

// subsequently adapted and moved to utils
function pad(block, len) {
  var padLength = len - block.length

  if (padLength <= 0) return block

  return Buffer.concat([
    block,
    new Buffer(new Array(padLength).fill(padLength))
  ])
}

// uses JSON.stringify to show padding bytes
console.log(
  JSON.stringify(
    pad(new Buffer('YELLOW SUBMARINE'), 20).toString()
  )
)
