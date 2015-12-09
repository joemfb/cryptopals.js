function pad(block, len) {
  if (len <= block.length) return block

  var padding = new Buffer(
    new Array(len - block.length).fill(4)
  )
  return Buffer.concat([block, padding])
}

console.log(
  JSON.stringify(
    pad(new Buffer('YELLOW SUBMARINE'), 20).toString()
  )
)
