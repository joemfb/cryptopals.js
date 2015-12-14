/**
 * ECB cut-and-paste
 *
 * http://cryptopals.com/sets/2/challenges/13/
 */

var crypto = require('crypto')
var utils = require('../lib/utils.js')
var cryptoLib = require('../lib/crypto.js')

var randomKey = crypto.randomBytes(16)

function parseKV(input) {
  var obj = {}

  input.split('&').forEach(function(pair) {
    var tokens = pair.split('=')
    obj[tokens[0]] = tokens[1]
  })

  return obj
}

function escapeKVChars(x) {
  return String(x).replace('=', '%3D').replace('&', '%26')
}

function encodeKV(obj) {
  return Object.keys(obj).map(function(key) {
    return escapeKVChars(key) + '=' + escapeKVChars(obj[key])
  }).join('&')
}

function profileFor(email) {
  var profile = {
    email: email,
    uid: 10,
    role: 'user'
  }

  return encodeKV(profile)
}

function encryptProfile(encoded) {
  return cryptoLib.encryptECB(new Buffer(encoded), randomKey)
}

function stripPadding(plaintext) {
  var lastByte = plaintext[ plaintext.length - 1 ]
  var index = plaintext.length - lastByte
  var isPadded = plaintext.slice(index).equals(
    utils.makeBuffer(lastByte, lastByte)
  )

  if (isPadded) {
    return plaintext.slice(0, index)
  }

  console.log('no padding')

  return plaintext
}

function decryptProfile(ciphertext) {
  var encoded = cryptoLib.decryptECB(ciphertext, randomKey)

  return parseKV(stripPadding(encoded).toString())
}

// get the offsets for the profile strings surrounding the email address
// Note: included only to demonstrate rationale; always returns { before: 6, after: 13 }
function getProfileOffsets() {
  var marker = '!'
  var sample = profileFor(marker)
  var tokens = sample.split(marker)
  var before = tokens[0]

  var roleMarker = 'role='
  var roleIndex = tokens[1].indexOf(roleMarker)
  var after = tokens[1].slice(0, roleIndex + roleMarker.length)

  return { before: before.length, after: after.length }
}

// get a ciphertext block containing only the desired role and padding
function getRoleBlock(role, blockSize, offsets) {
  var roleBlock = utils.pad(new Buffer(role), blockSize)

  // Note: this would need to be modular if either offset were > blockSize
  var before = utils.pad(new Buffer(0), blockSize - offsets.before)
  var after = utils.pad(new Buffer(0), blockSize - offsets.after)

  var input = Buffer.concat([before, roleBlock, after])
  var ciphertext = encryptProfile(profileFor(input))

  var blocks = utils.getBlocks(ciphertext, blockSize)
  var targetBlock = Math.ceil(offsets.before / blockSize) - 1

  return blocks[targetBlock]
}

function createAdminProfile(email) {
  // TODO: try to detect this ...
  var blockSize = 16
  var targetRole = 'admin'

  var offsets = getProfileOffsets()
  var roleBlock = getRoleBlock(targetRole, blockSize, offsets)

  // pad the email so that the role will be isolated on the last block
  var padEmail = blockSize - (offsets.before + offsets.after + email.length) % blockSize
  var padding = utils.makeBuffer(padEmail, email.charCodeAt(0))
  var paddedEmail = Buffer.concat([padding, new Buffer(email)])

  var ciphertext = encryptProfile(profileFor(paddedEmail))
  var blocks = utils.getBlocks(ciphertext, blockSize)

  blocks[blocks.length - 1] = roleBlock

  return decryptProfile(Buffer.concat(blocks))
}

console.log(createAdminProfile('bill@microsoft.com'))
