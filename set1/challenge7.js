var fs = require('fs')
var crypto = require('crypto')

var input = fs.readFileSync(__dirname + '/inputs/7.txt', 'utf-8')

var b = new Buffer(input, 'base64')
var key = new Buffer('YELLOW SUBMARINE')
var iv = ''

var decipher = crypto.createDecipheriv('aes-128-ecb', key, iv)
var plaintext = Buffer.concat([decipher.update(b), decipher.final()])

console.log(plaintext.toString())

var cipher = crypto.createCipheriv('aes-128-ecb', key, iv)
var encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()])

console.log()
console.log('encrypted plaintext matches input: ')
console.log( encrypted.toString('base64') === input.replace(/\s/g, '') )
