/**
 * Convert hex to base64
 *
 * http://cryptopals.com/sets/1/challenges/1/
 */

var input = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
var solution = 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'

var b = new Buffer(input, 'hex')

console.log('converted matches solution: ' + (b.toString('base64') === solution))
