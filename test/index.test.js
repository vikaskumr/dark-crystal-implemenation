const { describe } = require('tape-plus')
const { packLabel, unpackLabel } = require('..')

const secret = 'its nice to be important but its more important to be nice'
const label = 'This is the password'

describe('pack and unpack', (context) => {
  context('basic', (assert, next) => {
    const packed = packLabel(secret, label)
    assert.ok(Buffer.isBuffer(packed), 'returns a buffer')
    const unpacked = unpackLabel(packed)
    assert.equal(unpacked.secret.toString(), secret, 'secret is correct')
    assert.equal(unpacked.label, label, 'label is correct')
    next()
  })

  context('no label given', (assert, next) => {
    const packed = packLabel(secret)
    assert.ok(Buffer.isBuffer(packed), 'returns a buffer')
    const unpacked = unpackLabel(packed)
    assert.equal(unpacked.secret.toString(), secret, 'secret is correct')
    next()
  })
})
