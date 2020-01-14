const { describe } = require('tape-plus')
const { packLabel, unpackLabel, signingKeypair, signShard, openShard } = require('..')

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

describe('sign and verify', (context) => {
  context('basic', (assert, next) => {
    const shard = Buffer.from(secret) // TODO: real shard
    const keypair = signingKeypair()
    const signedShard = signShard(shard, keypair)
    assert.ok(Buffer.isBuffer(signedShard), 'signed shard is a buffer')
    const verifiedShard = openShard(signedShard, keypair.publicKey)
    assert.true(verifiedShard, 'Shard was verified')
    assert.equal(verifiedShard.toString('hex'), shard.toString('hex'), 'VerifiedShard is correct')
    next()
  })

  context('bad public key', (assert, next) => {
    const shard = Buffer.from(secret) // TODO: real shard
    const keypair = signingKeypair()
    const signedShard = signShard(shard, keypair)
    assert.ok(Buffer.isBuffer(signedShard), 'signed shard is a buffer')
    keypair.publicKey[0] = keypair.publicKey[0] === 1 ? 2 : 1
    const verifiedShard = openShard(signedShard, keypair.publicKey)
    assert.false(verifiedShard, 'Shard could not be verified')
    next()
  })
})
