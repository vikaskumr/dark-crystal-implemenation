const { describe } = require('tape-plus')
const s = require('..')

const secret = 'its nice to be important but its more important to be nice'
const label = 'This is the password'

describe('pack and unpack', (context) => {
  context('basic', (assert, next) => {
    const packed = s.packLabel(secret, label)
    assert.ok(Buffer.isBuffer(packed), 'returns a buffer')
    const unpacked = s.unpackLabel(packed)
    assert.equal(unpacked.secret.toString(), secret, 'secret is correct')
    assert.equal(unpacked.label, label, 'label is correct')
    next()
  })

  context('no label given', (assert, next) => {
    const packed = s.packLabel(secret)
    assert.ok(Buffer.isBuffer(packed), 'returns a buffer')
    const unpacked = s.unpackLabel(packed)
    assert.equal(unpacked.secret.toString(), secret, 'secret is correct')
    next()
  })
})

describe('sign and verify', (context) => {
  context('basic', (assert, next) => {
    const shard = Buffer.from(secret) // TODO: real shard
    const keypair = s.keypair()
    const signedShard = s.signShard(shard, keypair)
    assert.ok(Buffer.isBuffer(signedShard), 'signed shard is a buffer')
    const verifiedShard = s.openShard(signedShard, keypair.publicKey)
    assert.true(verifiedShard, 'Shard was verified')
    assert.equal(verifiedShard.toString('hex'), shard.toString('hex'), 'VerifiedShard is correct')
    next()
  })

  context('bad public key', (assert, next) => {
    const shard = Buffer.from(secret) // TODO: real shard
    const keypair = s.keypair()
    const signedShard = s.signShard(shard, keypair)
    assert.ok(Buffer.isBuffer(signedShard), 'signed shard is a buffer')
    keypair.publicKey[0] = keypair.publicKey[0] === 1 ? 2 : 1
    const verifiedShard = s.openShard(signedShard, keypair.publicKey)
    assert.false(verifiedShard, 'Shard could not be verified')
    next()
  })
})

describe('box and unbox', (context) => {
  context('basic', (assert, next) => {
    const shard = Buffer.from(secret) // TODO: real shard

    const sender = s.keypair()
    const recipient = s.keypair()
    assert.ok(Buffer.isBuffer(sender.publicKey), 'public key is a buffer')
    assert.ok(Buffer.isBuffer(sender.secretKey), 'secret key is a buffer')

    const cipherText = s.box(shard, recipient.publicKey, sender.secretKey)
    assert.ok(Buffer.isBuffer(cipherText), 'ciphertext is a buffer')

    const unboxed = s.unbox(cipherText, sender.publicKey, recipient.secretKey)
    assert.ok(unboxed, 'Decryption successful')
    assert.equal(unboxed.toString('hex'), shard.toString('hex'), 'Decrypted message correct')

    const unboxed2 = s.unbox(cipherText, recipient.publicKey, sender.secretKey)
    assert.ok(unboxed2, 'Sender can also decrypt message')
    assert.equal(unboxed2.toString('hex'), shard.toString('hex'), 'Decrypted message correct')
    next()
  })

  context('bad ciphertext', (assert, next) => {
    const shard = Buffer.from(secret) // TODO: real shard

    const sender = s.keypair()
    const recipient = s.keypair()
    assert.ok(Buffer.isBuffer(sender.publicKey), 'public key is a buffer')
    assert.ok(Buffer.isBuffer(sender.secretKey), 'secret key is a buffer')

    const cipherText = s.box(shard, recipient.publicKey, sender.secretKey)
    assert.ok(Buffer.isBuffer(cipherText), 'ciphertext is a buffer')
    cipherText[0] = cipherText[0] === 1 ? 2 : 1

    const unboxed = s.unbox(cipherText, sender.publicKey, recipient.secretKey)
    assert.notOk(unboxed, 'Decryption fails')
    next()
  })
})

describe('privatebox box and unbox', (context) => {
  context('basic', (assert, next) => {
    const shard = Buffer.from(secret) // TODO: real shard
    const sender = s.keypair()
    const recipient = s.keypair()

    const cipherText = s.privateBox(shard, [recipient.publicKey])
    assert.ok(Buffer.isBuffer(cipherText), 'ciphertext is a buffer')

    const unboxed = s.privateUnbox(cipherText, recipient.secretKey)
    assert.ok(unboxed, 'Decryption successful')
    assert.equal(unboxed.toString('hex'), shard.toString('hex'), 'Decrypted message correct')

    const unboxed2 = s.oneWayUnbox(cipherText, sender.secretKey)
    assert.notOk(unboxed2, 'Sender cannot also decrypt message')
    next()
  })
})

describe('one-way box and unbox', (context) => {
  context('basic', (assert, next) => {
    const shard = Buffer.from(secret) // TODO: real shard
    const sender = s.keypair()
    const recipient = s.keypair()

    const cipherText = s.oneWayBox(shard, recipient.publicKey)
    assert.ok(Buffer.isBuffer(cipherText), 'ciphertext is a buffer')

    const unboxed = s.oneWayUnbox(cipherText, recipient.secretKey)
    assert.ok(unboxed, 'Decryption successful')
    assert.equal(unboxed.toString('hex'), shard.toString('hex'), 'Decrypted message correct')

    const unboxed2 = s.oneWayUnbox(cipherText, sender.secretKey)
    assert.notOk(unboxed2, 'Sender cannot also decrypt message')
    next()
  })

  context('bad ciphertext', (assert, next) => {
    const shard = Buffer.from(secret) // TODO: real shard
    const recipient = s.keypair()

    const cipherText = s.oneWayBox(shard, recipient.publicKey)
    assert.ok(Buffer.isBuffer(cipherText), 'ciphertext is a buffer')
    cipherText[0] = cipherText[0] === 1 ? 2 : 1

    const unboxed = s.oneWayUnbox(cipherText, recipient.secretKey)
    assert.notOk(unboxed, 'Decryption not successful')

    next()
  })
})
