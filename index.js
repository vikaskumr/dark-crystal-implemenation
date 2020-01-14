const sodium = require('sodium-native')
const zero = sodium.sodium_memzero
const protobuf = require('protocol-buffers')
const assert = require('assert')

const messages = protobuf(`
message Secret {
  required bytes secret = 1;
  optional string label = 2;
}
`)

module.exports = {
  packLabel (secret, label) {
    if (!Buffer.isBuffer(secret)) secret = Buffer.from(secret)
    assert(typeof label === 'string' || !label, 'label, if given, must be a string')
    return messages.Secret.encode({ secret, label })
  },

  unpackLabel (packedSecret) {
    assert(Buffer.isBuffer(packedSecret), 'packedSecret must be a buffer')
    return messages.Secret.decode(packedSecret)
  },

  signingKeypair () {
    const publicKey = sodium.sodium_malloc(sodium.crypto_sign_PUBLICKEYBYTES)
    const secretKey = sodium.sodium_malloc(sodium.crypto_sign_SECRETKEYBYTES)
    sodium.crypto_sign_keypair(publicKey, secretKey)
    return { publicKey, secretKey }
  },

  signShard (shard, keypair) {
    const secretKey = typeof keypair === 'object' ? keypair.secretKey : keypair
    assert(Buffer.isBuffer(secretKey), 'secret key must be a buffer')
    assert(secretKey.length === sodium.crypto_sign_SECRETKEYBYTES, 'secret key is incorrect length')
    // TODO accept shard as hex
    assert(Buffer.isBuffer(shard), 'Badly formed shard')
    // TODO: optionally use crypto_sign_detached and store the signature separately
    const signedShard = sodium.sodium_malloc(sodium.crypto_sign_BYTES + shard.length)
    sodium.crypto_sign(signedShard, shard, secretKey)
    zero(secretKey)
    return signedShard
  },

  openShard (signedShard, publicKey) {
    assert(Buffer.isBuffer(publicKey), 'publicKey must be a buffer')
    assert(publicKey.length === sodium.crypto_sign_PUBLICKEYBYTES, 'publicKey is incorrect length')
    assert(Buffer.isBuffer(signedShard), 'signedShard must be a buffer')
    assert(signedShard.length > sodium.crypto_sign_BYTES, 'signedShard is too short')
    const shard = sodium.sodium_malloc(signedShard.length - sodium.crypto_sign_BYTES)
    const verified = sodium.crypto_sign_open(shard, signedShard, publicKey)
    return verified ? shard : false
  }
}
