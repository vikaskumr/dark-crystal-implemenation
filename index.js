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
  },

  signingKeypairToEncryptionKeypair (keypair) {
    const curveKeypair = {
      publicKey: sodium.sodium_malloc(sodium.crypto_box_PUBLICKEYBYTES),
      secretKey: sodium.sodium_malloc(sodium.crypto_box_SECRETKEYBYTES)
    }
    sodium.crypto_sign_ed25519_pk_to_curve25519(curveKeypair.publicKey, keypair.publicKey)
    sodium.crypto_sign_ed25519_sk_to_curve25519(curveKeypair.secretKey, keypair.secretKey)
    return curveKeypair
  },

  box (message, publicKey, secretKey) {
    const cipherText = sodium.sodium_malloc(message.length + sodium.crypto_box_MACBYTES)
    const nonce = randomBytes(sodium.crypto_box_NONCEBYTES)
    sodium.crypto_box_easy(cipherText, message, nonce, publicKey, secretKey)
    return Buffer.concat([nonce, cipherText])
  },

  unbox (cipherText, publicKey, secretKey) {
    assert(Buffer.isBuffer(cipherText), 'cipherText must be a buffer')
    assert(cipherText.length > sodium.crypto_box_MACBYTES, 'cipherText too short')
    const nonce = cipherText.slice(0, sodium.crypto_secretbox_NONCEBYTES)
    const messageWithMAC = cipherText.slice(sodium.crypto_secretbox_NONCEBYTES)
    const message = sodium.sodium_malloc(messageWithMAC.length - sodium.crypto_secretbox_MACBYTES)
    const decrypted = sodium.crypto_box_open_easy(message, messageWithMAC, nonce, publicKey, secretKey)
    return decrypted ? message : false
  }
}

function randomBytes (n) {
  const b = sodium.sodium_malloc(n)
  sodium.randombytes_buf(b)
  return b
}
