const sodium = require('sodium-native')
const zero = sodium.sodium_memzero
const protobuf = require('protocol-buffers')
const assert = require('assert')
const privateBox = require('private-box')

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

  keypair () {
    const publicKey = sodium.sodium_malloc(sodium.crypto_sign_PUBLICKEYBYTES)
    const secretKey = sodium.sodium_malloc(sodium.crypto_sign_SECRETKEYBYTES)
    sodium.crypto_sign_keypair(publicKey, secretKey)
    return { publicKey, secretKey }
  },

  signShards (shards, keypair) {
    return shards.map(shard => this.signShard(shard, keypair))
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
    return signedShard
  },

  openShards (signedShards, publicKey) {
    return signedShards.map(shard => this.openShard(shard, publicKey))
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

  encryptionKeypair () {
    const keypair = {
      publicKey: sodium.sodium_malloc(sodium.crypto_box_PUBLICKEYBYTES),
      secretKey: sodium.sodium_malloc(sodium.crypto_box_SECRETKEYBYTES)
    }
    sodium.crypto_box_keypair(keypair.publicKey, keypair.secretKey)
    return keypair
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
    const curvePublicKey = sodium.sodium_malloc(sodium.crypto_box_PUBLICKEYBYTES)
    const curveSecretKey = sodium.sodium_malloc(sodium.crypto_box_SECRETKEYBYTES)
    sodium.crypto_sign_ed25519_pk_to_curve25519(curvePublicKey, publicKey)
    sodium.crypto_sign_ed25519_sk_to_curve25519(curveSecretKey, secretKey)

    const cipherText = sodium.sodium_malloc(message.length + sodium.crypto_box_MACBYTES)
    const nonce = this.randomBytes(sodium.crypto_box_NONCEBYTES)
    sodium.crypto_box_easy(cipherText, message, nonce, curvePublicKey, curveSecretKey)
    return Buffer.concat([nonce, cipherText])
  },

  privateBox (message, publicKeys) {
    if (Buffer.isBuffer(publicKeys)) publicKeys = [publicKeys]
    assert(publicKeys.length <= 2, 'Maximum two public keys allowed')
    const curvePublicKeys = []
    publicKeys.forEach((pk) => {
      const curvePublicKey = sodium.sodium_malloc(sodium.crypto_box_PUBLICKEYBYTES)
      sodium.crypto_sign_ed25519_pk_to_curve25519(curvePublicKey, pk)
      curvePublicKeys.push(curvePublicKey)
    })
    return privateBox.encrypt(message, curvePublicKeys, 2)
  },

  privateUnbox (cipherText, secretKey) {
    const curveSecretKey = sodium.sodium_malloc(sodium.crypto_box_SECRETKEYBYTES)
    sodium.crypto_sign_ed25519_sk_to_curve25519(curveSecretKey, secretKey)
    return privateBox.decrypt(cipherText, curveSecretKey, 2)
  },

  unbox (cipherText, publicKey, secretKey) {
    const curvePublicKey = sodium.sodium_malloc(sodium.crypto_box_PUBLICKEYBYTES)
    const curveSecretKey = sodium.sodium_malloc(sodium.crypto_box_SECRETKEYBYTES)
    sodium.crypto_sign_ed25519_pk_to_curve25519(curvePublicKey, publicKey)
    sodium.crypto_sign_ed25519_sk_to_curve25519(curveSecretKey, secretKey)

    assert(Buffer.isBuffer(cipherText), 'cipherText must be a buffer')
    assert(cipherText.length > sodium.crypto_box_MACBYTES + sodium.crypto_box_NONCEBYTES, 'cipherText too short')
    const nonce = cipherText.slice(0, sodium.crypto_box_NONCEBYTES)
    const messageWithMAC = cipherText.slice(sodium.crypto_box_NONCEBYTES)
    const message = sodium.sodium_malloc(messageWithMAC.length - sodium.crypto_box_MACBYTES)
    const decrypted = sodium.crypto_box_open_easy(message, messageWithMAC, nonce, curvePublicKey, curveSecretKey)
    return decrypted ? message : false
  },

  oneWayBox (message, publicKey) {
    const curvePublicKey = sodium.sodium_malloc(sodium.crypto_box_PUBLICKEYBYTES)
    sodium.crypto_sign_ed25519_pk_to_curve25519(curvePublicKey, publicKey)

    const ephemeral = this.encryptionKeypair()
    const nonce = this.randomBytes(sodium.crypto_box_NONCEBYTES)
    const cipherText = sodium.sodium_malloc(message.length + sodium.crypto_box_MACBYTES)
    sodium.crypto_box_easy(cipherText, message, nonce, curvePublicKey, ephemeral.secretKey)
    zero(ephemeral.secretKey)
    return Buffer.concat([nonce, ephemeral.publicKey, cipherText])
  },

  oneWayUnbox (cipherText, secretKey) {
    const curveSecretKey = sodium.sodium_malloc(sodium.crypto_box_SECRETKEYBYTES)
    sodium.crypto_sign_ed25519_sk_to_curve25519(curveSecretKey, secretKey)

    assert(Buffer.isBuffer(cipherText), 'cipherText must be a buffer')
    assert(cipherText.length > sodium.crypto_box_MACBYTES + sodium.crypto_box_PUBLICKEYBYTES + sodium.crypto_box_NONCEBYTES, 'cipherText too short')

    const nonce = cipherText.slice(0, sodium.crypto_box_NONCEBYTES)
    const ephemeralPublicKey = cipherText.slice(sodium.crypto_box_NONCEBYTES, sodium.crypto_box_NONCEBYTES + sodium.crypto_box_PUBLICKEYBYTES)
    const messageWithMAC = cipherText.slice(sodium.crypto_box_NONCEBYTES + sodium.crypto_box_PUBLICKEYBYTES)
    const message = sodium.sodium_malloc(messageWithMAC.length - sodium.crypto_box_MACBYTES)
    const decrypted = sodium.crypto_box_open_easy(message, messageWithMAC, nonce, ephemeralPublicKey, curveSecretKey)
    return decrypted ? message : false
  },

  randomBytes (n) {
    const b = sodium.sodium_malloc(n)
    sodium.randombytes_buf(b)
    return b
  },

  genericHash (message, key) {
    const hash = sodium.sodium_malloc(sodium.crypto_generichash_BYTES)
    sodium.crypto_generichash(hash, message, key)
    return hash
  }
}
