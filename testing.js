var sodium = require('sodium-native');
var ed25519KeyPair = signingKeypair() // Create an Ed25519 keypair
var x25519KeyPair = {
    publicKey: sodium.sodium_malloc(sodium.crypto_box_PUBLICKEYBYTES),
    secretKey: sodium.sodium_malloc(sodium.crypto_box_SECRETKEYBYTES)
}
sodium.crypto_sign_ed25519_pk_to_curve25519(x25519KeyPair.publicKey, ed25519KeyPair.publicKey) // Convert the public Ed25519 into a public X25519 key
sodium.crypto_sign_ed25519_sk_to_curve25519(x25519KeyPair.secretKey, ed25519KeyPair.secretKey) // Convert the secret Ed25519 into a secret X25519 key
console.log(x25519KeyPair.publicKey.toString('hex'));
console.log(x25519KeyPair.secretKey.toString('hex'));

function signingKeypair () {
    const keypair = {
        publicKey: sodium.sodium_malloc(sodium.crypto_sign_PUBLICKEYBYTES),
        secretKey: sodium.sodium_malloc(sodium.crypto_sign_SECRETKEYBYTES)
    }
    sodium.crypto_sign_keypair(keypair.publicKey, keypair.secretKey)
    return keypair
}

function encryptionKeypair () {
    const keypair = {
      publicKey: sodium.sodium_malloc(sodium.crypto_box_PUBLICKEYBYTES),
      secretKey: sodium.sodium_malloc(sodium.crypto_box_SECRETKEYBYTES)
    }
    sodium.crypto_box_keypair(keypair.publicKey, keypair.secretKey)
    return keypair
  }