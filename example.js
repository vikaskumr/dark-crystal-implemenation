const secrets = require('secret-sharing')
const s = require('.')

const secret = s.randomBytes(32)
const label = 'My private key'

console.log('Secret to share:', secret.toString('hex'))

console.log(`Packing with label: '${label}'`)
const packedSecret = s.packLabel(secret, label)
console.log(`Packed secret: ${packedSecret.toString('hex')}`)
console.log(`Length of packed secret is ${packedSecret.length} bytes.`)
const signingKeypair = s.signingKeypair()
const encryptionKeypair = s.signingKeypairToEncryptionKeypair(signingKeypair)

const custodians = []
for (let i = 0; i < 5; i++) {
  custodians.push(s.encryptionKeypair())
}

console.log('Creating 5 shares, 3 needed to recover')
secrets.share(packedSecret, 5, 3).then((shards) => {
  console.log('Shards:')
  console.log(shards.map(s => s.toString('hex')))
  console.log('Signed shards:')
  const signedShards = s.signShards(shards, signingKeypair)
  console.log(signedShards.map(s => s.toString('hex')))

  const boxedShards = signedShards.map((shard, i) => {
    return s.oneWayBox(shard, custodians[i].publicKey)
  })
  console.log('Boxed shards:')
  console.log(boxedShards.map(s => s.toString('hex')))
  console.log(`Length of boxed shards are ${boxedShards[0].length} bytes.`)
  // secrets.combine(shards.slice(2)).then((result) => {
  //   console.log('Result of recombining 3 shares:', result.toString())
  // })
})
