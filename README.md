## Extra functions for Dark Crystal key backup

This adds:
 - packing secret together with a descriptive label using a protocol buffer.
 - signing a verifying shards

## API

```js
const packed = packLabel(secret, label)
```
```js
const { secret, label } = unpackLabel(packed)
```

```js
const keypair = singingKeypair()
```

```js
const signedShard = signShard(shard, keypair)
```
- shard is a buffer
- keypair is either a keypair object or a secret key given as a buffer.
- returns a buffer, which contains both the shard and the signature.

```js
const verifiedShard = openShard (signedShard, publicKey)
```
- publicKey is a buffer
- signedShard is a buffer
- returns either a buffer with the verified shard, or false if the shard could not be verified
