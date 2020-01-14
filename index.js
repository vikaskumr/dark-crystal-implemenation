const protobuf = require('protocol-buffers')
const messages = protobuf(`
message Secret {
  required bytes secret = 1;
  optional string label = 2;
}
`)

module.exports = {
  packLabel (secret, label) {
    if (!Buffer.isBuffer(secret)) secret = Buffer.from(secret)
    return messages.Secret.encode({ secret, label })
  },

  unpackLabel (packedSecret) {
    return messages.Secret.decode(packedSecret)
  }
}
