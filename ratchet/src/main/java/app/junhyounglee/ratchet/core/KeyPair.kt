package app.junhyounglee.ratchet.core

class KeyPair constructor(val publicKey: ByteArray, val secretKey: ByteArray) {
  operator fun component1(): ByteArray = publicKey
  operator fun component2(): ByteArray = secretKey
}