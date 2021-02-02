package app.junhyounglee.ratchet.core

class KeyPair constructor(val publicKey: ByteArray, val secretKey: ByteArray): Destroyable {
  operator fun component1(): ByteArray = publicKey
  operator fun component2(): ByteArray = secretKey

  override fun destroy() {
    publicKey.fill(0)
    secretKey.fill(0)
  }
}