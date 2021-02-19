package app.junhyounglee.ratchet.core

import java.nio.ByteBuffer

class KeyPair constructor(val publicKey: ByteBuffer, val secretKey: ByteBuffer): Destroyable {
  operator fun component1(): ByteBuffer = publicKey
  operator fun component2(): ByteBuffer = secretKey

  override fun destroy() {
    JniCommon.externalFreeByteBuffer(publicKey)
    JniCommon.externalFreeByteBuffer(secretKey)
  }
}
