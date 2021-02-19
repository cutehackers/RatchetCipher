package app.junhyounglee.ratchet.core

import java.nio.ByteBuffer

object JniCommon {
  @JvmStatic
  external fun externalNewByteBuffer(size: Int): ByteBuffer

  @JvmStatic
  external fun externalFreeByteBuffer(buffer: ByteBuffer)
}