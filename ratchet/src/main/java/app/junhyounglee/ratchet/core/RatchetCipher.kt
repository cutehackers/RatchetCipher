package app.junhyounglee.ratchet.core

import java.nio.ByteBuffer

/**
 * End to end encryption implementation core
 */
class RatchetCipher {

  companion object {
    init {
      System.loadLibrary("ratchet")
      externalInit()
    }

    /**
     * crypto_kx_PUBLICKEYBYTES
     */
    const val PUBLIC_KEY_SIZE: Int = 32

    /**
     * crypto_kx_SECRETKEYBYTES
     */
    const val SECRET_KEY_SIZE: Int = 32

    /**
     * crypto_kx_SESSIONKEYBYTES
     */
    const val SESSION_KEY_SIZE: Int = 32

    @JvmStatic
    external fun externalInit()

    @JvmStatic
    external fun externalNewKeyPair(): KeyPair

    /**
     * @exception InvalidKeyException would be thrown if key size of either [publicKey] or [secretKey] is not
     * appropriate
     */
    @JvmStatic
    external fun externalKeyPair(publicKey: ByteArray, secretKey: ByteArray): KeyPair

    @JvmStatic
    external fun externalNewSharedSecretKeyForServer(
      serverKeyPair: KeyPair,
      clientPublicKey: ByteBuffer
    ): ByteBuffer

    @JvmStatic
    external fun externalNewSharedSecretKeyForClient(
      clientKeyPair: KeyPair,
      serverPublicKey: ByteBuffer
    ): ByteBuffer

    @JvmStatic
    external fun externalSessionSetUpForServer(
      sharedSecretKey: ByteBuffer,
      serverKeyPair: KeyPair,
      clientPublicKey: ByteBuffer
    ): RatchetSessionState

    @JvmStatic
    external fun externalSessionSetUpForClient(
      sharedSecretKey: ByteBuffer,
      clientKeyPair: KeyPair
    ): RatchetSessionState

    @JvmStatic
    external fun externalFreeSessionState(externalRef: Long)

    /**
     * Encrypt a plain byte array
     * @param externalRef initiator's ratchet native object reference.
     * @throws IllegalArgumentException if value of externalRef is invalid, this will throw.
     */
    @JvmStatic
    external fun externalEncrypt(externalRef: Long, plain: ByteArray): ByteArray

    /**
     * Decrypt a encrypted byte array
     * @param externalRef recipient's ratchet native object reference.
     * @throws IllegalArgumentException if value of externalRef is invalid, this will throw.
     */
    @JvmStatic
    external fun externalDecrypt(externalRef: Long, decrypted: ByteArray): ByteArray
  }
}


fun ByteArray.toHex(): String = StringBuffer().let { sb ->
  forEach {
    sb.append(byte2hex(it))
  }
  sb.toString()
}

fun ByteBuffer.toHex(): String = StringBuffer().let { sb ->
  rewind()
  while (hasRemaining()) {
    sb.append(byte2hex(get()))
  }
  sb.toString()
}

internal fun byte2hex(byte: Byte) = String(
  charArrayOf(
    Character.forDigit((byte.toInt() shr 4) and 0xF, 16),
    Character.forDigit(byte.toInt() and 0xF, 16)
  )
)

fun String.hexToByteArray(): ByteArray {
  require(length % 2 == 0) { "Valid hexadecimal string required! String length should be an even number in order to convert." }

  val hex2byte = { hex: String ->
    ((hex[0].toDigit(radix = 16) shl 4) + hex[1].toDigit(radix = 16)).toByte()
  }

  val bytes = ByteArray(length / 2)
  for (i in 0 until length step 2) {
    bytes[i / 2] = hex2byte(substring(i, i+2))
  }
  return bytes
}

internal fun String.hex2byte(): Byte {
  require(length > 1 && length % 2 == 0) { "String length should be 2 which is an event number." }
  return ((this[0].toDigit(radix = 16) shl 4) + this[1].toDigit(radix = 16)).toByte()
}

fun Char.toDigit(radix: Int = 10): Int {
  val digit = Character.digit(this, radix)
  if (digit == -1) {
    throw IllegalArgumentException("Error while converting char(${this}) to hexadecimal number.")
  }
  return digit
}
