package app.junhyounglee.ratchet.core

/**
 * Please be careful when modifying class or package name.
 * This class holds states of ratchet session to be used for a ratchet cipher channel and the object
 * is created from JNI level.
 */
data class RatchetSessionState(internal val externalRef: Long): Destroyable {

  val isValidRef: Boolean = externalRef != 0L

  override fun destroy() {
    RatchetCipher.externalFreeSessionState(externalRef)
  }
}